// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
// RFC 9111: HTTP Caching implementation
#include "Cache.h"
#include <algorithm>
#include <ctime>
#include <sstream>
#include <cstring>

namespace httpd {

// ── CacheControl::parse (RFC 9111 §5.2) ──────────────────────────────────────
CacheControl CacheControl::parse(std::string_view v) {
    CacheControl cc;
    while(!v.empty()) {
        auto comma=v.find(','); auto tok=v.substr(0,comma);
        // trim
        while(!tok.empty()&&tok[0]==' ') tok=tok.substr(1);
        while(!tok.empty()&&tok.back()==' ') tok=tok.substr(0,tok.size()-1);

        auto eq=tok.find('=');
        auto dir=(eq==std::string_view::npos)?tok:tok.substr(0,eq);
        // trim dir
        while(!dir.empty()&&(dir.back()==' '||dir.front()==' '))
            dir=(dir.front()==' ')?dir.substr(1):dir.substr(0,dir.size()-1);

        auto getNum=[&]()->int64_t {
            if(eq==std::string_view::npos) return -1;
            auto s=tok.substr(eq+1);
            while(!s.empty()&&s[0]==' ') s=s.substr(1);
            if(!s.empty()&&s[0]=='"') { s=s.substr(1); auto q=s.find('"'); if(q!=std::string_view::npos) s=s.substr(0,q); }
            char tmp[32]; size_t l=std::min(s.size(),(size_t)31); memcpy(tmp,s.data(),l); tmp[l]=0;
            return strtoll(tmp,nullptr,10);
        };

        auto deqi=[](std::string_view a, const char* b)->bool{
            size_t lb=strlen(b);
            if(a.size()!=lb) return false;
            for(size_t i=0;i<lb;++i) if((a[i]|32)!=(b[i]|32)) return false;
            return true;
        };

        if     (deqi(dir,"no-cache"))            cc.noCache=true;
        else if(deqi(dir,"no-store"))            cc.noStore=true;
        else if(deqi(dir,"only-if-cached"))      cc.onlyIfCached=true;
        else if(deqi(dir,"must-revalidate"))     cc.mustRevalidate=true;
        else if(deqi(dir,"proxy-revalidate"))    cc.proxyRevalidate=true;
        else if(deqi(dir,"no-transform"))        cc.noTransform=true;
        else if(deqi(dir,"public"))              cc.isPublic=true;
        else if(deqi(dir,"private"))             cc.isPrivate=true;
        else if(deqi(dir,"immutable"))           cc.immutable=true;
        else if(deqi(dir,"max-age"))             cc.maxAge=getNum();
        else if(deqi(dir,"s-maxage"))            cc.sMaxAge=getNum();
        else if(deqi(dir,"max-stale"))           cc.maxStale=getNum();
        else if(deqi(dir,"min-fresh"))           cc.minFresh=getNum();
        else if(deqi(dir,"stale-while-revalidate")) cc.staleWhileRevalidate=getNum();

        if(comma==std::string_view::npos) break;
        v=v.substr(comma+1);
    }
    return cc;
}

// ── CacheEntry age/freshness (RFC 9111 §5.1) ─────────────────────────────────
int64_t CacheEntry::currentAge() const {
    time_t now; time(&now);
    int64_t age=(int64_t)(now-storedAt); // simplified: no age_value/response_delay
    return age;
}
int64_t CacheEntry::freshnessLifetime() const {
    if(maxAge>=0) return maxAge;
    if(expires>0&&date>0) return (int64_t)(expires-date);
    // Heuristic: 10% of (now - last-modified) (RFC 9111 §4.2.2)
    if(lastModified>0&&storedAt>0) {
        int64_t lmAge=(int64_t)(storedAt-lastModified);
        return lmAge/10;
    }
    return 0; // not cacheable without explicit freshness
}

// ── HttpCache ─────────────────────────────────────────────────────────────────
HttpCache::HttpCache() {}
HttpCache::HttpCache(Config cfg) : cfg_(std::move(cfg)) {}

std::string HttpCache::makeKey(const RawRequest& req) const {
    // RFC 9111 §2: primary cache key = effective request URI
    auto host=req.headers.get("host");
    return "http://"+std::string(host)+req.url.path+(req.url.query.empty()?"":"?"+req.url.query);
}

std::string HttpCache::varyKey(const RawRequest& req, const std::vector<std::string>& vary) const {
    std::string k;
    for(const auto& name:vary) { k+=name+"="+std::string(req.headers.get(name))+";"; }
    return k;
}

bool HttpCache::isCacheable(const RawRequest& req, const RawResponse& resp) {
    // Only cache GET/HEAD (RFC 9111 §4)
    if(req.method!=Method::GET&&req.method!=Method::HEAD) return false;

    // Check request Cache-Control
    auto cc=CacheControl::parse(req.headers.get("cache-control"));
    if(cc.noStore) return false;

    // Check response Cache-Control
    auto rcc=CacheControl::parse(resp.headers.get("cache-control"));
    if(rcc.noStore)  return false;
    if(rcc.isPrivate)return false;

    // Partial content can never be stored: makeKey() is the effective URI alone
    // with no range in it, so a stored 206 would be replayed — status,
    // Content-Range and truncated body — to a later request for the whole
    // representation. Rejected here, before the status-list logic below, because
    // that logic re-admits any status carrying an explicit max-age, and static
    // responses (206 included) always carry one.
    if(resp.statusCode==206 || resp.headers.has("content-range")) return false;

    // Cacheable status codes (RFC 9111 §4.2.1, §3.2). 206 handled above.
    static const int cacheable[]={200,203,204,300,301,302,404,405,410,414,501};
    bool okStatus=false;
    for(int s:cacheable) if(resp.statusCode==s){okStatus=true;break;}
    if(!okStatus) {
        // Also cacheable if explicit max-age/expires
        if(rcc.maxAge<0&&resp.headers.get("expires").empty()) return false;
        okStatus=true;
    }

    return okStatus;
}

std::shared_ptr<CacheEntry> HttpCache::lookup(const RawRequest& req) {
    if(req.method!=Method::GET&&req.method!=Method::HEAD) return nullptr;

    auto cc=CacheControl::parse(req.headers.get("cache-control"));
    if(cc.noStore) return nullptr;

    std::string key=makeKey(req);
    std::lock_guard<std::mutex> lk(mu_);
    auto it=mem_.find(key);
    if(it==mem_.end()) return nullptr;
    auto& e=it->second;

    // Vary matching (RFC 9111 §4.1)
    if(!e->varyHeaders.empty()) {
        std::string vk=varyKey(req,e->varyHeaders);
        if(vk!=e->varyValues) return nullptr;
    }

    // no-cache: must revalidate
    if(cc.noCache) return nullptr; // treat as miss for simplicity

    return e;
}

void HttpCache::store(const RawRequest& req, const RawResponse& resp) {
    if(!isCacheable(req,resp)) return;

    auto entry=std::make_shared<CacheEntry>();
    entry->url=makeKey(req);
    entry->statusCode=resp.statusCode;
    entry->headers=resp.headers;
    entry->body=resp.body;
    entry->size=resp.body.size()+512; // headers approx
    time(&entry->storedAt);

    // Date
    auto dateStr=resp.headers.get("date");
    entry->date=dateStr.empty()?entry->storedAt:parseHttpDate(dateStr);

    // Expires
    auto expStr=resp.headers.get("expires");
    if(!expStr.empty()) entry->expires=parseHttpDate(expStr);

    // Cache-Control max-age
    auto cc=CacheControl::parse(resp.headers.get("cache-control"));
    if(cc.sMaxAge>=0)       entry->maxAge=cc.sMaxAge;
    else if(cc.maxAge>=0)   entry->maxAge=cc.maxAge;

    // Last-Modified
    auto lm=resp.headers.get("last-modified");
    if(!lm.empty()) entry->lastModified=parseHttpDate(lm);

    // ETag
    entry->etag=std::string(resp.headers.get("etag"));

    // Vary (RFC 9111 §4.1)
    auto vary=resp.headers.get("vary");
    if(vary=="*") return; // never store vary:*
    if(!vary.empty()) {
        // Split comma-separated
        std::string vstr(vary); std::istringstream ss(vstr); std::string token;
        while(std::getline(ss,token,',')) {
            while(!token.empty()&&token[0]==' ') token=token.substr(1);
            while(!token.empty()&&token.back()==' ') token.pop_back();
            if(!token.empty()) entry->varyHeaders.push_back(token);
        }
        entry->varyValues=varyKey(req,entry->varyHeaders);
    }

    std::lock_guard<std::mutex> lk(mu_);
    evict(entry->size);
    mem_[entry->url]=entry;
    memBytes_+=entry->size;
}

void HttpCache::invalidate(const std::string& url) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it=mem_.find(url);
    if(it!=mem_.end()) { memBytes_-=it->second->size; mem_.erase(it); }
}

void HttpCache::update304(const std::string& key, const RawResponse& resp304) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it=mem_.find(key);
    if(it==mem_.end()) return;
    auto& e=it->second;
    // Update headers that were returned in 304
    for(const auto& h:resp304.headers.list) {
        // Only update validators and caching headers (RFC 9111 §4.3.4)
        auto n=h.name;
        if(n=="etag"||n=="last-modified"||n=="cache-control"||
           n=="expires"||n=="content-length") {
            e->headers.set(h.name,h.value);
        }
    }
    time(&e->storedAt); // reset age
}

void HttpCache::addConditionals(const CacheEntry& e, RawRequest& out) {
    if(!e.etag.empty())        out.headers.set("if-none-match",e.etag);
    if(e.lastModified>0)       out.headers.set("if-modified-since",httpDate(e.lastModified));
}

void HttpCache::evict(size_t need) {
    // Simple LRU-ish: remove oldest entries
    while(memBytes_+need>cfg_.maxMemBytes&&!mem_.empty()) {
        auto oldest=mem_.begin();
        for(auto it=mem_.begin();it!=mem_.end();++it)
            if(it->second->storedAt<oldest->second->storedAt) oldest=it;
        memBytes_-=oldest->second->size;
        mem_.erase(oldest);
    }
    while(mem_.size()>=cfg_.maxMemEntries&&!mem_.empty()) {
        auto oldest=mem_.begin();
        memBytes_-=oldest->second->size;
        mem_.erase(oldest);
    }
}

size_t HttpCache::entries() const { std::lock_guard<std::mutex> lk(mu_); return mem_.size(); }
size_t HttpCache::bytes()   const { std::lock_guard<std::mutex> lk(mu_); return memBytes_; }
void   HttpCache::purge()         { std::lock_guard<std::mutex> lk(mu_); mem_.clear(); memBytes_=0; }

} // namespace httpd
