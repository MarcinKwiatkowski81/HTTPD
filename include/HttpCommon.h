// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
// RFC 9110: HTTP Semantics — core types
#pragma once
#include "common.h"
#include <string>
#include <cctype>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <time.h>

namespace httpd {

// ── HTTP Methods (RFC 9110 §9) ────────────────────────────────────────────────
enum class Method : uint8_t {
    UNKNOWN=0, GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH
};
inline Method methodFromStr(std::string_view s) {
    if(s=="GET")     return Method::GET;
    if(s=="HEAD")    return Method::HEAD;
    if(s=="POST")    return Method::POST;
    if(s=="PUT")     return Method::PUT;
    if(s=="DELETE")  return Method::DELETE;
    if(s=="CONNECT") return Method::CONNECT;
    if(s=="OPTIONS") return Method::OPTIONS;
    if(s=="TRACE")   return Method::TRACE;
    if(s=="PATCH")   return Method::PATCH;
    return Method::UNKNOWN;
}
inline const char* methodStr(Method m) {
    switch(m) {
    case Method::GET:     return "GET";
    case Method::HEAD:    return "HEAD";
    case Method::POST:    return "POST";
    case Method::PUT:     return "PUT";
    case Method::DELETE:  return "DELETE";
    case Method::CONNECT: return "CONNECT";
    case Method::OPTIONS: return "OPTIONS";
    case Method::TRACE:   return "TRACE";
    case Method::PATCH:   return "PATCH";
    default:              return "UNKNOWN";
    }
}
inline bool methodSafe(Method m)      { return m==Method::GET||m==Method::HEAD||m==Method::OPTIONS||m==Method::TRACE; }
inline bool methodIdempotent(Method m){ return methodSafe(m)||m==Method::PUT||m==Method::DELETE; }

// ── HTTP Version ──────────────────────────────────────────────────────────────
enum class HttpVersion : uint8_t { HTTP10=0, HTTP11, HTTP2, HTTP3 };

// ── Status codes (RFC 9110 §15) ───────────────────────────────────────────────
struct Status {
    static const char* reason(int code) {
        switch(code) {
        case 100: return "Continue";
        case 101: return "Switching Protocols";
        case 200: return "OK";
        case 201: return "Created";
        case 202: return "Accepted";
        case 204: return "No Content";
        case 206: return "Partial Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 303: return "See Other";
        case 304: return "Not Modified";
        case 307: return "Temporary Redirect";
        case 308: return "Permanent Redirect";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 406: return "Not Acceptable";
        case 408: return "Request Timeout";
        case 409: return "Conflict";
        case 410: return "Gone";
        case 411: return "Length Required";
        case 412: return "Precondition Failed";
        case 413: return "Content Too Large";
        case 414: return "URI Too Long";
        case 415: return "Unsupported Media Type";
        case 416: return "Range Not Satisfiable";
        case 422: return "Unprocessable Content";
        case 429: return "Too Many Requests";
        case 431: return "Request Header Fields Too Large";
        case 500: return "Internal Server Error";
        case 501: return "Not Implemented";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        case 505: return "HTTP Version Not Supported";
        default:  return "Unknown";
        }
    }
};

// ── Single HTTP header ─────────────────────────────────────────────────────────
struct Header {
    std::string name;
    std::string value;
};

// ── HTTP Headers collection ───────────────────────────────────────────────────
struct Headers {
    std::vector<Header> list;

    void set(std::string_view name, std::string_view value) {
        for(auto& h:list) if(eqi(h.name,name)){ h.value=value; return; }
        list.push_back({std::string(name),std::string(value)});
    }
    void add(std::string_view name, std::string_view value) {
        list.push_back({std::string(name),std::string(value)});
    }
    void remove(std::string_view name) {
        list.erase(std::remove_if(list.begin(),list.end(),
            [&](const Header& h){ return eqi(h.name,name); }), list.end());
    }
    std::string_view get(std::string_view name) const {
        for(const auto& h:list) if(eqi(h.name,name)) return h.value;
        return {};
    }
    bool has(std::string_view name) const { return !get(name).empty(); }
    bool contains(std::string_view name, std::string_view val) const {
        auto v=get(name); return v.find(val)!=std::string_view::npos;
    }
    void clear() { list.clear(); }
    size_t size() const { return list.size(); }

    static bool eqi(std::string_view a, std::string_view b) {
        if(a.size()!=b.size()) return false;
        for(size_t i=0;i<a.size();++i)
            if((a[i]|32)!=(b[i]|32)) return false;
        return true;
    }
};

// ── Cookie (RFC 6265) ─────────────────────────────────────────────────────────
struct Cookie {
    std::string name;
    std::string value;
    std::string path    = "/";
    std::string domain;
    std::string sameSite= "Lax";      // Strict | Lax | None
    int64_t     maxAge  = -1;         // -1 = session cookie
    bool        secure  = false;
    bool        httpOnly= false;

    // Format Set-Cookie header value
    std::string format() const {
        std::string s = name + "=" + value;
        if(!path.empty())    s+="; Path="+path;
        if(!domain.empty())  s+="; Domain="+domain;
        if(maxAge>=0)        s+="; Max-Age="+std::to_string(maxAge);
        if(secure)           s+="; Secure";
        if(httpOnly)         s+="; HttpOnly";
        if(!sameSite.empty())s+="; SameSite="+sameSite;
        return s;
    }
};

// ── URL components ────────────────────────────────────────────────────────────
struct Url {
    std::string scheme;
    std::string host;
    uint16_t    port    = 0;
    std::string path;
    std::string query;
    std::string fragment;

    // Parse query string into key=value pairs
    std::unordered_map<std::string,std::string> parseQuery() const {
        std::unordered_map<std::string,std::string> m;
        const char* p=query.c_str();
        while(*p) {
            const char* eq=strchr(p,'=');
            const char* amp=strchr(p,'&');
            if(!amp) amp=p+strlen(p);
            if(eq&&eq<amp) {
                m[urlDecode({p,(size_t)(eq-p)})] = urlDecode({eq+1,(size_t)(amp-eq-1)});
            }
            p=*amp?amp+1:amp;
        }
        return m;
    }

    static std::string urlDecode(std::string_view s) {
        std::string out; out.reserve(s.size());
        for(size_t i=0;i<s.size();++i) {
            if(s[i]=='%'&&i+2<s.size()) {
                auto h=[](char c)->int{
                    if(c>='0'&&c<='9') return c-'0';
                    if(c>='a'&&c<='f') return c-'a'+10;
                    if(c>='A'&&c<='F') return c-'A'+10;
                    return -1;
                };
                int hi=h(s[i+1]),lo=h(s[i+2]);
                if(hi>=0&&lo>=0){ out+=(char)((hi<<4)|lo); i+=2; continue; }
            } else if(s[i]=='+') { out+=' '; continue; }
            out+=s[i];
        }
        return out;
    }
    static std::string urlEncode(std::string_view s) {
        static const char hex[]="0123456789ABCDEF";
        std::string out; out.reserve(s.size()*3);
        for(unsigned char c:s) {
            if(isalnum(c)||c=='-'||c=='_'||c=='.'||c=='~') out+=c;
            else { out+='%'; out+=hex[c>>4]; out+=hex[c&15]; }
        }
        return out;
    }
};

// ── MIME types ────────────────────────────────────────────────────────────────
inline const char* mimeFromExt(std::string_view ext) {
    if(ext=="html"||ext=="htm") return "text/html; charset=utf-8";
    if(ext=="css")              return "text/css; charset=utf-8";
    if(ext=="js")               return "application/javascript; charset=utf-8";
    if(ext=="json")             return "application/json";
    if(ext=="xml")              return "application/xml";
    if(ext=="png")              return "image/png";
    if(ext=="jpg"||ext=="jpeg") return "image/jpeg";
    if(ext=="gif")              return "image/gif";
    if(ext=="svg")              return "image/svg+xml";
    if(ext=="ico")              return "image/x-icon";
    if(ext=="woff")             return "font/woff";
    if(ext=="woff2")            return "font/woff2";
    if(ext=="ttf")              return "font/ttf";
    if(ext=="pdf")              return "application/pdf";
    if(ext=="zip")              return "application/zip";
    if(ext=="gz")               return "application/gzip";
    if(ext=="txt"||ext=="log")  return "text/plain; charset=utf-8";
    if(ext=="csv")              return "text/csv; charset=utf-8";
    if(ext=="mp4")              return "video/mp4";
    if(ext=="mp3")              return "audio/mpeg";
    if(ext=="webm")             return "video/webm";
    if(ext=="ogg")              return "audio/ogg";
    if(ext=="lua")              return "application/x-lua";
    if(ext=="wasm")             return "application/wasm";
    return "application/octet-stream";
}

// ── HTTP Date (RFC 9110 §5.6.7) IMF-fixdate ───────────────────────────────────
inline std::string httpDate(time_t t = 0) {
    if(!t) time(&t);
    struct tm tm{}; gmtime_r(&t,&tm);
    char buf[64];
    strftime(buf,sizeof buf,"%a, %d %b %Y %H:%M:%S GMT",&tm);
    return buf;
}
inline time_t parseHttpDate(std::string_view s) {
    struct tm tm{}; char buf[64];
    size_t n=std::min(s.size(),sizeof buf-1);
    memcpy(buf,s.data(),n); buf[n]=0;
    // Try IMF-fixdate, RFC 850, asctime
    if(strptime(buf,"%a, %d %b %Y %H:%M:%S GMT",&tm)) return timegm(&tm);
    if(strptime(buf,"%A, %d-%b-%y %H:%M:%S GMT",&tm)) return timegm(&tm);
    if(strptime(buf,"%a %b %d %H:%M:%S %Y",&tm))      return timegm(&tm);
    return 0;
}

// ── ETag ──────────────────────────────────────────────────────────────────────
struct ETag {
    std::string value;  // without quotes
    bool weak = false;
    std::string format() const { return weak ? "W/\""+value+"\"" : "\""+value+"\""; }
    static ETag parse(std::string_view s) {
        ETag e;
        if(s.substr(0,3)=="W/\"") { e.weak=true; s=s.substr(3); }
        else if(s[0]=='\"') s=s.substr(1);
        if(!s.empty()&&s.back()=='\"') s=s.substr(0,s.size()-1);
        e.value=std::string(s); return e;
    }
    bool matches(const ETag& o) const {
        if(weak||o.weak) return value==o.value; // weak comparison
        return value==o.value;
    }
};

// ── Range (RFC 9110 §14.1) ────────────────────────────────────────────────────
struct Range { int64_t first=-1, last=-1; };

// Parse a byte-range set against a known representation size, returning only
// satisfiable ranges with the RFC's clamping applied:
//   "bytes=0-1023" on a 500-byte file  → 0-499   (truncated, NOT rejected)
//   "bytes=-9999"  on a 500-byte file  → 0-499   (suffix longer than the whole)
//   "bytes=500-"   on a 500-byte file  → dropped (first byte past the end)
// So an empty result for a well-formed "bytes=" header means genuinely
// unsatisfiable, which is what lets a caller answer 416 rather than guess.
// Digits are parsed within the view rather than with strtoll(sv.data()), which
// would read past a non-null-terminated string_view.
namespace detail {
inline std::string_view trimOws(std::string_view s) {
    while(!s.empty() && (s.front()==' '||s.front()=='\t')) s.remove_prefix(1);
    while(!s.empty() && (s.back() ==' '||s.back() =='\t')) s.remove_suffix(1);
    return s;
}
inline bool allDigits(std::string_view s) {
    if(s.empty()) return false;
    for(char c : s) if(c < '0' || c > '9') return false;
    return true;
}
// Strip the "bytes=" unit prefix, returning false if the unit is absent or is
// some other (undefined, must-ignore) range unit.
inline bool stripBytesUnit(std::string_view& v) {
    auto eq = v.find('=');
    if(eq == std::string_view::npos) return false;
    if(trimOws(v.substr(0, eq)) != "bytes") return false;
    v = v.substr(eq + 1);
    return true;
}
} // namespace detail

// True when `v` is a syntactically well-formed byte-range-set, regardless of
// whether any range is satisfiable. Callers need this distinction because the
// two failures have different responses: an unparseable Range must be IGNORED
// (answer 200 with the whole representation), while a well-formed but
// unsatisfiable one is a 416.
inline bool rangeSyntaxValid(std::string_view v) {
    if(!detail::stripBytesUnit(v)) return false;
    if(detail::trimOws(v).empty()) return false;
    bool any = false;
    while(!v.empty()) {
        auto comma = v.find(',');
        auto chunk = detail::trimOws(v.substr(0, comma));
        v = (comma == std::string_view::npos) ? std::string_view{} : v.substr(comma + 1);
        if(chunk.empty()) continue;                  // tolerate empty list elements
        auto dash = chunk.find('-');
        if(dash == std::string_view::npos) return false;
        auto fs = detail::trimOws(chunk.substr(0, dash));
        auto ls = detail::trimOws(chunk.substr(dash + 1));
        if(fs.empty() && ls.empty()) return false;   // bare "-" is meaningless
        if(!fs.empty() && !detail::allDigits(fs)) return false;
        if(!ls.empty() && !detail::allDigits(ls)) return false;
        any = true;
    }
    return any;
}

inline std::vector<Range> parseRange(std::string_view v, int64_t total) {
    std::vector<Range> out;
    auto trim = detail::trimOws;
    // Only the "bytes" unit is defined; any other unit must be ignored.
    if(!detail::stripBytesUnit(v)) return out;
    if(total <= 0) return out;   // nothing in a zero-length representation is satisfiable

    auto num = [](std::string_view s, int64_t& n) {
        if(!detail::allDigits(s)) return false;
        n = 0;
        for(char ch : s) {
            if(n > (INT64_MAX - (ch - '0')) / 10) return false;   // overflow
            n = n * 10 + (ch - '0');
        }
        return true;
    };

    while(!v.empty()) {
        auto comma = v.find(',');
        auto chunk = trim(v.substr(0, comma));
        v = (comma == std::string_view::npos) ? std::string_view{} : v.substr(comma + 1);

        auto dash = chunk.find('-');
        if(dash == std::string_view::npos) continue;
        auto fs = trim(chunk.substr(0, dash));
        auto ls = trim(chunk.substr(dash + 1));

        Range r;
        int64_t a = 0, b = 0;
        if(fs.empty()) {                       // suffix-range: final N bytes
            if(!num(ls, b) || b <= 0) continue;
            r.first = (b >= total) ? 0 : total - b;
            r.last  = total - 1;
        } else {
            if(!num(fs, a) || a >= total) continue;
            r.first = a;
            if(ls.empty())            r.last = total - 1;
            else if(!num(ls, b))      continue;
            else if(b < a)            continue;
            else                      r.last = (b >= total) ? total - 1 : b;
        }
        if(r.first < 0 || r.last < r.first) continue;
        out.push_back(r);
    }
    return out;
}

} // namespace httpd
