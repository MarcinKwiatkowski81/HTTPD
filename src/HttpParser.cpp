// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
// RFC 9112: HTTP/1.1 parser implementation
#include "HttpParser.h"
#include <algorithm>
#include <cctype>

namespace httpd {

Http1Parser::Http1Parser() { reset(); }

void Http1Parser::reset() {
    phase_  = Phase::RequestLine;
    state_  = ParseState::Incomplete;
    errCode_= 400;
    req_    = RawRequest{};
    lineBuf_.clear();
    bodyRemain_=0; chunkSize_=0; chunkSizeBuf_.clear();
}

// Consume one line (terminated by CRLF or LF) from [data,data+len).
// Returns number of bytes consumed (including the terminator), or 0 if no line yet.
static size_t scanLine(const char* data, size_t len, std::string& out) {
    for(size_t i=0;i<len;++i) {
        if(data[i]=='\n') {
            out.append(data,(data[i-1]=='\r'&&i>0)?i-1:i);
            return i+1;
        }
    }
    return 0;
}

static std::string_view trim(std::string_view s) {
    while(!s.empty()&&(s.front()==' '||s.front()=='\t')) s=s.substr(1);
    while(!s.empty()&&(s.back() ==' '||s.back() =='\t')) s=s.substr(0,s.size()-1);
    return s;
}
static std::string toLower(std::string_view s) {
    std::string r(s); for(auto& c:r) c=(char)tolower((unsigned char)c); return r;
}

size_t Http1Parser::feed(const char* data, size_t len) {
    if(state_!=ParseState::Incomplete) return 0;
    size_t consumed=0;

    while(consumed<len && phase_!=Phase::Done && phase_!=Phase::Err) {
        switch(phase_) {
        case Phase::RequestLine:
        case Phase::Headers:
        case Phase::ChunkSize:
        case Phase::ChunkTrailer: {
            // Line-oriented phases
            std::string lineTmp;
            size_t n=scanLine(data+consumed,len-consumed,lineTmp);
            if(!n) { lineBuf_.append(data+consumed,len-consumed); consumed=len; break; }
            consumed+=n;
            // Combine any buffered prefix
            std::string full=lineBuf_+lineTmp; lineBuf_.clear();

            std::string_view line(full);

            if(phase_==Phase::RequestLine) {
                if(!parseRequestLine(line)) { phase_=Phase::Err; break; }
                phase_=Phase::Headers;
            } else if(phase_==Phase::Headers) {
                if(line.empty()) {
                    // End of headers
                    if(!finaliseHeaders()) { phase_=Phase::Err; break; }
                } else {
                    if(!parseHeaderLine(line)) { phase_=Phase::Err; break; }
                }
            } else if(phase_==Phase::ChunkSize) {
                // RFC 9112 §7.1: chunk-size in hex
                auto semi=line.find(';'); // extensions ignored
                auto hexPart=trim(line.substr(0,semi));
                chunkSize_=0;
                for(char c:hexPart) {
                    int d=-1;
                    if(c>='0'&&c<='9') d=c-'0';
                    else if(c>='a'&&c<='f') d=c-'a'+10;
                    else if(c>='A'&&c<='F') d=c-'A'+10;
                    if(d<0){ phase_=Phase::Err; break; }
                    chunkSize_=chunkSize_*16+d;
                    if(chunkSize_>(int64_t)kMaxBodyBuf){ errCode_=413; phase_=Phase::Err; break; }
                }
                if(phase_==Phase::Err) break;
                if(chunkSize_==0) { phase_=Phase::ChunkTrailer; }
                else              { phase_=Phase::ChunkData; }
            } else { // ChunkTrailer
                if(line.empty()) { phase_=Phase::Done; }
                // else: trailer header — ignored per RFC
            }
            break;
        }
        case Phase::ChunkData: {
            // Read chunkSize_ bytes then a CRLF
            size_t need=(size_t)chunkSize_+2; // +CRLF
            size_t avail=len-consumed;
            if(avail<need) {
                // Buffer partial chunk
                size_t take=std::min(avail,(size_t)chunkSize_-(req_.body.size()%((size_t)chunkSize_+2)));
                // Simpler: just append up to chunkSize_, skip CRLF later
                size_t bodyNeed=(size_t)chunkSize_-std::min((size_t)chunkSize_,req_.body.size()%65537);
                // Actually track with bodyRemain_
                (void)take; (void)bodyNeed;
                // Simplified: accumulate in bodyRemain_ counter
                size_t canTake=std::min(avail,(size_t)bodyRemain_);
                req_.body.append(data+consumed,canTake);
                bodyRemain_-=(int64_t)canTake; consumed+=canTake;
                if(bodyRemain_==0) { consumed+=std::min(avail-canTake,(size_t)2); phase_=Phase::ChunkSize; }
                goto loop_end;
            }
            req_.body.append(data+consumed,(size_t)chunkSize_);
            consumed+=(size_t)chunkSize_+2; // skip CRLF
            if((int64_t)req_.body.size()>=(int64_t)kMaxBodyBuf){ errCode_=413; phase_=Phase::Err; break; }
            phase_=Phase::ChunkSize;
            break;
        }
        case Phase::Body: {
            size_t need=(size_t)bodyRemain_;
            size_t avail=len-consumed;
            size_t take=std::min(need,avail);
            req_.body.append(data+consumed,take);
            consumed+=take; bodyRemain_-=(int64_t)take;
            if(bodyRemain_==0) phase_=Phase::Done;
            goto loop_end;
        }
        default: break;
        }
        loop_end:;
    }

    // Initialise bodyRemain_ on first entry into ChunkData
    if(phase_==Phase::ChunkData&&bodyRemain_==0) {
        bodyRemain_=chunkSize_;
    }

    if(phase_==Phase::Done) { state_=ParseState::Complete; req_.hasBody=!req_.body.empty(); }
    if(phase_==Phase::Err)  { state_=ParseState::Error; }
    return consumed;
}

bool Http1Parser::parseRequestLine(std::string_view line) {
    // METHOD SP request-target SP HTTP/version CRLF
    auto sp1=line.find(' '); if(sp1==std::string_view::npos) return false;
    auto sp2=line.find(' ',sp1+1); if(sp2==std::string_view::npos) return false;

    req_.method=methodFromStr(line.substr(0,sp1));
    if(req_.method==Method::UNKNOWN) return false;

    req_.target=std::string(line.substr(sp1+1,sp2-sp1-1));

    auto ver=line.substr(sp2+1);
    if(ver=="HTTP/1.1")      req_.version=HttpVersion::HTTP11;
    else if(ver=="HTTP/1.0") { req_.version=HttpVersion::HTTP10; req_.keepAlive=false; }
    else if(ver=="HTTP/2.0"||ver=="HTTP/2") req_.version=HttpVersion::HTTP2;
    else return false;

    if(!parseUrl(req_.target)) return false;
    return true;
}

bool Http1Parser::parseUrl(std::string_view target) {
    if(target=="*") { req_.url.path="*"; return true; }
    // absolute-form: http://host/path?query
    if(target.substr(0,7)=="http://"||target.substr(0,8)=="https://") {
        size_t off=target.find("://"); off+=3;
        auto rest=target.substr(off);
        auto slash=rest.find('/');
        auto hostport=rest.substr(0,slash);
        auto col=hostport.rfind(':');
        if(col!=std::string_view::npos) {
            req_.url.host=std::string(hostport.substr(0,col));
            req_.url.port=(uint16_t)strtoul(std::string(hostport.substr(col+1)).c_str(),nullptr,10);
        } else req_.url.host=std::string(hostport);
        if(slash!=std::string_view::npos) target=rest.substr(slash);
        else target="/";
    }
    // origin-form: /path?query#fragment
    auto query=target.find('?');
    auto frag =target.find('#');
    if(query!=std::string_view::npos) {
        req_.url.path=std::string(target.substr(0,query));
        auto qend=(frag!=std::string_view::npos)?frag:target.size();
        req_.url.query=std::string(target.substr(query+1,qend-query-1));
    } else {
        auto pend=(frag!=std::string_view::npos)?frag:target.size();
        req_.url.path=std::string(target.substr(0,pend));
    }
    if(frag!=std::string_view::npos) req_.url.fragment=std::string(target.substr(frag+1));
    return true;
}

bool Http1Parser::parseHeaderLine(std::string_view line) {
    // header-field = field-name ":" OWS field-value OWS
    auto colon=line.find(':');
    if(colon==std::string_view::npos) return false;
    auto name=trim(line.substr(0,colon));
    auto val =trim(line.substr(colon+1));
    if(name.empty()) return false;
    // Validate field-name: token chars only
    for(char c:name) if(!isgraph((unsigned char)c)||c==':') return false;
    req_.headers.add(toLower(name),val);
    return true;
}

bool Http1Parser::finaliseHeaders() {
    // Determine body mode
    auto te=req_.headers.get("transfer-encoding");
    auto cl=req_.headers.get("content-length");
    auto conn=req_.headers.get("connection");

    // Keep-alive
    if(req_.version==HttpVersion::HTTP10) req_.keepAlive=false;
    if(Headers::eqi(conn,"keep-alive")) req_.keepAlive=true;
    if(Headers::eqi(conn,"close"))      req_.keepAlive=false;

    // Chunked trumps Content-Length (RFC 9112 §6.3)
    if(!te.empty()&&te.find("chunked")!=std::string_view::npos) {
        req_.chunked=true;
        phase_=Phase::ChunkSize;
        return true;
    }
    if(!cl.empty()) {
        char* end;
        req_.contentLen=strtoll(std::string(cl).c_str(),&end,10);
        if(req_.contentLen<0||req_.contentLen>(int64_t)kMaxBodyBuf){ errCode_=413; return false; }
        if(req_.contentLen==0) { phase_=Phase::Done; return true; }
        bodyRemain_=req_.contentLen;
        phase_=Phase::Body;
        return true;
    }
    // No body for safe methods
    phase_=Phase::Done;

    // Parse cookies
    auto cookieHdr=req_.headers.get("cookie");
    if(!cookieHdr.empty()) parseCookies(cookieHdr);

    return true;
}

void Http1Parser::parseCookies(std::string_view s) {
    // RFC 6265 §5.2: Cookie: name=value; name2=value2
    while(!s.empty()) {
        while(!s.empty()&&(s[0]==' '||s[0]=='\t')) s=s.substr(1);
        auto semi=s.find(';');
        auto pair=s.substr(0,semi);
        auto eq=pair.find('=');
        if(eq!=std::string_view::npos) {
            auto name=trim(pair.substr(0,eq));
            auto val =trim(pair.substr(eq+1));
            if(!name.empty()) req_.cookies[std::string(name)]=std::string(val);
        }
        if(semi==std::string_view::npos) break;
        s=s.substr(semi+1);
    }
}

// ── RawResponse serialiser ────────────────────────────────────────────────────
std::string RawResponse::serialise(bool headOnly) const {
    std::string out;
    out.reserve(512+body.size());
    // Status line
    out+=(version==HttpVersion::HTTP10?"HTTP/1.0 ":"HTTP/1.1 ");
    out+=std::to_string(statusCode);
    out+=' '; out+=Status::reason(statusCode); out+="\r\n";
    // Date header always present (RFC 9110 §6.6.1)
    bool hasDate=headers.has("date");
    if(!hasDate) { out+="Date: "; out+=httpDate(); out+="\r\n"; }
    // Headers
    for(const auto& h:headers.list) {
        out+=h.name; out+=": "; out+=h.value; out+="\r\n";
    }
    out+="\r\n";
    if(!headOnly) out+=body;
    return out;
}

} // namespace httpd
