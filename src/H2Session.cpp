// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
// RFC 9113: HTTP/2 session implementation
#include "H2Session.h"
#include <cstring>
#include <algorithm>
#include <arpa/inet.h>

namespace httpd {

const char H2Session::kClientPreface[] =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"; // 24 bytes

// ── Frame serialise/parse ─────────────────────────────────────────────────────
void H2Frame::serialise(std::vector<uint8_t>& out) const {
    uint32_t plen=(uint32_t)payload.size();
    // 3-byte length
    out.push_back((plen>>16)&0xFF);
    out.push_back((plen>>8) &0xFF);
    out.push_back( plen     &0xFF);
    out.push_back((uint8_t)type);
    out.push_back(flags);
    // 4-byte stream id (R bit = 0)
    uint32_t sid=htonl(streamId&0x7FFFFFFF);
    out.insert(out.end(),(uint8_t*)&sid,(uint8_t*)&sid+4);
    out.insert(out.end(),payload.begin(),payload.end());
}

bool H2Frame::parse(const uint8_t* data, size_t len, H2Frame& f, size_t& consumed) {
    if(len<kHeaderLen) return false;
    uint32_t plen=((uint32_t)data[0]<<16)|((uint32_t)data[1]<<8)|data[2];
    if(len<kHeaderLen+plen) return false;
    f.type =(H2FrameType)data[3];
    f.flags=data[4];
    uint32_t sid; memcpy(&sid,data+5,4); f.streamId=ntohl(sid)&0x7FFFFFFF;
    f.payload.assign(data+kHeaderLen,data+kHeaderLen+plen);
    consumed=kHeaderLen+plen;
    return true;
}

// ── Session ───────────────────────────────────────────────────────────────────
H2Session::H2Session() {}

void H2Session::queueFrame(const H2Frame& f) { f.serialise(sendBuf_); }

std::vector<uint8_t> H2Session::takeSendBuf() {
    auto r=std::move(sendBuf_); sendBuf_.clear(); return r;
}

void H2Session::sendSettings(bool ack) {
    H2Frame f; f.type=H2FrameType::SETTINGS; f.streamId=0;
    if(ack) { f.flags=H2Flags::ACK; queueFrame(f); return; }
    // Advertise our settings
    auto& p=f.payload;
    auto addSetting=[&](uint16_t id, uint32_t val){
        p.push_back(id>>8); p.push_back(id&0xFF);
        p.push_back(val>>24); p.push_back((val>>16)&0xFF);
        p.push_back((val>>8)&0xFF); p.push_back(val&0xFF);
    };
    addSetting(H2Setting::HEADER_TABLE_SIZE,      localSettings_.headerTableSize);
    addSetting(H2Setting::ENABLE_PUSH,             0); // server push disabled
    addSetting(H2Setting::MAX_CONCURRENT_STREAMS,  localSettings_.maxConcurrentStreams);
    addSetting(H2Setting::INITIAL_WINDOW_SIZE,      localSettings_.initialWindowSize);
    addSetting(H2Setting::MAX_FRAME_SIZE,           localSettings_.maxFrameSize);
    addSetting(H2Setting::MAX_HEADER_LIST_SIZE,     localSettings_.maxHeaderListSize);
    queueFrame(f);
    settingsSent_=true;
}

void H2Session::sendWindowUpdate(uint32_t streamId, uint32_t increment) {
    H2Frame f; f.type=H2FrameType::WINDOW_UPDATE; f.streamId=streamId;
    uint32_t v=htonl(increment&0x7FFFFFFF);
    f.payload.assign((uint8_t*)&v,(uint8_t*)&v+4);
    queueFrame(f);
}

void H2Session::sendGoaway(uint32_t lastStream, uint32_t errorCode) {
    H2Frame f; f.type=H2FrameType::GOAWAY; f.streamId=0;
    uint32_t ls=htonl(lastStream), ec=htonl(errorCode);
    f.payload.resize(8);
    memcpy(f.payload.data(),&ls,4); memcpy(f.payload.data()+4,&ec,4);
    queueFrame(f); goaway_=true;
}

void H2Session::sendRstStream(uint32_t streamId, uint32_t errorCode) {
    H2Frame f; f.type=H2FrameType::RST_STREAM; f.streamId=streamId;
    uint32_t ec=htonl(errorCode);
    f.payload.assign((uint8_t*)&ec,(uint8_t*)&ec+4);
    queueFrame(f);
}

bool H2Session::sendResponse(uint32_t streamId, const RawResponse& resp) {
    auto it=streams_.find(streamId);
    if(it==streams_.end()||it->second.state==H2StreamState::Closed) return false;

    // Encode headers via HPACK
    std::vector<HpackHeader> hdrs;
    hdrs.push_back({":status",std::to_string(resp.statusCode)});
    hdrs.push_back({"date",httpDate()});
    for(const auto& h:resp.headers.list)
        hdrs.push_back({h.name,h.value});

    std::vector<uint8_t> hblock;
    encoder_.encode(hdrs,hblock);

    // HEADERS frame
    {
        H2Frame f; f.type=H2FrameType::HEADERS; f.streamId=streamId;
        f.flags=resp.body.empty()?(H2Flags::END_HEADERS|H2Flags::END_STREAM):H2Flags::END_HEADERS;
        f.payload=hblock;
        queueFrame(f);
    }

    // DATA frames (split at maxFrameSize)
    if(!resp.body.empty()) {
        const char* bp=resp.body.data(); size_t remain=resp.body.size();
        size_t maxFs=remoteSettings_.maxFrameSize;
        while(remain>0) {
            size_t chunk=std::min(remain,maxFs);
            H2Frame f; f.type=H2FrameType::DATA; f.streamId=streamId;
            remain-=chunk;
            f.flags=remain?0:H2Flags::END_STREAM;
            f.payload.assign((const uint8_t*)bp,(const uint8_t*)bp+chunk);
            bp+=chunk;
            queueFrame(f);
        }
    }

    it->second.state=H2StreamState::HalfClosedLocal;
    return true;
}

// ── Main data feed ────────────────────────────────────────────────────────────
bool H2Session::onData(const uint8_t* data, size_t len) {
    if(fatal_) return false;

    // Client connection preface (24 bytes, RFC 9113 §3.4)
    if(!prefaceDone_) {
        size_t prefLen=strlen(kClientPreface);
        size_t need=prefLen-prefacePos_;
        size_t take=std::min(need,len);
        bool match=!memcmp(data,kClientPreface+prefacePos_,take);
        if(!match) { fatal_=true; return false; }
        prefacePos_+=take; data+=take; len-=take;
        if(prefacePos_<prefLen) return true; // need more
        prefaceDone_=true;
        // Send our settings immediately
        sendSettings(false);
        // Send connection-level window update (expand to 64 MiB)
        sendWindowUpdate(0, (1<<24)-65535);
    }

    // Parse frames
    while(len>0) {
        H2Frame f; size_t consumed=0;
        if(!H2Frame::parse(data,len,f,consumed)) break; // incomplete frame
        data+=consumed; len-=consumed;
        if(!handleFrame(f)) return !fatal_;
    }
    return true;
}

bool H2Session::handleFrame(H2Frame& f) {
    // Connection-level frame size check
    if(f.payload.size()>remoteSettings_.maxFrameSize) {
        sendGoaway(lastPeerStream_,H2Error::FRAME_SIZE_ERROR);
        fatal_=true; return false;
    }
    switch(f.type) {
    case H2FrameType::HEADERS:       return handleHeaders(f);
    case H2FrameType::DATA:          return handleData(f);
    case H2FrameType::SETTINGS:      return handleSettings(f);
    case H2FrameType::WINDOW_UPDATE: return handleWindowUpdate(f);
    case H2FrameType::PING:          return handlePing(f);
    case H2FrameType::RST_STREAM:    return handleRstStream(f);
    case H2FrameType::GOAWAY:        return handleGoaway(f);
    case H2FrameType::PRIORITY:      handlePriority(f); return true;
    case H2FrameType::PUSH_PROMISE:  // server ignores client push-promise
        return true;
    default: // Unknown frames must be ignored per RFC 9113 §4.1
        return true;
    }
}

H2Stream& H2Session::getOrCreateStream(uint32_t id) {
    auto it=streams_.find(id);
    if(it!=streams_.end()) return it->second;
    H2Stream s; s.id=id; s.state=H2StreamState::Open;
    s.localWindow =localSettings_.initialWindowSize;
    s.remoteWindow=remoteSettings_.initialWindowSize;
    streams_[id]=std::move(s);
    return streams_[id];
}

bool H2Session::handleHeaders(H2Frame& f) {
    if(f.streamId==0) { sendGoaway(lastPeerStream_,H2Error::PROTOCOL_ERROR); return false; }
    if(f.streamId%2==0) { sendGoaway(lastPeerStream_,H2Error::PROTOCOL_ERROR); return false; }
    if(f.streamId<lastPeerStream_) { sendGoaway(lastPeerStream_,H2Error::PROTOCOL_ERROR); return false; }
    lastPeerStream_=f.streamId;

    H2Stream& s=getOrCreateStream(f.streamId);

    // Strip padding
    const uint8_t* p=f.payload.data();
    size_t plen=f.payload.size();
    if(f.flags&H2Flags::PADDED) {
        if(plen<1) { sendGoaway(lastPeerStream_,H2Error::PROTOCOL_ERROR); return false; }
        uint8_t padLen=*p++; plen--;
        if(padLen>=plen) { sendGoaway(lastPeerStream_,H2Error::PROTOCOL_ERROR); return false; }
        plen-=padLen;
    }
    // Strip PRIORITY
    if(f.flags&H2Flags::PRIORITY) {
        if(plen<5) { sendGoaway(lastPeerStream_,H2Error::PROTOCOL_ERROR); return false; }
        p+=5; plen-=5;
    }

    if(!decoder_.decode(p,plen,s.reqHeaders)) {
        sendGoaway(lastPeerStream_,H2Error::COMPRESSION_ERROR);
        fatal_=true; return false;
    }

    s.headersDone=true;
    s.endStream=(f.flags&H2Flags::END_STREAM)!=0;
    if(s.endStream||(f.flags&H2Flags::END_HEADERS)) {
        if(s.endStream) assembleRequest(s);
    }
    // Grant stream window
    sendWindowUpdate(f.streamId, localSettings_.initialWindowSize);
    return true;
}

bool H2Session::handleData(H2Frame& f) {
    if(f.streamId==0) { sendGoaway(lastPeerStream_,H2Error::PROTOCOL_ERROR); return false; }
    auto it=streams_.find(f.streamId);
    if(it==streams_.end()) { sendRstStream(f.streamId,H2Error::STREAM_CLOSED); return true; }
    H2Stream& s=it->second;

    // Strip padding
    const uint8_t* p=f.payload.data(); size_t plen=f.payload.size();
    if(f.flags&H2Flags::PADDED) {
        if(plen<1) return false;
        uint8_t pad=*p++; plen--;
        if(pad>=plen) return false;
        plen-=pad;
    }

    s.reqBody.append((const char*)p,plen);
    connectionWindow_-=(int32_t)plen;
    s.localWindow  -=(int32_t)plen;

    // Send window update when below half
    if(connectionWindow_<(int32_t)(localSettings_.initialWindowSize/2)) {
        uint32_t inc=localSettings_.initialWindowSize-connectionWindow_;
        sendWindowUpdate(0,inc); connectionWindow_+=(int32_t)inc;
    }
    if(s.localWindow<(int32_t)(localSettings_.initialWindowSize/2)) {
        uint32_t inc=localSettings_.initialWindowSize-s.localWindow;
        sendWindowUpdate(f.streamId,inc); s.localWindow+=(int32_t)inc;
    }

    if(f.flags&H2Flags::END_STREAM) { s.endStream=true; assembleRequest(s); }
    return true;
}

bool H2Session::handleSettings(H2Frame& f) {
    if(f.streamId!=0) { sendGoaway(0,H2Error::PROTOCOL_ERROR); return false; }
    if(f.flags&H2Flags::ACK) return true; // ACK to our settings

    const uint8_t* p=f.payload.data(); size_t len=f.payload.size();
    while(len>=6) {
        uint16_t id=((uint16_t)p[0]<<8)|p[1];
        uint32_t val=((uint32_t)p[2]<<24)|((uint32_t)p[3]<<16)|((uint32_t)p[4]<<8)|p[5];
        p+=6; len-=6;
        switch(id) {
        case H2Setting::HEADER_TABLE_SIZE:      remoteSettings_.headerTableSize=val; decoder_.setTableSize(val); break;
        case H2Setting::ENABLE_PUSH:            if(val>1){sendGoaway(0,H2Error::PROTOCOL_ERROR);return false;} break;
        case H2Setting::MAX_CONCURRENT_STREAMS: remoteSettings_.maxConcurrentStreams=val; break;
        case H2Setting::INITIAL_WINDOW_SIZE:
            if(val>0x7FFFFFFF){sendGoaway(0,H2Error::FLOW_CONTROL_ERROR);return false;}
            // Update all open stream windows
            for(auto& kv:streams_) kv.second.remoteWindow+=(int32_t)(val-remoteSettings_.initialWindowSize);
            remoteSettings_.initialWindowSize=val; break;
        case H2Setting::MAX_FRAME_SIZE:
            if(val<16384||val>16777215){sendGoaway(0,H2Error::PROTOCOL_ERROR);return false;}
            remoteSettings_.maxFrameSize=val; break;
        case H2Setting::MAX_HEADER_LIST_SIZE:   remoteSettings_.maxHeaderListSize=val; break;
        default: break; // unknown setting identifiers MUST be ignored
        }
    }
    sendSettings(true); // ACK
    return true;
}

bool H2Session::handleWindowUpdate(H2Frame& f) {
    const uint8_t* p=f.payload.data();
    if(f.payload.size()<4) { sendGoaway(0,H2Error::PROTOCOL_ERROR); return false; }
    uint32_t inc; memcpy(&inc,p,4); inc=ntohl(inc)&0x7FFFFFFF;
    if(inc==0) {
        if(f.streamId==0) { sendGoaway(0,H2Error::PROTOCOL_ERROR); return false; }
        sendRstStream(f.streamId,H2Error::PROTOCOL_ERROR); return true;
    }
    if(f.streamId==0) connectionWindow_+=(int32_t)inc;
    else {
        auto it=streams_.find(f.streamId);
        if(it!=streams_.end()) it->second.remoteWindow+=(int32_t)inc;
    }
    return true;
}

bool H2Session::handlePing(H2Frame& f) {
    if(f.streamId!=0) { sendGoaway(0,H2Error::PROTOCOL_ERROR); return false; }
    if(f.flags&H2Flags::ACK) return true;
    // Echo back with ACK
    H2Frame pong; pong.type=H2FrameType::PING; pong.flags=H2Flags::ACK;
    pong.streamId=0; pong.payload=f.payload;
    queueFrame(pong);
    return true;
}

bool H2Session::handleRstStream(H2Frame& f) {
    if(f.streamId==0) { sendGoaway(0,H2Error::PROTOCOL_ERROR); return false; }
    auto it=streams_.find(f.streamId);
    if(it!=streams_.end()) it->second.state=H2StreamState::Closed;
    return true;
}

bool H2Session::handleGoaway(H2Frame& f) {
    (void)f; goaway_=true; return true;
}

void H2Session::handlePriority(H2Frame& f) { (void)f; /* Advisory; we ignore */ }

void H2Session::assembleRequest(H2Stream& s) {
    auto req=std::make_shared<RawRequest>();
    for(const auto& h:s.reqHeaders) {
        if(h.name==":method")    req->method=methodFromStr(h.value);
        else if(h.name==":path") {
            req->target=h.value;
            Http1Parser tmp; tmp.feed((std::string("GET ")+h.value+" HTTP/2\r\n\r\n").c_str(),
                                      7+h.value.size()+10);
            if(tmp.complete()) { req->url=tmp.request().url; }
        }
        else if(h.name==":scheme") req->url.scheme=h.value;
        else if(h.name==":authority") req->headers.set("host",h.value);
        else req->headers.add(h.name,h.value);
    }
    req->body=s.reqBody;
    req->hasBody=!req->body.empty();
    req->version=HttpVersion::HTTP2;
    // Parse cookies
    auto cookieHdr=req->headers.get("cookie");
    if(!cookieHdr.empty()) {
        // Reuse cookie parser via Http1Parser
        Http1Parser tmp;
        std::string fake="GET / HTTP/1.1\r\ncookie: "+std::string(cookieHdr)+"\r\n\r\n";
        tmp.feed(fake.c_str(),fake.size());
        if(tmp.complete()) req->cookies=tmp.request().cookies;
    }
    s.request=req;
    if(onRequest_) onRequest_(s.id,req);
}

} // namespace httpd
