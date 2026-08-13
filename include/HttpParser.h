// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
// RFC 9112: HTTP/1.1 Message Parser
#pragma once
#include "HttpCommon.h"
#include <string>
#include <vector>

namespace httpd {

// ── Parsed HTTP/1.1 request ───────────────────────────────────────────────────
struct RawRequest {
    Method      method    = Method::UNKNOWN;
    HttpVersion version   = HttpVersion::HTTP11;
    std::string target;         // request-target (may be *, abs-path, absolute-form)
    Url         url;            // parsed target
    Headers     headers;
    std::string body;
    bool        hasBody   = false;
    bool        chunked   = false;
    int64_t     contentLen= -1;
    bool        keepAlive = true;
    // Parsed cookies from Cookie header (RFC 6265 §5.2)
    std::unordered_map<std::string,std::string> cookies;

    std::string_view host()    const { return headers.get("host"); }
    std::string_view ctype()   const { return headers.get("content-type"); }
    std::string_view accept()  const { return headers.get("accept"); }
    std::string_view ua()      const { return headers.get("user-agent"); }
};

// ── Parser result ─────────────────────────────────────────────────────────────
enum class ParseState { Incomplete, Complete, Error };

// ── HTTP/1.1 incremental parser (RFC 9112) ────────────────────────────────────
class Http1Parser {
public:
    Http1Parser();
    // Feed data; returns how many bytes consumed.
    // State transitions:  RequestLine → Headers → Body → Complete
    size_t feed(const char* data, size_t len);

    ParseState  state()    const { return state_; }
    bool        complete() const { return state_==ParseState::Complete; }
    bool        error()    const { return state_==ParseState::Error; }
    int         errCode()  const { return errCode_; }  // HTTP status code for error
    RawRequest& request()        { return req_; }
    void        reset();

private:
    enum class Phase {
        RequestLine, Headers, ChunkSize, ChunkData, ChunkTrailer, Body, Done, Err
    };
    Phase       phase_     = Phase::RequestLine;
    ParseState  state_     = ParseState::Incomplete;
    int         errCode_   = 400;
    RawRequest  req_;
    std::string lineBuf_;
    int64_t     bodyRemain_= 0;
    int64_t     chunkSize_ = 0;
    std::string chunkSizeBuf_;

    bool parseRequestLine(std::string_view line);
    bool parseHeaderLine(std::string_view line);
    bool finaliseHeaders();
    void parseCookies(std::string_view cookieHdr);
    bool parseUrl(std::string_view target);
};

// ── HTTP/1.1 response serialiser ──────────────────────────────────────────────
struct RawResponse {
    int         statusCode = 200;
    HttpVersion version    = HttpVersion::HTTP11;
    Headers     headers;
    std::string body;

    void set(std::string_view name, std::string_view value) { headers.set(name,value); }
    void setCookie(const Cookie& c) { headers.add("set-cookie",c.format()); }
    void setBody(std::string_view ct, std::string_view body_) {
        body=std::string(body_);
        headers.set("content-type",ct);
        headers.set("content-length",std::to_string(body.size()));
    }
    // Serialise to wire format (HTTP/1.1)
    std::string serialise(bool headOnly=false) const;
};

} // namespace httpd
