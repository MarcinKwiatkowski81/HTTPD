// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
// Reverse proxy: forward a request to an upstream HTTP server and relay
// the response back to the client.  Synchronous (runs on thread-pool thread).
#pragma once
#include "Config.h"
#include "HttpParser.h"
#include <string>
#include <vector>

namespace httpd {

class ReverseProxy {
public:
    // Forward req to the upstream defined in pp, fill resp.
    // Returns true on success (even if upstream returned 5xx).
    // Returns false only on transport / connection failure.
    bool forward(const ProxyPass& pp,
                 const RawRequest& clientReq,
                 RawResponse& resp,
                 std::string& error);

private:
    // Build the upstream request line + headers.
    static std::string buildUpstreamRequest(const ProxyPass& pp,
                                            const RawRequest& clientReq);

    // Parse upstream HTTP/1.x response (status line + headers + body).
    static bool parseUpstreamResponse(const std::string& raw,
                                      RawResponse& resp);

    // TCP connect to host:port with timeout_ms.
    static int tcpConnect(const std::string& host, uint16_t port,
                          int timeout_ms, std::string& error);

    // Read everything from fd until connection closes or timeout.
    static bool readAll(int fd, int timeout_ms, std::string& out);

    // Strip hop-by-hop headers before forwarding (RFC 9110 §7.6.1).
    static void stripHopByHop(Headers& h);

    // Write all bytes to fd; returns false on error.
    static bool writeAll(int fd, const std::string& data);
};

} // namespace httpd
