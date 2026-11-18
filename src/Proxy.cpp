// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
#include "Proxy.h"
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <cerrno>
#include <cstring>
#include <cstdio>
#include <algorithm>
#include <sstream>

namespace httpd {

// ── Hop-by-hop headers (RFC 9110 §7.6.1) ──────────────────────────────────────
static const char* const kHopByHop[] = {
    "connection","keep-alive","proxy-authenticate","proxy-authorization",
    "te","trailers","transfer-encoding","upgrade",
    nullptr
};

void ReverseProxy::stripHopByHop(Headers& h) {
    for(int i = 0; kHopByHop[i]; ++i)
        h.remove(kHopByHop[i]);
}

// ── TCP connect with timeout ───────────────────────────────────────────────────
int ReverseProxy::tcpConnect(const std::string& host, uint16_t port,
                              int timeout_ms, std::string& error) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    std::string portStr = std::to_string(port);
    int rc = getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res);
    if(rc != 0) {
        error = "getaddrinfo(" + host + ":" + portStr + "): " + gai_strerror(rc);
        return -1;
    }

    int fd = -1;
    for(struct addrinfo* ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype | SOCK_CLOEXEC, ai->ai_protocol);
        if(fd < 0) continue;

        // Non-blocking connect
        int fl = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, fl | O_NONBLOCK);

        int rv = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if(rv == 0) {
            // Immediate connect (loopback usually)
            fcntl(fd, F_SETFL, fl);  // restore blocking
            break;
        }
        if(errno != EINPROGRESS) {
            close(fd); fd = -1; continue;
        }

        // Wait for connection with poll
        struct pollfd pfd{};
        pfd.fd = fd; pfd.events = POLLOUT;
        rv = poll(&pfd, 1, timeout_ms);
        if(rv <= 0) {
            error = rv == 0 ? "Connect timeout to " + host : "poll error";
            close(fd); fd = -1; continue;
        }
        int err2 = 0;
        socklen_t sl = sizeof(err2);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err2, &sl);
        if(err2 != 0) {
            error = "Connect error to " + host + ": " + strerror(err2);
            close(fd); fd = -1; continue;
        }
        fcntl(fd, F_SETFL, fl);  // restore blocking
        break;
    }
    freeaddrinfo(res);

    if(fd < 0 && error.empty())
        error = "Could not connect to " + host + ":" + portStr;
    return fd;
}

// ── Write all bytes ───────────────────────────────────────────────────────────
bool ReverseProxy::writeAll(int fd, const std::string& data) {
    size_t sent = 0;
    while(sent < data.size()) {
        ssize_t n = send(fd, data.data() + sent, data.size() - sent, MSG_NOSIGNAL);
        if(n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

// ── Read all until EOF with timeout ──────────────────────────────────────────
bool ReverseProxy::readAll(int fd, int timeout_ms, std::string& out) {
    char buf[65536];
    for(;;) {
        struct pollfd pfd{};
        pfd.fd = fd; pfd.events = POLLIN;
        int rv = poll(&pfd, 1, timeout_ms);
        if(rv < 0) return false;
        if(rv == 0) break;  // timeout = done (server stopped sending)

        ssize_t n = recv(fd, buf, sizeof buf, 0);
        if(n < 0) { if(errno==EINTR) continue; return false; }
        if(n == 0) break;  // EOF
        out.append(buf, (size_t)n);
    }
    return true;
}

// ── Build upstream HTTP/1.1 request ──────────────────────────────────────────
std::string ReverseProxy::buildUpstreamRequest(const ProxyPass& pp,
                                                const RawRequest& req) {
    std::string upPath = req.url.path;

    // Strip the matching prefix from the path if configured
    const std::string& strip = pp.stripPrefix.empty() ? pp.location : pp.stripPrefix;
    if(!strip.empty() && upPath.size() >= strip.size() &&
       upPath.substr(0, strip.size()) == strip) {
        upPath = upPath.substr(strip.size());
        if(upPath.empty() || upPath[0] != '/') upPath = "/" + upPath;
    }

    if(!req.url.query.empty()) upPath += "?" + req.url.query;

    std::string out;
    out.reserve(2048 + req.body.size());

    // Request line
    out += std::string(methodStr(req.method));
    out += " "; out += upPath; out += " HTTP/1.1\r\n";

    // Forward headers (strip hop-by-hop first)
    Headers fwd = req.headers;
    stripHopByHop(fwd);

    // Host header
    if(pp.preserveHost) {
        // keep original Host
    } else {
        std::string upHost = pp.targetHost;
        uint16_t defPort = pp.targetTls ? 443 : 80;
        if(pp.targetPort != defPort)
            upHost += ":" + std::to_string(pp.targetPort);
        fwd.set("host", upHost);
    }

    // X-Forwarded-For
    std::string existingXFF = std::string(req.headers.get("x-forwarded-for"));
    if(!existingXFF.empty()) {
        // Don't append again if we're re-proxying a proxied request
    } else {
        fwd.set("x-forwarded-for", std::string(req.headers.get("x-forwarded-for")));
    }
    fwd.set("x-forwarded-proto", "http");  // caller could pass isTls if needed

    // Add configured headers ($remote_addr expansion is a no-op here without
    // connection context; pass them verbatim)
    for(const auto& [name, val] : pp.addHeaders)
        fwd.set(name, val);

    // Connection: close — we don't do upstream keep-alive
    fwd.set("connection", "close");
    if(req.body.empty()) fwd.remove("content-length");

    for(const auto& h : fwd.list)
        out += h.name + ": " + h.value + "\r\n";
    out += "\r\n";
    out += req.body;
    return out;
}

// ── Parse upstream HTTP/1.x response ─────────────────────────────────────────
bool ReverseProxy::parseUpstreamResponse(const std::string& raw, RawResponse& resp) {
    // Find end of headers
    auto hend = raw.find("\r\n\r\n");
    if(hend == std::string::npos) {
        hend = raw.find("\n\n");
        if(hend == std::string::npos) return false;
        hend += 2;
    } else {
        hend += 4;
    }

    std::string headerPart = raw.substr(0, hend);
    resp.body = raw.substr(hend);

    std::istringstream ss(headerPart);
    std::string line;

    // Status line
    if(!std::getline(ss, line)) return false;
    if(!line.empty() && line.back()=='\r') line.pop_back();
    // HTTP/1.1 200 OK
    auto sp1 = line.find(' ');
    if(sp1 == std::string::npos) return false;
    auto sp2 = line.find(' ', sp1+1);
    if(sp2 == std::string::npos) sp2 = line.size();
    std::string codeStr = line.substr(sp1+1, sp2-sp1-1);
    resp.statusCode = std::stoi(codeStr);

    // Headers
    while(std::getline(ss, line)) {
        if(!line.empty() && line.back()=='\r') line.pop_back();
        if(line.empty()) break;
        auto colon = line.find(':');
        if(colon == std::string::npos) continue;
        std::string name = line.substr(0, colon);
        std::string val  = line.substr(colon+1);
        while(!val.empty() && (val[0]==' '||val[0]=='\t')) val=val.substr(1);
        // lowercase name
        for(auto& c : name) c = (char)std::tolower((unsigned char)c);
        resp.headers.add(name, val);
    }

    return true;
}

// ── Main entry ────────────────────────────────────────────────────────────────
bool ReverseProxy::forward(const ProxyPass& pp,
                            const RawRequest& clientReq,
                            RawResponse& resp,
                            std::string& error) {
    // Connect
    int fd = tcpConnect(pp.targetHost, pp.targetPort, pp.connectTimeoutMs, error);
    if(fd < 0) {
        resp.statusCode = 502;
        resp.setBody("text/html; charset=utf-8",
                     "<h1>502 Bad Gateway</h1><p>" + error + "</p>");
        return false;
    }

    // Build and send request
    std::string upReq = buildUpstreamRequest(pp, clientReq);
    if(!writeAll(fd, upReq)) {
        close(fd);
        error = "Failed to write to upstream";
        resp.statusCode = 502;
        resp.setBody("text/html; charset=utf-8",
                     "<h1>502 Bad Gateway</h1><p>" + error + "</p>");
        return false;
    }

    // Read response
    std::string raw;
    if(!readAll(fd, pp.readTimeoutMs, raw)) {
        close(fd);
        error = "Failed to read upstream response";
        resp.statusCode = 504;
        resp.setBody("text/html; charset=utf-8",
                     "<h1>504 Gateway Timeout</h1>");
        return false;
    }
    close(fd);

    if(raw.empty()) {
        error = "Empty upstream response";
        resp.statusCode = 502;
        resp.setBody("text/html; charset=utf-8",
                     "<h1>502 Bad Gateway</h1><p>Empty response</p>");
        return false;
    }

    if(!parseUpstreamResponse(raw, resp)) {
        error = "Could not parse upstream response";
        resp.statusCode = 502;
        resp.setBody("text/html; charset=utf-8",
                     "<h1>502 Bad Gateway</h1><p>Malformed upstream response</p>");
        return false;
    }

    // Strip hop-by-hop from upstream response
    stripHopByHop(resp.headers);

    // Hide configured headers
    for(const auto& h : pp.hideHeaders) resp.headers.remove(h);

    // Fix content-length to match the actual body we have
    resp.headers.set("content-length", std::to_string(resp.body.size()));

    // Add Via header (RFC 9110 §7.6.3)
    std::string via = std::string(resp.headers.get("via"));
    std::string viaAdd = "1.1 httpd (httpd/1.0)";
    resp.headers.set("via", via.empty() ? viaAdd : via + ", " + viaAdd);

    return true;
}

} // namespace httpd
