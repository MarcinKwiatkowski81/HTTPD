// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
// CGI/1.1 handler (RFC 3875)
#pragma once
#include "HttpCommon.h"
#include "HttpParser.h"
#include <string>
#include <vector>
#include <chrono>

namespace httpd {

struct CgiConfig {
    std::string docRoot;
    std::string cgiDir       = "/cgi-bin";  // relative path under docRoot
    int         timeout_ms   = 30000;        // CGI process timeout
    size_t      maxOutput    = 16*1024*1024; // 16 MiB
    bool        forkEach     = true;         // fork per request (safer than thread)
    uid_t       runAsUid     = 0;            // 0 = current user
    gid_t       runAsGid     = 0;
};

// ── CGI handler ───────────────────────────────────────────────────────────────
class CgiHandler {
public:
    CgiHandler() = default;
    explicit CgiHandler(CgiConfig cfg) : cfg_(std::move(cfg)) {}

    // Execute CGI script; fills resp. Returns false on hard error.
    bool execute(const RawRequest& req, const std::string& scriptPath,
                 const std::string& pathInfo, RawResponse& resp);

private:
    CgiConfig cfg_;

    // Build CGI environment (RFC 3875 §4.1)
    std::vector<std::string> buildEnv(const RawRequest& req,
                                       const std::string& scriptPath,
                                       const std::string& pathInfo) const;
    // Parse CGI output into headers + body
    bool parseCgiOutput(const std::string& out, RawResponse& resp) const;
};

} // namespace httpd
