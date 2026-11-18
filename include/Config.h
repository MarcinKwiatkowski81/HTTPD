// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
// YAML configuration parser — no external library required.
// Supports a small but sufficient subset of YAML:
//   - Mappings (key: value), sequences (- item), scalars, quoted strings.
//   - Nested mappings via indentation.
//   - # comments, blank lines.
#pragma once
#include "HttpCommon.h"   // for TlsConfig, Status types
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <cstdint>

namespace httpd {

// ── Rewrite rule ──────────────────────────────────────────────────────────────
// Applied to the request URL path before routing.
struct RewriteRule {
    std::string pattern;         // regex pattern matched against request path
    std::string replacement;     // replacement string; $1..$9 for capture groups
    enum class Flag { None, Last, Redirect, Forbidden } flag = Flag::None;
    int         redirectCode = 302;   // used when flag == Redirect
    std::string condHeader;      // optional: only apply if request header exists
    std::string condValue;       // ... and matches this value (empty = any)
};

// ── Proxy upstream ────────────────────────────────────────────────────────────
struct ProxyPass {
    std::string location;        // URL prefix to match, e.g. "/api/"
    std::string target;          // upstream, e.g. "http://127.0.0.1:3000"
    std::string targetHost;      // parsed: host
    uint16_t    targetPort = 80; // parsed: port
    bool        targetTls  = false;
    std::string stripPrefix;     // remove this from path before forwarding
    bool        preserveHost = false;  // forward original Host header
    int         connectTimeoutMs = 5000;
    int         readTimeoutMs    = 30000;
    // Headers to add/override on the upstream request
    std::vector<std::pair<std::string,std::string>> addHeaders;
    // Headers to strip from upstream response before forwarding to client
    std::vector<std::string> hideHeaders;
};

// ── Virtual host ──────────────────────────────────────────────────────────────
struct VirtualHost {
    std::string name;              // logical name, used in logs
    std::vector<std::string> serverNames;  // Host: values to match (wildcard * ok)
    std::string docRoot;           // document root for this vhost
    std::string indexFiles;        // override global index files

    // TLS (SNI) — if non-empty, this vhost has its own cert/key
    std::string certFile;
    std::string keyFile;

    std::vector<RewriteRule> rewrites;
    std::vector<ProxyPass>   proxies;

    // Per-vhost cache-control override for static files
    std::optional<std::string> cacheControl;

    // Access log override (empty = use global)
    std::string accessLog;

    // Extra response headers always added
    std::vector<std::pair<std::string,std::string>> addHeaders;

    // SPA fallback for this vhost
    bool        spaFallback = false;
    std::string spaIndex    = "index.html";
    std::string spaApiPrefix = "/api";
};

// ── Top-level server configuration ───────────────────────────────────────────
struct YamlConfig {
    // --- Network ---
    std::string bindAddr      = "0.0.0.0";
    uint16_t    httpPort      = 8080;
    uint16_t    httpsPort     = 8443;
    bool        enableHttp    = true;
    bool        enableHttps   = false;

    // --- Process model ---
    int workers          = 0;   // 0 = auto (CPU count)
    int threadsPerWorker = 4;

    // --- Default document root (used when no vhost matches) ---
    std::string docRoot    = "./www";
    std::string indexFiles = "index.lhtml index.html index.htm index.lua";

    // --- TLS (global / default cert) ---
    std::string certFile;
    std::string keyFile;
    std::string caFile;
    bool        ktls    = true;
    bool        http2   = true;

    // --- CGI ---
    std::string cgiDir = "/cgi-bin";

    // --- Cache ---
    size_t  cacheMaxEntries  = 1024;
    size_t  cacheMaxMb       = 64;
    size_t  streamThresholdKb = 1024;

    // --- Logging ---
    bool        accessLog     = true;
    std::string accessLogFile;
    bool        errorLog      = true;

    // --- Timeouts ---
    int keepAliveTimeout = 60;
    int requestTimeout   = 30;

    // --- Limits ---
    size_t maxConns      = 10000;
    size_t maxBodyMb     = 64;

    // --- Global rewrites (applied before vhost matching) ---
    std::vector<RewriteRule> rewrites;

    // --- Global proxy rules (applied before vhost matching) ---
    std::vector<ProxyPass>   proxies;

    // --- Virtual hosts (ordered; first match wins) ---
    std::vector<VirtualHost> vhosts;

    // --- Module paths (additional .so beyond the auto-loaded Lua module) ---
    std::vector<std::string> modules;

    // --- SPA fallback (global default) ---
    bool        spaFallback  = false;
    std::string spaIndex     = "index.html";
    std::string spaApiPrefix = "/api";
};

// ── YAML config parser ────────────────────────────────────────────────────────
class ConfigParser {
public:
    // Parse a YAML file. Returns false and populates error on failure.
    bool parseFile(const std::string& path, YamlConfig& out, std::string& error);

    // Parse from a string (useful for tests).
    bool parseString(const std::string& yaml, YamlConfig& out, std::string& error);

private:
    // ── Mini YAML tree ────────────────────────────────────────────────────────
    struct Node {
        enum class Kind { Scalar, Mapping, Sequence };
        Kind kind = Kind::Scalar;
        std::string scalar;
        std::vector<std::pair<std::string, Node>> map;   // ordered keys
        std::vector<Node> seq;

        // Helpers
        const Node* get(const std::string& key) const {
            for(const auto& kv : map) if(kv.first == key) return &kv.second;
            return nullptr;
        }
        std::string str(const std::string& key, const std::string& def = "") const {
            const Node* n = get(key);
            return (n && n->kind == Kind::Scalar) ? n->scalar : def;
        }
        int64_t num(const std::string& key, int64_t def = 0) const {
            const Node* n = get(key);
            if(!n || n->kind != Kind::Scalar) return def;
            try { return std::stoll(n->scalar); } catch(...) { return def; }
        }
        bool boolean(const std::string& key, bool def = false) const {
            const Node* n = get(key);
            if(!n || n->kind != Kind::Scalar) return def;
            return n->scalar == "true" || n->scalar == "yes" || n->scalar == "on" || n->scalar == "1";
        }
    };

    bool parse(const std::string& text, Node& root, std::string& error);
    void applyRoot(const Node& root, YamlConfig& cfg);
    void applyVhost(const Node& node, VirtualHost& vh);
    void applyRewrite(const Node& node, RewriteRule& rr);
    void applyProxy(const Node& node, ProxyPass& pp);

    static void parseProxyTarget(const std::string& target, ProxyPass& pp);
};

} // namespace httpd
