// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
// RFC 9111: HTTP Caching
#pragma once
#include "HttpCommon.h"
#include "HttpParser.h"
#include <string>
#include <unordered_map>
#include <memory>
#include <vector>
#include <mutex>
#include <optional>

namespace httpd {

// ── Cache-Control directives (RFC 9111 §5.2) ─────────────────────────────────
struct CacheControl {
    // Request directives
    bool noCache       = false;
    bool noStore       = false;
    bool onlyIfCached  = false;
    int64_t maxAge     = -1;
    int64_t maxStale   = -1;
    int64_t minFresh   = -1;

    // Response directives
    bool mustRevalidate= false;
    bool proxyRevalidate=false;
    bool noTransform   = false;
    bool isPublic      = false;
    bool isPrivate     = false;
    bool immutable     = false;
    int64_t sMaxAge    = -1;
    int64_t staleWhileRevalidate = -1;

    static CacheControl parse(std::string_view v);
};

// ── Cached entry ──────────────────────────────────────────────────────────────
struct CacheEntry {
    std::string       url;           // cache key
    int               statusCode    = 200;
    Headers           headers;
    std::string       body;
    time_t            date          = 0;     // Date: header value
    time_t            expires       = 0;     // Expires: header
    int64_t           maxAge        = -1;    // from Cache-Control
    time_t            lastModified  = 0;
    std::string       etag;                  // raw (with quotes)
    std::vector<std::string> varyHeaders;    // Vary: fields
    std::string       varyValues;            // joined values for vary-key
    time_t            storedAt      = 0;     // when we stored it
    size_t            size          = 0;

    // Age calculation (RFC 9111 §5.1)
    int64_t currentAge() const;
    int64_t freshnessLifetime() const;
    bool    fresh() const { return currentAge() < freshnessLifetime(); }
    bool    stale() const { return !fresh(); }
};

// ── Cache lookup result ───────────────────────────────────────────────────────
enum class CacheResult { Miss, Hit, Stale, MustRevalidate };

// ── HTTP Cache (RFC 9111 compliant) ───────────────────────────────────────────
class HttpCache {
public:
    struct Config {
        size_t maxMemEntries  = 1024;
        size_t maxMemBytes    = 64*1024*1024; // 64 MiB
        std::string diskPath;                  // empty = memory-only
        size_t maxDiskBytes   = 1024*1024*1024; // 1 GiB
    };

    explicit HttpCache();
    explicit HttpCache(Config cfg);

    // Lookup — returns nullptr on miss.
    std::shared_ptr<CacheEntry> lookup(const RawRequest& req);

    // Store a response in cache (after checking storability).
    void store(const RawRequest& req, const RawResponse& resp);

    // Invalidate by URL (after non-safe method).
    void invalidate(const std::string& url);

    // RFC 9111 §4: is the response cacheable?
    static bool isCacheable(const RawRequest& req, const RawResponse& resp);

    // RFC 9111 §4.3: generate conditional request headers
    static void addConditionals(const CacheEntry& e, RawRequest& out);

    // RFC 9111 §4.3.4: validate 304 response → update stored entry
    void update304(const std::string& key, const RawResponse& resp304);

    // Stats
    size_t entries() const;
    size_t bytes()   const;
    void   purge();

private:
    Config  cfg_;
    mutable std::mutex mu_;
    std::unordered_map<std::string, std::shared_ptr<CacheEntry>> mem_;
    size_t  memBytes_ = 0;

    std::string makeKey(const RawRequest& req) const;
    std::string varyKey(const RawRequest& req, const std::vector<std::string>& vary) const;
    void evict(size_t need);
};

} // namespace httpd
