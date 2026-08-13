// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
//
// Unit tests for the pure logic: parsers, header handling, caches.
// Deliberately no external test framework — the project has no third-party
// dependencies beyond OpenSSL/zlib/Lua, and a few macros cover what is needed.
//
// Run:  ./build/unit_tests            (or: ctest --test-dir build)

#include "HttpCommon.h"
#include "HttpParser.h"
#include "Hpack.h"
#include "Cache.h"
#include "FileCache.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>

using namespace httpd;

// ── Tiny harness ──────────────────────────────────────────────────────────────
static int g_checks = 0, g_failures = 0;
static const char* g_section = "";

static void section(const char* name) { g_section = name; }

#define CHECK(cond)                                                            \
    do {                                                                       \
        ++g_checks;                                                            \
        if(!(cond)) {                                                          \
            ++g_failures;                                                      \
            fprintf(stderr, "  FAIL [%s] %s:%d: %s\n",                         \
                    g_section, __FILE__, __LINE__, #cond);                     \
        }                                                                      \
    } while(0)

// Separate macro so a mismatch prints both values instead of just the source.
#define CHECK_EQ(actual, expected)                                             \
    do {                                                                       \
        ++g_checks;                                                            \
        auto _a = (actual);                                                    \
        auto _e = (expected);                                                   \
        if(!(_a == _e)) {                                                      \
            ++g_failures;                                                      \
            fprintf(stderr, "  FAIL [%s] %s:%d: %s\n",                         \
                    g_section, __FILE__, __LINE__, #actual " == " #expected);   \
        }                                                                      \
    } while(0)

#define CHECK_STR(actual, expected)                                            \
    do {                                                                       \
        ++g_checks;                                                            \
        std::string _a(actual), _e(expected);                                  \
        if(_a != _e) {                                                          \
            ++g_failures;                                                      \
            fprintf(stderr, "  FAIL [%s] %s:%d: %s\n    got:      \"%s\"\n"    \
                            "    expected: \"%s\"\n",                          \
                    g_section, __FILE__, __LINE__, #actual,                    \
                    _a.c_str(), _e.c_str());                                   \
        }                                                                      \
    } while(0)

// ── Range parsing (RFC 9110 §14.1) ────────────────────────────────────────────
static void test_parse_range() {
    section("parseRange");
    const int64_t total = 500;

    auto r = parseRange("bytes=0-9", total);
    CHECK_EQ(r.size(), 1u);
    if(r.size() == 1) { CHECK_EQ(r[0].first, 0);   CHECK_EQ(r[0].last, 9); }

    r = parseRange("bytes=100-199", total);
    if(r.size() == 1) { CHECK_EQ(r[0].first, 100); CHECK_EQ(r[0].last, 199); }

    // Open-ended range runs to the last byte.
    r = parseRange("bytes=490-", total);
    if(r.size() == 1) { CHECK_EQ(r[0].first, 490); CHECK_EQ(r[0].last, 499); }

    // Suffix range: final N bytes.
    r = parseRange("bytes=-10", total);
    if(r.size() == 1) { CHECK_EQ(r[0].first, 490); CHECK_EQ(r[0].last, 499); }

    // Clamped, NOT rejected: an end past the last byte is truncated.
    r = parseRange("bytes=0-9999", total);
    CHECK_EQ(r.size(), 1u);
    if(r.size() == 1) { CHECK_EQ(r[0].first, 0);   CHECK_EQ(r[0].last, 499); }

    // A suffix longer than the representation yields the whole thing.
    r = parseRange("bytes=-9999", total);
    CHECK_EQ(r.size(), 1u);
    if(r.size() == 1) { CHECK_EQ(r[0].first, 0);   CHECK_EQ(r[0].last, 499); }

    // Unsatisfiable: first-byte-pos at or past the end.
    CHECK(parseRange("bytes=500-", total).empty());
    CHECK(parseRange("bytes=600-700", total).empty());
    CHECK(parseRange("bytes=-0", total).empty());          // zero-length suffix

    // Not a byte-range-set at all → no ranges (caller must ignore, not 416).
    CHECK(parseRange("bytes=abc", total).empty());
    CHECK(parseRange("bytes=", total).empty());
    CHECK(parseRange("items=0-5", total).empty());
    CHECK(parseRange("0-5", total).empty());               // missing unit

    // Digit overflow must not wrap into a valid-looking range.
    CHECK(parseRange("bytes=99999999999999999999-", total).empty());

    // Multiple ranges are returned in requested order; coalescing is the
    // caller's job (EventLoop::coalesceRanges).
    r = parseRange("bytes=0-9,20-29", total);
    CHECK_EQ(r.size(), 2u);
    if(r.size() == 2) { CHECK_EQ(r[0].last, 9); CHECK_EQ(r[1].first, 20); }

    // Optional whitespace around the unit and elements.
    r = parseRange("bytes = 0-9 , 20-29", total);
    CHECK_EQ(r.size(), 2u);

    // Nothing is satisfiable in a zero-length representation.
    CHECK(parseRange("bytes=0-", 0).empty());
    CHECK(parseRange("bytes=0-0", 0).empty());
}

static void test_range_syntax() {
    section("rangeSyntaxValid");
    // Well-formed: a 416 is only correct for these.
    CHECK(rangeSyntaxValid("bytes=0-9"));
    CHECK(rangeSyntaxValid("bytes=500-"));
    CHECK(rangeSyntaxValid("bytes=-10"));
    CHECK(rangeSyntaxValid("bytes=0-9,20-29"));
    CHECK(rangeSyntaxValid("bytes = 0-9 "));
    // Malformed or another unit: must be ignored, so these are NOT valid.
    CHECK(!rangeSyntaxValid("bytes=abc"));
    CHECK(!rangeSyntaxValid("bytes="));
    CHECK(!rangeSyntaxValid("bytes=1-2-3"));
    CHECK(!rangeSyntaxValid("bytes=-"));
    CHECK(!rangeSyntaxValid("items=0-5"));
    CHECK(!rangeSyntaxValid("0-9"));
    CHECK(!rangeSyntaxValid(""));
}

// ── URL handling ──────────────────────────────────────────────────────────────
static void test_url() {
    section("Url");
    CHECK_STR(Url::urlDecode("a%20b"), "a b");
    CHECK_STR(Url::urlDecode("a+b"), "a b");
    CHECK_STR(Url::urlDecode("%41%42%43"), "ABC");
    CHECK_STR(Url::urlDecode("plain"), "plain");
    CHECK_STR(Url::urlDecode("100%25"), "100%");
    // Invalid escape is passed through rather than dropped.
    CHECK_STR(Url::urlDecode("%zz"), "%zz");

    CHECK_STR(Url::urlEncode("a b"), "a%20b");
    CHECK_STR(Url::urlEncode("a-b_c.d~e"), "a-b_c.d~e");   // unreserved
    CHECK_STR(Url::urlEncode("/?&="), "%2F%3F%26%3D");

    Url u;
    u.query = "a=1&b=hello%20world&c=";
    auto m = u.parseQuery();
    CHECK_STR(m["a"], "1");
    CHECK_STR(m["b"], "hello world");
    CHECK_EQ(m.count("c"), 1u);       // present but empty
    CHECK_STR(m["c"], "");

    // A bare key with no '=' is not a pair and is skipped.
    Url u2; u2.query = "flag&a=1";
    auto m2 = u2.parseQuery();
    CHECK_EQ(m2.count("flag"), 0u);
    CHECK_STR(m2["a"], "1");
}

// ── Dates, ETags, MIME ────────────────────────────────────────────────────────
static void test_http_date() {
    section("httpDate");
    const time_t t = 1700000000;   // 2023-11-14T22:13:20Z
    std::string s = httpDate(t);
    CHECK_STR(s, "Tue, 14 Nov 2023 22:13:20 GMT");
    CHECK_EQ(parseHttpDate(s), t);                     // IMF-fixdate round-trip
    CHECK_EQ(parseHttpDate("Tue, 14 Nov 2023 22:13:20 GMT"), t);
    // asctime form (RFC 9110 §5.6.7 obs-date)
    CHECK_EQ(parseHttpDate("Tue Nov 14 22:13:20 2023"), t);
    CHECK_EQ(parseHttpDate("not a date"), 0);          // 0 signals failure
}

static void test_etag() {
    section("ETag");
    auto e = ETag::parse("\"abc123\"");
    CHECK_STR(e.value, "abc123");
    CHECK(!e.weak);
    CHECK_STR(e.format(), "\"abc123\"");

    auto w = ETag::parse("W/\"abc123\"");
    CHECK_STR(w.value, "abc123");
    CHECK(w.weak);
    CHECK_STR(w.format(), "W/\"abc123\"");
    CHECK(e.matches(w));    // weak comparison ignores the W/ marker
}

static void test_mime() {
    section("mimeFromExt");
    CHECK_STR(mimeFromExt("html"), "text/html; charset=utf-8");
    CHECK_STR(mimeFromExt("css"), "text/css; charset=utf-8");
    CHECK_STR(mimeFromExt("png"), "image/png");
    CHECK_STR(mimeFromExt("woff2"), "font/woff2");
    CHECK_STR(mimeFromExt("unknown-ext"), "application/octet-stream");
    CHECK_STR(mimeFromExt(""), "application/octet-stream");
}

static void test_methods() {
    section("methods");
    CHECK(methodFromStr("GET") == Method::GET);
    CHECK(methodFromStr("PATCH") == Method::PATCH);
    CHECK(methodFromStr("BOGUS") == Method::UNKNOWN);
    CHECK(methodFromStr("get") == Method::UNKNOWN);      // methods are case-sensitive
    CHECK_STR(methodStr(Method::HEAD), "HEAD");
    CHECK(methodSafe(Method::GET));
    CHECK(methodSafe(Method::HEAD));
    CHECK(!methodSafe(Method::POST));
    CHECK(methodIdempotent(Method::PUT));
    CHECK(!methodIdempotent(Method::POST));
}

// ── Header collection ─────────────────────────────────────────────────────────
static void test_headers() {
    section("Headers");
    Headers h;
    h.set("Content-Type", "text/html");
    CHECK_STR(h.get("content-type"), "text/html");     // lookup is case-insensitive
    CHECK_STR(h.get("CONTENT-TYPE"), "text/html");
    CHECK(h.has("Content-Type"));

    h.set("content-type", "text/plain");               // set replaces
    CHECK_EQ(h.size(), 1u);
    CHECK_STR(h.get("content-type"), "text/plain");

    h.add("set-cookie", "a=1");                        // add appends
    h.add("set-cookie", "b=2");
    CHECK_EQ(h.size(), 3u);
    CHECK_STR(h.get("set-cookie"), "a=1");             // get returns the first

    CHECK(h.contains("content-type", "plain"));        // substring match
    CHECK(!h.contains("content-type", "html"));

    h.remove("set-cookie");                            // removes every instance
    CHECK_EQ(h.size(), 1u);
    CHECK_STR(h.get("set-cookie"), "");

    CHECK(!h.has("no-such-header"));
}

static void test_cookie_format() {
    section("Cookie::format");
    Cookie c;
    c.name = "SID"; c.value = "abc";
    c.httpOnly = true; c.secure = true; c.maxAge = 3600;
    std::string s = c.format();
    CHECK_STR(s, "SID=abc; Path=/; Max-Age=3600; Secure; HttpOnly; SameSite=Lax");

    Cookie session;                                    // maxAge -1 → no Max-Age
    session.name = "S"; session.value = "1";
    CHECK_STR(session.format(), "S=1; Path=/; SameSite=Lax");
}

// ── HTTP/1.1 request parser ───────────────────────────────────────────────────
// Feeds a whole buffer and reports whether the message completed.
static bool feedAll(Http1Parser& p, const std::string& raw) {
    size_t consumed = p.feed(raw.data(), raw.size());
    (void)consumed;
    return p.complete();
}

static void test_parser_basic() {
    section("Http1Parser basic");
    Http1Parser p;
    CHECK(feedAll(p, "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"));
    auto& r = p.request();
    CHECK(r.method == Method::GET);
    CHECK(r.version == HttpVersion::HTTP11);
    CHECK_STR(r.url.path, "/index.html");
    CHECK_STR(r.headers.get("host"), "example.com");
    CHECK(r.keepAlive);                                // HTTP/1.1 defaults to keep-alive
    CHECK(!r.hasBody);
}

static void test_parser_query_and_target() {
    section("Http1Parser target");
    Http1Parser p;
    CHECK(feedAll(p, "GET /a/b?x=1&y=2 HTTP/1.1\r\nHost: h\r\n\r\n"));
    CHECK_STR(p.request().url.path, "/a/b");
    CHECK_STR(p.request().url.query, "x=1&y=2");

    Http1Parser p2;
    CHECK(feedAll(p2, "GET http://example.com/abs HTTP/1.1\r\nHost: h\r\n\r\n"));
    CHECK_STR(p2.request().url.path, "/abs");          // absolute-form
}

static void test_parser_body() {
    section("Http1Parser body");
    Http1Parser p;
    CHECK(feedAll(p, "POST /submit HTTP/1.1\r\nHost: h\r\n"
                     "Content-Length: 11\r\n\r\nhello world"));
    CHECK(p.request().method == Method::POST);
    CHECK_STR(p.request().body, "hello world");
    CHECK_EQ(p.request().contentLen, 11);
}

static void test_parser_chunked() {
    section("Http1Parser chunked");
    Http1Parser p;
    CHECK(feedAll(p, "POST /c HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
                     "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"));
    CHECK(p.request().chunked);
    CHECK_STR(p.request().body, "hello world");
}

static void test_parser_incremental() {
    section("Http1Parser incremental");
    // Byte-at-a-time delivery must produce the same result as one big feed.
    // Mirrors EventLoop::onReadable: accumulate, feed, drop consumed bytes.
    const std::string raw =
        "POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nabcde";
    Http1Parser p;
    std::string buf;
    bool done = false;
    for(size_t i = 0; i < raw.size() && !done; ++i) {
        buf += raw[i];
        size_t used = p.feed(buf.data(), buf.size());
        if(used > 0 && used <= buf.size()) buf.erase(0, used);
        CHECK(!p.error());
        done = p.complete();
    }
    CHECK(done);
    CHECK_STR(p.request().body, "abcde");
    CHECK_STR(p.request().headers.get("host"), "h");
}

// Regression: a line split exactly between its CR and its LF. scanLine can only
// strip CRLF when both bytes are in one chunk, so the CR used to survive into the
// parsed line and the request was rejected as malformed. The same input also
// used to read one byte before the buffer, because the LF landed at index 0.
static void test_parser_crlf_split() {
    section("Http1Parser CRLF split across reads");
    struct Case { const char* a; const char* b; };
    const Case cases[] = {
        // split inside the request line's terminator
        {"GET /p HTTP/1.1\r", "\nHost: h\r\n\r\n"},
        // split inside a header's terminator
        {"GET /p HTTP/1.1\r\nHost: h\r", "\nAccept: */*\r\n\r\n"},
        // split before the blank line that ends the headers
        {"GET /p HTTP/1.1\r\nHost: h\r\n\r", "\n"},
    };
    for(const auto& c : cases) {
        Http1Parser p;
        std::string buf(c.a);
        size_t used = p.feed(buf.data(), buf.size());
        buf.erase(0, used);
        CHECK(!p.error());
        buf += c.b;
        used = p.feed(buf.data(), buf.size());
        buf.erase(0, used);
        CHECK(!p.error());
        CHECK(p.complete());
        if(p.complete()) {
            CHECK_STR(p.request().url.path, "/p");
            CHECK_STR(p.request().headers.get("host"), "h");
        }
    }

    // A chunk that begins with LF is the case that read out of bounds.
    Http1Parser lone;
    std::string first = "GET /q HTTP/1.1\r";
    size_t u = lone.feed(first.data(), first.size());
    first.erase(0, u);
    std::string second = "\n";                 // LF alone, at index 0
    u = lone.feed(second.data(), second.size());
    CHECK(!lone.error());
    std::string rest = "Host: h\r\n\r\n";
    lone.feed(rest.data(), rest.size());
    CHECK(lone.complete());
    if(lone.complete()) CHECK_STR(lone.request().url.path, "/q");
}

static void test_parser_connection_and_cookies() {
    section("Http1Parser connection/cookies");
    Http1Parser p;
    CHECK(feedAll(p, "GET / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n"
                     "Cookie: a=1; b=two\r\n\r\n"));
    CHECK(!p.request().keepAlive);
    CHECK_EQ(p.request().cookies.size(), 2u);
    CHECK_STR(p.request().cookies["a"], "1");
    CHECK_STR(p.request().cookies["b"], "two");

    Http1Parser p10;
    CHECK(feedAll(p10, "GET / HTTP/1.0\r\nHost: h\r\n\r\n"));
    CHECK(p10.request().version == HttpVersion::HTTP10);
    CHECK(!p10.request().keepAlive);                    // HTTP/1.0 defaults to close
}

static void test_parser_errors() {
    section("Http1Parser errors");
    Http1Parser p;
    p.feed("NOT A REQUEST LINE\r\n\r\n", 22);
    CHECK(p.error());
    CHECK(p.errCode() >= 400);

    Http1Parser p2;                                    // reset must clear error state
    p2.feed("GARBAGE\r\n", 9);
    CHECK(p2.error());
    p2.reset();
    CHECK(!p2.error());
    CHECK(feedAll(p2, "GET / HTTP/1.1\r\nHost: h\r\n\r\n"));
}

// ── Response serialisation ────────────────────────────────────────────────────
static void test_response_serialise() {
    section("RawResponse::serialise");
    RawResponse r;
    r.statusCode = 404;
    r.headers.set("date", "Tue, 14 Nov 2023 22:13:20 GMT");   // pin for determinism
    r.setBody("text/plain", "missing");
    std::string out = r.serialise();
    CHECK(out.compare(0, 24, "HTTP/1.1 404 Not Found\r\n") == 0);
    CHECK(out.find("content-type: text/plain\r\n") != std::string::npos);
    CHECK(out.find("content-length: 7\r\n") != std::string::npos);
    CHECK(out.find("\r\n\r\nmissing") != std::string::npos);

    // headOnly keeps the headers (including content-length) but drops the body.
    std::string head = r.serialise(true);
    CHECK(head.find("content-length: 7\r\n") != std::string::npos);
    CHECK(head.find("missing") == std::string::npos);
    CHECK(head.size() == out.size() - 7);
}

// ── HPACK ─────────────────────────────────────────────────────────────────────
static void test_hpack_roundtrip() {
    section("HPACK round-trip");
    std::vector<HpackHeader> in = {
        {":method", "GET"},              // static table, indexed
        {":path", "/index.html"},        // static name, literal value
        {":scheme", "https"},
        {"host", "example.com"},
        {"user-agent", "test/1.0"},
        {"custom-key", "custom-value"},  // fully literal
        {"x-empty", ""},
    };
    HpackEncoder enc;
    HpackDecoder dec;
    std::vector<uint8_t> wire;
    enc.encode(in, wire);
    CHECK(!wire.empty());

    std::vector<HpackHeader> out;
    CHECK(dec.decode(wire.data(), wire.size(), out));
    CHECK_EQ(out.size(), in.size());
    for(size_t i = 0; i < out.size() && i < in.size(); ++i) {
        CHECK_STR(out[i].name, in[i].name);
        CHECK_STR(out[i].value, in[i].value);
    }
}

static void test_hpack_dyntable() {
    section("HPACK dynamic table");
    HpackDynTable t;
    CHECK_EQ(t.count(), 0u);
    t.insert("custom", "value");
    CHECK_EQ(t.count(), 1u);
    // Index 62 is the newest dynamic entry (1..61 are static).
    const HpackHeader* h = t.get(62);
    CHECK(h != nullptr);
    if(h) { CHECK_STR(h->name, "custom"); CHECK_STR(h->value, "value"); }
    CHECK_EQ(t.findNameValue("custom", "value"), 62u);
    CHECK_EQ(t.findNameValue("custom", "other"), 0u);   // 0 = not found

    // Static table is still reachable by index.
    const HpackHeader* s = t.get(2);
    CHECK(s != nullptr);
    if(s) CHECK_STR(s->name, ":method");

    // Shrinking the table evicts.
    t.setMaxSize(0);
    CHECK_EQ(t.count(), 0u);
}

// ── Cache-Control / cacheability ──────────────────────────────────────────────
static void test_cache_control() {
    section("CacheControl::parse");
    auto cc = CacheControl::parse("public, max-age=3600");
    CHECK(cc.isPublic);
    CHECK_EQ(cc.maxAge, 3600);
    CHECK(!cc.noStore);

    auto nc = CacheControl::parse("no-store, no-cache");
    CHECK(nc.noStore);
    CHECK(nc.noCache);

    auto pv = CacheControl::parse("private, s-maxage=60, must-revalidate");
    CHECK(pv.isPrivate);
    CHECK_EQ(pv.sMaxAge, 60);
    CHECK(pv.mustRevalidate);

    auto empty = CacheControl::parse("");
    CHECK_EQ(empty.maxAge, -1);
}

static void test_is_cacheable() {
    section("HttpCache::isCacheable");
    RawRequest get;  get.method = Method::GET;
    RawRequest post; post.method = Method::POST;

    RawResponse ok;
    ok.statusCode = 200;
    ok.headers.set("cache-control", "public, max-age=3600");
    CHECK(HttpCache::isCacheable(get, ok));
    CHECK(!HttpCache::isCacheable(post, ok));          // only GET/HEAD

    // Regression: a 206 must never be stored. The cache key is the URI with no
    // range in it, so a stored partial would be replayed to a later full GET as
    // a truncated body. Note the response carries max-age, which an earlier
    // version's status-list fallback used to re-admit.
    RawResponse partial;
    partial.statusCode = 206;
    partial.headers.set("cache-control", "public, max-age=3600");
    partial.headers.set("content-range", "bytes 0-9/500");
    CHECK(!HttpCache::isCacheable(get, partial));

    // Content-Range alone is enough to disqualify it.
    RawResponse cr;
    cr.statusCode = 200;
    cr.headers.set("cache-control", "public, max-age=3600");
    cr.headers.set("content-range", "bytes 0-9/500");
    CHECK(!HttpCache::isCacheable(get, cr));

    RawResponse nostore;
    nostore.statusCode = 200;
    nostore.headers.set("cache-control", "no-store");
    CHECK(!HttpCache::isCacheable(get, nostore));

    RawResponse priv;
    priv.statusCode = 200;
    priv.headers.set("cache-control", "private");
    CHECK(!HttpCache::isCacheable(get, priv));
}

static void test_cache_entry_freshness() {
    section("CacheEntry freshness");
    CacheEntry e;
    time(&e.storedAt);
    e.maxAge = 3600;
    CHECK(e.fresh());
    CHECK(!e.stale());

    CacheEntry expired;
    time(&expired.storedAt);
    expired.storedAt -= 7200;
    expired.maxAge = 3600;
    CHECK(expired.stale());

    // No explicit freshness and no Last-Modified → lifetime 0, never fresh.
    // This is why Lua responses were never served from the cache.
    CacheEntry bare;
    time(&bare.storedAt);
    CHECK_EQ(bare.freshnessLifetime(), 0);
    CHECK(bare.stale());
}

// ── FileCache ─────────────────────────────────────────────────────────────────
static std::string g_tmpdir;

static std::string writeTmp(const char* name, const std::string& content) {
    std::string path = g_tmpdir + "/" + name;
    FILE* f = fopen(path.c_str(), "wb");
    if(f) { fwrite(content.data(), 1, content.size(), f); fclose(f); }
    return path;
}

static void test_file_cache() {
    section("FileCache");
    FileCache::Config cfg;
    cfg.maxFileBytes = 1024;          // small so the ceiling is easy to cross
    cfg.maxTotalBytes = 4096;
    cfg.maxEntries = 8;
    FileCache fc(cfg);

    std::string p = writeTmp("fc1.txt", "hello");
    struct stat st{};
    CHECK_EQ(stat(p.c_str(), &st), 0);

    auto a = fc.get(p, st);
    CHECK(a != nullptr);
    if(a) CHECK_STR(*a, "hello");
    CHECK_EQ(fc.stats().misses, 1u);
    CHECK_EQ(fc.stats().entries, 1u);

    auto b = fc.get(p, st);                       // same stamp → hit
    CHECK_EQ(fc.stats().hits, 1u);
    CHECK(b != nullptr);
    if(b) CHECK_STR(*b, "hello");

    // Rewrite with different content and re-stat: the stamp changes, so the
    // cached copy must be discarded. Same-second edits are the interesting case,
    // which is why the stamp carries nanosecond mtime.
    writeTmp("fc1.txt", "goodbye!");
    struct stat st2{};
    CHECK_EQ(stat(p.c_str(), &st2), 0);
    auto c = fc.get(p, st2);
    CHECK(c != nullptr);
    if(c) CHECK_STR(*c, "goodbye!");
    CHECK_EQ(fc.stats().misses, 2u);

    // A stale stamp must not resurrect old content either.
    auto d = fc.get(p, st2);
    CHECK(d != nullptr);
    if(d) CHECK_STR(*d, "goodbye!");

    // Over the per-file ceiling: served, but not retained.
    std::string big(cfg.maxFileBytes + 100, 'x');
    std::string bp = writeTmp("fc_big.txt", big);
    struct stat bst{};
    CHECK_EQ(stat(bp.c_str(), &bst), 0);
    size_t entriesBefore = fc.stats().entries;
    auto e = fc.get(bp, bst);
    CHECK(e != nullptr);
    if(e) CHECK_EQ(e->size(), big.size());
    CHECK_EQ(fc.stats().entries, entriesBefore);   // not added

    // Missing file → nullptr, not a crash.
    struct stat nst = st2;
    CHECK(fc.get(g_tmpdir + "/does-not-exist", nst) == nullptr);

    // Byte budget forces eviction while keeping every answer correct.
    FileCache::Config small;
    small.maxFileBytes = 512;
    small.maxTotalBytes = 1024;       // only ~2 x 500-byte files fit
    small.maxEntries = 8;
    FileCache fc2(small);
    std::vector<std::string> paths;
    for(int i = 0; i < 6; ++i) {
        char nm[32]; snprintf(nm, sizeof nm, "ev%d.bin", i);
        paths.push_back(writeTmp(nm, std::string(500, char('a' + i))));
    }
    for(int pass = 0; pass < 2; ++pass) {
        for(int i = 0; i < 6; ++i) {
            struct stat es{};
            CHECK_EQ(stat(paths[i].c_str(), &es), 0);
            auto got = fc2.get(paths[i], es);
            CHECK(got != nullptr);
            if(got) {
                CHECK_EQ(got->size(), 500u);
                CHECK(got->at(0) == char('a' + i));   // never a neighbour's bytes
            }
        }
    }
    CHECK(fc2.stats().evictions > 0);                 // budget was actually enforced
    CHECK(fc2.stats().bytes <= small.maxTotalBytes);
    CHECK(fc2.stats().entries <= small.maxEntries);

    fc2.clear();
    CHECK_EQ(fc2.stats().entries, 0u);
    CHECK_EQ(fc2.stats().bytes, 0u);
}

static void test_file_stamp() {
    section("FileStamp");
    std::string p = writeTmp("stamp.txt", "abc");
    struct stat a{}, b{};
    CHECK_EQ(stat(p.c_str(), &a), 0);
    auto s = FileStamp::of(a);
    CHECK(s.sameAs(a));

    // Same size, different content, rewritten immediately: only nanosecond mtime
    // (or inode) can tell these apart.
    writeTmp("stamp.txt", "xyz");
    CHECK_EQ(stat(p.c_str(), &b), 0);
    bool differs = !s.sameAs(b);
    if(!differs) {
        // Filesystem without nanosecond timestamps — report rather than fail,
        // since the code is correct and the platform simply cannot distinguish.
        fprintf(stderr, "  NOTE [FileStamp] filesystem lacks sub-second mtime; "
                        "same-size same-second edits cannot be detected here\n");
    }
    CHECK(differs || a.st_mtim.tv_nsec == b.st_mtim.tv_nsec);
}

// ── common.h primitives ───────────────────────────────────────────────────────
static void test_str() {
    section("Str<N>");
    Str<8> s("hello");
    CHECK_EQ(s.len, 5u);
    CHECK_STR(s.c_str(), "hello");
    CHECK(s == "hello");
    CHECK(s != "hellO");
    CHECK(s.eqi("HELLO"));

    CHECK(s.append("!!", 2));
    CHECK_STR(s.c_str(), "hello!!");
    // Capacity is a hard ceiling; append reports the truncation.
    CHECK(!s.append("world", 5));
    CHECK_EQ(s.len, 8u);

    s.clear();
    CHECK(s.empty());

    Str<16> f;
    f.fmt("%d-%s", 42, "x");
    CHECK_STR(f.c_str(), "42-x");
}

static void test_ringbuf() {
    section("RingBuf");
    RingBuf<8> rb;
    CHECK_EQ(rb.readable(), 0u);
    CHECK_EQ(rb.writable(), 8u);

    CHECK_EQ(rb.write("abcd", 4), 4u);
    CHECK_EQ(rb.readable(), 4u);

    char out[8] = {};
    CHECK_EQ(rb.read(out, 4), 4u);
    CHECK_STR(std::string(out, 4), "abcd");
    CHECK_EQ(rb.readable(), 0u);

    // Writes past capacity are truncated, not overflowed.
    CHECK_EQ(rb.write("0123456789", 10), 8u);
    CHECK_EQ(rb.readable(), 8u);

    // Wrap-around: read part, write part, verify ordering holds.
    rb.reset();
    rb.write("12345", 5);
    char five[5] = {};
    rb.read(five, 3);
    rb.write("678", 3);
    char rest[8] = {};
    size_t n = rb.read(rest, sizeof rest);
    CHECK_STR(std::string(rest, n), "45678");
}

static void test_result() {
    section("Result");
    Result<int> ok(42);
    CHECK(ok.ok());
    CHECK(static_cast<bool>(ok));
    CHECK_EQ(*ok, 42);

    Result<int> bad(Err::NotFound);
    CHECK(!bad.ok());
    CHECK(bad.e == Err::NotFound);

    Res v;
    CHECK(v.ok());
    Res e(Err::Timeout);
    CHECK(!e.ok());
    CHECK(e.e == Err::Timeout);
}

// ── main ──────────────────────────────────────────────────────────────────────
int main() {
    char tmpl[] = "/tmp/httpd_unit_XXXXXX";
    char* dir = mkdtemp(tmpl);
    if(!dir) { fprintf(stderr, "cannot create temp dir\n"); return 2; }
    g_tmpdir = dir;

    printf("httpd unit tests\n");

    test_parse_range();
    test_range_syntax();
    test_url();
    test_http_date();
    test_etag();
    test_mime();
    test_methods();
    test_headers();
    test_cookie_format();
    test_parser_basic();
    test_parser_query_and_target();
    test_parser_body();
    test_parser_chunked();
    test_parser_incremental();
    test_parser_crlf_split();
    test_parser_connection_and_cookies();
    test_parser_errors();
    test_response_serialise();
    test_hpack_roundtrip();
    test_hpack_dyntable();
    test_cache_control();
    test_is_cacheable();
    test_cache_entry_freshness();
    test_file_cache();
    test_file_stamp();
    test_str();
    test_ringbuf();
    test_result();

    // Best-effort cleanup; leaving files behind must not fail the run.
    char cmd[512];
    snprintf(cmd, sizeof cmd, "rm -rf '%s'", g_tmpdir.c_str());
    if(system(cmd) != 0) fprintf(stderr, "  NOTE: temp dir %s left behind\n",
                                 g_tmpdir.c_str());

    printf("\n%d checks, %d failure%s\n",
           g_checks, g_failures, g_failures == 1 ? "" : "s");
    return g_failures == 0 ? 0 : 1;
}
