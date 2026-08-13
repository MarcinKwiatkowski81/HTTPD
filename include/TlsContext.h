// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
// TLS layer via OpenSSL — wraps SSL_CTX + per-connection SSL*
#pragma once
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string>
#include <memory>
#include <cstdio>
#include <sys/types.h>

namespace httpd {

// ── TLS configuration ─────────────────────────────────────────────────────────
struct TlsConfig {
    std::string certFile;    // PEM certificate chain
    std::string keyFile;     // PEM private key
    std::string caFile;      // CA bundle (optional)
    bool verifyClient= false;
    int  sessionTimeout= 300;
    // Cipher list (TLS 1.2 and below)
    std::string ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:"
                          "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
                          "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305";
    // TLS 1.3 cipher suites
    std::string ciphersuites= "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";
    bool enableHttp2 = true;
    // Ask OpenSSL for kernel TLS offload, which is what allows a TLS response
    // body to be streamed with SSL_sendfile() instead of buffered. Harmless when
    // unavailable: OpenSSL silently keeps encrypting in user space. Requires the
    // kernel "tls" module, an AEAD cipher, and OpenSSL built with KTLS.
    bool enableKtls = true;
};

// ── TLS server context (shared across connections) ────────────────────────────
class TlsContext {
public:
    TlsContext() = default;
    ~TlsContext();
    TlsContext(const TlsContext&) = delete;
    TlsContext& operator=(const TlsContext&) = delete;

    bool init(const TlsConfig& cfg);
    SSL* newSsl(int fd);     // returns SSL* for a new accepted connection
    void freeSsl(SSL* ssl);

    bool valid() const { return ctx_ != nullptr; }

    static void initLibrary();  // call once at startup

private:
    SSL_CTX* ctx_ = nullptr;
    static bool libInited_;
};

// ── Per-connection TLS wrapper ────────────────────────────────────────────────
class TlsConn {
public:
    enum class IOResult { Ok, WantRead, WantWrite, Error, Closed };

    TlsConn() = default;
    ~TlsConn() { if(ssl_) SSL_free(ssl_); }
    TlsConn(const TlsConn&) = delete;
    TlsConn& operator=(const TlsConn&) = delete;

    void attach(SSL* ssl) { ssl_=ssl; }

    // Returns true when handshake complete.
    IOResult doHandshake();

    // Non-blocking read; n = bytes read, or -1 on error.
    IOResult read(char* buf, size_t cap, ssize_t& n);
    IOResult write(const char* buf, size_t len, ssize_t& n);
    void shutdown();

    bool handshakeDone() const { return done_; }

    // True when the kernel is performing record encryption for writes on this
    // connection (KTLS tx offload) — the precondition for sendFile() below.
    // Only meaningful once the handshake has completed, since KTLS is set up
    // from the negotiated keys.
    bool ktlsSend() const;

    // Send `count` bytes of `fd` starting at `offset` directly to the socket,
    // with the kernel encrypting them. Valid ONLY when ktlsSend() is true.
    // Unlike ::sendfile(), this does not advance `offset` — the caller must.
    IOResult sendFile(int fd, off_t offset, size_t count, ssize_t& n);

    // ALPN negotiated protocol (e.g. "h2" or "http/1.1")
    const char* alpn() const;

    bool isHttp2() const { const char* a=alpn(); return a&&std::string(a)=="h2"; }

private:
    SSL* ssl_  = nullptr;
    bool done_ = false;
};

} // namespace httpd
