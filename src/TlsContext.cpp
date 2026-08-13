// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
#include "TlsContext.h"
#include <openssl/err.h>
#include <cstring>

namespace httpd {

bool TlsContext::libInited_ = false;

void TlsContext::initLibrary() {
    if(libInited_) return;
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    libInited_=true;
}

TlsContext::~TlsContext() { if(ctx_) SSL_CTX_free(ctx_); }

bool TlsContext::init(const TlsConfig& cfg) {
    initLibrary();
    // TLS 1.2+ only
    ctx_=SSL_CTX_new(TLS_server_method());
    if(!ctx_) return false;

    SSL_CTX_set_min_proto_version(ctx_,TLS1_2_VERSION);

    // Load certificate
    if(!cfg.certFile.empty()) {
        if(SSL_CTX_use_certificate_chain_file(ctx_,cfg.certFile.c_str())!=1) {
            fprintf(stderr,"[TLS] Failed to load cert: %s\n",cfg.certFile.c_str());
            ERR_print_errors_fp(stderr); return false;
        }
    }
    if(!cfg.keyFile.empty()) {
        if(SSL_CTX_use_PrivateKey_file(ctx_,cfg.keyFile.c_str(),SSL_FILETYPE_PEM)!=1) {
            fprintf(stderr,"[TLS] Failed to load key: %s\n",cfg.keyFile.c_str());
            ERR_print_errors_fp(stderr); return false;
        }
        if(!SSL_CTX_check_private_key(ctx_)) {
            fprintf(stderr,"[TLS] Private key mismatch\n"); return false;
        }
    }
    if(!cfg.caFile.empty()) SSL_CTX_load_verify_locations(ctx_,cfg.caFile.c_str(),nullptr);

    // Ciphers
    SSL_CTX_set_cipher_list(ctx_,cfg.ciphers.c_str());
    SSL_CTX_set_ciphersuites(ctx_,cfg.ciphersuites.c_str());

    // Security options
    SSL_CTX_set_options(ctx_,SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|
                             SSL_OP_NO_COMPRESSION|SSL_OP_SINGLE_DH_USE|
                             SSL_OP_SINGLE_ECDH_USE|SSL_OP_CIPHER_SERVER_PREFERENCE);

    // Kernel TLS offload. Requesting it is safe unconditionally: if the kernel
    // "tls" module is missing, the cipher is not AEAD, or OpenSSL was built
    // without KTLS, OpenSSL just keeps encrypting in user space and
    // TlsConn::ktlsSend() reports false, so callers fall back to buffering.
    //
    // Deliberately NOT enabling SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE: it lets
    // the crypto read page cache in place, so a file modified while it is being
    // sent produces corrupt ciphertext. This server treats live edits as normal
    // (see the mtime-validated caches), so that trade is wrong here.
#ifdef SSL_OP_ENABLE_KTLS
    if(cfg.enableKtls) SSL_CTX_set_options(ctx_, SSL_OP_ENABLE_KTLS);
#endif

    // ECDH
    SSL_CTX_set_ecdh_auto(ctx_,1);

    // Session
    SSL_CTX_set_session_cache_mode(ctx_,SSL_SESS_CACHE_SERVER);
    SSL_CTX_set_timeout(ctx_,cfg.sessionTimeout);

    // ALPN — negotiate h2 or http/1.1
    if(cfg.enableHttp2) {
        static const unsigned char alpnProtos[]="\x02h2\x08http/1.1";
        SSL_CTX_set_alpn_protos(ctx_,alpnProtos,sizeof(alpnProtos)-1);
        SSL_CTX_set_alpn_select_cb(ctx_,
            [](SSL*, const unsigned char** out, unsigned char* outlen,
               const unsigned char* in, unsigned int inlen, void*) -> int {
                // Prefer h2 over http/1.1
                static const unsigned char h2[]="\x02h2";
                static const unsigned char h11[]="\x08http/1.1";
                if(SSL_select_next_proto((unsigned char**)out,outlen,h2,3,in,inlen)==OPENSSL_NPN_NEGOTIATED) return SSL_TLSEXT_ERR_OK;
                if(SSL_select_next_proto((unsigned char**)out,outlen,h11,9,in,inlen)==OPENSSL_NPN_NEGOTIATED) return SSL_TLSEXT_ERR_OK;
                return SSL_TLSEXT_ERR_NOACK;
            }, nullptr);
    }

    // Client verification
    if(cfg.verifyClient)
        SSL_CTX_set_verify(ctx_,SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT,nullptr);

    return true;
}

SSL* TlsContext::newSsl(int fd) {
    if(!ctx_) return nullptr;
    SSL* ssl=SSL_new(ctx_);
    if(!ssl) return nullptr;
    SSL_set_fd(ssl,fd);
    SSL_set_accept_state(ssl);
    return ssl;
}

void TlsContext::freeSsl(SSL* ssl) { if(ssl) SSL_free(ssl); }

// ── TlsConn ───────────────────────────────────────────────────────────────────
TlsConn::IOResult TlsConn::doHandshake() {
    if(done_) return IOResult::Ok;
    int r=SSL_do_handshake(ssl_);
    if(r==1) { done_=true; return IOResult::Ok; }
    int err=SSL_get_error(ssl_,r);
    if(err==SSL_ERROR_WANT_READ)  return IOResult::WantRead;
    if(err==SSL_ERROR_WANT_WRITE) return IOResult::WantWrite;
    return IOResult::Error;
}

TlsConn::IOResult TlsConn::read(char* buf, size_t cap, ssize_t& n) {
    int r=SSL_read(ssl_,buf,(int)cap);
    if(r>0)  { n=r; return IOResult::Ok; }
    if(r==0) { n=0; return IOResult::Closed; }
    int err=SSL_get_error(ssl_,r);
    if(err==SSL_ERROR_WANT_READ)  { n=0; return IOResult::WantRead; }
    if(err==SSL_ERROR_WANT_WRITE) { n=0; return IOResult::WantWrite; }
    n=-1; return IOResult::Error;
}

// BIO_get_ktls_send is a macro in every OpenSSL 3.x build — it expands to a
// BIO_ctrl query when KTLS is compiled in and to a literal 0 when it is not, so
// no preprocessor guard is needed at the call site.
bool TlsConn::ktlsSend() const {
    if(!ssl_ || !done_) return false;
    BIO* wbio = SSL_get_wbio(ssl_);
    return wbio && BIO_get_ktls_send(wbio);
}

TlsConn::IOResult TlsConn::sendFile(int fd, off_t offset, size_t count, ssize_t& n) {
    n = 0;
    if(!ssl_) return IOResult::Error;
    ossl_ssize_t r = SSL_sendfile(ssl_, fd, offset, count, 0);
    if(r > 0) { n = (ssize_t)r; return IOResult::Ok; }
    int err = SSL_get_error(ssl_, (int)r);
    if(err==SSL_ERROR_WANT_WRITE) return IOResult::WantWrite;
    if(err==SSL_ERROR_WANT_READ)  return IOResult::WantRead;
    return IOResult::Error;
}

TlsConn::IOResult TlsConn::write(const char* buf, size_t len, ssize_t& n) {
    int r=SSL_write(ssl_,buf,(int)len);
    if(r>0)  { n=r; return IOResult::Ok; }
    if(r==0) { n=0; return IOResult::Closed; }
    int err=SSL_get_error(ssl_,r);
    if(err==SSL_ERROR_WANT_READ)  { n=0; return IOResult::WantRead; }
    if(err==SSL_ERROR_WANT_WRITE) { n=0; return IOResult::WantWrite; }
    n=-1; return IOResult::Error;
}

void TlsConn::shutdown() { if(ssl_) SSL_shutdown(ssl_); }

const char* TlsConn::alpn() const {
    if(!ssl_) return nullptr;
    const unsigned char* proto=nullptr; unsigned int plen=0;
    SSL_get0_alpn_selected(ssl_,&proto,&plen);
    if(!proto||!plen) return nullptr;
    static thread_local char buf[32];
    size_t l=std::min((size_t)plen,(size_t)31);
    memcpy(buf,proto,l); buf[l]=0;
    return buf;
}

} // namespace httpd
