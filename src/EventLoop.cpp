// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
// epoll event loop — HTTP/1.1 + HTTP/2 connection handling
#include "EventLoop.h"

#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/eventfd.h>
#include <sys/wait.h>
#include <signal.h>
#include <cstring>
#include <cstdio>
#include <cerrno>
#include <algorithm>
#include <sstream>

namespace httpd {

// ── helpers ───────────────────────────────────────────────────────────────────
static void setNonBlocking(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}
static void setTcpNoDelay(int fd) { int v=1; setsockopt(fd,IPPROTO_TCP,TCP_NODELAY,&v,sizeof v); }
static void setReusePort(int fd)  { int v=1; setsockopt(fd,SOL_SOCKET,SO_REUSEPORT,&v,sizeof v); }
static void setReuseAddr(int fd)  { int v=1; setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&v,sizeof v); }

// Safely canonicalise path — returns empty string on traversal attempt
static std::string canonicalisePath(const std::string& docRoot,
                                    const std::string& urlPath) {
    // Build candidate
    std::string p = docRoot;
    if(!urlPath.empty() && urlPath[0] != '/') p += '/';
    p += urlPath;
    // Resolve with realpath-style manual check (no allocation)
    // Reject anything that escapes docRoot after naive normalisation
    // Simple check: reject paths that contain ".."
    for(size_t i = 0; i + 1 < p.size(); ++i) {
        if(p[i]=='.'&&p[i+1]=='.'&&
           (i==0||p[i-1]=='/')&&
           (i+2>=p.size()||p[i+2]=='/'||p[i+2]=='\0'))
            return {};  // path traversal
    }
    return p;
}

// Strong validator derived purely from the file's identity and version, so it
// can be recomputed from a stat() alone. That is what lets a cached response be
// revalidated against the filesystem without re-reading the body. Nanosecond
// mtime is included so a same-second edit still changes the validator.
static std::string fileETag(const struct stat& st) {
    char buf[80];
    snprintf(buf, sizeof buf, "\"%lx-%llx-%lx-%lx\"",
             (unsigned long)st.st_ino,
             (unsigned long long)st.st_size,
             (unsigned long)st.st_mtim.tv_sec,
             (unsigned long)st.st_mtim.tv_nsec);
    return buf;
}

// ── Multi-range support ───────────────────────────────────────────────────────
// Hard cap on parts. Unbounded multi-range is an amplification DoS (the 2011
// "Apache killer", CVE-2011-3192): thousands of one-byte ranges cost ~120 bytes
// of framing each. RFC 9110 §14.2 explicitly permits rejecting such requests;
// over the cap we ignore Range and serve the whole representation.
static constexpr size_t kMaxRangeParts = 16;
// Gap below which two ranges are merged anyway — roughly one part's framing, so
// splitting would cost more bytes than the gap it saves.
static constexpr int64_t kRangeGapMerge = 80;

// Sort and merge ranges that overlap or nearly touch (RFC 9110 §14.2 permits
// coalescing). Two payoffs beyond smaller responses: the parts come out
// disjoint, so the body can never exceed the file size no matter what the client
// asks for, and a request full of tiny adjacent ranges collapses instead of
// amplifying. Note this sorts, so parts may not follow the requested order —
// RFC 9110 makes that order a SHOULD, and coalescing inherently reorders.
static std::vector<Range> coalesceRanges(std::vector<Range> in) {
    std::sort(in.begin(), in.end(),
              [](const Range& a, const Range& b){ return a.first < b.first; });
    std::vector<Range> out;
    for(const auto& r : in) {
        if(!out.empty() && r.first <= out.back().last + 1 + kRangeGapMerge)
            out.back().last = std::max(out.back().last, r.last);
        else
            out.push_back(r);
    }
    return out;
}

// 128 bits of randomness, so a boundary colliding with the file's own bytes is
// not a practical concern (the alternative — scanning the payload for every
// candidate — would defeat the point of not reading the file).
static std::string randomBoundary() {
    unsigned char raw[16] = {};
    size_t got = 0;
    if(FILE* f = fopen("/dev/urandom", "rb")) {
        got = fread(raw, 1, sizeof raw, f);
        fclose(f);
    }
    if(got != sizeof raw) {
        // Fallback: unique per response, just less unpredictable.
        static std::atomic<uint64_t> seq{0};
        uint64_t a = (uint64_t)nowWallMs(), b = (uint64_t)getpid();
        uint64_t s = seq.fetch_add(1);
        memcpy(raw, &a, 8); memcpy(raw + 8, &b, 4); memcpy(raw + 12, &s, 4);
    }
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(sizeof raw * 2);
    for(unsigned char ch : raw) { out += hex[ch >> 4]; out += hex[ch & 15]; }
    return out;
}

// Resolve a request path to the file that would actually be served: docroot-
// confined, with the directory-index probe applied. The static handler and the
// cache revalidation must agree on this, so they share one implementation —
// otherwise a cached "/" would never be revalidated against its index file.
// Returns 0 on success, or the HTTP status to send (403 traversal, 404 missing).
static int resolveStaticTarget(const std::string& docRoot,
                               const std::string& indexFiles,
                               const std::string& urlPath,
                               std::string& outPath, struct stat& outSt) {
    std::string path = canonicalisePath(docRoot, urlPath);
    if(path.empty()) return 403;

    struct stat st{};
    if(stat(path.c_str(), &st) < 0) return 404;

    if(S_ISDIR(st.st_mode)) {
        std::istringstream ss(indexFiles);
        std::string idx;
        while(ss >> idx) {
            std::string full = path + "/" + idx;
            struct stat ist{};
            if(stat(full.c_str(), &ist) == 0 && S_ISREG(ist.st_mode)) {
                path = full;
                st   = ist;
                break;
            }
        }
    }
    outPath = path;
    outSt   = st;
    return 0;
}

// ── EventLoop lifecycle ───────────────────────────────────────────────────────
EventLoop::EventLoop()  = default;
EventLoop::~EventLoop() {
    poolRunning_ = false;
    pthread_cond_broadcast(&taskCv_);
    for(auto t : threads_) pthread_join(t, nullptr);
    if(epfd_   >= 0) close(epfd_);
    if(wakefd_ >= 0) close(wakefd_);
    pthread_mutex_destroy(&taskMu_);
    pthread_cond_destroy(&taskCv_);
}

bool EventLoop::init(const ServerConfig& cfg,
                     RequestHandler handler,
                     std::shared_ptr<TlsContext> tls,
                     std::shared_ptr<HttpCache>  cache,
                     std::shared_ptr<ModuleRegistry> modules) {
    cfg_     = cfg;
    handler_ = std::move(handler);
    tls_     = std::move(tls);
    cache_   = std::move(cache);
    modules_ = std::move(modules);

    epfd_ = epoll_create1(EPOLL_CLOEXEC);
    if(epfd_ < 0) { perror("epoll_create1"); return false; }

    wakefd_ = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if(wakefd_ < 0) { perror("eventfd"); return false; }

    struct epoll_event ev{};
    ev.events      = EPOLLIN;
    // Store wakefd as .fd (integer) — we distinguish it from Connection*
    // pointers in the event loop by testing data.u64.
    ev.data.fd     = wakefd_;
    epoll_ctl(epfd_, EPOLL_CTL_ADD, wakefd_, &ev);

    startPool(cfg_.threadsPerWorker);
    return true;
}

// ── Thread pool ───────────────────────────────────────────────────────────────
void EventLoop::startPool(int n) {
    poolRunning_ = true;
    for(int i = 0; i < n; ++i) {
        pthread_t t;
        pthread_create(&t, nullptr, threadFn, this);
        threads_.push_back(t);
    }
}

// Thread pool workers now only process tasks that are explicitly enqueued
// for them (e.g. H/2 request dispatch). Connection I/O is event-loop only.
void* EventLoop::threadFn(void* arg) {
    auto* loop = static_cast<EventLoop*>(arg);
    for(;;) {
        pthread_mutex_lock(&loop->taskMu_);
        while(loop->taskQueue_.empty() && loop->poolRunning_.load())
            pthread_cond_wait(&loop->taskCv_, &loop->taskMu_);
        if(!loop->poolRunning_.load() && loop->taskQueue_.empty()) {
            pthread_mutex_unlock(&loop->taskMu_); break;
        }
        Task t = std::move(loop->taskQueue_.front());
        loop->taskQueue_.pop_front();
        pthread_mutex_unlock(&loop->taskMu_);
        t.fn();
    }
    return nullptr;
}

void EventLoop::postTask(Task t) {
    pthread_mutex_lock(&taskMu_);
    taskQueue_.push_back(std::move(t));
    pthread_mutex_unlock(&taskMu_);
    // Wake the epoll thread so it drains the task queue promptly.
    uint64_t v = 1;
    (void)write(wakefd_, &v, 8);
}

// ── epoll helpers ─────────────────────────────────────────────────────────────
void EventLoop::addToEpoll(Connection* c, uint32_t events) {
    struct epoll_event ev{};
    ev.events  = events;
    ev.data.ptr = c;
    epoll_ctl(c->epfd, EPOLL_CTL_ADD, c->fd, &ev);
}
void EventLoop::modEpoll(Connection* c, uint32_t events) {
    struct epoll_event ev{};
    ev.events  = events;
    ev.data.ptr = c;
    epoll_ctl(c->epfd, EPOLL_CTL_MOD, c->fd, &ev);
}
void EventLoop::closeConn(Connection* c) {
    epoll_ctl(c->epfd, EPOLL_CTL_DEL, c->fd, nullptr);
    if(c->isTls) c->tls.shutdown();
    close(c->fd);
    conns_.erase(c->fd);   // destroys unique_ptr → destroys Connection
}

// addConn is called from the ACCEPT thread — it must NOT touch conns_ directly.
// Post the work onto the EventLoop thread via the task queue instead.
void EventLoop::addConn(int fd, bool isTls, const char* peerAddr, uint16_t peerPort) {
    setNonBlocking(fd);
    setTcpNoDelay(fd);

    // Capture everything by value so the lambda is self-contained.
    std::string peer(peerAddr);
    postTask({ [this, fd, isTls, peer, peerPort]() {
        // Now we ARE on the EventLoop thread — safe to touch conns_.
        auto c = std::make_unique<Connection>();
        c->fd       = fd;
        c->epfd     = epfd_;
        c->isTls    = isTls;
        c->peerAddr = peer;
        c->peerPort = peerPort;
        c->createdMs = c->lastActiveMs = nowMs();
        c->deadlineMs = c->createdMs + (int64_t)cfg_.requestTimeout * 1000;

        if(isTls && tls_ && tls_->valid()) {
            SSL* ssl = tls_->newSsl(fd);
            if(!ssl) { close(fd); return; }
            c->tls.attach(ssl);
            c->state = ConnState::TlsHandshake;
        }

        Connection* ptr = c.get();
        conns_[fd] = std::move(c);
        addToEpoll(ptr, EPOLLIN | EPOLLET);
    }});
}

// ── Main event loop ───────────────────────────────────────────────────────────
void EventLoop::run() {
    running_     = true;
    nextSweepMs_ = nowMs() + 5000;

    constexpr int kMaxEv = 256;
    struct epoll_event evs[kMaxEv];

    while(running_) {
        int64_t now  = nowMs();
        int timeout  = (int)std::max((int64_t)100, nextSweepMs_ - now);
        int n        = epoll_wait(epfd_, evs, kMaxEv, timeout);
        if(n < 0) { if(errno == EINTR) continue; break; }

        // Drain tasks posted from the accept thread BEFORE processing I/O.
        // This ensures addConn() tasks run on OUR thread.
        {
            pthread_mutex_lock(&taskMu_);
            std::deque<Task> pending;
            pending.swap(taskQueue_);
            pthread_mutex_unlock(&taskMu_);
            for(auto& t : pending) t.fn();
        }

        for(int i = 0; i < n; ++i) {
            // The wakefd was added with data.fd; connection fds with data.ptr.
            // Use u64 to distinguish: wakefd is a small integer stored as .fd
            // whose upper 32 bits are zero on any sane system.
            if(evs[i].data.u64 == (uint64_t)(uint32_t)wakefd_) {
                uint64_t v; (void)read(wakefd_, &v, 8); continue;
            }
            auto* c = static_cast<Connection*>(evs[i].data.ptr);
            if(!c) continue;
            // Guard: connection might have been closed in an earlier iteration
            if(conns_.find(c->fd) == conns_.end()) continue;

            uint32_t ev = evs[i].events;
            if(ev & (EPOLLERR | EPOLLHUP)) { closeConn(c); continue; }
            if(ev & EPOLLIN)  onReadable(c);
            // Re-check: onReadable may have closed the connection
            if(ev & EPOLLOUT) {
                if(conns_.find(c->fd) != conns_.end()) onWritable(c);
            }
        }

        if(nowMs() >= nextSweepMs_) {
            sweepTimeouts();
            nextSweepMs_ = nowMs() + 5000;
        }
    }
}

void EventLoop::sweepTimeouts() {
    int64_t now = nowMs();
    std::vector<int> toClose;
    for(auto& kv : conns_) {
        auto* c = kv.second.get();
        if(c->deadlineMs > 0 && now > c->deadlineMs)
            toClose.push_back(c->fd);
    }
    for(int fd : toClose) {
        auto it = conns_.find(fd);
        if(it != conns_.end()) closeConn(it->second.get());
    }
}

// ── I/O dispatch ─────────────────────────────────────────────────────────────
void EventLoop::onError(Connection* c) { closeConn(c); }

void EventLoop::onReadable(Connection* c) {
    c->lastActiveMs = nowMs();

    // ── TLS handshake ────────────────────────────────────────────────────────
    if(c->state == ConnState::TlsHandshake) {
        auto r = c->tls.doHandshake();
        switch(r) {
        case TlsConn::IOResult::Ok:
            // Report KTLS status once per worker: whether TLS bodies can stream
            // is invisible otherwise, and silently buffering is easy to miss.
            {
                static std::atomic<bool> ktlsLogged{false};
                if(!ktlsLogged.exchange(true)) {
                    if(c->tls.ktlsSend())
                        printf("[TLS] KTLS tx active — TLS bodies stream via SSL_sendfile\n");
                    else
                        printf("[TLS] KTLS tx unavailable — TLS bodies buffered "
                               "(needs the kernel 'tls' module and an AEAD cipher)\n");
                }
            }
            if(c->tls.isHttp2()) {
                c->state = ConnState::Http2;
                c->h2 = std::make_unique<H2Session>();
                c->h2->setRequestCb([this, c](uint32_t sid,
                                               std::shared_ptr<RawRequest> req) {
                    dispatchH2(c, sid, std::move(req));
                });
            } else {
                c->state = ConnState::ReadRequest;
            }
            return;
        case TlsConn::IOResult::WantRead:
            // The normal case: the handshake consumed everything available and
            // needs more from the peer. Falling through to the default below
            // would close the connection, which made TLS unusable entirely.
            // Safe under edge-triggered epoll because WANT_READ means the socket
            // read already returned EAGAIN, so fresh data raises a new edge.
            modEpoll(c, EPOLLIN | EPOLLET); return;
        case TlsConn::IOResult::WantWrite:
            modEpoll(c, EPOLLOUT | EPOLLET); return;
        default:
            closeConn(c); return;
        }
    }

    // ── HTTP/2 ───────────────────────────────────────────────────────────────
    if(c->state == ConnState::Http2) {
        for(;;) {
            char buf[kRecvBufSize]; ssize_t n;
            if(c->isTls) {
                auto r = c->tls.read(buf, sizeof buf, n);
                if(r == TlsConn::IOResult::WantRead)  break;
                if(r != TlsConn::IOResult::Ok)        { closeConn(c); return; }
            } else {
                n = ::recv(c->fd, buf, sizeof buf, 0);
                if(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
                if(n <= 0) { closeConn(c); return; }
            }
            if(!c->h2->onData(reinterpret_cast<const uint8_t*>(buf), (size_t)n)) {
                closeConn(c); return;
            }
            auto sb = c->h2->takeSendBuf();
            if(!sb.empty()) {
                c->h2SendBuf.insert(c->h2SendBuf.end(), sb.begin(), sb.end());
                modEpoll(c, EPOLLIN | EPOLLOUT | EPOLLET);
            }
            if(c->h2->goaway()) { closeConn(c); return; }
        }
        return;
    }

    // ── HTTP/1.1 read ────────────────────────────────────────────────────────
    for(;;) {
        size_t avail = sizeof(c->recvBuf) - c->recvLen;
        if(avail == 0) { handleBadReq(c, 431); return; }

        ssize_t n;
        if(c->isTls) {
            auto r = c->tls.read(c->recvBuf + c->recvLen, avail, n);
            if(r == TlsConn::IOResult::WantRead) break;
            if(r != TlsConn::IOResult::Ok) { closeConn(c); return; }
        } else {
            n = ::recv(c->fd, c->recvBuf + c->recvLen, avail, 0);
            if(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            if(n <= 0) { closeConn(c); return; }
        }
        c->recvLen += (size_t)n;

        size_t consumed = c->parser.feed(c->recvBuf, c->recvLen);
        if(consumed > 0 && consumed <= c->recvLen) {
            memmove(c->recvBuf, c->recvBuf + consumed, c->recvLen - consumed);
            c->recvLen -= consumed;
        } else if(consumed == 0 && c->recvLen == sizeof(c->recvBuf)) {
            // Buffer full, nothing consumed → request too large
            handleBadReq(c, 413); return;
        }

        if(c->parser.error())    { handleBadReq(c, c->parser.errCode()); return; }
        if(c->parser.complete()) {
            RawRequest req = std::move(c->parser.request());
            c->parser.reset();
            c->recvLen   = 0;
            c->keepAlive = req.keepAlive;
            dispatch11(c, req);
            return;
        }
    }
}

void EventLoop::onWritable(Connection* c) {
    c->lastActiveMs = nowMs();

    if(c->state == ConnState::TlsHandshake) { onReadable(c); return; }

    // ── HTTP/2 send ──────────────────────────────────────────────────────────
    if(c->state == ConnState::Http2) {
        while(c->h2SendPos < c->h2SendBuf.size()) {
            size_t rem = c->h2SendBuf.size() - c->h2SendPos;
            ssize_t n;
            if(c->isTls) {
                auto r = c->tls.write(
                    reinterpret_cast<const char*>(c->h2SendBuf.data()) + c->h2SendPos,
                    rem, n);
                if(r == TlsConn::IOResult::WantWrite) return;
                if(r != TlsConn::IOResult::Ok) { closeConn(c); return; }
            } else {
                n = ::send(c->fd,
                           reinterpret_cast<const char*>(c->h2SendBuf.data()) + c->h2SendPos,
                           rem, MSG_NOSIGNAL);
                if(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
                if(n <= 0) { closeConn(c); return; }
            }
            c->h2SendPos += (size_t)n;
        }
        c->h2SendBuf.clear(); c->h2SendPos = 0;
        modEpoll(c, EPOLLIN | EPOLLET);
        return;
    }

    // ── HTTP/1.1 send ────────────────────────────────────────────────────────
    while(c->sendPos < c->sendBuf.size()) {
        size_t rem = c->sendBuf.size() - c->sendPos;
        ssize_t n;
        if(c->isTls) {
            auto r = c->tls.write(c->sendBuf.data() + c->sendPos, rem, n);
            if(r == TlsConn::IOResult::WantWrite) return;
            if(r != TlsConn::IOResult::Ok) { closeConn(c); return; }
        } else {
            n = ::send(c->fd, c->sendBuf.data() + c->sendPos, rem, MSG_NOSIGNAL);
            if(n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            if(n <= 0) { closeConn(c); return; }
        }
        c->sendPos += (size_t)n;
    }
    c->sendBuf.clear(); c->sendPos = 0;

    // ── Streamed body: literal + sendfile segments ───────────────────────────
    // Reached only after the headers are fully out. Streaming connections are
    // armed level-triggered (see buildAndSendResp), so returning early is safe:
    // epoll re-reports writability. That is what lets one big download yield to
    // other connections on this thread instead of monopolising it until done.
    if(c->streaming()) {
        constexpr off_t kPerCallChunk = 1024*1024;   // bound per syscall
        constexpr off_t kPerEventCap  = 4*1024*1024; // bound per event: fairness
        off_t sentNow = 0;
        // Socket buffer full. Refresh the deadline so a slow but progressing
        // client is not swept as idle mid-transfer.
        auto wouldBlock = [&]{ c->deadlineMs = nowMs() + 30000; };
        auto progressed = [&](ssize_t n){
            sentNow += n; c->lastActiveMs = nowMs(); c->deadlineMs = nowMs() + 30000;
        };

        while(!c->outSegs.empty()) {
            if(sentNow >= kPerEventCap) return;      // yield; LT will wake us again
            auto& seg = c->outSegs.front();

            if(!seg.literal.empty()) {
                while(c->outSegPos < seg.literal.size()) {
                    ssize_t n;
                    if(c->isTls) {
                        auto r = c->tls.write(seg.literal.data() + c->outSegPos,
                                              seg.literal.size() - c->outSegPos, n);
                        if(r == TlsConn::IOResult::WantWrite ||
                           r == TlsConn::IOResult::WantRead) { wouldBlock(); return; }
                        if(r != TlsConn::IOResult::Ok) { closeConn(c); return; }
                    } else {
                        n = ::send(c->fd, seg.literal.data() + c->outSegPos,
                                   seg.literal.size() - c->outSegPos, MSG_NOSIGNAL);
                        if(n < 0) {
                            if(errno == EINTR) continue;
                            if(errno == EAGAIN || errno == EWOULDBLOCK) { wouldBlock(); return; }
                            closeConn(c); return;
                        }
                        if(n == 0) { closeConn(c); return; }
                    }
                    c->outSegPos += (size_t)n;
                    progressed(n);
                }
            } else {
                while(seg.len > 0) {
                    if(sentNow >= kPerEventCap) return;
                    ssize_t n;
                    size_t want = (size_t)std::min(seg.len, kPerCallChunk);
                    if(c->isTls) {
                        // KTLS path: the kernel encrypts. SSL_sendfile takes the
                        // offset by value and does NOT advance it, unlike
                        // ::sendfile() below which updates it through the pointer.
                        auto r = c->tls.sendFile(c->fileFd, seg.off, want, n);
                        if(r == TlsConn::IOResult::WantWrite ||
                           r == TlsConn::IOResult::WantRead) { wouldBlock(); return; }
                        if(r != TlsConn::IOResult::Ok) { closeConn(c); return; }
                        seg.off += n;
                    } else {
                        n = ::sendfile(c->fd, c->fileFd, &seg.off, want);
                        if(n < 0) {
                            if(errno == EINTR) continue;
                            if(errno == EAGAIN || errno == EWOULDBLOCK) { wouldBlock(); return; }
                            closeConn(c); return;
                        }
                    }
                    // A short file means content-length can no longer be met, and
                    // continuing would desync a keep-alive connection. Drop it
                    // rather than leave the client waiting for bytes never coming.
                    if(n == 0) { closeConn(c); return; }
                    seg.len -= n;
                    progressed(n);
                }
            }
            c->outSegs.pop_front();
            c->outSegPos = 0;
        }
        c->closeFile();
    }

    if(!c->keepAlive) { closeConn(c); return; }
    c->state     = ConnState::ReadRequest;
    c->deadlineMs = nowMs() + (int64_t)cfg_.keepAliveTimeout * 1000;
    modEpoll(c, EPOLLIN | EPOLLET);
}

// ── HTTP dispatch ─────────────────────────────────────────────────────────────
void EventLoop::dispatch11(Connection* c, RawRequest& req) {
    RawResponse resp;
    resp.version = req.version;

    // Cache lookup (RFC 9111 §4). Range requests bypass it: entries are stored
    // whole under a URI-only key, so a hit would answer a range request with the
    // full 200 body. Legal (a server may ignore Range) but it breaks media
    // seeking and download resume, which expect 206. Let the handler serve them.
    if(cache_ && methodSafe(req.method) && req.headers.get("range").empty()) {
        auto cached = cache_->lookup(req);
        if(cached && cached->fresh() && !cachedEntryStale(req, *cached)) {
            resp.statusCode = cached->statusCode;
            resp.headers    = cached->headers;
            checkConditionals(req, resp, cached->lastModified,
                              cached->etag, (int64_t)cached->body.size());
            if(resp.statusCode != 304 && req.method != Method::HEAD)
                resp.body = cached->body;
            resp.headers.set("age", std::to_string(cached->currentAge()));
            addCommonHeaders(resp);
            logAccess(c, req, resp);
            buildAndSendResp(c, req, resp);
            return;
        }
    }

    // Invalidate on unsafe methods
    if(cache_ && !methodSafe(req.method)) {
        std::string url = "http://" + std::string(req.host()) + req.url.path;
        cache_->invalidate(url);
    }

    handler_(c, req, resp);

    addCommonHeaders(resp);
    // Never store a response whose bytes are not actually in memory — a body
    // streamed with sendfile(), or a HEAD that skipped the read. The entry would
    // carry a content-length with nothing behind it, and a later hit would send
    // headers promising N bytes and then no body, hanging the client until it
    // timed out. Checked as an invariant rather than a flag so any future
    // no-body-in-memory path is covered too.
    auto clHdr = resp.headers.get("content-length");
    bool bodyMissing = resp.body.empty() && !clHdr.empty() && clHdr != "0";
    if(cache_ && !bodyMissing) cache_->store(req, resp);
    logAccess(c, req, resp);
    buildAndSendResp(c, req, resp);
}

// A stored response whose URL still resolves to a regular file is only usable
// while that file is unchanged. Without this check, a static entry stored with
// the default max-age=3600 keeps being served for an hour after the file is
// edited, since RFC 9111 freshness alone has no idea the origin is local disk.
// Costs one stat() on the cache-hit path; a re-read of the body costs far more.
bool EventLoop::cachedEntryStale(const RawRequest& req, const CacheEntry& e) const {
    std::string path;
    struct stat st{};
    if(resolveStaticTarget(cfg_.docRoot, cfg_.indexFiles, req.url.path, path, st) != 0)
        return false;                       // not file-backed: nothing to revalidate
    if(!S_ISREG(st.st_mode)) return false;
    if(e.etag.empty()) return false;        // no validator to compare (dynamic response)
    return e.etag != fileETag(st);
}

void EventLoop::dispatchH2(Connection* c, uint32_t streamId,
                            std::shared_ptr<RawRequest> req) {
    // Run on thread-pool to keep epoll thread free
    postTask({ [this, c, streamId, req]() {
        RawResponse resp;
        resp.version = HttpVersion::HTTP2;
        handler_(c, *req, resp);
        addCommonHeaders(resp);

        if(cache_) cache_->store(*req, resp);

        c->h2->sendResponse(streamId, resp);
        auto sb = c->h2->takeSendBuf();
        if(!sb.empty()) {
            c->h2SendBuf.insert(c->h2SendBuf.end(), sb.begin(), sb.end());
            uint64_t v = 1; (void)write(wakefd_, &v, 8);
            modEpoll(c, EPOLLIN | EPOLLOUT | EPOLLET);
        }
    }});
}

void EventLoop::buildAndSendResp(Connection* c, RawRequest& req, RawResponse& resp) {
    bool headOnly = (req.method == Method::HEAD);
    if(req.keepAlive && req.version == HttpVersion::HTTP11) {
        resp.headers.set("connection", "keep-alive");
        resp.headers.set("keep-alive",
                         "timeout=" + std::to_string(cfg_.keepAliveTimeout));
    } else {
        resp.headers.set("connection", "close");
        c->keepAlive = false;
    }
    c->sendBuf  = resp.serialise(headOnly);
    c->sendPos  = 0;
    c->state    = ConnState::WriteResponse;
    c->deadlineMs = nowMs() + 30000;
    // A streamed body is armed level-triggered so onWritable can return after a
    // fairness budget and still be re-notified; edge-triggered would require
    // draining to EAGAIN in one go, letting a single large file stall the thread.
    modEpoll(c, c->streaming() ? EPOLLOUT : (EPOLLOUT | EPOLLET));
}

void EventLoop::addCommonHeaders(RawResponse& resp) {
    resp.headers.set("server", "httpd/1.0");
    if(!resp.headers.has("date")) resp.headers.set("date", httpDate());
    // Security headers (RFC 9110 best practices)
    resp.headers.set("x-content-type-options",  "nosniff");
    resp.headers.set("x-frame-options",          "SAMEORIGIN");
    resp.headers.set("referrer-policy",          "strict-origin-when-cross-origin");
}

void EventLoop::checkConditionals(const RawRequest& req, RawResponse& resp,
                                   time_t mtime, const std::string& etag,
                                   int64_t /*size*/) {
    // RFC 9110 §13 conditional request evaluation
    auto inm = req.headers.get("if-none-match");
    auto ims = req.headers.get("if-modified-since");

    bool etagMatch = (!inm.empty() && !etag.empty() &&
                      (inm == "*" || inm.find(etag) != std::string_view::npos));
    bool dateMatch = (!ims.empty() && mtime > 0 &&
                      mtime <= parseHttpDate(ims));

    if(etagMatch || (dateMatch && inm.empty())) {
        resp.statusCode = 304;
        resp.body.clear();
        resp.headers.set("content-length", "0");
    }
}

// ── Static file serving ───────────────────────────────────────────────────────
void EventLoop::serveFile(Connection* c, RawRequest& req, RawResponse& resp,
                           const std::string& rawPath) {
    // Canonicalise and reject traversal
    std::string path = canonicalisePath(cfg_.docRoot, req.url.path);
    if(path.empty()) {
        resp.statusCode = 403;
        resp.body = "<h1>403 Forbidden</h1>";
        resp.headers.set("content-type",   "text/html; charset=utf-8");
        resp.headers.set("content-length", std::to_string(resp.body.size()));
        return;
    }
    (void)rawPath;

    struct stat st{};
    if(stat(path.c_str(), &st) < 0) {
        if(errno == ENOENT || errno == ENOTDIR) handleNotFound(resp);
        else { resp.statusCode = 403; resp.body = "<h1>403 Forbidden</h1>";
               resp.headers.set("content-type","text/html; charset=utf-8");
               resp.headers.set("content-length",std::to_string(resp.body.size())); }
        return;
    }
    if(S_ISDIR(st.st_mode)) { serveDir(c, req, resp, path); return; }
    if(!S_ISREG(st.st_mode))  { handleNotFound(resp); return; }

    // Determine extension
    auto dot = path.rfind('.');
    std::string ext = (dot != std::string::npos) ? path.substr(dot + 1) : "";
    for(auto& ch : ext) ch = (char)tolower((unsigned char)ch);

    // Module handler (Lua, etc.)
    if(modules_) {
        auto* mod = modules_->findByExt(ext);
        if(mod && mod->handle_fn) {
            RequestCtx ctx;
            ctx.req        = &req;
            ctx.resp       = &resp;
            ctx.docRoot    = cfg_.docRoot;
            ctx.scriptPath = path;
            int r = mod->handle_fn(&ctx);
            if(r > 0 || ctx.handled) return;
        }
    }

    // CGI  — any executable under cgi-bin
    if(!cfg_.cgi.cgiDir.empty()) {
        std::string cgiRoot = cfg_.docRoot + cfg_.cgi.cgiDir;
        if(path.substr(0, cgiRoot.size()) == cgiRoot && (st.st_mode & S_IXUSR)) {
            CgiHandler cgi(cfg_.cgi);
            cgi.execute(req, path, "", resp);
            return;
        }
    }

    // ── Plain static file ────────────────────────────────────────────────────
    std::string mimeType = mimeFromExt(ext);

    // ETag: hex(ino-size-mtime)
    char etagBuf[64];
    snprintf(etagBuf, sizeof etagBuf, "\"%lx-%llx-%lx\"",
             (unsigned long)st.st_ino,
             (unsigned long long)st.st_size,
             (unsigned long)st.st_mtime);
    std::string etag = etagBuf;

    checkConditionals(req, resp, st.st_mtime, etag, (int64_t)st.st_size);
    resp.headers.set("etag",          etag);
    resp.headers.set("last-modified", httpDate(st.st_mtime));
    resp.headers.set("accept-ranges", "bytes");
    if(resp.statusCode == 304) return;

    // Range request (RFC 9110 §14)
    auto rangeHdr = req.headers.get("range");
    if(!rangeHdr.empty() && req.method == Method::GET) {
        auto ranges = parseRange(rangeHdr, (int64_t)st.st_size);
        if(ranges.size() == 1) {
            auto& r = ranges[0];
            int64_t rlen = r.last - r.first + 1;
            FILE* fp = fopen(path.c_str(), "rb");
            if(fp) {
                fseek(fp, (long)r.first, SEEK_SET);
                resp.body.resize((size_t)rlen);
                size_t nr = fread(resp.body.data(), 1, (size_t)rlen, fp);
                resp.body.resize(nr);
                fclose(fp);
            }
            resp.statusCode = 206;
            resp.headers.set("content-range",
                "bytes " + std::to_string(r.first) + "-" +
                           std::to_string(r.last)  + "/" +
                           std::to_string(st.st_size));
            resp.headers.set("content-type",   mimeType);
            resp.headers.set("content-length", std::to_string(resp.body.size()));
            return;
        }
    }

    // Full file
    FILE* fp = fopen(path.c_str(), "rb");
    if(!fp) {
        resp.statusCode = 403; resp.body = "<h1>403 Forbidden</h1>";
        resp.headers.set("content-type","text/html; charset=utf-8");
        resp.headers.set("content-length",std::to_string(resp.body.size()));
        return;
    }
    resp.body.resize((size_t)st.st_size);
    size_t nr = fread(resp.body.data(), 1, (size_t)st.st_size, fp);
    resp.body.resize(nr);
    fclose(fp);

    resp.statusCode = 200;
    resp.headers.set("content-type",   mimeType);
    resp.headers.set("content-length", std::to_string(resp.body.size()));
    if(!resp.headers.has("cache-control"))
        resp.headers.set("cache-control", "public, max-age=3600");
}

void EventLoop::serveDir(Connection* /*c*/, RawRequest& req,
                          RawResponse& resp, const std::string& dirPath) {
    // Try index files
    std::istringstream ss(cfg_.indexFiles);
    std::string idx;
    while(ss >> idx) {
        std::string full = dirPath + "/" + idx;
        struct stat st{};
        if(stat(full.c_str(), &st) == 0 && S_ISREG(st.st_mode)) {
            // Re-route through serveFile with the resolved path
            auto dot = full.rfind('.');
            std::string ext = (dot != std::string::npos) ? full.substr(dot+1) : "";
            for(auto& ch : ext) ch = (char)tolower((unsigned char)ch);
            std::string mime = mimeFromExt(ext);

            if(modules_) {
                auto* mod = modules_->findByExt(ext);
                if(mod && mod->handle_fn) {
                    RequestCtx ctx; ctx.req=&req; ctx.resp=&resp;
                    ctx.docRoot=cfg_.docRoot; ctx.scriptPath=full;
                    if(mod->handle_fn(&ctx) > 0 || ctx.handled) return;
                }
            }
            FILE* fp = fopen(full.c_str(), "rb");
            if(fp) {
                resp.body.resize((size_t)st.st_size);
                size_t nr = fread(resp.body.data(),1,(size_t)st.st_size,fp);
                resp.body.resize(nr); fclose(fp);
                resp.statusCode = 200;
                resp.headers.set("content-type",   mime);
                resp.headers.set("content-length", std::to_string(resp.body.size()));
            }
            return;
        }
    }

    // Redirect /path to /path/ for dir without trailing slash
    if(req.url.path.empty() || req.url.path.back() != '/') {
        resp.statusCode = 301;
        resp.headers.set("location", req.url.path + "/");
        resp.headers.set("content-length", "0");
        return;
    }

    // Auto-index
    DIR* d = opendir(dirPath.c_str());
    if(!d) {
        resp.statusCode = 403; resp.body = "<h1>403 Forbidden</h1>";
        resp.headers.set("content-type","text/html; charset=utf-8");
        resp.headers.set("content-length",std::to_string(resp.body.size()));
        return;
    }
    std::string html =
        "<!DOCTYPE html><html><head><meta charset='utf-8'>"
        "<title>Index of " + req.url.path + "</title>"
        "<style>body{font-family:monospace;background:#0d1117;color:#c9d1d9;max-width:900px;margin:2em auto}"
        "a{color:#79c0ff}hr{border-color:#30363d}</style></head>"
        "<body><h1>Index of " + req.url.path + "</h1><hr><pre>\n";
    if(req.url.path != "/") html += "<a href='../'>../</a>\n";

    std::vector<std::string> entries;
    struct dirent* de;
    while((de = readdir(d))) {
        std::string nm = de->d_name;
        if(nm == "." || nm == "..") continue;
        entries.push_back(nm);
    }
    closedir(d);
    std::sort(entries.begin(), entries.end());
    for(const auto& nm : entries) {
        struct stat st{};
        stat((dirPath + "/" + nm).c_str(), &st);
        bool isDir = S_ISDIR(st.st_mode);
        html += "<a href='" + Url::urlEncode(nm) + (isDir ? "/" : "") + "'>" +
                nm + (isDir ? "/" : "") + "</a>\n";
    }
    html += "</pre><hr></body></html>";

    resp.statusCode = 200;
    resp.headers.set("content-type",   "text/html; charset=utf-8");
    resp.headers.set("content-length", std::to_string(html.size()));
    resp.body = std::move(html);
}

void EventLoop::handleNotFound(RawResponse& resp) {
    resp.statusCode = 404;
    resp.body = "<!DOCTYPE html><html><body>"
                "<h1>404 Not Found</h1></body></html>";
    resp.headers.set("content-type",   "text/html; charset=utf-8");
    resp.headers.set("content-length", std::to_string(resp.body.size()));
}

void EventLoop::handleBadReq(Connection* c, int code) {
    RawResponse resp;
    resp.statusCode = code;
    resp.body = "<h1>" + std::to_string(code) + " " +
                Status::reason(code) + "</h1>";
    resp.headers.set("content-type",   "text/html; charset=utf-8");
    resp.headers.set("content-length", std::to_string(resp.body.size()));
    resp.headers.set("connection",     "close");
    addCommonHeaders(resp);
    c->keepAlive = false;
    c->sendBuf = resp.serialise();
    c->sendPos = 0;
    c->state   = ConnState::WriteResponse;
    modEpoll(c, EPOLLOUT | EPOLLET);
}

void EventLoop::logAccess(Connection* c, const RawRequest& req,
                           const RawResponse& resp) {
    if(!cfg_.accessLog) return;
    // Prefer content-length: a streamed or HEAD response has no body in memory.
    // This is the byte count promised, not yet confirmed sent — the log line is
    // written before sendfile() runs.
    size_t bytes = resp.body.size();
    if(resp.body.empty()) {
        auto cl = resp.headers.get("content-length");
        if(!cl.empty()) bytes = strtoull(std::string(cl).c_str(), nullptr, 10);
    }
    fprintf(stdout, "%s \"%s %s HTTP/%s\" %d %zu \"%s\"\n",
            c->peerAddr.c_str(),
            methodStr(req.method),
            req.url.path.c_str(),
            req.version == HttpVersion::HTTP2 ? "2" : "1.1",
            resp.statusCode,
            bytes,
            std::string(req.headers.get("user-agent")).c_str());
    fflush(stdout);
}

// ── Server (master process) ───────────────────────────────────────────────────
static int createListenSock(const char* addr, uint16_t port) {
    // Try IPv6 dual-stack first, fall back to IPv4
    int fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    bool ipv6 = (fd >= 0);
    if(!ipv6) {
        fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if(fd < 0) return -1;
    }
    setReuseAddr(fd);
    setReusePort(fd);

    if(ipv6) {
        int v6only = 0;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof v6only);
        struct sockaddr_in6 sa{};
        sa.sin6_family = AF_INET6;
        sa.sin6_port   = htons(port);
        sa.sin6_addr   = in6addr_any;
        if(bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) < 0) {
            close(fd); return -1;
        }
    } else {
        struct sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port   = htons(port);
        if(!addr || !*addr)
            sa.sin_addr.s_addr = INADDR_ANY;
        else
            inet_pton(AF_INET, addr, &sa.sin_addr);
        if(bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) < 0) {
            close(fd); return -1;
        }
    }
    if(listen(fd, SOMAXCONN) < 0) { close(fd); return -1; }
    return fd;
}

bool Server::bindPorts() {
    if(cfg_.enableHttp) {
        httpFd_ = createListenSock(cfg_.bindAddr.c_str(), cfg_.httpPort);
        if(httpFd_ < 0) {
            fprintf(stderr, "[SERVER] bind HTTP port %u: %s\n",
                    cfg_.httpPort, strerror(errno));
            return false;
        }
        printf("[SERVER] HTTP  listening on :%u\n", cfg_.httpPort);
    }
    if(cfg_.enableTls && tls_ && tls_->valid()) {
        httpsFd_ = createListenSock(cfg_.bindAddr.c_str(), cfg_.httpsPort);
        if(httpsFd_ < 0) {
            fprintf(stderr, "[SERVER] bind HTTPS port %u: %s\n",
                    cfg_.httpsPort, strerror(errno));
            return false;
        }
        printf("[SERVER] HTTPS listening on :%u  (TLS 1.2/1.3, ALPN h2)\n",
               cfg_.httpsPort);
    }
    return true;
}

bool Server::init(ServerConfig cfg) {
    cfg_     = std::move(cfg);
    cache_   = std::make_shared<HttpCache>(cfg_.cache);
    modules_ = std::make_shared<ModuleRegistry>();

    TlsContext::initLibrary();
    if(cfg_.enableTls && (!cfg_.tls.certFile.empty() || !cfg_.tls.keyFile.empty())) {
        tls_ = std::make_shared<TlsContext>();
        if(!tls_->init(cfg_.tls)) {
            fprintf(stderr, "[SERVER] TLS init failed\n");
            cfg_.enableTls = false;
            tls_.reset();
        }
    }

    // Load .so modules
    for(const auto& me : cfg_.modules)
        modules_->load(me.path, me.config);

    cfg_.cgi.docRoot = cfg_.docRoot;
    cgi_ = CgiHandler(cfg_.cgi);

    if(!bindPorts()) return false;
    running_ = true;
    return true;
}

RequestHandler Server::makeHandler() {
    return [this](Connection* c, RawRequest& req, RawResponse& resp) {
        dispatchRequest(c, req, resp);
    };
}

void Server::dispatchRequest(Connection* c, RawRequest& req, RawResponse& resp) {
    // Docroot-confined path + directory-index probe, shared with the cache
    // revalidation in EventLoop::cachedEntryStale.
    std::string path;
    struct stat st{};
    int err = resolveStaticTarget(cfg_.docRoot, cfg_.indexFiles,
                                  req.url.path, path, st);
    if(err != 0) {
        resp.statusCode = err;
        resp.body = (err == 404)
            ? "<!DOCTYPE html><html><body><h1>404 Not Found</h1></body></html>"
            : "<h1>403 Forbidden</h1>";
        resp.headers.set("content-type","text/html; charset=utf-8");
        resp.headers.set("content-length",std::to_string(resp.body.size()));
        return;
    }

    if(S_ISDIR(st.st_mode)) {
        // No index file matched. Only redirect when the request-target lacks the
        // trailing slash — redirecting "/dir/" to "/dir/" is a self-loop.
        if(req.url.path.empty() || req.url.path.back() != '/') {
            resp.statusCode = 301;
            resp.headers.set("location", req.url.path + "/");
            resp.headers.set("content-length","0");
            return;
        }
        // Normalised path, no index file: directory listing is not served.
        resp.statusCode = 403;
        resp.body = "<h1>403 Forbidden</h1>";
        resp.headers.set("content-type","text/html; charset=utf-8");
        resp.headers.set("content-length",std::to_string(resp.body.size()));
        return;
    }

    auto dot = path.rfind('.');
    std::string ext = (dot != std::string::npos) ? path.substr(dot+1) : "";
    for(auto& ch : ext) ch = (char)tolower((unsigned char)ch);

    // Module handler
    if(modules_) {
        auto* mod = modules_->findByExt(ext);
        if(mod && mod->handle_fn) {
            RequestCtx ctx;
            ctx.req = &req; ctx.resp = &resp;
            ctx.docRoot = cfg_.docRoot; ctx.scriptPath = path;
            if(mod->handle_fn(&ctx) > 0 || ctx.handled) return;
        }
    }

    // CGI
    if(!cfg_.cgi.cgiDir.empty()) {
        std::string cgiRoot = cfg_.docRoot + cfg_.cgi.cgiDir;
        if(path.size() >= cgiRoot.size() &&
           path.substr(0, cgiRoot.size()) == cgiRoot &&
           (st.st_mode & S_IXUSR)) {
            cgi_.execute(req, path, "", resp);
            return;
        }
    }

    // ── Static file ──────────────────────────────────────────────────────────
    const std::string etag = fileETag(st);

    // Conditional request (RFC 9110 §13). EventLoop::dispatch11 has its own
    // check for cache hits, but streamed and HEAD responses are deliberately not
    // cached, so without this a conditional request for a large file would
    // re-send the whole thing every time.
    {
        auto inm = req.headers.get("if-none-match");
        auto ims = req.headers.get("if-modified-since");
        bool notModified =
            !inm.empty() ? (inm == "*" || inm.find(etag) != std::string_view::npos)
                         : (!ims.empty() && st.st_mtime <= parseHttpDate(ims));
        if(notModified) {
            resp.statusCode = 304;
            resp.headers.set("etag",          etag);
            resp.headers.set("last-modified", httpDate(st.st_mtime));
            resp.headers.set("content-length","0");
            return;
        }
    }

    const bool headOnly = (req.method == Method::HEAD);

    // Can this connection have a body handed to the kernel at all?
    // Plaintext: yes. TLS: only with KTLS tx offload, because sendfile() never
    // enters user space and so cannot feed OpenSSL's own record layer. HTTP/2 is
    // always excluded — its bytes must be wrapped in DATA frames first.
    const bool transportCanStream =
        c && !c->h2
        && req.version != HttpVersion::HTTP2
        && req.version != HttpVersion::HTTP3
        && (!c->isTls || c->tls.ktlsSend());

    // ── Range (RFC 9110 §14) ─────────────────────────────────────────────────
    // Single range only. Multiple ranges would need a multipart/byteranges body;
    // the spec permits a server to ignore Range, so those get the full 200.
    int64_t rangeFirst = 0, rangeLen = st.st_size;
    bool partial = false;
    if(!headOnly) {
        auto rangeHdr = req.headers.get("range");
        if(!rangeHdr.empty()) {
            // If-Range: a validator that no longer matches means the client holds
            // a different version, so splicing our bytes into its copy would
            // corrupt it. Send the whole representation instead.
            auto ifRange = req.headers.get("if-range");
            bool validatorOk =
                ifRange.empty()
                || ifRange.find(etag) != std::string_view::npos
                || (ifRange.find('"') == std::string_view::npos
                    && parseHttpDate(ifRange) == st.st_mtime);

            if(validatorOk) {
                auto ranges = parseRange(rangeHdr, st.st_size);
                // parseRange clamps anything satisfiable, so an empty result from a
                // well-formed header means genuinely unsatisfiable → 416. An
                // unparseable header, or one naming another range unit, must
                // instead be ignored: fall through and serve the full 200.
                if(ranges.empty() && rangeSyntaxValid(rangeHdr)) {
                    resp.statusCode = 416;
                    resp.headers.set("content-range",
                                     "bytes */" + std::to_string((uint64_t)st.st_size));
                    resp.headers.set("content-length", "0");
                    resp.headers.set("etag",          etag);
                    resp.headers.set("last-modified", httpDate(st.st_mtime));
                    resp.headers.set("accept-ranges", "bytes");
                    return;
                }
                if(!ranges.empty()) ranges = coalesceRanges(std::move(ranges));

                if(ranges.size() > kMaxRangeParts) {
                    // Too many parts even after coalescing: ignore Range entirely.
                } else if(ranges.size() == 1) {
                    rangeFirst = ranges[0].first;
                    rangeLen   = ranges[0].last - ranges[0].first + 1;
                    partial    = true;
                } else if(ranges.size() > 1) {
                    // ── multipart/byteranges (RFC 9110 §14.6) ────────────────
                    // Each part's framing is prepended to its data; the CRLF that
                    // must precede a boundary delimiter is carried at the front of
                    // the *next* part's header, so no separate trailing segments
                    // are needed. content-length is therefore exactly computable
                    // without touching the file.
                    const std::string boundary = randomBoundary();
                    const std::string ctype    = mimeFromExt(ext);
                    std::vector<std::string> frames(ranges.size());
                    uint64_t total = 0;
                    for(size_t i = 0; i < ranges.size(); ++i) {
                        std::string h = (i == 0) ? "--" : "\r\n--";
                        h += boundary;                       h += "\r\n";
                        h += "Content-Type: ";  h += ctype;  h += "\r\n";
                        h += "Content-Range: bytes "
                           + std::to_string(ranges[i].first) + "-"
                           + std::to_string(ranges[i].last)  + "/"
                           + std::to_string((uint64_t)st.st_size) + "\r\n\r\n";
                        total += h.size()
                               + (uint64_t)(ranges[i].last - ranges[i].first + 1);
                        frames[i] = std::move(h);
                    }
                    const std::string terminator = "\r\n--" + boundary + "--\r\n";
                    total += terminator.size();

                    // Same transport rules as a single body.
                    const bool canSeg = transportCanStream
                                        && total > cfg_.streamThreshold;

                    bool built = false;
                    if(canSeg) {
                        int mfd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
                        if(mfd >= 0) {
                            c->closeFile();
                            c->fileFd = mfd;
                            for(size_t i = 0; i < ranges.size(); ++i) {
                                c->outSegs.push_back({ frames[i], 0, 0 });
                                c->outSegs.push_back({ std::string(), ranges[i].first,
                                                       ranges[i].last - ranges[i].first + 1 });
                            }
                            c->outSegs.push_back({ terminator, 0, 0 });
                            resp.body.clear();
                            built = true;
                        }
                    }
                    if(!built) {
                        // Buffered assembly: read each slice with pread rather than
                        // pulling the whole file through FileCache for fragments.
                        int mfd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
                        if(mfd < 0) {
                            resp.statusCode = 500;
                            resp.body = "<h1>500 Internal Server Error</h1>";
                            resp.headers.set("content-type","text/html; charset=utf-8");
                            resp.headers.set("content-length",
                                             std::to_string(resp.body.size()));
                            return;
                        }
                        std::string out;
                        out.reserve((size_t)total);
                        bool ok = true;
                        for(size_t i = 0; i < ranges.size() && ok; ++i) {
                            out += frames[i];
                            size_t want = (size_t)(ranges[i].last - ranges[i].first + 1);
                            size_t at   = out.size();
                            out.resize(at + want);
                            size_t got2 = 0;
                            while(got2 < want) {
                                ssize_t n = ::pread(mfd, out.data() + at + got2,
                                                    want - got2,
                                                    (off_t)ranges[i].first + (off_t)got2);
                                if(n <= 0) break;
                                got2 += (size_t)n;
                            }
                            ok = (got2 == want);
                        }
                        ::close(mfd);
                        if(!ok) {
                            resp.statusCode = 500;
                            resp.body = "<h1>500 Internal Server Error</h1>";
                            resp.headers.set("content-type","text/html; charset=utf-8");
                            resp.headers.set("content-length",
                                             std::to_string(resp.body.size()));
                            return;
                        }
                        out += terminator;
                        resp.body = std::move(out);
                    }

                    resp.statusCode = 206;
                    resp.headers.set("content-type",
                                     "multipart/byteranges; boundary=" + boundary);
                    resp.headers.set("content-length", std::to_string(total));
                    resp.headers.set("etag",          etag);
                    resp.headers.set("last-modified", httpDate(st.st_mtime));
                    resp.headers.set("accept-ranges", "bytes");
                    return;
                }
            }
        }
    }

    // HEAD needs no body at all, and reading a multi-GB file only for
    // serialise() to discard it is waste. Sized on the range, not the file: a
    // 4 KB slice of a 1 GB file is small.
    const bool canStream = transportCanStream && !headOnly
                           && (size_t)rangeLen > cfg_.streamThreshold;

    bool streamed = false;
    if(canStream) {
        int ffd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
        if(ffd >= 0) {
            c->closeFile();                  // release any fd left by a prior response
            c->fileFd = ffd;
            // A whole file or single range is one file segment; sendfile() starts
            // at rangeFirst (0 when not a range request).
            c->outSegs.push_back({ std::string(), rangeFirst, rangeLen });
            streamed = true;
        }
        // open() failure falls through to the buffered path, which reports it
    }

    if(streamed || headOnly) {
        resp.body.clear();                   // bytes are not in memory
    } else if(partial) {
        // Read just the slice. Going through FileCache would buffer the entire
        // file to hand back a fragment — pathological for a small range of a
        // large file on the TLS/H2 fallback path.
        int rfd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
        bool ok = (rfd >= 0);
        if(ok) {
            resp.body.resize((size_t)rangeLen);
            size_t got = 0;
            while(got < (size_t)rangeLen) {
                ssize_t n = ::pread(rfd, resp.body.data() + got,
                                    (size_t)rangeLen - got,
                                    (off_t)rangeFirst + (off_t)got);
                if(n <= 0) break;            // EOF or error: file changed under us
                got += (size_t)n;
            }
            ::close(rfd);
            ok = (got == (size_t)rangeLen);
            if(!ok) resp.body.clear();
        }
        if(!ok) {
            resp.statusCode = 500;
            resp.body = "<h1>500 Internal Server Error</h1>";
            resp.headers.set("content-type","text/html; charset=utf-8");
            resp.headers.set("content-length",std::to_string(resp.body.size()));
            return;
        }
    } else {
        auto data = files_.get(path, st);
        if(!data) {
            resp.statusCode = 403;
            resp.body = "<h1>403 Forbidden</h1>";
            resp.headers.set("content-type","text/html; charset=utf-8");
            resp.headers.set("content-length",std::to_string(resp.body.size()));
            return;
        }
        resp.body = *data;
    }

    resp.statusCode = partial ? 206 : 200;
    resp.headers.set("content-type", mimeFromExt(ext));
    resp.headers.set("content-length",
                     std::to_string(streamed || headOnly
                                    ? (uint64_t)rangeLen
                                    : (uint64_t)resp.body.size()));
    if(partial)
        resp.headers.set("content-range",
                         "bytes " + std::to_string(rangeFirst) + "-"
                         + std::to_string(rangeFirst + rangeLen - 1) + "/"
                         + std::to_string((uint64_t)st.st_size));

    // ETag / Last-Modified. The ETag must match fileETag() exactly, since the
    // cache revalidation compares against a value recomputed from stat().
    resp.headers.set("etag",          etag);
    resp.headers.set("last-modified", httpDate(st.st_mtime));
    resp.headers.set("accept-ranges", "bytes");
    if(!resp.headers.has("cache-control"))
        resp.headers.set("cache-control","public, max-age=3600");
}

void Server::run() {
    int nWorkers = cfg_.workers;
    if(nWorkers <= 0) nWorkers = (int)sysconf(_SC_NPROCESSORS_ONLN);
    nWorkers = std::max(1, nWorkers);

    signal(SIGCHLD, SIG_DFL);
    signal(SIGPIPE, SIG_IGN);

    if(nWorkers == 1) {
        printf("[SERVER] Running single-process (workers=1)\n");
        workerMain(httpFd_, httpsFd_);
        return;
    }

    printf("[SERVER] Forking %d worker processes\n", nWorkers);
    for(int i = 0; i < nWorkers; ++i) {
        pid_t pid = fork();
        if(pid < 0)  { perror("fork"); continue; }
        if(pid == 0) {
            signal(SIGTERM, SIG_DFL);
            workerMain(httpFd_, httpsFd_);
            _exit(0);
        }
        workers_.push_back(pid);
    }

    // Parent: reap + respawn
    int wstatus;
    pid_t p;
    while(running_.load() && (p = wait(&wstatus)) > 0) {
        if(!running_.load()) break;
        printf("[SERVER] Worker %d exited (status=%d), restarting\n", p, wstatus);
        workers_.erase(std::remove(workers_.begin(), workers_.end(), p), workers_.end());
        pid_t pid = fork();
        if(pid == 0) { workerMain(httpFd_, httpsFd_); _exit(0); }
        if(pid > 0)  workers_.push_back(pid);
    }
}

void Server::workerMain(int httpFd, int httpsFd) {
    int nThreads = std::max(1, cfg_.threadsPerWorker);
    auto handler = makeHandler();

    // Create one EventLoop per I/O thread
    struct LoopThread { EventLoop* loop; pthread_t tid; };
    std::vector<LoopThread> loops;
    loops.reserve((size_t)nThreads);

    for(int i = 0; i < nThreads; ++i) {
        auto* loop = new EventLoop();
        if(!loop->init(cfg_, handler, tls_, cache_, modules_)) {
            delete loop; continue;
        }
        pthread_t t;
        pthread_create(&t, nullptr, [](void* arg) -> void* {
            static_cast<EventLoop*>(arg)->run(); return nullptr;
        }, loop);
        loops.push_back({loop, t});
    }
    if(loops.empty()) return;

    // Accept loop in this thread — round-robin to EventLoops
    int acceptEpfd = epoll_create1(EPOLL_CLOEXEC);
    auto addListen = [&](int fd) {
        if(fd < 0) return;
        struct epoll_event ev{}; ev.events = EPOLLIN; ev.data.fd = fd;
        epoll_ctl(acceptEpfd, EPOLL_CTL_ADD, fd, &ev);
    };
    addListen(httpFd);
    addListen(httpsFd);

    size_t rrIdx = 0;
    struct epoll_event evs[64];

    while(running_.load()) {
        int n = epoll_wait(acceptEpfd, evs, 64, 500);
        if(n < 0) { if(errno == EINTR) continue; break; }
        for(int i = 0; i < n; ++i) {
            int lfd    = evs[i].data.fd;
            bool isTls = (lfd == httpsFd);
            for(;;) {
                struct sockaddr_in6 sa{}; socklen_t sl = sizeof sa;
                int fd = accept4(lfd,
                                 reinterpret_cast<sockaddr*>(&sa), &sl,
                                 SOCK_NONBLOCK | SOCK_CLOEXEC);
                if(fd < 0) { if(errno==EAGAIN||errno==EWOULDBLOCK) break; continue; }

                char ip[INET6_ADDRSTRLEN] = "?";
                uint16_t port = 0;
                if(sa.sin6_family == AF_INET6) {
                    inet_ntop(AF_INET6, &sa.sin6_addr, ip, sizeof ip);
                    port = ntohs(sa.sin6_port);
                } else {
                    auto* s4 = reinterpret_cast<sockaddr_in*>(&sa);
                    inet_ntop(AF_INET, &s4->sin_addr, ip, sizeof ip);
                    port = ntohs(s4->sin_port);
                }

                auto* loop = loops[rrIdx++ % loops.size()].loop;
                loop->addConn(fd, isTls, ip, port);  // posts task to loop thread
            }
        }
    }

    close(acceptEpfd);
    for(auto& lt : loops) {
        lt.loop->stop();
        uint64_t v = 1; (void)write(lt.loop->wakeFd(), &v, 8);
        pthread_join(lt.tid, nullptr);
        delete lt.loop;
    }
}

void Server::stop() {
    running_ = false;
    for(pid_t p : workers_) kill(p, SIGTERM);
}

Server::~Server() {
    stop();
    if(httpFd_  >= 0) close(httpFd_);
    if(httpsFd_ >= 0) close(httpsFd_);
}

} // namespace httpd
