// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
#pragma once
#include "TlsContext.h"
#include "HttpParser.h"
#include "H2Session.h"
#include "Cache.h"
#include "FileCache.h"
#include "Module.h"
#include "Cgi.h"
#include "common.h"
#include <functional>
#include <memory>
#include <vector>
#include <unordered_map>
#include <string>
#include <atomic>
#include <deque>
#include <sys/epoll.h>
#include <pthread.h>
#include <unistd.h>
namespace httpd {
struct ServerConfig {
    std::string bindAddr="0.0.0.0";
    uint16_t httpPort=8080, httpsPort=8443;
    bool enableTls=false, enableHttp=true, enableHttp2=true;
    TlsConfig tls; CgiConfig cgi;
    std::string docRoot="./www",
                indexFiles="index.lhtml index.html index.htm index.lua";
    int workers=0, threadsPerWorker=4, keepAliveTimeout=60, requestTimeout=30;
    size_t maxConns=10000, maxHeadersSize=65536, maxBodySize=67108864;
    // Files larger than this are streamed with sendfile() rather than buffered.
    // Matches FileCache::Config::maxFileBytes so the two policies meet exactly:
    // at or below it a file is cached in memory, above it it is never buffered.
    size_t streamThreshold=1024*1024;
    struct ModuleEntry { std::string path, config; };
    std::vector<ModuleEntry> modules;
    HttpCache::Config cache;
    bool accessLog=true; std::string accessLogFile; bool errorLog=true;
};
enum class ConnState { TlsHandshake, ReadRequest, Processing, WriteResponse, KeepAlive, Http2, Closing };
struct Connection {
    int fd=-1, epfd=-1; ConnState state=ConnState::ReadRequest;
    bool isTls=false; TlsConn tls; Http1Parser parser;
    std::string sendBuf; size_t sendPos=0; bool keepAlive=true;
    std::unique_ptr<H2Session> h2; std::vector<uint8_t> h2SendBuf; size_t h2SendPos=0;
    int64_t createdMs=0, lastActiveMs=0, deadlineMs=0;
    char recvBuf[kRecvBufSize]={}; size_t recvLen=0;
    std::string peerAddr; uint16_t peerPort=0;

    // ── Streamed response body ───────────────────────────────────────────────
    // One piece of body still to write: either literal bytes (multipart framing)
    // or a region of fileFd handed to sendfile(). A whole file or a single range
    // is one file segment; multipart/byteranges alternates literal and file
    // segments. Set only for plaintext HTTP/1.1 — see Server::dispatchRequest
    // for why TLS and HTTP/2 cannot use sendfile at all.
    struct OutSeg {
        std::string literal;          // non-empty → literal segment
        off_t       off=0, len=0;     // len>0 with empty literal → file region
    };
    int   fileFd=-1;
    std::deque<OutSeg> outSegs;
    size_t outSegPos=0;               // bytes of the front literal already sent

    bool streaming() const { return !outSegs.empty(); }
    void closeFile(){
        if(fileFd>=0){ ::close(fileFd); fileFd=-1; }
        outSegs.clear(); outSegPos=0;
    }

    void reset(){ state=ConnState::ReadRequest; parser.reset(); sendBuf.clear(); sendPos=0; keepAlive=true; recvLen=0; closeFile(); }
    // Guarantees the streamed fd is released however the connection ends —
    // closeConn() erases the owning unique_ptr, which runs this.
    ~Connection(){ closeFile(); }
};
using RequestHandler = std::function<void(Connection*, RawRequest&, RawResponse&)>;
struct Task { std::function<void()> fn; };
class EventLoop {
public:
    EventLoop(); ~EventLoop();
    bool init(const ServerConfig& cfg, RequestHandler handler,
              std::shared_ptr<TlsContext> tls, std::shared_ptr<HttpCache> cache,
              std::shared_ptr<ModuleRegistry> modules);
    void addConn(int fd, bool isTls, const char* peerAddr, uint16_t peerPort);
    void run(); void stop(){running_=false;} void postTask(Task t);
    int  wakeFd() const { return wakefd_; }
private:
    int epfd_=-1, wakefd_=-1; bool running_=false;
    ServerConfig cfg_; RequestHandler handler_;
    std::shared_ptr<TlsContext> tls_; std::shared_ptr<HttpCache> cache_;
    std::shared_ptr<ModuleRegistry> modules_;
    std::unordered_map<int,std::unique_ptr<Connection>> conns_;
    std::vector<pthread_t> threads_; std::deque<Task> taskQueue_;
    pthread_mutex_t taskMu_=PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t  taskCv_=PTHREAD_COND_INITIALIZER;
    std::atomic<bool> poolRunning_{false};
    void onReadable(Connection* c); void onWritable(Connection* c); void onError(Connection* c);
    void closeConn(Connection* c); void addToEpoll(Connection* c, uint32_t ev); void modEpoll(Connection* c, uint32_t ev);
    void dispatch11(Connection* c, RawRequest& req);
    void dispatchH2(Connection* c, uint32_t sid, std::shared_ptr<RawRequest> req);
    void buildAndSendResp(Connection* c, RawRequest& req, RawResponse& resp);
    void serveFile(Connection* c, RawRequest& req, RawResponse& resp, const std::string& path);
    void serveDir (Connection* c, RawRequest& req, RawResponse& resp, const std::string& path);
    void handleNotFound(RawResponse& resp); void handleBadReq(Connection* c, int code);
    void checkConditionals(const RawRequest& req, RawResponse& resp, time_t mtime, const std::string& etag, int64_t size);
    void addCommonHeaders(RawResponse& resp);
    void logAccess(Connection* c, const RawRequest& req, const RawResponse& resp);
    // True when a cached response is backed by a file that has since changed.
    bool cachedEntryStale(const RawRequest& req, const CacheEntry& e) const;
    static void* threadFn(void* arg); void startPool(int n);
    void sweepTimeouts(); int64_t nextSweepMs_=0;
};
class Server {
public:
    bool init(ServerConfig cfg); void run(); void stop(); ~Server();
private:
    ServerConfig cfg_;
    std::shared_ptr<TlsContext> tls_; std::shared_ptr<HttpCache> cache_;
    std::shared_ptr<ModuleRegistry> modules_; CgiHandler cgi_;
    FileCache files_;   // shared by every I/O thread of this worker
    std::vector<pid_t> workers_; int httpFd_=-1, httpsFd_=-1;
    std::atomic<bool> running_{false};
    bool bindPorts(); void workerMain(int httpFd, int httpsFd);
    RequestHandler makeHandler();
    void dispatchRequest(Connection* c, RawRequest& req, RawResponse& resp);
};
} // namespace httpd
