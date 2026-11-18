// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
#include "EventLoop.h"
#include "Config.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>   // readlink
#include <libgen.h>   // dirname

static httpd::Server* gServer = nullptr;
static void sigHandler(int s) {
    (void)s;
    if(gServer) gServer->stop();
}

// Return directory containing this executable
static std::string selfDir() {
    char buf[4096] = {};
    ssize_t n = readlink("/proc/self/exe", buf, sizeof buf - 1);
    if(n < 0) return ".";
    buf[n] = '\0';
    return dirname(buf);   // mutates buf, returns pointer into buf
}

static void usage(const char* prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "\n"
        "  -r <dir>      Document root          (default: ./www)\n"
        "  -p <port>     HTTP  port             (default: 8080)\n"
        "  -s <port>     HTTPS port             (default: 8443)\n"
        "  -c <cert.pem> TLS certificate chain  (enables HTTPS)\n"
        "  -k <key.pem>  TLS private key        (enables HTTPS)\n"
        "  -w <n>        Worker processes        (default: CPU count)\n"
        "  -t <n>        I/O threads per worker  (default: 4)\n"
        "  -m <path>     Load module .so         (repeatable; default: auto)\n"
        "  -g <dir>      CGI directory under docroot (default: /cgi-bin)\n"
        "  -S            SPA fallback: serve index.html for unknown routes\n"
        "  -f <file>     YAML configuration file\n"
        "  -h            Show this help\n"
        "\n"
        "  CLI flags override values from the YAML file.\n"
        "\n"
        "Examples:\n"
        "  %s -f /etc/httpd/httpd.yaml\n"
        "  %s -r /var/www -p 80\n"
        "  %s -r /var/www -c cert.pem -k key.pem -w 4\n",
        prog, prog, prog, prog);
}

int main(int argc, char* argv[]) {
    // Disable stdout/stderr buffering so logs appear immediately
    // even when redirected to a file or pipe.
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    httpd::ServerConfig cfg;
    bool userModules = false;
    std::string yamlFile;

    int opt;
    while((opt = getopt(argc, argv, "f:r:p:s:c:k:w:t:m:g:Sh")) != -1) {
        switch(opt) {
        case 'f': yamlFile              = optarg;                       break;
        case 'r': cfg.docRoot           = optarg;                       break;
        case 'p': cfg.httpPort          = (uint16_t)atoi(optarg);       break;
        case 's': cfg.httpsPort         = (uint16_t)atoi(optarg);       break;
        case 'c': cfg.tls.certFile      = optarg; cfg.enableTls = true; break;
        case 'k': cfg.tls.keyFile       = optarg; cfg.enableTls = true; break;
        case 'w': cfg.workers           = atoi(optarg);                 break;
        case 't': cfg.threadsPerWorker  = atoi(optarg);                 break;
        case 'm': cfg.modules.push_back({optarg,""}); userModules=true; break;
        case 'g': cfg.cgi.cgiDir        = optarg;                       break;
        case 'S': cfg.spaFallback       = true;                         break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 1;
        }
    }

    if(!yamlFile.empty()) {
        httpd::ConfigParser parser;
        httpd::YamlConfig   ycfg;
        std::string         yamlErr;
        if(!parser.parseFile(yamlFile, ycfg, yamlErr)) {
            fprintf(stderr, "[CONFIG] %s: %s\n", yamlFile.c_str(), yamlErr.c_str());
            return 1;
        }
        httpd::ServerConfig dfl;
        if(cfg.docRoot          == dfl.docRoot)          cfg.docRoot          = ycfg.docRoot;
        if(cfg.httpPort         == dfl.httpPort)         cfg.httpPort         = ycfg.httpPort;
        if(cfg.httpsPort        == dfl.httpsPort)        cfg.httpsPort        = ycfg.httpsPort;
        if(cfg.workers          == dfl.workers)          cfg.workers          = ycfg.workers;
        if(cfg.threadsPerWorker == dfl.threadsPerWorker) cfg.threadsPerWorker = ycfg.threadsPerWorker;
        if(cfg.tls.certFile.empty() && !ycfg.certFile.empty()){
            cfg.tls.certFile = ycfg.certFile; cfg.enableTls = true;
        }
        if(cfg.tls.keyFile.empty()  && !ycfg.keyFile.empty()){
            cfg.tls.keyFile = ycfg.keyFile;   cfg.enableTls = true;
        }
        if(!ycfg.caFile.empty())   cfg.tls.caFile      = ycfg.caFile;
        cfg.tls.enableKtls      = ycfg.ktls;
        cfg.tls.enableHttp2     = ycfg.http2;
        cfg.enableHttp2         = ycfg.http2;
        if(cfg.cgi.cgiDir == dfl.cgi.cgiDir) cfg.cgi.cgiDir = ycfg.cgiDir;
        cfg.cache.maxMemEntries = ycfg.cacheMaxEntries;
        cfg.cache.maxMemBytes   = ycfg.cacheMaxMb * 1024 * 1024;
        cfg.streamThreshold     = ycfg.streamThresholdKb * 1024;
        cfg.accessLog           = ycfg.accessLog;
        cfg.accessLogFile       = ycfg.accessLogFile;
        cfg.keepAliveTimeout    = ycfg.keepAliveTimeout;
        cfg.requestTimeout      = ycfg.requestTimeout;
        cfg.maxConns            = ycfg.maxConns;
        cfg.maxBodySize         = ycfg.maxBodyMb * 1024 * 1024;
        cfg.indexFiles          = ycfg.indexFiles;
        if(!cfg.spaFallback) {
            cfg.spaFallback  = ycfg.spaFallback;
            cfg.spaIndex     = ycfg.spaIndex;
            cfg.spaApiPrefix = ycfg.spaApiPrefix;
        }
        for(const auto& m : ycfg.modules)
            if(!m.empty()) cfg.modules.push_back({m, ""});
        cfg.yamlCfg = std::make_shared<httpd::YamlConfig>(std::move(ycfg));
        if(!cfg.yamlCfg->vhosts.empty())
            cfg.vhostSelector = std::make_shared<httpd::VHostSelector>(*cfg.yamlCfg);
    }

    // Auto-load Lua module from same directory as binary if not overridden
    if(!userModules) {
        std::string dir = selfDir();
        // Check <bindir>/modules/lua_module.so  (build tree)
        std::string soPath = dir + "/modules/lua_module.so";
        FILE* f = fopen(soPath.c_str(), "rb");
        if(f) { fclose(f); cfg.modules.push_back({soPath,""}); }
        else {
            // Installed: <prefix>/lib/httpd/modules/lua_module.so
            std::string inst = dir + "/../lib/httpd/modules/lua_module.so";
            FILE* f2 = fopen(inst.c_str(), "rb");
            if(f2) { fclose(f2); cfg.modules.push_back({inst,""}); }
        }
    }

    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║  httpd/1.0 — C++ RFC-compliant application server ║\n");
    printf("║  HTTP/1.1 · HTTP/2 · TLS · Lua · CGI · Cache    ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");
    printf("  Document root  : %s\n", cfg.docRoot.c_str());
    printf("  HTTP  port     : %u\n", cfg.httpPort);
    if(cfg.enableTls)
        printf("  HTTPS port     : %u  (TLS 1.2/1.3 + ALPN h2)\n", cfg.httpsPort);
    printf("  Workers        : %s\n",
           cfg.workers ? std::to_string(cfg.workers).c_str() : "auto (CPU count)");
    printf("  Threads/worker : %d\n", cfg.threadsPerWorker);
    if(!yamlFile.empty())
        printf("  Config file    : %s\n", yamlFile.c_str());
    if(cfg.vhostSelector)
        printf("  Virtual hosts  : %zu\n", cfg.yamlCfg->vhosts.size());
    if(cfg.spaFallback)
        printf("  SPA fallback   : %s\n", cfg.spaIndex.c_str());
    printf("\n");

    signal(SIGINT,  sigHandler);
    signal(SIGTERM, sigHandler);
    signal(SIGPIPE, SIG_IGN);

    httpd::Server server;
    gServer = &server;
    if(!server.init(cfg)) {
        fprintf(stderr, "[FATAL] Server initialisation failed.\n");
        return 1;
    }
    server.run();

    printf("\n[SERVER] Shutdown complete.\n");
    return 0;
}
