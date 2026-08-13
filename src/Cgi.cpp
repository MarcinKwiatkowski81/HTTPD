// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
// CGI/1.1 implementation (RFC 3875)
#include "Cgi.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <poll.h>
#include <cstring>
#include <cstdio>
#include <cerrno>
#include <algorithm>
#include <sstream>

extern char** environ;
namespace httpd {

std::vector<std::string> CgiHandler::buildEnv(
        const RawRequest& req, const std::string& scriptPath,
        const std::string& pathInfo) const {
    // RFC 3875 §4.1: CGI environment variables
    std::vector<std::string> env;
    auto add=[&](const char* k, const std::string& v){ env.push_back(std::string(k)+"="+v); };
    auto addSV=[&](const char* k, std::string_view v){ env.push_back(std::string(k)+"="+std::string(v)); };

    add("GATEWAY_INTERFACE","CGI/1.1");
    add("SERVER_SOFTWARE","httpd/1.0");
    add("SERVER_NAME",std::string(req.headers.get("host")));
    add("SERVER_PORT","80");
    add("SERVER_PROTOCOL","HTTP/1.1");

    add("REQUEST_METHOD",methodStr(req.method));
    add("SCRIPT_FILENAME",scriptPath);
    add("SCRIPT_NAME",scriptPath.substr(cfg_.docRoot.size()));
    add("PATH_INFO",pathInfo);
    add("PATH_TRANSLATED",cfg_.docRoot+pathInfo);
    add("QUERY_STRING",req.url.query);
    add("REQUEST_URI",req.url.path+(req.url.query.empty()?"":"?"+req.url.query));
    add("DOCUMENT_ROOT",cfg_.docRoot);

    if(!req.body.empty()) {
        add("CONTENT_LENGTH",std::to_string(req.body.size()));
        addSV("CONTENT_TYPE",req.headers.get("content-type"));
    } else { add("CONTENT_LENGTH","0"); add("CONTENT_TYPE",""); }

    // Remote address from headers (X-Forwarded-For or Via)
    auto xff=req.headers.get("x-forwarded-for");
    add("REMOTE_ADDR",xff.empty()?"127.0.0.1":std::string(xff));
    add("REMOTE_PORT","0");
    add("REMOTE_HOST","");

    // Map HTTP request headers to HTTP_* env vars
    for(const auto& h:req.headers.list) {
        std::string name="HTTP_";
        for(char c:h.name) name+=(c=='-')?'_':(char)toupper((unsigned char)c);
        env.push_back(name+"="+h.value);
    }

    // Cookies
    auto cookie=req.headers.get("cookie");
    if(!cookie.empty()) addSV("HTTP_COOKIE",cookie);

    // Redirect inherited env (PATH, TZ etc.)
    char** envp_global = ::environ;
    for(char** e=envp_global;*e;++e) {
        std::string ev(*e);
        if(ev.substr(0,5)=="PATH="||ev.substr(0,3)=="TZ="||
           ev.substr(0,5)=="HOME="||ev.substr(0,5)=="USER=")
            env.push_back(ev);
    }
    return env;
}

bool CgiHandler::execute(const RawRequest& req, const std::string& scriptPath,
                         const std::string& pathInfo, RawResponse& resp) {
    // Pipes: in=parent→child(stdin), out=child→parent(stdout+stderr merged)
    int inPipe[2]={-1,-1}, outPipe[2]={-1,-1};
    if(pipe(inPipe)||pipe(outPipe)) { resp.statusCode=500; return false; }
    // Mark parent ends non-blocking
    fcntl(outPipe[0],F_SETFL,O_NONBLOCK);

    auto env=buildEnv(req,scriptPath,pathInfo);
    std::vector<char*> envp; for(auto& s:env) envp.push_back(s.data()); envp.push_back(nullptr);

    pid_t pid=fork();
    if(pid<0) { close(inPipe[0]);close(inPipe[1]);close(outPipe[0]);close(outPipe[1]);
                resp.statusCode=500; return false; }

    if(pid==0) {
        // ── Child ──
        // Drop privileges if configured
        if(cfg_.runAsGid) setgid(cfg_.runAsGid);
        if(cfg_.runAsUid) setuid(cfg_.runAsUid);

        // Redirect stdin
        dup2(inPipe[0],STDIN_FILENO); close(inPipe[0]); close(inPipe[1]);
        // Redirect stdout+stderr to output pipe
        dup2(outPipe[1],STDOUT_FILENO); dup2(outPipe[1],STDERR_FILENO);
        close(outPipe[0]); close(outPipe[1]);

        // Change to script directory
        std::string dir=scriptPath.substr(0,scriptPath.rfind('/'));
        chdir(dir.c_str());

        // Resolve to absolute path so execve works after chdir
        char absPath[4096];
        if(!realpath(scriptPath.c_str(), absPath)) {
            strncpy(absPath, scriptPath.c_str(), sizeof(absPath)-1);
            absPath[sizeof(absPath)-1] = '\0';
        }
        const char* absArgv[] = { absPath, nullptr };
        execve(absPath, (char**)absArgv, envp.data());
        // exec failed — try via /bin/sh as fallback
        const char* shArgv[] = { "/bin/sh", absPath, nullptr };
        execve("/bin/sh", (char**)shArgv, envp.data());
        const char* bashArgv[] = { "/usr/bin/bash", absPath, nullptr };
        execve("/usr/bin/bash", (char**)bashArgv, envp.data());
        fprintf(stdout,"Status: 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\nCGI exec failed: %s\n",
                strerror(errno));
        _exit(1);
    }

    // ── Parent ──
    close(inPipe[0]);
    close(outPipe[1]);

    // Write request body to child's stdin
    if(!req.body.empty()) {
        const char* bp=req.body.data(); size_t remain=req.body.size();
        while(remain>0) {
            ssize_t n=write(inPipe[1],bp,remain);
            if(n<0) break;
            bp+=n; remain-=(size_t)n;
        }
    }
    close(inPipe[1]);

    // Read child's output with timeout
    std::string output; output.reserve(4096);
    char buf[8192];
    int64_t deadline=nowMs()+cfg_.timeout_ms;
    for(;;) {
        int64_t left=(int64_t)(deadline-nowMs());
        if(left<=0) { kill(pid,SIGKILL); break; }
        struct pollfd pfd{outPipe[0],POLLIN,0};
        int pr=poll(&pfd,1,(int)std::min(left,(int64_t)1000));
        if(pr<0&&errno==EINTR) continue;
        if(pr<=0) continue;
        ssize_t n=read(outPipe[0],buf,sizeof buf);
        if(n<0&&errno==EAGAIN) continue;
        if(n<=0) break;
        output.append(buf,(size_t)n);
        if(output.size()>cfg_.maxOutput) { kill(pid,SIGKILL); resp.statusCode=500; break; }
    }
    close(outPipe[0]);

    int status=0;
    waitpid(pid,&status,0);

    if(!parseCgiOutput(output,resp)) { resp.statusCode=500; return false; }
    return true;
}

bool CgiHandler::parseCgiOutput(const std::string& out, RawResponse& resp) const {
    // CGI output: header lines, blank line, body
    // RFC 3875 §6: CGI response
    size_t pos=0, len=out.size();

    resp.statusCode=200;
    bool inHeaders=true;
    std::string bodyStart;

    while(pos<len&&inHeaders) {
        // Find end of line
        size_t eol=out.find('\n',pos);
        if(eol==std::string::npos) eol=len;
        std::string_view line(out.data()+pos,(eol>pos&&out[eol-1]=='\r')?eol-pos-1:eol-pos);
        pos=eol+1;

        if(line.empty()) { inHeaders=false; break; }

        auto colon=line.find(':');
        if(colon==std::string_view::npos) continue;
        auto name=line.substr(0,colon);
        auto val =line.substr(colon+1);
        while(!val.empty()&&val[0]==' ') val=val.substr(1);

        // Special CGI headers
        if(Headers::eqi(name,"status")) {
            resp.statusCode=(int)strtol(std::string(val).c_str(),nullptr,10);
        } else if(Headers::eqi(name,"location")) {
            resp.statusCode=302;
            resp.headers.set("location",val);
        } else if(Headers::eqi(name,"content-type")) {
            resp.headers.set("content-type",val);
        } else {
            resp.headers.add(std::string(name),std::string(val));
        }
    }

    // Rest is body
    resp.body=out.substr(pos);
    if(resp.headers.get("content-type").empty())
        resp.headers.set("content-type","text/html; charset=utf-8");
    resp.headers.set("content-length",std::to_string(resp.body.size()));
    return true;
}

} // namespace httpd
