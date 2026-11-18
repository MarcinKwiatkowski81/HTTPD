// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
#include "Config.h"
#include <fstream>
#include <sstream>
#include <cctype>
#include <cstring>
#include <algorithm>
#include <cstdlib>

namespace httpd {

// ── Utility ───────────────────────────────────────────────────────────────────
static std::string ltrim(std::string_view s) {
    size_t i = 0;
    while(i < s.size() && (s[i]==' '||s[i]=='\t')) ++i;
    return std::string(s.substr(i));
}
static std::string rtrim(std::string_view s) {
    size_t i = s.size();
    while(i>0 && (s[i-1]==' '||s[i-1]=='\t'||s[i-1]=='\r'||s[i-1]=='\n')) --i;
    return std::string(s.substr(0,i));
}
static std::string trim(std::string_view s) { return ltrim(rtrim(s)); }

static int indent(const std::string& line) {
    int n = 0;
    for(char c : line) { if(c==' ') ++n; else if(c=='\t') n+=2; else break; }
    return n;
}

// ── Mini YAML parser ──────────────────────────────────────────────────────────
// Supported subset:
//   key: scalar
//   key: "quoted scalar"
//   key:
//     nested_key: value
//   - sequence item
//   - key: value       (sequence of mappings)
//
bool ConfigParser::parse(const std::string& text, Node& root, std::string& error) {
    root.kind = Node::Kind::Mapping;

    // Split into lines, stripping comments
    std::vector<std::pair<int,std::string>> lines;  // (indent, content)
    std::istringstream ss(text);
    std::string raw;
    int lineNo = 0;
    while(std::getline(ss, raw)) {
        ++lineNo;
        // Strip trailing \r
        if(!raw.empty() && raw.back()=='\r') raw.pop_back();
        // Strip inline comment (careful: don't strip '#' inside quotes)
        bool inQ = false; char qc = 0;
        for(size_t i=0;i<raw.size();++i) {
            char c=raw[i];
            if(!inQ && (c=='"'||c=='\'')) { inQ=true; qc=c; }
            else if(inQ && c==qc) inQ=false;
            else if(!inQ && c=='#') { raw=raw.substr(0,i); break; }
        }
        std::string content = rtrim(raw);
        if(content.empty() || trim(content).empty()) continue;  // blank / comment-only
        int ind = indent(content);
        content = ltrim(content);
        lines.push_back({ind, content});
    }

    // Recursive descent parser
    // Returns the index past the last consumed line.
    std::function<size_t(size_t, int, Node&, std::string&)> parseBlock;
    parseBlock = [&](size_t idx, int baseInd, Node& node, std::string& err) -> size_t {
        (void)err;
        // Determine if this block is a sequence or mapping
        while(idx < lines.size()) {
            auto& [ind, content] = lines[idx];
            if(ind < baseInd) return idx;  // back to parent

            if(content[0] == '-') {
                // Sequence entry
                if(node.kind == Node::Kind::Mapping && node.map.empty() && node.seq.empty())
                    node.kind = Node::Kind::Sequence;
                if(node.kind != Node::Kind::Sequence) { err="Mix of mapping and sequence"; return idx; }

                std::string rest = ltrim(content.substr(1));
                Node item;
                if(rest.empty()) {
                    // next lines form the item body
                    item.kind = Node::Kind::Mapping;
                    ++idx;
                    if(idx < lines.size() && lines[idx].first > ind)
                        idx = parseBlock(idx, lines[idx].first, item, err);
                } else if(rest.find(':') != std::string::npos
                          && rest[0] != '"' && rest[0] != '\'') {
                    // - key: value  or  - key:\n    sub: val
                    item.kind = Node::Kind::Mapping;
                    // treat rest as a line at increased indent
                    std::vector<std::pair<int,std::string>> tmp = {{ind+2, rest}};
                    // scan following lines that belong to this item
                    ++idx;
                    while(idx < lines.size() && lines[idx].first > ind) {
                        tmp.push_back(lines[idx]);
                        ++idx;
                    }
                    // parse tmp as a mini-block
                    std::vector<std::pair<int,std::string>> savedLines = lines;
                    size_t savedIdx = idx;
                    lines = tmp;
                    parseBlock(0, 0, item, err);
                    lines = savedLines;
                    idx = savedIdx;
                } else {
                    item.kind = Node::Kind::Scalar;
                    // unquote
                    if(!rest.empty() && (rest[0]=='"'||rest[0]=='\'')) {
                        char q = rest[0];
                        size_t e2 = rest.rfind(q);
                        item.scalar = (e2>0) ? rest.substr(1,e2-1) : rest.substr(1);
                    } else { item.scalar = trim(rest); }
                    ++idx;
                }
                node.seq.push_back(std::move(item));
            } else if(content.find(':') != std::string::npos) {
                // Mapping entry
                if(node.kind == Node::Kind::Sequence) { err="Mix of seq and map"; return idx; }
                node.kind = Node::Kind::Mapping;

                size_t colon = content.find(':');
                // Check it's not inside quotes
                bool inQ2=false; char qc2=0; size_t realColon=std::string::npos;
                for(size_t i=0;i<content.size();++i){
                    char c=content[i];
                    if(!inQ2&&(c=='"'||c=='\'')){ inQ2=true; qc2=c; }
                    else if(inQ2&&c==qc2) inQ2=false;
                    else if(!inQ2&&c==':'){
                        // colon must be followed by space/newline or be end-of-line
                        if(i+1>=content.size()||content[i+1]==' '||content[i+1]=='\t'){
                            realColon=i; break;
                        }
                    }
                }
                if(realColon==std::string::npos) { ++idx; continue; }  // not a kv line
                colon = realColon;

                std::string key = trim(content.substr(0, colon));
                std::string val = (colon+1<content.size()) ? trim(content.substr(colon+1)) : "";

                Node valNode;
                if(!val.empty()) {
                    valNode.kind = Node::Kind::Scalar;
                    if(!val.empty() && (val[0]=='"'||val[0]=='\'')) {
                        char q = val[0];
                        size_t e2 = val.rfind(q);
                        valNode.scalar = (e2>0) ? val.substr(1,e2-1) : val.substr(1);
                    } else { valNode.scalar = val; }
                    ++idx;
                    // Check if there are sub-entries at higher indent
                    if(idx < lines.size() && lines[idx].first > ind) {
                        valNode.kind = Node::Kind::Mapping;
                        valNode.scalar.clear();
                        idx = parseBlock(idx, lines[idx].first, valNode, err);
                    }
                } else {
                    // Empty value — look for sub-block
                    ++idx;
                    if(idx < lines.size() && lines[idx].first > ind) {
                        valNode.kind = Node::Kind::Mapping;
                        idx = parseBlock(idx, lines[idx].first, valNode, err);
                    } else {
                        valNode.kind = Node::Kind::Scalar;
                        valNode.scalar = "";
                    }
                }
                node.map.push_back({key, std::move(valNode)});
            } else {
                ++idx;  // unknown line, skip
            }
        }
        return idx;
    };

    std::string parseErr;
    parseBlock(0, 0, root, parseErr);
    if(!parseErr.empty()) { error = parseErr; return false; }
    return true;
}

// ── Proxy target parser ───────────────────────────────────────────────────────
void ConfigParser::parseProxyTarget(const std::string& target, ProxyPass& pp) {
    // e.g. "http://127.0.0.1:3000" or "https://backend:443"
    std::string url = target;
    if(url.substr(0,7)=="http://")  { pp.targetTls=false; url=url.substr(7); }
    else if(url.substr(0,8)=="https://") { pp.targetTls=true; url=url.substr(8); }

    // Strip trailing path
    auto slash = url.find('/');
    if(slash!=std::string::npos) url=url.substr(0,slash);

    // host:port
    auto colon = url.rfind(':');
    if(colon!=std::string::npos) {
        pp.targetHost = url.substr(0,colon);
        pp.targetPort = (uint16_t)std::strtoul(url.substr(colon+1).c_str(),nullptr,10);
    } else {
        pp.targetHost = url;
        pp.targetPort = pp.targetTls ? 443 : 80;
    }
}

// ── Rewrite rule builder ──────────────────────────────────────────────────────
void ConfigParser::applyRewrite(const Node& n, RewriteRule& rr) {
    rr.pattern     = n.str("pattern");
    rr.replacement = n.str("replacement");
    std::string fl = n.str("flag");
    if(fl=="last")          rr.flag = RewriteRule::Flag::Last;
    else if(fl=="redirect") rr.flag = RewriteRule::Flag::Redirect;
    else if(fl=="forbidden")rr.flag = RewriteRule::Flag::Forbidden;
    rr.redirectCode = (int)n.num("redirect_code", 302);
    rr.condHeader   = n.str("if_header");
    rr.condValue    = n.str("if_value");
}

// ── Proxy pass builder ────────────────────────────────────────────────────────
void ConfigParser::applyProxy(const Node& n, ProxyPass& pp) {
    pp.location     = n.str("location");
    pp.target       = n.str("target");
    pp.stripPrefix  = n.str("strip_prefix");
    pp.preserveHost = n.boolean("preserve_host", false);
    pp.connectTimeoutMs = (int)n.num("connect_timeout_ms", 5000);
    pp.readTimeoutMs    = (int)n.num("read_timeout_ms",    30000);

    if(!pp.target.empty()) parseProxyTarget(pp.target, pp);

    // add_headers:
    //   - "X-Real-IP: $remote_addr"
    const Node* ah = n.get("add_headers");
    if(ah && ah->kind == Node::Kind::Sequence) {
        for(const auto& item : ah->seq) {
            auto& s = item.scalar;
            auto colon = s.find(':');
            if(colon!=std::string::npos) {
                std::string name = trim(s.substr(0,colon));
                std::string val  = trim(s.substr(colon+1));
                pp.addHeaders.push_back({name, val});
            }
        }
    }

    const Node* hh = n.get("hide_headers");
    if(hh && hh->kind == Node::Kind::Sequence) {
        for(const auto& item : hh->seq)
            pp.hideHeaders.push_back(trim(item.scalar));
    }
}

// ── Virtual host builder ──────────────────────────────────────────────────────
void ConfigParser::applyVhost(const Node& n, VirtualHost& vh) {
    vh.name       = n.str("name");
    vh.docRoot    = n.str("root");
    vh.indexFiles = n.str("index_files");
    vh.certFile   = n.str("cert_file");
    vh.keyFile    = n.str("key_file");
    vh.accessLog  = n.str("access_log");
    vh.spaFallback  = n.boolean("spa_fallback", false);
    vh.spaIndex     = n.str("spa_index", "index.html");
    vh.spaApiPrefix = n.str("spa_api_prefix", "/api");

    std::string cc = n.str("cache_control");
    if(!cc.empty()) vh.cacheControl = cc;

    // server_names: list or single string
    const Node* sn = n.get("server_names");
    if(sn) {
        if(sn->kind == Node::Kind::Sequence)
            for(const auto& i : sn->seq) vh.serverNames.push_back(i.scalar);
        else if(sn->kind == Node::Kind::Scalar)
            vh.serverNames.push_back(sn->scalar);
    }

    // rewrites:
    const Node* rw = n.get("rewrites");
    if(rw && rw->kind == Node::Kind::Sequence) {
        for(const auto& item : rw->seq) {
            RewriteRule rr;
            applyRewrite(item, rr);
            if(!rr.pattern.empty()) vh.rewrites.push_back(std::move(rr));
        }
    }

    // proxies:
    const Node* px = n.get("proxies");
    if(px && px->kind == Node::Kind::Sequence) {
        for(const auto& item : px->seq) {
            ProxyPass pp;
            applyProxy(item, pp);
            if(!pp.location.empty() && !pp.target.empty())
                vh.proxies.push_back(std::move(pp));
        }
    }

    // add_headers:
    const Node* ah = n.get("add_headers");
    if(ah && ah->kind == Node::Kind::Sequence) {
        for(const auto& item : ah->seq) {
            auto& s = item.scalar;
            auto colon = s.find(':');
            if(colon!=std::string::npos) {
                std::string name = trim(s.substr(0,colon));
                std::string val  = trim(s.substr(colon+1));
                vh.addHeaders.push_back({name,val});
            }
        }
    }
}

// ── Root config builder ───────────────────────────────────────────────────────
void ConfigParser::applyRoot(const Node& root, YamlConfig& cfg) {
    cfg.bindAddr           = root.str("bind",         cfg.bindAddr);
    cfg.httpPort           = (uint16_t)root.num("port",        cfg.httpPort);
    cfg.httpsPort          = (uint16_t)root.num("https_port",  cfg.httpsPort);
    cfg.enableHttp         = root.boolean("enable_http",  true);
    cfg.enableHttps        = root.boolean("enable_https", false);
    cfg.workers            = (int)root.num("workers",     0);
    cfg.threadsPerWorker   = (int)root.num("threads",     4);
    cfg.docRoot            = root.str("root",         cfg.docRoot);
    cfg.indexFiles         = root.str("index_files",  cfg.indexFiles);
    cfg.certFile           = root.str("cert_file");
    cfg.keyFile            = root.str("key_file");
    cfg.caFile             = root.str("ca_file");
    cfg.ktls               = root.boolean("ktls",  true);
    cfg.http2              = root.boolean("http2", true);
    cfg.cgiDir             = root.str("cgi_dir",      cfg.cgiDir);
    cfg.cacheMaxEntries    = (size_t)root.num("cache_max_entries",   1024);
    cfg.cacheMaxMb         = (size_t)root.num("cache_max_mb",        64);
    cfg.streamThresholdKb  = (size_t)root.num("stream_threshold_kb", 1024);
    cfg.accessLog          = root.boolean("access_log",  true);
    cfg.accessLogFile      = root.str("access_log_file");
    cfg.keepAliveTimeout   = (int)root.num("keepalive_timeout", 60);
    cfg.requestTimeout     = (int)root.num("request_timeout",   30);
    cfg.maxConns           = (size_t)root.num("max_conns",  10000);
    cfg.maxBodyMb          = (size_t)root.num("max_body_mb", 64);
    cfg.spaFallback        = root.boolean("spa_fallback", false);
    cfg.spaIndex           = root.str("spa_index",      "index.html");
    cfg.spaApiPrefix       = root.str("spa_api_prefix", "/api");

    if(!cfg.certFile.empty() || !cfg.keyFile.empty()) cfg.enableHttps = true;

    // modules:
    const Node* mods = root.get("modules");
    if(mods && mods->kind == Node::Kind::Sequence)
        for(const auto& item : mods->seq) cfg.modules.push_back(item.scalar);

    // global rewrites:
    const Node* rw = root.get("rewrites");
    if(rw && rw->kind == Node::Kind::Sequence) {
        for(const auto& item : rw->seq) {
            RewriteRule rr; applyRewrite(item, rr);
            if(!rr.pattern.empty()) cfg.rewrites.push_back(std::move(rr));
        }
    }

    // global proxies:
    const Node* px = root.get("proxies");
    if(px && px->kind == Node::Kind::Sequence) {
        for(const auto& item : px->seq) {
            ProxyPass pp; applyProxy(item, pp);
            if(!pp.location.empty()&&!pp.target.empty())
                cfg.proxies.push_back(std::move(pp));
        }
    }

    // virtual_hosts:
    const Node* vh = root.get("virtual_hosts");
    if(vh && vh->kind == Node::Kind::Sequence) {
        for(const auto& item : vh->seq) {
            VirtualHost v; applyVhost(item, v);
            if(!v.name.empty() || !v.serverNames.empty() || !v.docRoot.empty())
                cfg.vhosts.push_back(std::move(v));
        }
    }
}

// ── Public API ────────────────────────────────────────────────────────────────
bool ConfigParser::parseFile(const std::string& path, YamlConfig& out,
                              std::string& error) {
    std::ifstream f(path);
    if(!f) { error = "Cannot open: " + path; return false; }
    std::ostringstream ss; ss << f.rdbuf();
    return parseString(ss.str(), out, error);
}

bool ConfigParser::parseString(const std::string& yaml, YamlConfig& out,
                                std::string& error) {
    Node root;
    if(!parse(yaml, root, error)) return false;
    applyRoot(root, out);
    return true;
}

} // namespace httpd
