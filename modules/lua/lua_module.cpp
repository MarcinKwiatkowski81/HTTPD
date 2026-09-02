// Copyright (C) 2025 Marcin Kwiatkowski
// SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
//
// Lua 5.4 scripting module — httpd module C ABI
//
// Each .lua file is a script that runs per-request.
// The script interacts with the HTTP layer via the global "httpd" table:
//
//   httpd.write(str)              -- append to response body
//   httpd.header(name, value)     -- set response header
//   httpd.status(code)            -- set HTTP status code
//   httpd.method()                -- request method string
//   httpd.path()                  -- request path
//   httpd.query()                 -- raw query string
//   httpd.get_param(name)         -- decoded query-string parameter (nil if absent)
//   httpd.get_params()            -- table of ALL query-string params
//   httpd.get_header(name)        -- request header value (nil if absent)
//   httpd.get_cookie(name)        -- cookie value
//   httpd.set_cookie(name,val,{}) -- set response cookie
//   httpd.body()                  -- raw request body
//   httpd.redirect(url[,code])    -- HTTP redirect
//   httpd.escape_html(str)        -- HTML-escape a string
//   httpd.urlencode(str)          -- percent-encode a string
//   httpd.json_encode(table)      -- simple JSON serialiser
//   httpd.log(level, msg)         -- log to stderr + syslog
//   httpd.remote_addr()           -- client IP (respects X-Forwarded-For)
//   httpd.script_dir()            -- directory of the running script
//   httpd.session_create(user)    -- create/replace session → sid
//   httpd.session_get(sid)        -- sid → username | nil
//   httpd.session_destroy(sid)    -- invalidate session
//   httpd.session_list()          -- all active sessions (admin)
//   httpd.session_count()         -- integer
//   httpd.parse_form(body)        -- URL-form-encoded → table

#include "../../include/Module.h"
#include "../../include/HttpCommon.h"
#include "../../include/common.h"

#include <lua5.4/lua.hpp>
#include <unistd.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <sstream>
#include <string>
#include <vector>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <pthread.h>
#include <syslog.h>

// ── Visibility macro ──────────────────────────────────────────────────────────
#define HTTPD_EXPORT extern "C" __attribute__((visibility("default")))

// ── Per-request context threaded through Lua via TLS ─────────────────────────
struct LuaReqCtx {
    httpd::RequestCtx* rctx   = nullptr;
    std::string        output;          // accumulates httpd.write() calls
};

static pthread_key_t  gCtxKey;
static pthread_once_t gOnce = PTHREAD_ONCE_INIT;
static void initKey() { pthread_key_create(&gCtxKey, nullptr); }

// Working directory captured at module init — used to pin package.path so that
// require('lua.db') resolves correctly even in forked child processes where the
// OS-reported cwd may differ from the project root.
static std::string gModuleCwd;

// ── Lua API: httpd.* ──────────────────────────────────────────────────────────

static LuaReqCtx* ctx(lua_State*) {
    return static_cast<LuaReqCtx*>(pthread_getspecific(gCtxKey));
}

// httpd.write(str)
static int l_write(lua_State* L) {
    size_t len; const char* s = luaL_checklstring(L, 1, &len);
    if(auto* c = ctx(L)) c->output.append(s, len);
    return 0;
}

// httpd.header(name, value)
static int l_header(lua_State* L) {
    const char* n = luaL_checkstring(L, 1);
    const char* v = luaL_checkstring(L, 2);
    if(auto* c = ctx(L)) if(c->rctx && c->rctx->resp) c->rctx->resp->headers.set(n, v);
    return 0;
}

// httpd.status(code)
static int l_status(lua_State* L) {
    int code = (int)luaL_checkinteger(L, 1);
    if(auto* c = ctx(L)) if(c->rctx && c->rctx->resp) c->rctx->resp->statusCode = code;
    return 0;
}

// httpd.method()
static int l_method(lua_State* L) {
    if(auto* c = ctx(L)) if(c->rctx && c->rctx->req)
        { lua_pushstring(L, httpd::methodStr(c->rctx->req->method)); return 1; }
    lua_pushstring(L, "GET"); return 1;
}

// httpd.path()
static int l_path(lua_State* L) {
    if(auto* c = ctx(L)) if(c->rctx && c->rctx->req)
        { lua_pushstring(L, c->rctx->req->url.path.c_str()); return 1; }
    lua_pushstring(L, "/"); return 1;
}

// httpd.query()
static int l_query(lua_State* L) {
    if(auto* c = ctx(L)) if(c->rctx && c->rctx->req)
        { lua_pushstring(L, c->rctx->req->url.query.c_str()); return 1; }
    lua_pushstring(L, ""); return 1;
}

// httpd.get_param(name)  →  decoded query-string value or nil (absent → nil)
static int l_get_param(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    if(auto* c = ctx(L)) if(c->rctx && c->rctx->req) {
        auto params = c->rctx->req->url.parseQuery();
        auto it = params.find(name);
        if(it != params.end()) { lua_pushstring(L, it->second.c_str()); return 1; }
    }
    lua_pushnil(L); return 1;
}

// httpd.get_params() → table of ALL decoded query-string parameters
static int l_get_params(lua_State* L) {
    lua_newtable(L);
    if(auto* c = ctx(L)) if(c->rctx && c->rctx->req) {
        auto params = c->rctx->req->url.parseQuery();
        for(auto& [k, v] : params) {
            lua_pushlstring(L, k.data(), k.size());
            lua_pushlstring(L, v.data(), v.size());
            lua_settable(L, -3);
        }
    }
    return 1;
}

// httpd.get_header(name)
static int l_get_header(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    if(auto* c = ctx(L)) if(c->rctx && c->rctx->req) {
        auto v = c->rctx->req->headers.get(name);
        if(!v.empty()) { lua_pushlstring(L, v.data(), v.size()); return 1; }
    }
    lua_pushnil(L); return 1;
}

// httpd.get_cookie(name)
static int l_get_cookie(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    if(auto* c = ctx(L)) if(c->rctx && c->rctx->req) {
        auto it = c->rctx->req->cookies.find(name);
        if(it != c->rctx->req->cookies.end())
            { lua_pushstring(L, it->second.c_str()); return 1; }
    }
    lua_pushnil(L); return 1;
}

// httpd.set_cookie(name, value [, opts_table])
static int l_set_cookie(lua_State* L) {
    const char* name  = luaL_checkstring(L, 1);
    const char* value = luaL_checkstring(L, 2);
    httpd::Cookie ck;
    ck.name  = name;
    ck.value = value;
    if(lua_istable(L, 3)) {
        auto getStr = [&](const char* key) -> std::string {
            lua_getfield(L, 3, key);
            std::string r = lua_isstring(L,-1) ? lua_tostring(L,-1) : "";
            lua_pop(L,1); return r;
        };
        auto getInt = [&](const char* key) -> int64_t {
            lua_getfield(L, 3, key);
            int64_t r = lua_isnumber(L,-1) ? (int64_t)lua_tointeger(L,-1) : -1;
            lua_pop(L,1); return r;
        };
        auto getBool = [&](const char* key) -> bool {
            lua_getfield(L, 3, key);
            bool r = lua_toboolean(L,-1);
            lua_pop(L,1); return r;
        };
        auto p = getStr("path");    if(!p.empty())  ck.path     = p;
        auto d = getStr("domain");  if(!d.empty())  ck.domain   = d;
        auto ss= getStr("sameSite");if(!ss.empty()) ck.sameSite = ss;
        int64_t ma = getInt("maxAge"); if(ma >= 0)  ck.maxAge   = ma;
        ck.secure   = getBool("secure");
        ck.httpOnly = getBool("httpOnly");
    }
    if(auto* c = ctx(L)) if(c->rctx && c->rctx->resp)
        c->rctx->resp->headers.add("set-cookie", ck.format());
    return 0;
}

// httpd.body()
static int l_body(lua_State* L) {
    if(auto* c = ctx(L)) if(c->rctx && c->rctx->req) {
        const auto& b = c->rctx->req->body;
        lua_pushlstring(L, b.data(), b.size()); return 1;
    }
    lua_pushstring(L, ""); return 1;
}

// httpd.redirect(url [, code=302])
static int l_redirect(lua_State* L) {
    const char* url = luaL_checkstring(L, 1);
    int code = lua_isnumber(L, 2) ? (int)lua_tointeger(L, 2) : 302;
    if(auto* c = ctx(L)) if(c->rctx && c->rctx->resp) {
        c->rctx->resp->statusCode = code;
        c->rctx->resp->headers.set("location", url);
        c->rctx->handled = true;
    }
    return 0;
}

// httpd.escape_html(str)
static int l_escape_html(lua_State* L) {
    size_t len; const char* s = luaL_optlstring(L, 1, "", &len);
    std::string out; out.reserve(len + 32);
    for(size_t i = 0; i < len; ++i) {
        switch(s[i]) {
        case '&':  out += "&amp;";  break;
        case '<':  out += "&lt;";   break;
        case '>':  out += "&gt;";   break;
        case '"':  out += "&quot;"; break;
        case '\'': out += "&#39;";  break;
        default:   out += s[i];     break;
        }
    }
    lua_pushlstring(L, out.data(), out.size());
    return 1;
}

// httpd.urlencode(str)
static int l_urlencode(lua_State* L) {
    size_t len; const char* s = luaL_optlstring(L, 1, "", &len);
    auto enc = httpd::Url::urlEncode(std::string_view(s, len));
    lua_pushlstring(L, enc.data(), enc.size());
    return 1;
}

// httpd.log(level, msg)  — "debug"|"info"|"warn"|"error"
static int l_log(lua_State* L) {
    const char* level = luaL_optstring(L, 1, "info");
    size_t len; const char* msg = luaL_checklstring(L, 2, &len);
    int prio = LOG_INFO;
    if     (strcmp(level,"debug")==0) prio = LOG_DEBUG;
    else if(strcmp(level,"warn") ==0) prio = LOG_WARNING;
    else if(strcmp(level,"error")==0) prio = LOG_ERR;
    fprintf(stderr, "[LUA][%s] %.*s\n", level, (int)len, msg);
    syslog(prio, "[lua] %.*s", (int)len, msg);
    return 0;
}

// httpd.remote_addr() → client IP (respects X-Forwarded-For / X-Real-IP)
static int l_remote_addr(lua_State* L) {
    if(auto* c = ctx(L)) if(c->rctx && c->rctx->req) {
        auto xff = c->rctx->req->headers.get("x-forwarded-for");
        if(!xff.empty()) { lua_pushlstring(L, xff.data(), xff.size()); return 1; }
        auto xri = c->rctx->req->headers.get("x-real-ip");
        if(!xri.empty()) { lua_pushlstring(L, xri.data(), xri.size()); return 1; }
    }
    lua_pushstring(L, "127.0.0.1"); return 1;
}

// httpd.script_dir() → directory of the executing script (trailing slash)
static int l_script_dir(lua_State* L) {
    if(auto* c = ctx(L)) if(c->rctx) {
        const std::string& sp = c->rctx->scriptPath;
        auto slash = sp.rfind('/');
        std::string dir = (slash != std::string::npos) ? sp.substr(0, slash+1) : "./";
        lua_pushlstring(L, dir.data(), dir.size()); return 1;
    }
    lua_pushstring(L, "./"); return 1;
}

// httpd.json_encode(value)
static std::string jsonEncodeValue(lua_State* L, int idx, int depth);

static std::string jsonEncodeValue(lua_State* L, int idx, int depth) {
    if(depth > 32) return "null";
    idx = lua_absindex(L, idx);
    int t = lua_type(L, idx);
    if(t == LUA_TNIL)     return "null";
    if(t == LUA_TBOOLEAN) return lua_toboolean(L, idx) ? "true" : "false";
    if(t == LUA_TNUMBER) {
        if(lua_isinteger(L, idx)) return std::to_string(lua_tointeger(L, idx));
        char buf[64]; snprintf(buf, sizeof buf, "%.17g", lua_tonumber(L, idx));
        return buf;
    }
    if(t == LUA_TSTRING) {
        size_t l; const char* s = lua_tolstring(L, idx, &l);
        std::string out; out.reserve(l + 2); out += '"';
        for(size_t i = 0; i < l; ++i) {
            unsigned char c = (unsigned char)s[i];
            if(c == '"')       out += "\\\"";
            else if(c == '\\') out += "\\\\";
            else if(c == '\n') out += "\\n";
            else if(c == '\r') out += "\\r";
            else if(c == '\t') out += "\\t";
            else if(c < 0x20)  { char esc[8]; snprintf(esc,sizeof esc,"\\u%04x",c); out+=esc; }
            else               out += (char)c;
        }
        out += '"'; return out;
    }
    if(t == LUA_TTABLE) {
        lua_len(L, idx);
        lua_Integer n = lua_tointeger(L, -1); lua_pop(L, 1);
        bool isArray = (n > 0);
        if(isArray) {
            std::string out = "[";
            for(lua_Integer i = 1; i <= n; ++i) {
                if(i > 1) out += ',';
                lua_geti(L, idx, i);
                out += jsonEncodeValue(L, -1, depth+1);
                lua_pop(L, 1);
            }
            out += ']'; return out;
        } else {
            std::string out = "{";
            bool first = true;
            lua_pushnil(L);
            while(lua_next(L, idx)) {
                if(!first) out += ','; first = false;
                lua_pushvalue(L, -2);
                size_t kl; const char* k = lua_tolstring(L, -1, &kl);
                out += '"'; if(k) out += std::string(k,kl); out += '"';
                out += ':';
                lua_pop(L, 1);
                out += jsonEncodeValue(L, -1, depth+1);
                lua_pop(L, 1);
            }
            out += '}'; return out;
        }
    }
    return "null";
}

static int l_json_encode(lua_State* L) {
    luaL_checkany(L, 1);
    std::string r = jsonEncodeValue(L, 1, 0);
    lua_pushlstring(L, r.data(), r.size());
    return 1;
}

// ── Thread-safe in-process session store ─────────────────────────────────────
// Shared across all I/O threads (mutex-protected). When WORKERS=1 (default for
// FinApp) this covers all requests. For multi-worker deployments, move to
// SQLite-backed sessions in lua/middleware/auth.lua using db.exec().
//
// TTL: 24 h idle expiry, enforced lazily on session_create() when map > 4096.

struct Session {
    std::string username;
    int64_t     createdWallMs    = 0;
    int64_t     lastAccessWallMs = 0;
};

static std::mutex                                  gSessionMu;
static std::unordered_map<std::string, Session>    gSessions;   // sid → Session
static std::unordered_map<std::string, std::string> gUserSid;   // username → sid

static constexpr int64_t kSessionTTLMs  = 86400LL * 1000; // 24 h
static constexpr size_t  kReapThreshold = 4096;

static std::string generateSid() {
    uint8_t buf[24] = {};
    FILE* f = fopen("/dev/urandom", "rb");
    if(f) { (void)fread(buf, 1, sizeof buf, f); fclose(f); }
    else {
        uint64_t t = (uint64_t)httpd::nowWallMs();
        uint64_t p = (uint64_t)getpid();
        for(int i=0;i<8;++i){ buf[i]=(uint8_t)(t>>(i*8)); buf[i+8]=(uint8_t)(p>>(i*8)); }
    }
    static const char hex[] = "0123456789abcdef";
    std::string r; r.reserve(48);
    for(auto b : buf) { r += hex[b>>4]; r += hex[b&0xf]; }
    return r;
}

// Evict sessions idle for more than kSessionTTLMs. Called with gSessionMu held.
static void reapExpiredSessions() {
    int64_t now = httpd::nowWallMs();
    for(auto it = gSessions.begin(); it != gSessions.end(); ) {
        if(now - it->second.lastAccessWallMs > kSessionTTLMs) {
            gUserSid.erase(it->second.username);
            it = gSessions.erase(it);
        } else { ++it; }
    }
}

// httpd.session_create(username) → sid
static int l_session_create(lua_State* L) {
    const char* username = luaL_checkstring(L, 1);
    std::string sid = generateSid();
    {
        std::lock_guard<std::mutex> lk(gSessionMu);
        if(gSessions.size() >= kReapThreshold) reapExpiredSessions();
        auto uit = gUserSid.find(username);
        if(uit != gUserSid.end()) {
            gSessions.erase(uit->second);
            gUserSid.erase(uit);
        }
        int64_t now = httpd::nowWallMs();
        gSessions[sid] = { username, now, now };
        gUserSid[username] = sid;
    }
    lua_pushstring(L, sid.c_str());
    return 1;
}

// httpd.session_get(sid) → username | nil
static int l_session_get(lua_State* L) {
    const char* sid = luaL_optstring(L, 1, "");
    if(!sid || !*sid) { lua_pushnil(L); return 1; }
    std::lock_guard<std::mutex> lk(gSessionMu);
    auto it = gSessions.find(sid);
    if(it == gSessions.end()) { lua_pushnil(L); return 1; }
    it->second.lastAccessWallMs = httpd::nowWallMs();
    lua_pushstring(L, it->second.username.c_str());
    return 1;
}

// httpd.session_destroy(sid)
static int l_session_destroy(lua_State* L) {
    const char* sid = luaL_optstring(L, 1, "");
    if(!sid || !*sid) return 0;
    std::lock_guard<std::mutex> lk(gSessionMu);
    auto it = gSessions.find(sid);
    if(it != gSessions.end()) {
        gUserSid.erase(it->second.username);
        gSessions.erase(it);
    }
    return 0;
}

// httpd.session_list() → array of { sid, username, last_access_ms }
static int l_session_list(lua_State* L) {
    std::lock_guard<std::mutex> lk(gSessionMu);
    lua_newtable(L);
    int i = 1;
    for(auto& [sid, sess] : gSessions) {
        lua_newtable(L);
        lua_pushstring(L, sid.c_str());            lua_setfield(L,-2,"sid");
        lua_pushstring(L, sess.username.c_str());  lua_setfield(L,-2,"username");
        lua_pushinteger(L, sess.lastAccessWallMs); lua_setfield(L,-2,"last_access_ms");
        lua_rawseti(L, -2, i++);
    }
    return 1;
}

// httpd.session_count() → integer
static int l_session_count(lua_State* L) {
    std::lock_guard<std::mutex> lk(gSessionMu);
    lua_pushinteger(L, (lua_Integer)gSessions.size());
    return 1;
}

// httpd.parse_form(body_str) → table
static int l_parse_form(lua_State* L) {
    size_t len; const char* raw = luaL_checklstring(L, 1, &len);
    lua_newtable(L);
    auto decode = [](const std::string& s) {
        std::string out; out.reserve(s.size());
        for(size_t i = 0; i < s.size(); ++i) {
            if(s[i] == '+') { out += ' '; }
            else if(s[i] == '%' && i+2 < s.size()) {
                char h1 = s[++i], h2 = s[++i];
                auto hv = [](char c) -> int {
                    if(c>='0'&&c<='9') return c-'0';
                    if(c>='a'&&c<='f') return 10+c-'a';
                    if(c>='A'&&c<='F') return 10+c-'A';
                    return 0;
                };
                out += (char)((hv(h1)<<4)|hv(h2));
            } else { out += s[i]; }
        }
        return out;
    };
    std::string body(raw, len);
    std::istringstream ss(body);
    std::string token;
    while(std::getline(ss, token, '&')) {
        auto eq = token.find('=');
        std::string k = decode(eq != std::string::npos ? token.substr(0, eq) : token);
        std::string v = decode(eq != std::string::npos ? token.substr(eq+1) : "");
        if(k.empty()) continue;
        lua_pushlstring(L, k.data(), k.size());
        lua_pushlstring(L, v.data(), v.size());
        lua_settable(L, -3);
    }
    return 1;
}

// ── httpd table registration ──────────────────────────────────────────────────
static const luaL_Reg kHttpdLib[] = {
    {"write",          l_write},
    {"header",         l_header},
    {"status",         l_status},
    {"method",         l_method},
    {"path",           l_path},
    {"query",          l_query},
    {"get_param",      l_get_param},
    {"get_params",     l_get_params},
    {"get_header",     l_get_header},
    {"get_cookie",     l_get_cookie},
    {"set_cookie",     l_set_cookie},
    {"body",           l_body},
    {"redirect",       l_redirect},
    {"escape_html",    l_escape_html},
    {"urlencode",      l_urlencode},
    {"json_encode",    l_json_encode},
    {"log",            l_log},
    {"remote_addr",    l_remote_addr},
    {"script_dir",     l_script_dir},
    {"session_create", l_session_create},
    {"session_get",    l_session_get},
    {"session_destroy",l_session_destroy},
    {"session_list",   l_session_list},
    {"session_count",  l_session_count},
    {"parse_form",     l_parse_form},
    {nullptr, nullptr}
};

// ── Compiled-chunk cache (per I/O thread) ────────────────────────────────────
// Cache key: script path. Invalidated by mtime+size+inode change (stat-based).

static const char* kChunkTable = "httpd.chunks";

struct ChunkStamp {
    dev_t  dev = 0; ino_t ino = 0; off_t size = 0;
    time_t sec = 0; long  nsec = 0;

    static ChunkStamp of(const struct stat& st) {
        return { st.st_dev, st.st_ino, st.st_size,
                 st.st_mtim.tv_sec, st.st_mtim.tv_nsec };
    }
    bool sameAs(const struct stat& st) const {
        return dev  == st.st_dev  && ino  == st.st_ino && size == st.st_size
            && sec  == st.st_mtim.tv_sec && nsec == st.st_mtim.tv_nsec;
    }
};

static constexpr size_t kMaxCachedChunks = 512;
static thread_local std::unordered_map<std::string, ChunkStamp> tChunkStamps;

static void resetChunkCache(lua_State* L) {
    lua_newtable(L);
    lua_setfield(L, LUA_REGISTRYINDEX, kChunkTable);
    tChunkStamps.clear();
}

static bool pushCachedChunk(lua_State* L, const std::string& path, const struct stat& st) {
    auto it = tChunkStamps.find(path);
    if(it == tChunkStamps.end() || !it->second.sameAs(st)) return false;
    lua_getfield(L, LUA_REGISTRYINDEX, kChunkTable);
    if(lua_getfield(L, -1, path.c_str()) != LUA_TFUNCTION) {
        lua_pop(L, 2); tChunkStamps.erase(it); return false;
    }
    lua_remove(L, -2);
    return true;
}

static void storeChunk(lua_State* L, const std::string& path, const struct stat& st) {
    if(tChunkStamps.size() >= kMaxCachedChunks) {
        fprintf(stderr, "[LUA] chunk cache hit %zu entries — flushing\n", kMaxCachedChunks);
        resetChunkCache(L);
    }
    lua_getfield(L, LUA_REGISTRYINDEX, kChunkTable);
    lua_pushvalue(L, -2);
    lua_setfield(L, -2, path.c_str());
    lua_pop(L, 1);
    tChunkStamps[path] = ChunkStamp::of(st);
}

// ── Per-thread Lua state pool ─────────────────────────────────────────────────
static std::mutex                              gStateMu;
static std::unordered_map<pthread_t, lua_State*> gStates;

static lua_State* getState() {
    pthread_t self = pthread_self();
    {
        std::lock_guard<std::mutex> lk(gStateMu);
        auto it = gStates.find(self);
        if(it != gStates.end()) return it->second;
    }

    lua_State* L = luaL_newstate();
    luaL_openlibs(L);

    // ── Pin package.path to project root captured at init ──────────────────
    // This ensures require('lua.db') resolves to <projectRoot>/lua/db.lua
    // regardless of cwd changes in forked workers or thread-pool chdir() calls.
    if(!gModuleCwd.empty()) {
        lua_getglobal(L, "package");

        // Lua path: project root first, then defaults
        lua_getfield(L, -1, "path");
        std::string curpath = lua_isstring(L,-1) ? lua_tostring(L,-1) : "";
        lua_pop(L, 1);
        std::string newpath =
            gModuleCwd + "/?.lua;"          +
            gModuleCwd + "/?/init.lua;"     +
            curpath;
        lua_pushstring(L, newpath.c_str());
        lua_setfield(L, -2, "path");

        // C path: add cwd for local .so overrides (lsqlite3 etc.)
        lua_getfield(L, -1, "cpath");
        std::string curcpath = lua_isstring(L,-1) ? lua_tostring(L,-1) : "";
        lua_pop(L, 1);
        std::string newcpath = gModuleCwd + "/?.so;" + curcpath;
        lua_pushstring(L, newcpath.c_str());
        lua_setfield(L, -2, "cpath");

        lua_pop(L, 1); // pop package
    }

    // Register httpd table
    luaL_newlib(L, kHttpdLib);
    lua_setglobal(L, "httpd");
    resetChunkCache(L);

    {
        std::lock_guard<std::mutex> lk(gStateMu);
        gStates[self] = L;
    }
    return L;
}


// ── LHTML template compiler ───────────────────────────────────────────────────
static std::string compileLhtml(const std::string& src, const std::string& filename) {
    std::string out;
    out.reserve(src.size() * 2 + 256);
    out += "-- @" + filename + "\n";

    auto addLiteral = [&](const std::string& text) {
        if(text.empty()) return;
        int lvl = 0;
        for(;;) {
            std::string close = "]" + std::string((size_t)lvl, '=') + "]";
            if(text.find(close) == std::string::npos) break;
            ++lvl;
        }
        std::string open  = "[" + std::string((size_t)lvl, '=') + "[";
        std::string close = "]" + std::string((size_t)lvl, '=') + "]";
        out += "httpd.write(" + open + "\n" + text + close + ");\n";
    };

    size_t pos = 0;
    const size_t len = src.size();
    while(pos < len) {
        size_t tag = src.find("<%", pos);
        if(tag == std::string::npos) { addLiteral(src.substr(pos)); break; }
        if(tag > pos) addLiteral(src.substr(pos, tag - pos));

        if(src.compare(tag, 4, "<%--") == 0) {
            size_t end = src.find("--%>", tag + 4);
            size_t skip = 4;
            if(end == std::string::npos) { end = src.find("%>", tag+4); skip = 2; }
            if(end == std::string::npos) {
                fprintf(stderr, "[LUA] %s: unterminated <%%-- comment\n", filename.c_str());
                break;
            }
            pos = end + skip; continue;
        }

        size_t end = src.find("%>", tag + 2);
        if(end == std::string::npos) { addLiteral(src.substr(tag)); break; }
        std::string code = src.substr(tag + 2, end - (tag + 2));
        pos = end + 2;

        if(!code.empty() && code[0] == '=') {
            out += "do local _v=tostring((" + code.substr(1) + ") or '');"
                   " httpd.write(httpd.escape_html(_v)); end\n";
        } else if(!code.empty() && code[0] == '!') {
            out += "do local _v=tostring((" + code.substr(1) + ") or '');"
                   " httpd.write(_v); end\n";
        } else {
            out += code; out += '\n';
        }
    }
    return out;
}

static bool readFile(const std::string& path, std::string& out) {
    FILE* f = fopen(path.c_str(), "rb");
    if(!f) return false;
    fseek(f, 0, SEEK_END); long sz = ftell(f); rewind(f);
    if(sz > 0) { out.resize((size_t)sz); (void)fread(out.data(), 1, (size_t)sz, f); }
    fclose(f); return true;
}

// ── C ABI ─────────────────────────────────────────────────────────────────────
HTTPD_EXPORT const char* httpd_module_name()    { return "lua"; }
HTTPD_EXPORT const char* httpd_module_version() { return "1.0.0"; }

HTTPD_EXPORT int httpd_module_init(const char* /*config*/) {
    pthread_once(&gOnce, initKey);
    openlog("httpd-lua", LOG_PID, LOG_DAEMON);

    // Capture cwd BEFORE any fork() so child processes inherit the correct path.
    char cwdbuf[4096] = {};
    if(getcwd(cwdbuf, sizeof cwdbuf)) {
        gModuleCwd = cwdbuf;
        fprintf(stderr, "[LUA] package.path root: %s\n", cwdbuf);
    } else {
        fprintf(stderr, "[LUA] warning: getcwd() failed — package.path may be wrong\n");
    }

    // Promote liblua5.4 to global symbol scope so C extensions loaded via
    // require() (lsqlite3, cjson, …) can resolve lua_* symbols.
    if(!dlopen("liblua5.4.so.0", RTLD_NOW | RTLD_GLOBAL | RTLD_NOLOAD))
        fprintf(stderr, "[LUA] warning: could not promote liblua to global scope (%s)\n",
                dlerror() ? dlerror() : "unknown");

    printf("[LUA] Lua 5.4 module initialised (one state per I/O thread)\n");
    return 0;
}

HTTPD_EXPORT void httpd_module_fini() {
    std::lock_guard<std::mutex> lk(gStateMu);
    for(auto& kv : gStates) lua_close(kv.second);
    gStates.clear();
    closelog();
}

HTTPD_EXPORT const char** httpd_module_extensions() {
    static const char* exts[] = { "lua", "luax", "lhtml", nullptr };
    return exts;
}

HTTPD_EXPORT int httpd_module_handle(httpd::RequestCtx* ctx_ptr) {
    if(!ctx_ptr || !ctx_ptr->req || !ctx_ptr->resp || ctx_ptr->scriptPath.empty())
        return 0;

    lua_State* L = getState();

    LuaReqCtx lrc;
    lrc.rctx = ctx_ptr;
    pthread_setspecific(gCtxKey, &lrc);

    // Default response headers
    ctx_ptr->resp->headers.set("content-type", "text/html; charset=utf-8");
    ctx_ptr->resp->statusCode = 200;

    struct stat st{};
    bool haveStat = (stat(ctx_ptr->scriptPath.c_str(), &st) == 0 && S_ISREG(st.st_mode));

    int rc = LUA_OK;
    if(!(haveStat && pushCachedChunk(L, ctx_ptr->scriptPath, st))) {
        bool isLhtml = false;
        {
            const std::string& sp = ctx_ptr->scriptPath;
            auto dot = sp.rfind('.');
            if(dot != std::string::npos) {
                std::string ext = sp.substr(dot + 1);
                for(auto& c : ext) c = (char)tolower((unsigned char)c);
                isLhtml = (ext == "lhtml");
            }
        }

        if(isLhtml) {
            std::string src;
            if(!readFile(ctx_ptr->scriptPath, src)) {
                ctx_ptr->resp->statusCode = 500;
                ctx_ptr->resp->body = "<h1>500 — Cannot read template</h1>";
                ctx_ptr->resp->headers.set("content-length",
                                           std::to_string(ctx_ptr->resp->body.size()));
                ctx_ptr->handled = true;
                pthread_setspecific(gCtxKey, nullptr);
                return 1;
            }
            std::string chunk = compileLhtml(src, ctx_ptr->scriptPath);
            std::string chunkName = "@" + ctx_ptr->scriptPath;
            rc = luaL_loadbuffer(L, chunk.c_str(), chunk.size(), chunkName.c_str());
        } else {
            rc = luaL_loadfile(L, ctx_ptr->scriptPath.c_str());
        }

        if(rc == LUA_OK && haveStat)
            storeChunk(L, ctx_ptr->scriptPath, st);
    }

    if(rc != LUA_OK) {
        const char* err = lua_tostring(L, -1);
        fprintf(stderr, "[LUA] Load error %s: %s\n", ctx_ptr->scriptPath.c_str(), err ? err : "?");
        ctx_ptr->resp->statusCode = 500;
        ctx_ptr->resp->body  = "<h1>500 — Lua Load Error</h1><pre>";
        ctx_ptr->resp->body += (err ? err : "unknown error");
        ctx_ptr->resp->body += "</pre>";
        ctx_ptr->resp->headers.set("content-length", std::to_string(ctx_ptr->resp->body.size()));
        lua_pop(L, 1);
        ctx_ptr->handled = true;
        pthread_setspecific(gCtxKey, nullptr);
        return 1;
    }

    rc = lua_pcall(L, 0, 0, 0);
    if(rc != LUA_OK) {
        const char* err = lua_tostring(L, -1);
        fprintf(stderr, "[LUA] Runtime error %s: %s\n", ctx_ptr->scriptPath.c_str(), err ? err : "?");
        ctx_ptr->resp->statusCode = 500;
        ctx_ptr->resp->body  = "<h1>500 — Lua Runtime Error</h1><pre>";
        ctx_ptr->resp->body += (err ? err : "unknown error");
        ctx_ptr->resp->body += "</pre>";
        ctx_ptr->resp->headers.set("content-length", std::to_string(ctx_ptr->resp->body.size()));
        lua_pop(L, 1);
        ctx_ptr->handled = true;
        pthread_setspecific(gCtxKey, nullptr);
        return 1;
    }

    if(!lrc.output.empty()) {
        ctx_ptr->resp->body = std::move(lrc.output);
        ctx_ptr->resp->headers.set("content-length", std::to_string(ctx_ptr->resp->body.size()));
    }
    ctx_ptr->handled = true;
    pthread_setspecific(gCtxKey, nullptr);
    return 1;
}
