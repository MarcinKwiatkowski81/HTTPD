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
//   httpd.get_param(name)         -- decoded query-string parameter
//   httpd.get_header(name)        -- request header value
//   httpd.get_cookie(name)        -- cookie value
//   httpd.set_cookie(name,val,{}) -- set response cookie
//   httpd.body()                  -- raw request body
//   httpd.redirect(url[,code])    -- HTTP redirect
//   httpd.escape_html(str)        -- HTML-escape a string
//   httpd.urlencode(str)          -- percent-encode a string
//   httpd.json_encode(table)      -- simple JSON serialiser
//
// All exported C symbols carry __attribute__((visibility("default"))) so they
// are reachable via dlsym() regardless of the caller's -fvisibility setting.

#include "../../include/Module.h"
#include "../../include/HttpCommon.h"
#include "../../include/common.h"

#include <lua5.4/lua.hpp>
#include <unistd.h>
#include <sys/stat.h>
#include <sstream>
#include <string>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <unordered_map>
#include <pthread.h>
#include <sstream>

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

// httpd.get_param(name)  →  decoded query-string value or ""
// Absent values return nil, not "". An empty string is truthy in Lua, so
// returning "" makes the idiomatic `httpd.get_param("x") or "default"` never
// take the default — silently yielding empty output instead.
static int l_get_param(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    if(auto* c = ctx(L)) if(c->rctx && c->rctx->req) {
        auto params = c->rctx->req->url.parseQuery();
        auto it = params.find(name);
        if(it != params.end()) { lua_pushstring(L, it->second.c_str()); return 1; }
    }
    lua_pushnil(L); return 1;
}

// httpd.get_header(name)
static int l_get_header(lua_State* L) {
    const char* name = luaL_checkstring(L, 1);
    if(auto* c = ctx(L)) if(c->rctx && c->rctx->req) {
        auto v = c->rctx->req->headers.get(name);
        // headers.get() returns an empty view for a missing header, so an empty
        // result here means absent — report it as nil for consistency.
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
// opts: { path="/", maxAge=N, secure=true, httpOnly=true, sameSite="Lax", domain="" }
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
        auto p = getStr("path");   if(!p.empty())       ck.path     = p;
        auto d = getStr("domain"); if(!d.empty())       ck.domain   = d;
        auto ss= getStr("sameSite");if(!ss.empty())     ck.sameSite = ss;
        int64_t ma = getInt("maxAge"); if(ma >= 0)      ck.maxAge   = ma;
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
// Tolerates nil (yielding ""), so a missing request value passed straight in
// renders as empty rather than raising and turning the page into a 500.
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

// httpd.json_encode(value)  — handles nil/bool/number/string/array-table/dict-table
static int l_json_encode(lua_State* L);  // forward
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
            else if(c < 0x20) { char esc[8]; snprintf(esc,sizeof esc,"\\u%04x",c); out+=esc; }
            else               out += (char)c;
        }
        out += '"'; return out;
    }
    if(t == LUA_TTABLE) {
        // Detect array vs object
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
                if(!first) out += ',';
                first = false;
                // key
                lua_pushvalue(L, -2);
                size_t kl; const char* k = lua_tolstring(L, -1, &kl);
                out += '"'; if(k) out += std::string(k,kl); out += '"';
                out += ':';
                lua_pop(L, 1); // pop key copy
                // value
                out += jsonEncodeValue(L, -1, depth+1);
                lua_pop(L, 1); // pop value
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


// ── Thread-safe session store ─────────────────────────────────────────────────
// Shared across ALL threads / Lua states. Enforces one session per user.

struct Session {
    std::string username;
    int64_t     createdWallMs  = 0;
    int64_t     lastAccessWallMs = 0;
};

static std::mutex                              gSessionMu;
static std::unordered_map<std::string,Session> gSessions;   // sid → Session
static std::unordered_map<std::string,std::string> gUserSid; // username → sid

static std::string generateSid() {
    uint8_t buf[24] = {};
    FILE* f = fopen("/dev/urandom", "rb");
    if(f) { (void)fread(buf, 1, sizeof buf, f); fclose(f); }
    else   { /* fallback: XOR pid+time */
        uint64_t t = (uint64_t)httpd::nowWallMs();
        uint64_t p = (uint64_t)getpid();
        for(int i=0;i<8;++i){ buf[i]=(uint8_t)(t>>(i*8)); buf[i+8]=(uint8_t)(p>>(i*8)); }
    }
    static const char hex[] = "0123456789abcdef";
    std::string r; r.reserve(48);
    for(auto b : buf) { r += hex[b>>4]; r += hex[b&0xf]; }
    return r;
}

// httpd.session_create(username) → sid
// If user already has a session, the old one is INVALIDATED (single-session rule).
static int l_session_create(lua_State* L) {
    const char* username = luaL_checkstring(L, 1);
    std::string sid = generateSid();
    {
        std::lock_guard<std::mutex> lk(gSessionMu);
        // Kill previous session for this user
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
// Returns nil if sid is unknown or expired.
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

// httpd.parse_form(body_str) → table  (URL-form-encoded decoder)
static int l_parse_form(lua_State* L) {
    size_t len; const char* raw = luaL_checklstring(L, 1, &len);
    lua_newtable(L);
    // Decode percent-encoded form data
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
    {"write",       l_write},
    {"header",      l_header},
    {"status",      l_status},
    {"method",      l_method},
    {"path",        l_path},
    {"query",       l_query},
    {"get_param",   l_get_param},
    {"get_header",  l_get_header},
    {"get_cookie",  l_get_cookie},
    {"set_cookie",  l_set_cookie},
    {"body",        l_body},
    {"redirect",    l_redirect},
    {"escape_html", l_escape_html},
    {"urlencode",   l_urlencode},
    {"json_encode",       l_json_encode},
    // Session management
    {"session_create",    l_session_create},
    {"session_get",       l_session_get},
    {"session_destroy",   l_session_destroy},
    // Utility
    {"parse_form",        l_parse_form},
    {nullptr, nullptr}
};

// ── Compiled-chunk cache (the PHP opcache equivalent) ────────────────────────
//
// Skips read + LHTML-compile + Lua-parse on a cache hit, leaving one stat() as
// the only per-request filesystem work.
//
// A loaded chunk is a closure owned by exactly one lua_State and must never be
// shared between states, so the cache is PER-STATE — which here means per I/O
// thread. The functions live in that state's registry (which also keeps them
// reachable from the GC); the validation stamps live in a thread_local map,
// matching per-state lifetime because getState() pins one state per thread.
//
// Reusing the closure is safe: a main chunk's only upvalue is _ENV, which is
// the state's globals table either way, and its top-level `local`s are function
// locals that are re-initialised on every call. Globals already persisted
// across requests because the state does; that is unchanged.

static const char* kChunkTable = "httpd.chunks";   // registry field

struct ChunkStamp {
    dev_t  dev = 0; ino_t ino = 0; off_t size = 0;
    time_t sec = 0; long  nsec = 0;

    static ChunkStamp of(const struct stat& st) {
        return { st.st_dev, st.st_ino, st.st_size,
                 st.st_mtim.tv_sec, st.st_mtim.tv_nsec };
    }
    // Nanosecond mtime + inode + size: a same-second rewrite still invalidates,
    // and so does a replacement file that happens to match size and mtime.
    bool sameAs(const struct stat& st) const {
        return dev  == st.st_dev  && ino  == st.st_ino && size == st.st_size
            && sec  == st.st_mtim.tv_sec && nsec == st.st_mtim.tv_nsec;
    }
};

// Bounded by the number of script files on disk (a path must resolve to a real
// file under docRoot to reach this module), so a plain flush on overflow is
// sufficient — no LRU bookkeeping for a limit that should never be hit.
static constexpr size_t kMaxCachedChunks = 512;
static thread_local std::unordered_map<std::string, ChunkStamp> tChunkStamps;

static void resetChunkCache(lua_State* L) {
    lua_newtable(L);
    lua_setfield(L, LUA_REGISTRYINDEX, kChunkTable);
    tChunkStamps.clear();
}

// On a valid hit, leaves the chunk function on top of the stack and returns
// true. Otherwise returns false with the stack unchanged.
static bool pushCachedChunk(lua_State* L, const std::string& path,
                            const struct stat& st) {
    auto it = tChunkStamps.find(path);
    if(it == tChunkStamps.end() || !it->second.sameAs(st)) return false;

    lua_getfield(L, LUA_REGISTRYINDEX, kChunkTable);          // +1 table
    if(lua_getfield(L, -1, path.c_str()) != LUA_TFUNCTION) {  // +1 value
        // Stamp without a function: registry and stamps disagree, so drop it.
        lua_pop(L, 2);
        tChunkStamps.erase(it);
        return false;
    }
    lua_remove(L, -2);                                        // drop table
    return true;
}

// Caches the function on top of the stack, leaving the stack as it was found.
static void storeChunk(lua_State* L, const std::string& path,
                       const struct stat& st) {
    if(tChunkStamps.size() >= kMaxCachedChunks) {
        fprintf(stderr, "[LUA] chunk cache hit %zu entries — flushing\n",
                kMaxCachedChunks);
        resetChunkCache(L);
    }
    lua_getfield(L, LUA_REGISTRYINDEX, kChunkTable);  // +1 table
    lua_pushvalue(L, -2);                             // +1 copy of the function
    lua_setfield(L, -2, path.c_str());                // table[path] = function
    lua_pop(L, 1);                                    // drop table
    tChunkStamps[path] = ChunkStamp::of(st);
}

// ── Per-thread Lua state pool ─────────────────────────────────────────────────
static std::mutex              gStateMu;
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
//
// Transforms a .lhtml file into an executable Lua chunk.
// Syntax:
//   <% code %>      — execute Lua (no automatic output)
//   <%= expr %>     — output tostring(expr), HTML-escaped
//   <%! expr %>     — output tostring(expr), raw (unescaped)
//   <%-- text --%>  — template comment (stripped, never sent)
//
// All code blocks share the same Lua scope (one chunk per template).
// A leading synthetic \n is inserted after every [=*[ so Lua's
// "strip first newline" rule never eats content characters.

static std::string compileLhtml(const std::string& src,
                                  const std::string& filename) {
    std::string out;
    out.reserve(src.size() * 2 + 256);

    // Header comment — Lua uses "@name" as the chunk name in error messages
    out += "-- @" + filename + "\n";

    // Emit a literal text fragment safely as a Lua long string.
    // We choose the minimum [===[ level so no closing bracket appears in text.
    // A synthetic leading '\n' is placed right after the opening bracket;
    // Lua strips exactly that one '\n', so our content is preserved verbatim.
    auto addLiteral = [&](const std::string& text) {
        if (text.empty()) return;
        int lvl = 0;
        for (;;) {
            std::string close = "]" + std::string((size_t)lvl, '=') + "]";
            if (text.find(close) == std::string::npos) break;
            ++lvl;
        }
        std::string open  = "[" + std::string((size_t)lvl, '=') + "[";
        std::string close = "]" + std::string((size_t)lvl, '=') + "]";
        out += "httpd.write(" + open + "\n" + text + close + ");\n";
    };

    size_t pos = 0;
    const size_t len = src.size();

    while (pos < len) {
        size_t tag = src.find("<%", pos);

        // No more tags — rest is literal
        if (tag == std::string::npos) {
            addLiteral(src.substr(pos));
            break;
        }

        // Literal before this tag
        if (tag > pos) addLiteral(src.substr(pos, tag - pos));

        // A comment is delimited by its own "--%>" and must be scanned for that
        // rather than for the first "%>": a comment containing a tag (or any
        // literal "%>") would otherwise end early and spill the remainder of its
        // own text to the client as markup.
        if (src.compare(tag, 4, "<%--") == 0) {
            size_t end = src.find("--%>", tag + 4);
            size_t skip = 4;
            // Lenient fallback for a comment closed with a bare "%>", which the
            // older single-pass scanner accepted.
            if (end == std::string::npos) { end = src.find("%>", tag + 4); skip = 2; }
            if (end == std::string::npos) {
                // Never emit an unclosed comment. Falling back to literal text
                // would ship the author's private notes to the client, which is
                // the whole failure this branch exists to prevent. Warn on the
                // server side instead, where it is actionable.
                fprintf(stderr, "[LUA] %s: unterminated <%%-- comment; "
                                "discarding to end of template\n", filename.c_str());
                break;
            }
            pos = end + skip;      // discard entirely
            continue;
        }

        size_t end = src.find("%>", tag + 2);
        if (end == std::string::npos) {
            // Unclosed tag — treat remainder as literal
            addLiteral(src.substr(tag));
            break;
        }

        // Code content between <% and %>
        std::string code = src.substr(tag + 2, end - (tag + 2));
        pos = end + 2;

        if (!code.empty() && code[0] == '=') {
            // <%= expr %> — HTML-escaped output
            // "do local" isolates the temp variable from template scope
            out += "do local _v=tostring((" + code.substr(1) + ") or '');"
                   " httpd.write(httpd.escape_html(_v)); end\n";

        } else if (!code.empty() && code[0] == '!') {
            // <%! expr %> — raw (unescaped) output
            out += "do local _v=tostring((" + code.substr(1) + ") or '');"
                   " httpd.write(_v); end\n";

        } else {
            // <% code %> — execute verbatim
            out += code;
            out += '\n';
        }
    }

    return out;
}

// Read a whole file into a string.  Returns false on error.
static bool readFile(const std::string& path, std::string& out) {
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) return false;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz > 0) {
        out.resize((size_t)sz);
        (void)fread(out.data(), 1, (size_t)sz, f);
    }
    fclose(f);
    return true;
}

// ── C ABI — symbols that dlsym() must find ────────────────────────────────────

HTTPD_EXPORT const char* httpd_module_name()    { return "lua"; }
HTTPD_EXPORT const char* httpd_module_version() { return "1.0.0"; }

HTTPD_EXPORT int httpd_module_init(const char* /*config*/) {
    pthread_once(&gOnce, initKey);
    printf("[LUA] Lua 5.4 module initialised (one state per I/O thread)\n");
    return 0;
}

HTTPD_EXPORT void httpd_module_fini() {
    std::lock_guard<std::mutex> lk(gStateMu);
    for(auto& kv : gStates) lua_close(kv.second);
    gStates.clear();
}

HTTPD_EXPORT const char** httpd_module_extensions() {
    static const char* exts[] = { "lua", "luax", "lhtml", nullptr };
    return exts;
}

HTTPD_EXPORT int httpd_module_handle(httpd::RequestCtx* ctx_ptr) {
    if(!ctx_ptr || !ctx_ptr->req || !ctx_ptr->resp || ctx_ptr->scriptPath.empty())
        return 0;

    lua_State* L = getState();

    // Bind context to this thread
    LuaReqCtx lrc;
    lrc.rctx = ctx_ptr;
    pthread_setspecific(gCtxKey, &lrc);

    // Default response headers
    ctx_ptr->resp->headers.set("content-type", "text/html; charset=utf-8");
    ctx_ptr->resp->statusCode = 200;

    // Stamp the file up front: this is both the cache key validation and the
    // only filesystem call made on a cache hit. Core already stat()ed this path
    // to route the request, but RequestCtx does not carry the result and adding
    // a field to it would change the module ABI, so re-stat instead.
    struct stat st{};
    bool haveStat = (stat(ctx_ptr->scriptPath.c_str(), &st) == 0
                     && S_ISREG(st.st_mode));

    int rc = LUA_OK;
    if(!(haveStat && pushCachedChunk(L, ctx_ptr->scriptPath, st))) {
        // Determine whether this is a plain .lua file or a .lhtml template
        bool isLhtml = false;
        {
            const std::string& sp = ctx_ptr->scriptPath;
            auto dot = sp.rfind('.');
            if (dot != std::string::npos) {
                std::string ext = sp.substr(dot + 1);
                for (auto& c : ext) c = (char)tolower((unsigned char)c);
                isLhtml = (ext == "lhtml");
            }
        }

        if (isLhtml) {
            // Compile the .lhtml template into a Lua chunk string, then load it
            std::string src;
            if (!readFile(ctx_ptr->scriptPath, src)) {
                ctx_ptr->resp->statusCode = 500;
                ctx_ptr->resp->body = "<h1>500 — Cannot read template</h1>";
                ctx_ptr->resp->headers.set("content-length",
                                            std::to_string(ctx_ptr->resp->body.size()));
                ctx_ptr->handled = true;
                pthread_setspecific(gCtxKey, nullptr);
                return 1;
            }
            std::string chunk = compileLhtml(src, ctx_ptr->scriptPath);
            // Use "@filename" as chunk name so Lua error messages show the source path
            std::string chunkName = "@" + ctx_ptr->scriptPath;
            rc = luaL_loadbuffer(L, chunk.c_str(), chunk.size(), chunkName.c_str());
        } else {
            // Plain .lua script — load directly from file
            rc = luaL_loadfile(L, ctx_ptr->scriptPath.c_str());
        }

        // Cache only a chunk that loaded cleanly, so a syntax error is retried
        // (and re-reported) on the next request rather than being memoised.
        if(rc == LUA_OK && haveStat)
            storeChunk(L, ctx_ptr->scriptPath, st);
    }

    if(rc != LUA_OK) {
        const char* err = lua_tostring(L, -1);
        fprintf(stderr, "[LUA] Load error %s: %s\n",
                ctx_ptr->scriptPath.c_str(), err ? err : "?");
        ctx_ptr->resp->statusCode = 500;
        ctx_ptr->resp->body  = "<h1>500 — Lua Load Error</h1><pre>";
        ctx_ptr->resp->body += (err ? err : "unknown error");
        ctx_ptr->resp->body += "</pre>";
        ctx_ptr->resp->headers.set("content-length",
                                   std::to_string(ctx_ptr->resp->body.size()));
        lua_pop(L, 1);
        ctx_ptr->handled = true;
        pthread_setspecific(gCtxKey, nullptr);
        return 1;
    }

    rc = lua_pcall(L, 0, 0, 0);
    if(rc != LUA_OK) {
        const char* err = lua_tostring(L, -1);
        fprintf(stderr, "[LUA] Runtime error %s: %s\n",
                ctx_ptr->scriptPath.c_str(), err ? err : "?");
        ctx_ptr->resp->statusCode = 500;
        ctx_ptr->resp->body  = "<h1>500 — Lua Runtime Error</h1><pre>";
        ctx_ptr->resp->body += (err ? err : "unknown error");
        ctx_ptr->resp->body += "</pre>";
        ctx_ptr->resp->headers.set("content-length",
                                   std::to_string(ctx_ptr->resp->body.size()));
        lua_pop(L, 1);
        ctx_ptr->handled = true;
        pthread_setspecific(gCtxKey, nullptr);
        return 1;
    }

    // Commit output produced by httpd.write()
    if(!lrc.output.empty()) {
        ctx_ptr->resp->body = std::move(lrc.output);
        ctx_ptr->resp->headers.set("content-length",
                                   std::to_string(ctx_ptr->resp->body.size()));
    }
    ctx_ptr->handled = true;
    pthread_setspecific(gCtxKey, nullptr);
    return 1;
}
