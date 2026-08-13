# README.md

## What this is

`httpd` — a from-scratch C++17 HTTP application server: HTTP/1.1 (RFC 9112), HTTP/2 + HPACK (RFC 9113/7541), TLS 1.2/1.3 with ALPN, an RFC 9111 response cache, fork-based CGI/1.1, and a Lua 5.4 scripting module loaded as a `dlopen`'d `.so`. No external framework dependencies — only OpenSSL, zlib, pthreads, and Lua.

Dual-licensed: `GPL-3.0-only OR LicenseRef-Httpd-Commercial`. Every source file carries the copyright + SPDX header — keep it on new files.

## Build & run

```bash
cmake -S . -B build                  # add -DCMAKE_BUILD_TYPE=Debug for -g3
cmake --build build -j
./build/httpd -r ./www -p 8080       # serves ./www on :8080
./build/httpd -h                     # full flag list
```

- Release (the CMake default when `CMAKE_BUILD_TYPE` is unset in a *fresh* tree) adds `-O3 -march=native -flto` — binaries are not portable off the build machine. Note the existing `build/` was configured with an empty build type, so it currently compiles without those flags.
- `-w <n>` workers (default: CPU count), `-t <n>` I/O threads per worker (default 4), `-c/-k` cert+key to enable HTTPS on `-s <port>`, `-m <path.so>` to load a module explicitly.
- With no `-m`, `main.cpp` auto-loads `<bindir>/modules/lua_module.so` (build tree) or `<bindir>/../lib/httpd/modules/lua_module.so` (installed).
- HTTP/2 is reachable **only** via TLS ALPN (`-c`/`-k` required). There is no `h2c` upgrade path in the plaintext read loop.
- To exercise TLS/H2 locally: `openssl req -x509 -newkey rsa:2048 -keyout k.pem -out c.pem -days 2 -nodes -subj /CN=localhost`, then `./build/httpd -r ./www -p 8080 -s 8443 -c c.pem -k k.pem` and `curl -k --http2 https://127.0.0.1:8443/`.

There is no test suite, lint config, or formatter in the repo — `tests/`, `conf/`, and `examples/` are empty directories. Verification is manual (`curl`, `curl --http2`, browsing `www/`). Don't invent a test command; if a change needs coverage, say so.

## Architecture

### Process / thread model
`Server::run` (src/EventLoop.cpp) pre-forks `workers` processes over `SO_REUSEPORT` listen sockets, and the parent reaps + respawns dead children. Each worker (`Server::workerMain`) creates `threadsPerWorker` `EventLoop` objects, each on its own thread with its own epoll fd; the worker's main thread runs a separate accept loop and hands accepted fds round-robin to the loops via `EventLoop::addConn`, which posts a task rather than touching another thread's epoll set. Each `EventLoop` additionally owns a small pthread pool (`postTask`/`threadFn`) used to keep blocking work (HTTP/2 request dispatch) off the epoll thread; `wakefd_` is an eventfd used to wake the loop after a pool thread queues output.

Consequence: **any state in a module is per-worker-process, not global.** The Lua session store is an in-process `unordered_map`, so with the default worker count a logged-in user bounces between workers and appears logged out. Run session-based apps with `-w 1`.

### KTLS (kernel TLS offload)
`sendfile()` never enters user space, so it cannot feed OpenSSL's own record layer — which is why TLS originally had to buffer. KTLS moves record encryption into the kernel, making `SSL_sendfile()` possible, so a TLS body can stream too.

`TlsContext::init` requests it with `SSL_OP_ENABLE_KTLS` (gated on `TlsConfig::enableKtls`, default on). **Requesting it is unconditionally safe**: without the kernel `tls` module, an AEAD cipher, or a KTLS-enabled OpenSSL build, OpenSSL silently keeps encrypting in user space. Every streaming decision therefore goes through `Server::dispatchRequest`'s `transportCanStream`, which is `!h2 && (!isTls || tls.ktlsSend())` — one predicate shared by the single-range, whole-file, and multipart paths. `TlsConn::ktlsSend()` queries `BIO_get_ktls_send()` on the write BIO and is only meaningful after the handshake, since KTLS is derived from the negotiated keys.

Each worker logs its KTLS status once on the first completed handshake. Silently buffering is otherwise invisible, and "why is HTTPS slower" is a miserable thing to debug from throughput alone.

Two traps:

- **`SSL_sendfile()` does not advance the offset**, unlike `::sendfile()` which updates it through a pointer. The segment loop in `onWritable` adds `seg.off += n` on the TLS branch only. Getting this wrong re-sends the same block forever.
- **`SSL_OP_ENABLE_KTLS_TX_ZEROCOPY_SENDFILE` is deliberately not enabled.** It lets the crypto read page cache in place, so a file modified while being sent yields corrupt ciphertext. This server treats live edits as normal — the whole caching layer is built around mtime invalidation — so that trade is wrong here. Enable it only for immutable content.

KTLS needs the kernel module loaded (`sudo modprobe tls`). It is **not** auto-loaded for unprivileged processes: `setsockopt(TCP_ULP, "tls")` fails with `ENOENT` instead. Check with `grep -w tls /proc/modules`. On a host without it the server logs `KTLS tx unavailable` and buffers TLS bodies exactly as before.

It **fails closed**, which is the property that matters if `ktlsSend()` ever returns a false positive: forcing the gate open on a host without KTLS makes `SSL_sendfile()` error, `onWritable` drop the connection after the headers, and the client see a truncated response. Verified by inspecting the decrypted stream for a plaintext marker — zero body bytes, zero leakage. Preserve that ordering if you refactor: the error branch must `closeConn()`, never fall through to a plaintext write.

### TLS handshake state machine
`EventLoop::onReadable`'s `TlsHandshake` branch must handle **all** of `doHandshake()`'s return values. It previously had cases only for `Ok` and `WantWrite`, so `WantRead` — the normal outcome when the handshake needs more bytes from the peer — hit `default: closeConn()`. That killed every TLS connection mid-handshake, which meant HTTPS *and* HTTP/2 (TLS-ALPN-only here) were entirely non-functional despite the CMake summary advertising both. `WantRead` now re-arms `EPOLLIN | EPOLLET`; that is safe under edge-triggering because `SSL_ERROR_WANT_READ` implies the socket read already returned `EAGAIN`, so incoming data raises a fresh edge. If you add TLS states, enumerate the cases explicitly rather than relying on `default`.

### Request path
`EventLoop::onReadable` → `Http1Parser::feed` (incremental, `RequestLine → Headers → Body/Chunked → Complete`) → `EventLoop::dispatch11`, which does the RFC 9111 cache lookup / invalidation and then calls the `RequestHandler` closure. That handler is `Server::dispatchRequest`, which is where routing actually lives, in this order:

1. `resolveStaticTarget` — `canonicalisePath` (docroot confinement → 403) then `stat` (→ 404), then the `indexFiles` probe for directories (`index.lhtml index.html index.htm index.lua`, dynamic first as with Apache's `DirectoryIndex index.php ...`). **`EventLoop::cachedEntryStale` calls this same helper**, so keep them sharing it: if the two ever disagree about which file a URL maps to, cache revalidation silently stops working for the paths they disagree on.
2. if still a directory: 301 to add a missing trailing slash, else 403 (no directory listing)
3. **module by file extension** (`ModuleRegistry::findByExt`) — returns if `handle_fn > 0` or `ctx.handled`
4. **CGI** if the resolved path is under `docRoot + cgi.cgiDir` and is user-executable
5. conditional-request check (`If-None-Match`, then `If-Modified-Since`) → 304
6. `Range` (single range; `If-Range`-gated) → 206 or 416
7. static file: **streamed** via `sendfile()` when eligible, else `pread()` slice for a partial, else body from `FileCache`; ETag from `fileETag()`, Last-Modified, `accept-ranges`, default `cache-control: public, max-age=3600`

`EventLoop::serveFile`/`serveDir`/`handleNotFound` are a parallel, more feature-complete static-file implementation (range requests, autoindex) that nothing currently reaches — `dispatch11` calls `handler_`, never `serveFile`. If you fix static-serving behaviour, check which of the two paths you're editing; the live one is `Server::dispatchRequest`.

HTTP/2 requests bypass `dispatch11`: `H2Session::setRequestCb` → `EventLoop::dispatchH2` posts to the thread pool, calls the same handler, then `H2Session::sendResponse` and wakes the loop. So the `HttpCache` *lookup* is HTTP/1.1-only; the *store* happens on both paths. H2 therefore always runs the handler — which is why the static body cache matters more there than on HTTP/1.1.

### Two caches, two different jobs
Do not conflate these; they sit at different layers and a change to one does not cover the other.

- **`HttpCache`** (include/Cache.h) — RFC 9111 *response* cache keyed by effective URI, consulted in `dispatch11` before the handler runs. Holds status + headers + body.
- **`FileCache`** (include/FileCache.h) — *file body* cache keyed by filesystem path, consulted inside the static branch of `Server::dispatchRequest`. Holds bytes only.

An HTTP/1.1 GET of an unchanged static file is answered by `HttpCache` and never reaches `FileCache` at all. `FileCache` covers everything else: HTTP/2, first request per URL, `no-cache` requests, distinct query strings, and post-eviction refills. Files over 1 MiB now reach it only on the TLS/H2 fallback paths, since plaintext HTTP/1.1 streams them instead.

**`freshnessLifetime()` is why Lua responses were never cached even before the chunk cache existed**: it returns 0 without an explicit `max-age`/`Expires`/`Last-Modified`, and the Lua module sets none, so those entries are stored but never fresh. Static responses *do* get `max-age=3600` from the static branch, which is what made them cacheable — and stale.

Responses are buffered whole into `Connection::sendBuf` (or `h2SendBuf`) and drained by `onWritable` under `EPOLLOUT | EPOLLET` — **except** static files over `cfg_.streamThreshold` on plaintext HTTP/1.1, which stream with `sendfile()` (see below).

### Module ABI (include/Module.h)
A module is a `MODULE` library exporting six `extern "C"` symbols resolved by `dlsym`: `httpd_module_name`, `_version`, `_init(const char* config)`, `_fini`, `_extensions` (NULL-terminated string array of extensions it claims), `_handle(RequestCtx*)` returning `0` = not handled, `1` = handled, `<0` = error. `RequestCtx` hands over raw `RawRequest*`/`RawResponse*` plus `docRoot`/`scriptPath`/`pathInfo`.

The ABI crosses a `dlopen` boundary while passing C++ objects, so **core and modules must be compiled by the same toolchain and stay in lockstep** — changing `RawRequest`, `RawResponse`, `Headers`, or `RequestCtx` layout silently breaks any pre-built `.so`.

Critical CMake detail (already commented in CMakeLists.txt): `httpd_core` and `httpd` build with `-fvisibility=hidden`, module targets must override to `-fvisibility=default` or `dlsym` finds nothing.

### Lua module (modules/lua/lua_module.cpp)
Claims extensions `lua`, `luax`, `lhtml`. One `lua_State` per I/O thread, cached in a `pthread_t → lua_State*` map; the per-request context is passed to C functions through a pthread TSD key (`gCtxKey`), so the bound `httpd.*` functions read the current request from thread-local state — never cache a `RequestCtx*` across requests.

**Compiled-chunk cache.** Loaded chunks are cached (the PHP opcache equivalent), so a hit skips file read, LHTML compilation, and Lua parsing, leaving one `stat()` as the only per-request filesystem work. A loaded chunk is a closure owned by one `lua_State` and must never cross states, so the cache is per-state — the functions live in that state's registry field `httpd.chunks` (which also keeps them GC-reachable) and the validation stamps in a `thread_local` map, whose lifetime matches because `getState()` pins one state per thread. Consequences worth knowing before changing this code:

- Invalidation compares `dev`/`ino`/`size`/`mtim.tv_sec`/`mtim.tv_nsec`, so same-second edits and same-size replacements both invalidate. Editing under `www/` still takes effect on the next request — there is no dev/prod mode to toggle.
- Only chunks that load cleanly are cached, so a syntax error is re-reported each request instead of being memoised.
- Reusing a closure is safe because a main chunk's only upvalue is `_ENV` (the same globals table either way) and its top-level `local`s are function locals re-initialised per call. Globals still persist across requests — they always did, since the state does.
- The cache is capped at 512 entries per state and flushed wholesale on overflow (logged). Real growth is bounded by script files on disk, since a path must resolve to a regular file under docRoot to reach the module.
- The module re-`stat()`s the script even though `Server::dispatchRequest` just did. Passing that result through would mean adding a field to `RequestCtx`, i.e. an ABI break; one extra `stat()` is the cheaper trade.

Measured on a 41 KB / 300-row template (`-w 1 -t 4`, `ab -n 3000 -c 8`): 558 → ~3900-4400 req/s. That ~7× is real because the cache removes *CPU* work (LHTML compile + Lua parse), not just I/O.

Global `httpd` table: `write, header, status, method, path, query, get_param, get_header, get_cookie, set_cookie, body, redirect, escape_html, urlencode, json_encode, session_create, session_get, session_destroy, parse_form`. `session_create(username)` enforces one session per user by evicting the user's previous sid. Output accumulates in `LuaReqCtx::output` and is committed to `resp.body` after `lua_pcall`; Lua load/runtime errors become a 500 with the error text in the body.

`.lhtml` files are compiled to a Lua chunk by `compileLhtml` before loading: `<% code %>`, `<%= escaped %>`, `<%! raw %>`, `<%-- comment --%>`. Literal text is emitted as `httpd.write([=*[ ... ]=*])` with the bracket level chosen to avoid collisions and a synthetic leading newline to defeat Lua's first-newline stripping — preserve both tricks if you touch it.

`.lhtml` is the intended way to write pages: static-by-default markup with inline dynamic blocks, PHP-style. `www/example.lhtml` is the reference page (logic block up top, markup below). `www/app/{index,login,logout}.lua` is the reference *app* (cookie `HTTPSID` + session store) and writes markup from Lua via `httpd.write` — the older, more verbose style. `www/hello.lua`, `www/counter.lua` are smaller samples.

A `.html` file is served as static bytes and is **never** scanned for `<% %>` — the extension alone decides whether a file is executed. Keep it that way: scanning every static response for template tags would put a substring search on the static path and make any literal `<%` in hand-written HTML a latent execution bug.

### Static file cache + filesystem revalidation (include/FileCache.h)
`FileCache` holds file bodies as `shared_ptr<const std::string>`, validated per call against a caller-supplied `stat()` using `FileStamp` (dev/ino/size + **nanosecond** mtime). No TTL, so an edited file is picked up on the next request. Per-file ceiling 1 MiB (larger files are served but not retained, so one big download cannot evict the working set), 64 MiB total, 4096 entries, LRU eviction by sorting on overflow rather than maintaining a list on every hit.

Locking is the load-bearing detail: hits take a **shared** lock and record recency via an atomic counter, and cold reads happen entirely outside the lock. An earlier version used a plain `std::mutex` and measured *slower than reading from the page cache* (1274 vs 1429 req/s on a 900 KB file) — with four I/O threads, exclusive locking cost more than the `read()` it was avoiding. If you touch this, re-measure rather than assuming a cache is a win.

`EventLoop::cachedEntryStale` closes the hole this exposed. A static response stored with `max-age=3600` was served for an hour after the file changed, because RFC 9111 freshness has no idea the origin is local disk. On a fresh `HttpCache` hit the entry is now revalidated by recomputing `fileETag()` from a `stat()` and comparing it with the stored ETag — one `stat()`, no body re-read. Consequences:

- **`fileETag()` and the static branch's ETag must stay identical.** Revalidation compares a recomputed value against the stored one; any divergence makes every hit look stale (silent perf loss) or never stale (silent staleness).
- The ETag includes `mtim.tv_nsec`, so a same-second edit changes it. With second granularity a client's `If-None-Match` could get a bogus 304 for changed content.
- Entries with no ETag are left alone, so dynamic responses are unaffected.

Honest measurement (`-w 1 -t 4`, warm local filesystem): the body cache is roughly **performance-neutral** — small files ~7400 vs ~8000 req/s reading from disk (inside run-to-run variance), 900 KB files ~1507 vs 1429. The OS page cache already eliminates the I/O, and `RawResponse::body` is an owned `std::string`, so the response copy happens either way. It pays off on cold cache, network filesystems, and slow disks, and on the H2 path. The correctness fix, not the throughput, is the reason this code exists.

### sendfile() streaming for large files
Static files over `ServerConfig::streamThreshold` (1 MiB, matching `FileCache::Config::maxFileBytes` so the two policies meet exactly) are sent with `sendfile()` straight from page cache to socket. `Connection` carries `fileFd` plus a `deque<OutSeg>` of pending body pieces — each either literal bytes or a file region — and `Connection::streaming()` reports whether any remain. The handler opens the fd, queues segments, and leaves `resp.body` empty with a manually-set `content-length` (`serialise()` appends only `body` and never recomputes the header, which is what makes this work). A whole file or single range is one file segment; multipart interleaves literals and file regions through the same loop.

**Eligibility is narrow, and each exclusion is load-bearing.** `sendfile()` never enters user space, so it cannot feed the TLS record layer or HTTP/2's DATA framing — TLS and H2 fall back to buffering. HEAD skips the body entirely rather than reading a multi-GB file for `serialise(headOnly)` to discard. If `open()` fails, control falls through to the buffered path.

Three traps if you modify this:

- **Never let a bodyless response into `HttpCache`.** `dispatch11` guards on the invariant "empty body + non-zero content-length ⇒ do not store". Without it, a streamed or HEAD response would be cached as headers promising N bytes with nothing behind them, and a later hit would hang the client until timeout. The guard is written as an invariant, not a flag, so future no-body paths are covered.
- **Streaming connections are armed level-triggered** (`EPOLLOUT` without `EPOLLET`) while every other path uses edge-triggered. Edge-triggered would force draining to `EAGAIN` in one `onWritable` call, letting a single large file monopolise the thread; LT lets the loop return after a 4 MiB-per-event budget and be re-notified. Verified: small requests still complete in ~10 ms while a 300 MB stream runs on the *same single-threaded* loop.
- **Refresh `deadlineMs` as bytes move.** `sweepTimeouts` closes anything past its deadline and `buildAndSendResp` sets it 30 s out, so a transfer slower than 30 s would be killed mid-flight. The loop re-stamps it on every successful `sendfile()` and on `EAGAIN`.

`Connection::~Connection()` and `reset()` both call `closeFile()`, so the fd is released however the connection ends — verified by killing a client mid-transfer and watching `/proc/<pid>/fd` return to baseline.

Measured on a 300 MB file (`-w 1 -t 4`): **peak RSS 931 MB → 9.6 MB, wall 1.83 s → 0.39 s.** The buffered path held three live copies (FileCache read → `resp.body` → `sendBuf`), which is why peak was ~3× the file size. Four concurrent 300 MB streams (1.2 GB in flight) peaked at 10 MB. Streamed throughput ~259 req/s × 5 MB ≈ 1.3 GB/s.

Because streamed responses skip `HttpCache`, the static branch does its own conditional-request handling; otherwise a conditional GET for a large file would re-send it in full every time.

### Range requests (RFC 9110 §14)
Handled in the static branch of `Server::dispatchRequest`, reusing the sendfile plumbing via `Connection::outSegs`. A whole file or a single range is one file segment; `multipart/byteranges` alternates literal framing segments with file segments.

The streaming decision is sized on the *range*, not the file, so a 4 KB slice of a 1 GB file is buffered rather than streamed. Buffered ranges use `pread()` for just the slice instead of `FileCache`, which would otherwise buffer an entire file to return a fragment of it — the pathological case being a small range of a large file on the TLS/H2 fallback path.

**Two failure modes with different answers**, which is why `rangeSyntaxValid()` exists alongside `parseRange()`:

- *Unparseable* header (`bytes=abc`, `bytes=`, `bytes=1-2-3`) or another range unit (`items=0-5`) → **ignore Range, serve 200** with the whole representation.
- *Well-formed but unsatisfiable* (`bytes=500-` on a 500-byte file, `bytes=-0`) → **416** with `Content-Range: bytes */<total>`.

Collapsing these two into one "no ranges parsed" check yields 416 for junk headers, which breaks clients that send them.

`parseRange` clamps rather than rejects, per spec: `bytes=0-9999` on a 500-byte file is 206 `0-499`, and `bytes=-9999` is the whole file. The old implementation rejected both (they became 416) and called `strtoll(sv.data(), …)` on a non-null-terminated `string_view`, which only worked by accident of the underlying `std::string`'s terminator.

`If-Range` is honoured: a validator that no longer matches means the client holds a different version, so splicing our bytes into its copy would corrupt the file — the full representation is sent instead. Range is ignored for HEAD (the response reports the full `content-length`).

### multipart/byteranges (RFC 9110 §14.6)
More than one range produces a multipart body. The framing convention matters: **the CRLF that must precede a boundary delimiter is carried at the front of the *next* part's header**, not appended after the previous part's data. That keeps every part a single literal + a single file region, so `content-length` is exactly computable without touching the file — which is what allows a multipart response to stream at all. Wire shape:

```
--<boundary>CRLF Content-Type:…CRLF Content-Range: bytes a-b/totalCRLF CRLF <data>
CRLF--<boundary>CRLF …next part…
CRLF--<boundary>--CRLF
```

Boundaries are 128 random bits from `/dev/urandom`. Scanning the payload for a colliding boundary would mean reading the file, defeating the point.

**Two bounds are security-relevant, not just tidiness:**

- `kMaxRangeParts` (16) — unbounded multi-range is the 2011 "Apache killer" amplification DoS (CVE-2011-3192): thousands of one-byte ranges cost ~120 bytes of framing each. Over the cap, Range is ignored and the whole representation is served, which RFC 9110 §14.2 explicitly permits.
- `coalesceRanges()` — sorts and merges ranges that overlap or sit within `kRangeGapMerge` (80 bytes, about one part's framing). Beyond shrinking responses this **guarantees the parts are disjoint, so the body can never exceed the file size** regardless of what the client asks. Verified: 2000 one-byte ranges collapse to a single 2000-byte response. Because it sorts, parts may not follow the requested order — RFC 9110 makes that order a SHOULD and coalescing inherently reorders.

Transport rules match the single-range path: plaintext HTTP/1.1 over `streamThreshold` uses segments, TLS/H2 buffers the whole multipart (`pread` per slice rather than pulling the entire file through `FileCache`). Measured: a 160 MB two-part multipart streamed with **0 kB peak RSS delta**, byte-exact, no fd leak after aborting mid-transfer, and small requests still ~10 ms on the same single-threaded loop.

If you change `onWritable`'s segment loop, note that a `sendfile()` returning 0 (file truncated under us) now **closes the connection**. Continuing would break the `content-length` promise and desync a keep-alive connection, leaving the client waiting for bytes that will never arrive.

**206 must never enter `HttpCache`.** `isCacheable` rejects `206`/`Content-Range` *early*, before the status-code list — because the list has a fallback that re-admits any status carrying an explicit `max-age`, and static responses always set `max-age=3600`. Removing 206 from the list alone is **not** sufficient; that bug shipped a 206 into the cache which was then replayed to a full GET, truncating it to 10 bytes. Range requests also bypass the cache *lookup*, since entries are stored whole under a URI-only key and a hit would answer a range request with the full body — legal, but it breaks media seeking and resume.

### Core primitives (include/common.h)
Hand-rolled, deliberately allocation-light: `Result<T>`/`Res` with an `Err` enum instead of exceptions, fixed-capacity `Str<N>`, SPSC lock-free `RingBuf<CAP>`, intrusive `List`, `nowMs()` (monotonic) vs `nowWallMs()` (realtime), and the `kMax*` request limits. Match this style in core code — prefer these over STL containers on hot paths, and return `Err`/status codes rather than throwing. `HttpCommon.h` similarly keeps `Headers`, `Cookie`, `Url` (with `parseQuery`/`urlDecode`/`urlEncode`), MIME lookup, `httpDate`/`parseHttpDate`, `ETag`, and `parseRange` header-only.

`Headers` lookup is a linear scan with case-insensitive compare, and header names are stored lowercase when written by the response path — compare case-insensitively, never assume canonical casing.

## Gotchas

- `Result<T>` stores `T` in a raw aligned byte buffer and never runs `~T()`. It leaks for non-trivial `T`; use it with trivially destructible types or `Res`.
- `Server::init` loads modules *before* `run()` forks, so `httpd_module_init` runs once in the parent and each worker inherits a copy-on-write state — module init side effects are not per-worker.
- Signal handling installs `sigHandler` in the parent only; workers reset `SIGTERM` to default and are killed by `Server::stop`.
- `checkConditionals` treats a bare `if-modified-since` as `304` only when `if-none-match` is absent, and its ETag match is a substring search — fine for single ETags, wrong for `If-None-Match` lists.
- Buffered static bodies still cost ~3 live copies of the file (FileCache read → `resp.body` → `sendBuf`). Over 1 MiB this is avoided by `sendfile()` on plaintext HTTP/1.1, and on TLS too when KTLS is active. **Without KTLS, TLS pays the full multiplier** — a 300 MB HTTPS download is ~900 MB peak. **HTTP/2 always pays it**, since DATA framing needs the bytes in user space regardless of KTLS.
- `EventLoop::serveFile`/`serveDir` remain unreachable dead code and have *not* been updated for streaming, the FileCache, or `fileETag()` — they still build a second-precision ETag. Don't mine them for behaviour; they will mislead you.
- CGI runs `fork` + `exec` per request with a 30 s timeout and 16 MiB output cap (`CgiConfig`); `runAsUid/Gid` default to 0 meaning "current user", not root.
- The build currently emits `-Wunused-result` warnings from the two `fread` calls in `lua_module.cpp`; that's pre-existing, not something you introduced.
