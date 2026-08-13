#!/usr/bin/env bash
# Copyright (C) 2025 Marcin Kwiatkowski
# SPDX-License-Identifier: GPL-3.0-only OR LicenseRef-Httpd-Commercial
#
# End-to-end HTTP tests: starts a real server against a scratch docroot and
# drives it with curl. Covers the behaviour that unit tests cannot reach —
# streaming, caching across requests, range framing on the wire, Lua execution.
#
# Usage: tests/integration.sh [path-to-httpd] [path-to-www]
#        (defaults to ./build/httpd and ./www; ctest passes both explicitly)

set -uo pipefail

HTTPD="${1:-./build/httpd}"
WWW_SRC="${2:-./www}"
PORT="${HTTPD_TEST_PORT:-18099}"
TLS_PORT="${HTTPD_TEST_TLS_PORT:-18443}"
BASE="http://127.0.0.1:${PORT}"

pass=0; fail=0; skipped=0
SRV_PID=""
TMP=""

cleanup() {
    [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
    [ -n "$SRV_PID" ] && wait "$SRV_PID" 2>/dev/null
    [ -n "$TMP" ] && rm -rf "$TMP"
}
trap cleanup EXIT

ok()   { pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  FAIL %s\n         expected: %s\n         actual:   %s\n' "$1" "$2" "$3"; }
skip() { skipped=$((skipped+1)); printf '  skip %s (%s)\n' "$1" "$2"; }

# eq <label> <expected> <actual>
eq() { [ "$2" = "$3" ] && ok "$1" || bad "$1" "$2" "$3"; }

# --- preflight -----------------------------------------------------------------
command -v curl >/dev/null || { echo "curl not found; cannot run integration tests" >&2; exit 2; }
[ -x "$HTTPD" ] || { echo "server binary not found or not executable: $HTTPD" >&2; exit 2; }

TMP="$(mktemp -d)"
DOC="$TMP/www"
mkdir -p "$DOC"
# Copy the sample docroot so tests can mutate files without touching the repo.
cp -r "$WWW_SRC/." "$DOC/" 2>/dev/null || true

# --- fixtures ------------------------------------------------------------------
printf 'hello static\n' > "$DOC/plain.txt"
mkdir -p "$DOC/emptydir"
# 500 deterministic bytes: byte i == i % 251, so any slice is checkable.
python3 -c "open('$DOC/ranges.bin','wb').write(bytes(i%251 for i in range(500)))" 2>/dev/null \
  || perl -e 'open(F,">","'"$DOC"'/ranges.bin"); print F chr($_%251) for 0..499'
# 3 MiB so it crosses the 1 MiB streaming threshold.
head -c 3145728 /dev/urandom > "$DOC/big.bin"
cat > "$DOC/tpl.lhtml" <<'EOF'
<% local who = httpd.get_param("who") or "world" %>
who=<%= who %>
<%-- a comment containing a tag <%= 1 %> and a bare close 50%> --%>
done
EOF

# Point the DB sample at scratch storage. Exported before the server starts so
# the Lua page inherits it, and kept out of the docroot so it is not downloadable.
export HTTPD_DB_PATH="$TMP/notes.db"

# --- start server --------------------------------------------------------------
"$HTTPD" -r "$DOC" -p "$PORT" -w 1 -t 2 > "$TMP/server.log" 2>&1 &
SRV_PID=$!

for _ in $(seq 1 50); do
    curl -s -o /dev/null "$BASE/plain.txt" && break
    kill -0 "$SRV_PID" 2>/dev/null || { echo "server exited early:"; cat "$TMP/server.log"; exit 2; }
    sleep 0.1
done
curl -s -o /dev/null "$BASE/plain.txt" || { echo "server never became ready:"; cat "$TMP/server.log"; exit 2; }

code()  { curl -s -o /dev/null -w '%{http_code}' "$@"; }
body()  { curl -s "$@"; }
hdr()   { curl -s -D - -o /dev/null "$@" | tr -d '\r'; }
size()  { curl -s -o /dev/null -w '%{size_download}' "$@"; }

echo "== static =="
eq "static file served"        "hello static" "$(body "$BASE/plain.txt")"
eq "missing file is 404"       "404" "$(code "$BASE/no-such-file")"
eq "directory index"           "200" "$(code "$BASE/")"
eq "index-less dir is 403"     "403" "$(code "$BASE/emptydir/")"
eq "no redirect loop on dir"   "0"   "$(curl -s -o /dev/null -w '%{num_redirects}' -L --max-redirs 3 "$BASE/emptydir/")"
eq "path traversal blocked"    "403" "$(code --path-as-is "$BASE/../../etc/passwd")"
eq "HEAD has no body"          "0"   "$(curl -s -o /dev/null -w '%{size_download}' -I "$BASE/plain.txt")"

echo "== conditional requests =="
ETAG="$(hdr "$BASE/ranges.bin" | awk '/^etag:/{print $2}')"
[ -n "$ETAG" ] && ok "etag present" || bad "etag present" "an etag" "(none)"
eq "If-None-Match -> 304"      "304" "$(code -H "If-None-Match: $ETAG" "$BASE/ranges.bin")"
eq "If-None-Match mismatch"    "200" "$(code -H 'If-None-Match: "stale"' "$BASE/ranges.bin")"
eq "If-Modified-Since future"  "304" "$(code -H 'If-Modified-Since: Wed, 01 Jan 2031 00:00:00 GMT' "$BASE/ranges.bin")"

echo "== range requests =="
eq "single range status"       "206" "$(code -H 'Range: bytes=100-199' "$BASE/ranges.bin")"
eq "single range length"       "100" "$(size -H 'Range: bytes=100-199' "$BASE/ranges.bin")"
eq "content-range header"      "content-range: bytes 100-199/500" \
   "$(hdr -H 'Range: bytes=100-199' "$BASE/ranges.bin" | grep -i '^content-range:')"
eq "suffix range"              "10"  "$(size -H 'Range: bytes=-10' "$BASE/ranges.bin")"
eq "open-ended range"          "10"  "$(size -H 'Range: bytes=490-' "$BASE/ranges.bin")"
eq "end past EOF is clamped"   "500" "$(size -H 'Range: bytes=0-9999' "$BASE/ranges.bin")"
eq "unsatisfiable is 416"      "416" "$(code -H 'Range: bytes=500-' "$BASE/ranges.bin")"
eq "416 carries content-range" "content-range: bytes */500" \
   "$(hdr -H 'Range: bytes=500-' "$BASE/ranges.bin" | grep -i '^content-range:')"
eq "malformed range ignored"   "200" "$(code -H 'Range: bytes=abc' "$BASE/ranges.bin")"
eq "other unit ignored"        "200" "$(code -H 'Range: items=0-5' "$BASE/ranges.bin")"
eq "If-Range stale -> full"    "500" "$(size -H 'If-Range: "stale"' -H 'Range: bytes=0-9' "$BASE/ranges.bin")"

# Range bytes must be the right bytes, not merely the right length.
curl -s -o "$TMP/slice" -H 'Range: bytes=100-199' "$BASE/ranges.bin"
python3 - "$DOC/ranges.bin" "$TMP/slice" <<'PY' && ok "range bytes exact" || bad "range bytes exact" "slice==file[100:200]" "mismatch"
import sys
disk = open(sys.argv[1],'rb').read()
got  = open(sys.argv[2],'rb').read()
sys.exit(0 if got == disk[100:200] else 1)
PY

echo "== multipart/byteranges =="
eq "multi-range is multipart" "1" \
   "$(hdr -H 'Range: bytes=0-9,200-209' "$BASE/ranges.bin" | grep -ic 'content-type: multipart/byteranges')"
curl -s -D "$TMP/mp.h" -o "$TMP/mp.b" -H 'Range: bytes=0-9,200-209,400-409' "$BASE/ranges.bin"
python3 - "$DOC/ranges.bin" "$TMP/mp.h" "$TMP/mp.b" <<'PY' && ok "multipart framing + bytes" || bad "multipart framing + bytes" "3 valid parts" "see above"
import re, sys
disk = open(sys.argv[1],'rb').read()
hdrs = open(sys.argv[2],'rb').read().decode('latin1')
body = open(sys.argv[3],'rb').read()
m = re.search(r'(?im)^content-type:\s*multipart/byteranges;\s*boundary=(\S+)\s*$', hdrs)
if not m: print("   no multipart content-type"); sys.exit(1)
b = m.group(1).strip().encode()
cl = re.search(r'(?im)^content-length:\s*(\d+)', hdrs)
if not cl or int(cl.group(1)) != len(body):
    print(f"   content-length {cl and cl.group(1)} != body {len(body)}"); sys.exit(1)
close = b"\r\n--" + b + b"--\r\n"
if not body.endswith(close): print("   missing close delimiter"); sys.exit(1)
inner = body[:-len(close)]
chunks = inner.split(b"\r\n--" + b + b"\r\n")
chunks[0] = chunks[0][len(b"--" + b + b"\r\n"):]
if len(chunks) != 3: print(f"   {len(chunks)} parts, want 3"); sys.exit(1)
for ch in chunks:
    he = ch.find(b"\r\n\r\n")
    if he < 0: print("   part without header terminator"); sys.exit(1)
    h, d = ch[:he].decode(), ch[he+4:]
    cr = re.search(r'Content-Range:\s*bytes (\d+)-(\d+)/(\d+)', h)
    if not cr: print("   part without Content-Range"); sys.exit(1)
    a, z, tot = int(cr.group(1)), int(cr.group(2)), int(cr.group(3))
    if tot != len(disk): print("   wrong total"); sys.exit(1)
    if d != disk[a:z+1]: print(f"   part {a}-{z} bytes wrong"); sys.exit(1)
sys.exit(0)
PY

# Adjacent and overlapping ranges coalesce into one, so the reply is a single
# 206 rather than multipart.
eq "adjacent ranges coalesce"    "0" \
   "$(hdr -H 'Range: bytes=0-9,10-19' "$BASE/ranges.bin" | grep -ic 'multipart/byteranges')"
eq "coalesced length"            "20" "$(size -H 'Range: bytes=0-9,10-19' "$BASE/ranges.bin")"
eq "overlapping ranges coalesce" "15" "$(size -H 'Range: bytes=0-9,5-14' "$BASE/ranges.bin")"

# Amplification guard: many separated ranges exceed the part cap and the Range
# header is ignored; a flood of tiny ranges coalesces instead of amplifying.
# Ranges must be spaced well beyond the coalescing window (80 bytes) or they
# merge and never reach the cap — hence the larger file and 10 kB spacing.
UNDER="bytes=$(python3 -c "print(','.join('%d-%d'%(i*10000,i*10000+1) for i in range(16)))")"
OVER="bytes=$(python3 -c "print(','.join('%d-%d'%(i*10000,i*10000+1) for i in range(20)))")"
eq "16 parts is still multipart" "1" \
   "$(hdr -H "Range: $UNDER" "$BASE/big.bin" | grep -ic 'multipart/byteranges')"
eq "over the part cap -> full 200"   "200"     "$(code -H "Range: $OVER" "$BASE/big.bin")"
eq "over the cap sends whole file"   "3145728" "$(size -H "Range: $OVER" "$BASE/big.bin")"
FLOOD="bytes=$(python3 -c "print(','.join('%d-%d'%(i,i) for i in range(400)))")"
FLOOD_LEN="$(size -H "Range: $FLOOD" "$BASE/ranges.bin")"
[ "$FLOOD_LEN" -le 500 ] && ok "tiny-range flood does not amplify" \
    || bad "tiny-range flood does not amplify" "<= 500 bytes" "$FLOOD_LEN"

echo "== large body streaming =="
curl -s -o "$TMP/big.out" "$BASE/big.bin"
cmp -s "$TMP/big.out" "$DOC/big.bin" && ok "3MiB streamed byte-identical" \
    || bad "3MiB streamed byte-identical" "identical" "differs"
eq "streamed range is exact-length" "1048576" "$(size -H 'Range: bytes=0-1048575' "$BASE/big.bin")"
# Peak RSS must not track file size: the body is never buffered.
RSS="$(awk '/VmHWM/{print $2}' /proc/$SRV_PID/status 2>/dev/null || echo 0)"
if [ "$RSS" -gt 0 ]; then
    [ "$RSS" -lt 262144 ] && ok "peak RSS stayed under 256MiB (${RSS}kB)" \
        || bad "peak RSS bounded" "< 262144 kB" "${RSS} kB"
else
    skip "peak RSS bounded" "no /proc access"
fi

echo "== keep-alive =="
eq "3 requests on one connection" "200,200,200," \
   "$(curl -s -o /dev/null -o /dev/null -o /dev/null -w '%{http_code},' \
      "$BASE/plain.txt" "$BASE/ranges.bin" "$BASE/plain.txt")"

echo "== caching and revalidation =="
printf 'v1\n' > "$DOC/mutable.html"
FIRST="$(body "$BASE/mutable.html")"
body "$BASE/mutable.html" > /dev/null          # populate the response cache
printf 'v2\n' > "$DOC/mutable.html"
eq "edited file is revalidated" "v2" "$(body "$BASE/mutable.html")"
eq "first read was v1"          "v1" "$FIRST"

echo "== lua / lhtml =="
eq "lhtml renders"              "200" "$(code "$BASE/tpl.lhtml")"
eq "absent param takes default" "1" "$(body "$BASE/tpl.lhtml" | grep -c '^who=world$')"
eq "param is used when given"   "1" "$(body "$BASE/tpl.lhtml?who=marcin" | grep -c '^who=marcin$')"
eq "param is html-escaped"      "1" "$(body "$BASE/tpl.lhtml?who=%3Cb%3E" | grep -c 'who=&lt;b&gt;')"
eq "comment text never leaks"   "0" "$(body "$BASE/tpl.lhtml" | grep -ci 'bare close\|a comment containing')"
eq "template edit picked up"    "changed" \
   "$(printf 'changed\n' > "$DOC/tpl2.lhtml"; body "$BASE/tpl2.lhtml" >/dev/null; \
      printf 'changed\n' > "$DOC/tpl2.lhtml"; body "$BASE/tpl2.lhtml" | tr -d '\n')"
if [ -f "$DOC/counter.lua" ]; then
    eq "counter.lua (nil cookie path)" "200" "$(code "$BASE/counter.lua")"
fi
if [ -f "$DOC/app/login.lua" ]; then
    JAR="$TMP/jar"
    eq "login redirects on success" "302" \
       "$(code -c "$JAR" -d 'username=u&password=pu' "$BASE/app/login.lua")"
    eq "session grants access"      "200" "$(code -b "$JAR" "$BASE/app/")"
    eq "bad password re-renders"    "200" "$(code -d 'username=u&password=wrong' "$BASE/app/login.lua")"
fi

echo "== database sample (LuaSQL via require) =="
if [ ! -f "$DOC/db/index.lhtml" ]; then
    skip "database sample" "no www/db/index.lhtml in docroot"
elif body "$BASE/db/" | grep -q 'LuaSQL driver unavailable'; then
    skip "database sample" "luasql driver not installed"
else
    eq "db page renders"          "200" "$(code "$BASE/db/")"
    eq "starts empty"             "1"   "$(body "$BASE/db/" | grep -c 'No notes yet')"
    eq "post redirects"           "302" "$(code -d 'author=Tester&body=hello+db' "$BASE/db/")"
    eq "row is listed"            "1"   "$(body "$BASE/db/" | grep -c 'hello db')"
    eq "author is listed"         "1"   "$(body "$BASE/db/" | grep -c 'by Tester')"
    eq "validation rejects blank" "1"   "$(body -d 'author=&body=' "$BASE/db/" | grep -c 'are required')"

    # The driver has no bound parameters, so escaping is the only defence. A
    # quote-carrying payload must be stored as text and must not execute.
    curl -s -o /dev/null -d "author=Robert'); DROP TABLE notes;--&body=payload" "$BASE/db/"
    eq "table survives injection"  "200" "$(code "$BASE/db/")"
    eq "payload stored literally"  "1"   "$(body "$BASE/db/" | grep -c 'payload')"
    eq "earlier row still present" "1"   "$(body "$BASE/db/" | grep -c 'hello db')"
    eq "quote escaped on output"   "1"   "$(body "$BASE/db/" | grep -c '&#39;')"
    # A .db file inside the docroot would be downloadable; this one is outside.
    eq "db file is not web-reachable" "404" "$(code "$BASE/notes.db")"
fi

echo "== cgi =="
if [ -x "$DOC/cgi-bin/hello.sh" ]; then
    eq "cgi executes" "200" "$(code "$BASE/cgi-bin/hello.sh")"
else
    skip "cgi executes" "no cgi-bin/hello.sh in docroot"
fi

echo "== tls / http2 =="
if command -v openssl >/dev/null; then
    openssl req -x509 -newkey rsa:2048 -keyout "$TMP/k.pem" -out "$TMP/c.pem" \
        -days 2 -nodes -subj /CN=localhost >/dev/null 2>&1
    "$HTTPD" -r "$DOC" -p "$((PORT+1))" -s "$TLS_PORT" \
             -c "$TMP/c.pem" -k "$TMP/k.pem" -w 1 -t 2 > "$TMP/tls.log" 2>&1 &
    TLS_PID=$!
    for _ in $(seq 1 50); do
        curl -sk -o /dev/null "https://127.0.0.1:${TLS_PORT}/plain.txt" && break
        sleep 0.1
    done
    TB="https://127.0.0.1:${TLS_PORT}"
    eq "tls handshake completes" "200" "$(curl -sk -o /dev/null -w '%{http_code}' --http1.1 "$TB/plain.txt")"
    eq "http2 over alpn"         "2"   "$(curl -sk -o /dev/null -w '%{http_version}' --http2 "$TB/plain.txt")"
    curl -sk -o "$TMP/tls.big" --http1.1 "$TB/big.bin"
    cmp -s "$TMP/tls.big" "$DOC/big.bin" && ok "tls large body intact" \
        || bad "tls large body intact" "identical" "differs"
    eq "tls range works" "100" "$(curl -sk -o /dev/null -w '%{size_download}' -H 'Range: bytes=0-99' "$TB/ranges.bin")"
    grep -q 'KTLS tx' "$TMP/tls.log" && ok "ktls status reported in log" \
        || bad "ktls status reported in log" "a KTLS line" "(none)"
    kill "$TLS_PID" 2>/dev/null; wait "$TLS_PID" 2>/dev/null
else
    skip "tls / http2" "openssl(1) not available"
fi

echo "== server health =="
kill -0 "$SRV_PID" 2>/dev/null && ok "server still running" \
    || bad "server still running" "alive" "exited"
CRASH="$(grep -ciE 'segmentation|sanitizer|assertion' "$TMP/server.log" || true)"
eq "no crashes in log" "0" "$CRASH"

printf '\n%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skipped"
[ "$fail" -eq 0 ] || { echo "--- server log ---"; tail -30 "$TMP/server.log"; }
exit $([ "$fail" -eq 0 ] && echo 0 || echo 1)
