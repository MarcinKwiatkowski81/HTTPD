-- Cookie-based counter demo (RFC 6265)
local count = tonumber(httpd.get_cookie("visits")) or 0
count = count + 1

httpd.set_cookie("visits", tostring(count), {
    path     = "/",
    maxAge   = 3600,
    httpOnly = true,
    sameSite = "Lax"
})

httpd.header("content-type", "text/html; charset=utf-8")
httpd.write([[<!DOCTYPE html><html><head><meta charset="utf-8"><title>Counter</title>
<style>body{font-family:monospace;background:#0d1117;color:#c9d1d9;max-width:600px;margin:2em auto}
h1{color:#58a6ff}.n{font-size:3em;color:#3fb950}</style></head><body>
<h1>🍪 Cookie counter</h1>
<p>You have visited this page <span class="n">]] .. count .. [[</span> time(s).</p>
<p><a href="/counter.lua">Reload</a> | <a href="/">Home</a></p>
</body></html>]])
