-- Lua demo page
local t = os.date("!%Y-%m-%dT%H:%M:%SZ")

httpd.header("content-type", "text/html; charset=utf-8")
httpd.header("x-powered-by", "httpd-lua/1.0")

httpd.write([[<!DOCTYPE html><html><head>
<meta charset="utf-8"><title>Lua Demo</title>
<style>body{font-family:monospace;background:#0d1117;color:#c9d1d9;max-width:700px;margin:2em auto}
h1{color:#58a6ff}.box{background:#161b22;padding:1em;border-radius:6px}</style>
</head><body>
<h1>🌙 Lua scripting demo</h1>
<div class="box">
]])

httpd.write("<p><b>Server time (UTC):</b> " .. t .. "</p>\n")
httpd.write("<p><b>Method:</b> "  .. httpd.method() .. "</p>\n")
httpd.write("<p><b>Path:</b> "    .. httpd.escape_html(httpd.path()) .. "</p>\n")
httpd.write("<p><b>Query:</b> "   .. httpd.escape_html(httpd.query()) .. "</p>\n")
httpd.write("<p><b>UA:</b> "      .. httpd.escape_html(httpd.get_header("user-agent")) .. "</p>\n")

-- URL params
local name = httpd.get_param("name")
if name and name ~= "" then
    httpd.write("<p><b>Hello, " .. httpd.escape_html(name) .. "!</b></p>\n")
end

httpd.write([[</div>
<p>Try: <a href="/hello.lua?name=World">/hello.lua?name=World</a></p>
<p>Try: <a href="/counter.lua">Cookie counter</a></p>
</body></html>]])
