-- logout.lua — Destroys the session and redirects to login

local sid = httpd.get_cookie("HTTPSID")

if sid and sid ~= "" then
    httpd.session_destroy(sid)
end

-- Expire the cookie immediately (maxAge=0)
httpd.set_cookie("HTTPSID", "", {
    httpOnly = true,
    path     = "/",
    maxAge   = 0,
    sameSite = "Lax",
})

-- Show a brief "signed out" page before redirecting
httpd.write([[<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="2;url=/app/login.lua">
  <title>Signed out</title>
  <style>
    body { font-family: 'Segoe UI', system-ui, sans-serif;
           background: #0d1117; color: #c9d1d9;
           display: flex; align-items: center; justify-content: center;
           min-height: 100vh; margin: 0; }
    .box { text-align: center; }
    .icon { font-size: 3rem; margin-bottom: 1rem; }
    h1   { color: #e6edf3; margin-bottom: 0.5rem; }
    p    { color: #8b949e; }
    a    { color: #79c0ff; }
  </style>
</head>
<body>
<div class="box">
  <div class="icon">👋</div>
  <h1>You have been signed out.</h1>
  <p>Redirecting to <a href="/app/login.lua">login</a> in 2 seconds&hellip;</p>
</div>
</body>
</html>
]])
