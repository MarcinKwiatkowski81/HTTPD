-- index.lua — Main page: greets the logged-in user
--             If not logged in, redirects to /login.lua

local sid      = httpd.get_cookie("HTTPSID")
local username = nil

if sid and sid ~= "" then
    username = httpd.session_get(sid)
end

if not username then
    httpd.redirect("/app/login.lua")
    return
end

-- Format server time
local now = os.date("!%Y-%m-%d %H:%M:%S UTC")

httpd.write(string.format([[<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Welcome, %s</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #0d1117; color: #c9d1d9;
      min-height: 100vh;
      display: flex; align-items: center; justify-content: center;
    }
    .card {
      background: #161b22; border: 1px solid #30363d;
      border-radius: 12px; padding: 2.5rem;
      width: 100%%; max-width: 480px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.4);
    }
    .avatar {
      width: 72px; height: 72px; border-radius: 50%%;
      background: linear-gradient(135deg,#388bfd,#8957e5);
      display: flex; align-items: center; justify-content: center;
      font-size: 2rem; margin: 0 auto 1.5rem;
    }
    h1 { text-align: center; font-size: 1.5rem; color: #e6edf3;
         margin-bottom: 0.5rem; }
    .sub { text-align: center; color: #8b949e; font-size: 0.9rem;
           margin-bottom: 2rem; }
    .info-box {
      background: #0d1117; border: 1px solid #30363d;
      border-radius: 8px; padding: 1rem 1.25rem;
      margin-bottom: 1.5rem; font-size: 0.875rem;
    }
    .info-box dl { display: grid; grid-template-columns: auto 1fr; gap: 0.4rem 1rem; }
    dt { color: #8b949e; }
    dd { color: #e6edf3; font-family: monospace; word-break: break-all; }
    .btn-group { display: flex; gap: 0.75rem; }
    .btn {
      flex: 1; padding: 0.65rem;
      border: none; border-radius: 6px;
      font-size: 0.9rem; font-weight: 600;
      cursor: pointer; text-align: center;
      text-decoration: none; display: block;
    }
    .btn-ghost {
      background: #21262d; color: #c9d1d9;
      border: 1px solid #30363d;
    }
    .btn-ghost:hover { background: #30363d; }
    .btn-danger { background: #b62324; color: #fff; }
    .btn-danger:hover { background: #d73a3a; }
    .notice {
      text-align: center; font-size: 0.8rem; color: #6e7681;
      margin-top: 1.25rem;
    }
  </style>
</head>
<body>
<div class="card">
  <div class="avatar">👤</div>
  <h1>Hello, %s!</h1>
  <p class="sub">You are successfully authenticated.</p>

  <div class="info-box">
    <dl>
      <dt>Username</dt>  <dd>%s</dd>
      <dt>Session ID</dt><dd>%s&hellip;</dd>
      <dt>Server time</dt><dd>%s</dd>
      <dt>Your request</dt><dd>%s %s</dd>
    </dl>
  </div>

  <div class="btn-group">
    <a class="btn btn-ghost" href="/app/login.lua">⟳ New login<br><small style="font-weight:400">(invalidates session)</small></a>
    <a class="btn btn-danger" href="/app/logout.lua">Sign out →</a>
  </div>
  <p class="notice">
    Sessions are server-side only.<br>
    Opening a new login for the same user invalidates this session.
  </p>
</div>
</body>
</html>
]],
    httpd.escape_html(username),   -- title
    httpd.escape_html(username),   -- h1
    httpd.escape_html(username),   -- dl username
    string.sub(sid, 1, 16),        -- truncated session id
    now,                            -- server time
    httpd.escape_html(httpd.method()),
    httpd.escape_html(httpd.path())
))
