-- login.lua — Login page with session creation
-- Password rule: password = "p" + username

local method = httpd.method()
local err    = ""
local info   = ""

if method == "POST" then
    local form = httpd.parse_form(httpd.body())
    local username = form.username or ""
    local password = form.password or ""
    local expected = "p" .. username

    if username == "" then
        err = "Username is required."
    elseif password ~= expected then
        err = "Invalid username or password."
    else
        -- Create session — any previous session for this user is invalidated
        local sid = httpd.session_create(username)
        httpd.set_cookie("HTTPSID", sid, {
            httpOnly = true,
            path     = "/",
            maxAge   = 3600,   -- 1 hour
            sameSite = "Lax",
        })
        httpd.redirect("/app/")
        return
    end
end

-- Already logged in? Redirect home.
local existing_sid = httpd.get_cookie("HTTPSID")
if existing_sid and existing_sid ~= "" then
    local who = httpd.session_get(existing_sid)
    if who then
        httpd.redirect("/app/")
        return
    end
end

-- Render login form
httpd.write([[<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Sign In — httpd demo</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #0d1117; color: #c9d1d9;
      min-height: 100vh;
      display: flex; align-items: center; justify-content: center;
    }
    .card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 12px;
      padding: 2.5rem;
      width: 100%; max-width: 380px;
      box-shadow: 0 8px 32px rgba(0,0,0,0.4);
    }
    .logo { text-align: center; margin-bottom: 1.5rem; }
    .logo span { font-size: 2.5rem; }
    h1 { text-align: center; font-size: 1.25rem; color: #e6edf3;
         margin-bottom: 1.5rem; font-weight: 600; }
    .error {
      background: #3d1e1e; border: 1px solid #f85149;
      color: #f85149; border-radius: 6px;
      padding: 0.75rem 1rem; margin-bottom: 1.25rem;
      font-size: 0.875rem;
    }
    label { display: block; font-size: 0.875rem; color: #8b949e;
            margin-bottom: 0.35rem; font-weight: 500; }
    input[type=text], input[type=password] {
      width: 100%; padding: 0.65rem 0.875rem;
      background: #0d1117; border: 1px solid #30363d;
      color: #e6edf3; border-radius: 6px; font-size: 0.95rem;
      margin-bottom: 1rem; transition: border-color .15s;
      outline: none;
    }
    input:focus { border-color: #388bfd; box-shadow: 0 0 0 3px rgba(56,139,253,0.15); }
    .btn {
      width: 100%; padding: 0.7rem;
      background: #238636; color: #fff;
      border: none; border-radius: 6px;
      font-size: 1rem; font-weight: 600;
      cursor: pointer; transition: background .15s;
    }
    .btn:hover { background: #2ea043; }
    .hint {
      text-align: center; margin-top: 1.25rem;
      font-size: 0.8rem; color: #6e7681;
    }
    .hint code { color: #79c0ff; font-family: monospace; }
  </style>
</head>
<body>
<div class="card">
  <div class="logo"><span>🔐</span></div>
  <h1>Sign in</h1>
]])

if err ~= "" then
    httpd.write('  <div class="error">⚠ ' .. httpd.escape_html(err) .. '</div>\n')
end

httpd.write([[
  <form method="POST" action="/app/login.lua" autocomplete="off">
    <label for="u">Username</label>
    <input id="u" type="text" name="username" autofocus required
           placeholder="Your name">
    <label for="p">Password</label>
    <input id="p" type="password" name="password" required
           placeholder="p + username">
    <button class="btn" type="submit">Sign in →</button>
  </form>
  <p class="hint">
    Hint: password&nbsp;=&nbsp;<code>p</code>&nbsp;+&nbsp;your username<br>
    e.g. user <code>Alice</code> → password <code>pAlice</code>
  </p>
</div>
</body>
</html>
]])
