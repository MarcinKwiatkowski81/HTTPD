-- dns/login.lua — logowanie do panelu DNS
local method = httpd.method()
local err    = ""

-- Hasło pobierane ze zmiennej środowiskowej DNS_PANEL_PASS (domyślnie: admin)
local PASS = os.getenv("DNS_PANEL_PASS") or "admin"
local USER = os.getenv("DNS_PANEL_USER") or "admin"

if method == "POST" then
    local body   = httpd.body()
    local params = httpd.parse_form(body)
    local user   = params.username or ""
    local pass   = params.password or ""

    if user == USER and pass == PASS then
        local sid = httpd.session_create(user)
        httpd.set_cookie("DNSSID", sid, {
            path = "/dns/", maxAge = 28800,
            httpOnly = true, sameSite = "Lax"
        })
        httpd.redirect("/dns/")
        return
    else
        err = "Nieprawidłowy login lub hasło."
    end
end

httpd.header("content-type", "text/html; charset=utf-8")
httpd.write(string.format([[<!DOCTYPE html>
<html lang="pl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Panel DNS — logowanie</title>
  <style>
    :root { --bg:#0d1117; --surface:#161b22; --border:#30363d;
            --text:#c9d1d9; --muted:#8b949e; --accent:#388bfd;
            --red:#f85149; }
    *,*::before,*::after { box-sizing:border-box; margin:0; padding:0; }
    body { font:14px/1.6 'Segoe UI',system-ui,sans-serif;
           background:var(--bg); color:var(--text);
           min-height:100vh; display:flex;
           align-items:center; justify-content:center; }
    .card { background:var(--surface); border:1px solid var(--border);
            border-radius:12px; padding:2.5rem; width:100%%; max-width:380px;
            box-shadow:0 8px 32px rgba(0,0,0,.4); }
    .logo { text-align:center; font-size:2.5rem; margin-bottom:1rem; }
    h1 { text-align:center; font-size:1.25rem; margin-bottom:.25rem; }
    .sub { text-align:center; color:var(--muted); font-size:.8rem;
           margin-bottom:2rem; }
    label { display:block; font-size:.8rem; color:var(--muted);
            margin-bottom:.35rem; }
    input[type=text], input[type=password] {
      width:100%%; padding:.6rem .75rem;
      background:#0d1117; border:1px solid var(--border);
      border-radius:6px; color:var(--text); font-size:.9rem;
      margin-bottom:1rem; outline:none;
      transition:border-color .15s; }
    input:focus { border-color:var(--accent); }
    .btn { width:100%%; padding:.7rem; background:var(--accent);
           color:#fff; border:none; border-radius:6px;
           font-size:.9rem; font-weight:600; cursor:pointer;
           transition:background .15s; }
    .btn:hover { background:#1f6feb; }
    .err { background:rgba(248,81,73,.12); border:1px solid rgba(248,81,73,.3);
           color:var(--red); border-radius:6px; padding:.6rem .75rem;
           font-size:.8rem; margin-bottom:1rem; }
  </style>
</head>
<body>
<div class="card">
  <div class="logo">⬡</div>
  <h1>Panel DNS</h1>
  <p class="sub">SoftStudio · serwer DNS</p>
  %s
  <form method="POST" action="/dns/login.lua">
    <label for="u">Login</label>
    <input id="u" type="text" name="username" autocomplete="username" required>
    <label for="p">Hasło</label>
    <input id="p" type="password" name="password" autocomplete="current-password" required>
    <button class="btn" type="submit">Zaloguj →</button>
  </form>
</div>
</body></html>]],
    err ~= "" and '<div class="err">✗ ' .. httpd.escape_html(err) .. '</div>' or ""
))
