-- dns/logout.lua
local sid = httpd.get_cookie("DNSSID")
if sid then httpd.session_destroy(sid) end
httpd.set_cookie("DNSSID", "", { path="/dns/", maxAge=0 })
httpd.redirect("/dns/login.lua")
