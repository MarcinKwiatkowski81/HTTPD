-- dns/delete_record.lua — usuwa rekord (wysyła polecenie do serwera DNS)
local ok_lib, lib = pcall(dofile, "/home/mkwiatkowski/Website/HTTPD/www/dns/lib.lua")
local sid      = httpd.get_cookie("DNSSID")
local username = sid and httpd.session_get(sid) or nil
if not username then httpd.redirect("/dns/login.lua"); return end

local uid  = httpd.get_param("uid")  or ""
local zone = httpd.get_param("zone") or ""

if uid == "" or zone == "" then
    httpd.redirect("/dns/records.lhtml?err=" ..
        httpd.urlencode("Brakuje parametrów uid lub zone."))
    return
end

local ok, err = lib.send_cmd({ op="delete", uid=uid, zone=zone })
if ok then
    httpd.redirect("/dns/records.lhtml?zone=" .. httpd.urlencode(zone) ..
                   "&ok=" .. httpd.urlencode("Rekord oznaczony do usunięcia."))
else
    httpd.redirect("/dns/records.lhtml?zone=" .. httpd.urlencode(zone) ..
                   "&err=" .. httpd.urlencode("Błąd: " .. (err or "?")))
end
