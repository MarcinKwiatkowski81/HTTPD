-- dns/lib.lua — wspólne funkcje pomocnicze panelu DNS
-- Ładowane przez: local lib = dofile(httpd.path():match("^(.*/)") .. "lib.lua")

local M = {}

-- ── Ścieżka do pliku stanu serwera DNS ───────────────────────────────────────
-- Musi zgadzać się z `state_file` w config.yaml serwera DNS.
M.STATE_FILE = os.getenv("DNS_STATE") or "/tmp/dns_state.yaml"
M.STATE_LOCK = M.STATE_FILE .. ".lock"

-- ── Prymitywny parser YAML (wystarczający dla naszego formatu) ───────────────
-- Obsługuje tylko format generowany przez zone.py: listy słowników z wcięciami.
function M.parse_yaml(text)
    local zones = {}
    local cur_zone = nil
    local cur_rec  = nil

    for line in (text .. "\n"):gmatch("([^\n]*)\n") do
        -- Poziom wcięcia
        local indent = #line:match("^(%s*)") 

        -- Nowa strefa: "- zone: internal.lan."
        local zname = line:match("^%s*zone:%s*(.+)$")
        if zname then
            cur_zone = { name = zname:gsub('"',''), records = {} }
            cur_rec  = nil
            table.insert(zones, cur_zone)
        end

        -- Nowy rekord w strefie
        if cur_zone and line:match("^%s*-%s*uid:") then
            cur_rec = {}
            table.insert(cur_zone.records, cur_rec)
        end

        if cur_rec then
            -- uid / name / rtype / ttl / deleted / origin / seq / ts
            for k, v in line:gmatch("%s+(%w+):%s+(.+)$") do
                v = v:gsub("^'(.*)'$","%1"):gsub('^"(.*)"$',"%1")
                cur_rec[k] = v
            end
            -- rdata (podpole): "    value: 192.168.1.1"
            local rk, rv = line:match("^%s+(%w+):%s+(.+)$")
            if rk and cur_rec.rdata == nil and
               (rk == "value" or rk == "priority" or rk == "port" or
                rk == "mname" or rk == "rname"  or rk == "serial" or
                rk == "weight" or rk == "flags" or rk == "tag") then
                cur_rec.rdata = cur_rec.rdata or {}
                if type(cur_rec.rdata) == "string" then cur_rec.rdata = {} end
                cur_rec.rdata[rk] = rv:gsub("^'(.*)'$","%1"):gsub('^"(.*)"$',"%1")
            end
        end
    end
    return zones
end

-- ── Odczyt pliku stanu ────────────────────────────────────────────────────────
function M.load_zones()
    local f = io.open(M.STATE_FILE, "r")
    if not f then return {}, "Brak pliku stanu: " .. M.STATE_FILE end
    local txt = f:read("*a")
    f:close()
    local ok, zones = pcall(M.parse_yaml, txt)
    if not ok then return {}, "Błąd parsowania: " .. tostring(zones) end
    return zones, nil
end

-- ── Zapis pliku stanu (append polecenia przez plik .cmd) ─────────────────────
-- Panel wysyła polecenia przez plik kolejki; serwer DNS obserwuje i wykonuje.
-- Format: JSON, jeden obiekt na linię.
M.CMD_FILE = os.getenv("DNS_CMD") or "/tmp/dns_cmd.jsonl"

function M.send_cmd(obj)
    local f = io.open(M.CMD_FILE, "a")
    if not f then return false, "Nie można otworzyć pliku poleceń" end
    f:write(httpd.json_encode(obj) .. "\n")
    f:close()
    return true
end

-- ── Pomocnicze ───────────────────────────────────────────────────────────────
function M.flash(session_id, kind, msg)
    -- kind: "ok" | "err"
    local key = "flash_" .. kind
    -- używamy session store jako prostego flash-store
    httpd.session_create("__flash_" .. kind .. "__" .. msg)
end

function M.h(s)
    return httpd.escape_html(tostring(s or ""))
end

function M.rdata_str(rec)
    -- Zwraca czytelną wartość rdata dla kolumny "Wartość"
    if not rec.rdata or type(rec.rdata) ~= "table" then
        return tostring(rec.rdata or "")
    end
    local rd = rec.rdata
    local t  = rec.rtype or ""
    if t == "MX" then
        return (rd.priority or "?") .. " " .. (rd.value or "")
    elseif t == "SOA" then
        return (rd.mname or "?") .. " " .. (rd.rname or "?")
    elseif t == "SRV" then
        return string.format("%s %s %s %s",
            rd.priority or 0, rd.weight or 0,
            rd.port or 0, rd.value or "?")
    elseif t == "CAA" then
        return string.format("%s %s \"%s\"",
            rd.flags or 0, rd.tag or "?", rd.value or "")
    else
        return rd.value or rd.mname or ""
    end
end

return M
