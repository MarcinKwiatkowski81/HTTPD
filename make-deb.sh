#!/usr/bin/env bash
# make-deb.sh — buduje paczkę .deb bez dpkg-dev / cmake cpack
# Wymaga: dpkg, fakeroot lub root
# Użycie: ./make-deb.sh [release_build_dir]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${1:-$SCRIPT_DIR/build}"
PKG_NAME="httpd"
PKG_VER="1.0.0"
PKG_REL="1"
ARCH="$(dpkg --print-architecture 2>/dev/null || echo amd64)"
DEB_NAME="${PKG_NAME}_${PKG_VER}-${PKG_REL}_${ARCH}.deb"

# ── Sprawdź binarki ───────────────────────────────────────────────────────────
HTTPD_BIN="$BUILD_DIR/httpd"
LUA_SO="$BUILD_DIR/modules/lua_module.so"
if [[ ! -f "$HTTPD_BIN" ]]; then
    echo "[ERROR] $HTTPD_BIN not found. Build first:" >&2
    echo "  cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j" >&2
    exit 1
fi

# ── Tymczasowy katalog staging ────────────────────────────────────────────────
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# Struktura katalogów
install -d "$STAGE/usr/bin"
install -d "$STAGE/usr/lib/httpd/modules"
install -d "$STAGE/etc/httpd"
install -d "$STAGE/var/www/httpd"
install -d "$STAGE/var/log/httpd"
install -d "$STAGE/lib/systemd/system"
install -d "$STAGE/usr/share/doc/$PKG_NAME"
install -d "$STAGE/usr/share/$PKG_NAME/www"
install -d "$STAGE/DEBIAN"

# Binaria
strip --strip-unneeded "$HTTPD_BIN" -o "$STAGE/usr/bin/httpd"
chmod 0755 "$STAGE/usr/bin/httpd"
if [[ -f "$LUA_SO" ]]; then
    strip --strip-unneeded "$LUA_SO" -o "$STAGE/usr/lib/httpd/modules/lua_module.so"
    chmod 0644 "$STAGE/usr/lib/httpd/modules/lua_module.so"
fi

# Konfiguracja (jako conffile — nie nadpisywana przy upgrade jeśli zmodyfikowana)
install -m 0644 "$SCRIPT_DIR/conf/httpd.yaml" "$STAGE/etc/httpd/httpd.yaml"

# Systemd unit
install -m 0644 "$SCRIPT_DIR/debian/httpd.service" \
    "$STAGE/lib/systemd/system/httpd.service"

# www (przykładowe pliki)
if [[ -d "$SCRIPT_DIR/www" ]]; then
    cp -r "$SCRIPT_DIR/www/." "$STAGE/usr/share/$PKG_NAME/www/"
fi

# Dokumentacja
install -m 0644 "$SCRIPT_DIR/README.md" \
    "$STAGE/usr/share/doc/$PKG_NAME/README.md"
gzip -9 -n --keep "$STAGE/usr/share/doc/$PKG_NAME/README.md" 2>/dev/null || true

# ── DEBIAN/control ────────────────────────────────────────────────────────────
# Uwaga: single-quoted heredoc ('CTRL') wyłącza ekspansję $zmiennych w opisie,
# więc dynamiczne pola (Package, Version, …) zapisujemy osobno przez printf.
{
    printf 'Package: %s\n'          "$PKG_NAME"
    printf 'Version: %s-%s\n'       "$PKG_VER" "$PKG_REL"
    printf 'Architecture: %s\n'     "$ARCH"
    printf 'Maintainer: %s\n'       "Marcin Kwiatkowski <marcin@example.com>"
    printf 'Section: %s\n'          "httpd"
    printf 'Priority: %s\n'         "optional"
    printf 'Depends: %s\n'          "libssl3 (>= 3.0) | libssl1.1, zlib1g (>= 1.2), liblua5.4-0"
    printf 'Recommends: %s\n'       "lua5.4, lua-socket, lua-sql-sqlite3"
    printf 'Suggests: %s\n'         "certbot"
    # Opis — single-quoted heredoc, brak ekspansji $, $1, $9 itp.
    cat <<'CTRL'
Description: httpd - C++17 HTTP/1.1+HTTP/2 application server
 From-scratch C++17 HTTP server implementing RFC 9112/9113/9111/9110.
 .
 Features:
  * HTTP/1.1 (RFC 9112) with chunked encoding, keep-alive, pipelining
  * HTTP/2 + HPACK (RFC 9113/7541) over TLS ALPN
  * TLS 1.2/1.3 with ALPN, kernel TLS offload (KTLS)
  * RFC 9111 response cache with file-system revalidation
  * sendfile() streaming for large files, multipart byte-ranges
  * CGI/1.1 (fork-based)
  * Lua 5.4 scripting (.lua / .lhtml templates)
  * Virtual hosts (name-based, wildcard, SNI per-vhost cert)
  * URL rewrite engine (ECMAScript regex, \$1-\$9 back-refs, flags)
  * Reverse proxy (HTTP upstream, X-Forwarded-For, hop-by-hop strip)
  * YAML configuration file
  * Pre-fork + epoll + thread-pool process model
CTRL
} > "$STAGE/DEBIAN/control"

# ── DEBIAN/conffiles ──────────────────────────────────────────────────────────
echo "/etc/httpd/httpd.yaml" > "$STAGE/DEBIAN/conffiles"

# ── DEBIAN/postinst ───────────────────────────────────────────────────────────
install -m 0755 "$SCRIPT_DIR/debian/postinst" "$STAGE/DEBIAN/postinst"
install -m 0755 "$SCRIPT_DIR/debian/prerm"    "$STAGE/DEBIAN/prerm"

# ── Uprawnienia ───────────────────────────────────────────────────────────────
find "$STAGE" -type d -exec chmod 0755 {} \;
chmod 0755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm"

# ── Buduj .deb ────────────────────────────────────────────────────────────────
OUT_DEB="$SCRIPT_DIR/$DEB_NAME"
if command -v fakeroot >/dev/null 2>&1; then
    fakeroot dpkg-deb --build "$STAGE" "$OUT_DEB"
else
    dpkg-deb --build "$STAGE" "$OUT_DEB"
fi

echo ""
echo "✓ Paczka DEB gotowa: $OUT_DEB"
echo ""
dpkg-deb --info "$OUT_DEB"
echo ""
echo "Instalacja: sudo dpkg -i $DEB_NAME"
echo "Usunięcie:  sudo dpkg -r $PKG_NAME"
