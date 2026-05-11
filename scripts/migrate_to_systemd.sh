#!/bin/bash
# Migrate a SupportProxy host from the apache2 + cron deployment
# model to nginx (TLS termination + /dashboard proxy) + systemd
# (supportproxy.service + supportproxy-webadmin.service).
#
# Run as root on the target host.
#
# Required env vars:
#   SP_USER    — local user that owns ~/SupportProxy + ~/proxy
#                (e.g. "fire" on FireVPS, "support" on neon).
#   SP_DOMAIN  — public DNS name with an existing Let's Encrypt cert
#                in /etc/letsencrypt/live/$SP_DOMAIN/  (e.g.
#                "firevps.tridgell.net").
#
# Optional:
#   SP_PURGE_APACHE=1  — apt-get purge apache2 at the end.
#                        Default is to leave it stopped+disabled so a
#                        rollback is one `systemctl start apache2`
#                        away. Re-run with this flag once the new
#                        stack has bedded in for a day or two.
#
# What it does:
#   1. Sanity-check the user, home dir, source dir, data dir, cert dir.
#   2. Stop + disable apache2 (preserves binary + config for rollback).
#   3. Install nginx + python3-certbot-nginx.
#   4. Drop /etc/nginx/sites-available/$SP_DOMAIN (HTTPS via the
#      existing LE cert, /dashboard proxied to 127.0.0.1:8080).
#   5. Drop a minimal landing page at /var/www/$SP_DOMAIN/index.html
#      that links to /dashboard/.
#   6. nginx -t, enable + reload.
#   7. Migrate the certbot renewer to the nginx installer so future
#      `certbot renew` runs don't try to drive apache.
#   8. Patch webui.json: host=127.0.0.1, behind_proxy=true.
#   9. Install the two systemd units (with /home/support →
#      /home/$SP_USER substitution), reap any running supportproxy /
#      udpproxy / webadmin processes, then enable --now both units.
#   10. Print the verification curls.

set -e

: "${SP_USER:?set SP_USER, e.g. SP_USER=fire}"
: "${SP_DOMAIN:?set SP_DOMAIN, e.g. SP_DOMAIN=firevps.tridgell.net}"

HOMEDIR="$(getent passwd "$SP_USER" | cut -d: -f6)"
[ -n "$HOMEDIR" ] || { echo "no such user: $SP_USER" >&2; exit 1; }

SRC="$HOMEDIR/SupportProxy"
DATA="$HOMEDIR/proxy"
CERT="/etc/letsencrypt/live/$SP_DOMAIN"

[ -d "$SRC" ]  || { echo "missing source dir $SRC" >&2; exit 1; }
[ -d "$DATA" ] || { echo "missing data dir $DATA — keys.tdb must live there" >&2; exit 1; }
[ -d "$CERT" ] || { echo "missing LE cert dir $CERT" >&2; exit 1; }
[ -f "$SRC/systemd/supportproxy.service" ] \
    || { echo "missing $SRC/systemd/supportproxy.service — run scripts/update_server.sh first" >&2; exit 1; }
[ -f "$SRC/start_webadmin.sh" ] \
    || { echo "missing $SRC/start_webadmin.sh — run scripts/update_server.sh first" >&2; exit 1; }

SUDO=
[ "$(id -u)" = "0" ] || SUDO=sudo

echo "===== migrate $SP_DOMAIN (user=$SP_USER home=$HOMEDIR) ====="
echo

# ----- 1. Stop + disable apache2 -------------------------------------
echo "--- step 1/9: stop and disable apache2 (preserved on disk for rollback) ---"
if systemctl is-enabled apache2 >/dev/null 2>&1 \
        || systemctl is-active apache2 >/dev/null 2>&1; then
    $SUDO systemctl stop apache2 || true
    $SUDO systemctl disable apache2 || true
    echo "apache2 stopped + disabled (still installed, run with SP_PURGE_APACHE=1 to remove)"
else
    echo "apache2 not active; skipping"
fi

# ----- 2. Install nginx + certbot nginx plugin -----------------------
echo
echo "--- step 2/9: install nginx + python3-certbot-nginx ---"
DEBIAN_FRONTEND=noninteractive $SUDO apt-get update -qq
DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y -qq \
    nginx python3-certbot-nginx

# ----- 3. nginx vhost ------------------------------------------------
echo
echo "--- step 3/9: write /etc/nginx/sites-available/$SP_DOMAIN ---"
VHOST=/etc/nginx/sites-available/$SP_DOMAIN
if [ -f "$VHOST" ]; then
    $SUDO cp -p "$VHOST" "$VHOST.bak.$(date +%Y%m%d-%H%M%S)"
fi
$SUDO tee "$VHOST" >/dev/null <<NGINX
server {
    server_name $SP_DOMAIN;

    listen 443 ssl;
    http2 on;
    ssl_certificate     $CERT/fullchain.pem;
    ssl_certificate_key $CERT/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    access_log /var/log/nginx/$SP_DOMAIN.access.log;
    error_log  /var/log/nginx/$SP_DOMAIN.error.log;

    root /var/www/$SP_DOMAIN;
    index index.html;

    # SupportProxy web admin UI (proxied to gunicorn on loopback).
    # X-Forwarded-Prefix /dashboard lets Flask's url_for() regenerate
    # the prefix on outbound URLs; the trailing / on proxy_pass strips
    # /dashboard before forwarding.
    location = /dashboard {
        return 301 /dashboard/;
    }
    location ^~ /dashboard/ {
        proxy_pass http://127.0.0.1:8080/;
        proxy_http_version 1.1;
        proxy_set_header Host              \$host;
        proxy_set_header X-Real-IP         \$remote_addr;
        proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host  \$host;
        proxy_set_header X-Forwarded-Prefix /dashboard;
        add_header X-Content-Type-Options nosniff always;
        proxy_read_timeout 60s;
    }
}

server {
    if (\$host = $SP_DOMAIN) {
        return 301 https://\$host\$request_uri;
    }
    listen 80;
    server_name $SP_DOMAIN;
    return 404;
}
NGINX

$SUDO ln -sf "$VHOST" /etc/nginx/sites-enabled/$SP_DOMAIN
# Stock nginx default vhost wants :80 default_server and would fight ours.
$SUDO rm -f /etc/nginx/sites-enabled/default

# ----- 4. Landing page ------------------------------------------------
echo
echo "--- step 4/9: write landing page /var/www/$SP_DOMAIN/index.html ---"
$SUDO mkdir -p /var/www/$SP_DOMAIN
$SUDO tee /var/www/$SP_DOMAIN/index.html >/dev/null <<HTML
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>$SP_DOMAIN — SupportProxy</title>
<style>
body { font-family: system-ui, sans-serif; margin: 4em auto; max-width: 40em; padding: 0 1em; }
a { color: #06c; }
</style>
</head>
<body>
<h1>$SP_DOMAIN</h1>
<p>This host runs a <a href="https://github.com/ArduPilot/SupportProxy">SupportProxy</a> daemon.</p>
<p>Web admin: <a href="/dashboard/">/dashboard/</a></p>
</body>
</html>
HTML

# ----- 5. nginx validate + reload ------------------------------------
echo
echo "--- step 5/9: nginx -t + enable + reload ---"
$SUDO nginx -t
$SUDO systemctl enable --now nginx
$SUDO systemctl reload nginx

# ----- 6. Migrate certbot to nginx installer -------------------------
echo
echo "--- step 6/9: switch certbot renewer to nginx installer ---"
RENEW_CONF=/etc/letsencrypt/renewal/$SP_DOMAIN.conf
if [ -f "$RENEW_CONF" ]; then
    $SUDO cp -p "$RENEW_CONF" "$RENEW_CONF.bak.$(date +%Y%m%d-%H%M%S)"
    # The minimal change: tell certbot to use the nginx installer/auth
    # plugin instead of apache for the next renewal.
    $SUDO sed -i -E \
        -e 's/^(installer = ).*/\1nginx/' \
        -e 's/^(authenticator = ).*/\1nginx/' \
        "$RENEW_CONF"
    echo "certbot renewer now uses nginx; next renewal will not touch apache"
else
    echo "no $RENEW_CONF — cert may have been issued differently; check certbot manually"
fi

# ----- 7. webui.json -------------------------------------------------
echo
echo "--- step 7/9: update $DATA/webui.json (host=127.0.0.1 + behind_proxy) ---"
WUI=$DATA/webui.json
if [ -f "$WUI" ]; then
    $SUDO cp -p "$WUI" "$WUI.bak.$(date +%Y%m%d-%H%M%S)"
fi
$SUDO -u "$SP_USER" tee "$WUI" >/dev/null <<JSON
{
    "title": "SupportProxy ($SP_DOMAIN)",
    "mode": "standalone",
    "host": "127.0.0.1",
    "port": 8080,
    "behind_proxy": true
}
JSON

# ----- 8. systemd units ----------------------------------------------
echo
echo "--- step 8/9: install systemd units ---"
# The committed units have /home/support hardcoded. Substitute for
# this host's user. The sed also fixes User=/Group= when SP_USER !=
# support (the existing units already say User=support).
for u in supportproxy.service supportproxy-webadmin.service; do
    $SUDO sed \
        -e "s|/home/support|$HOMEDIR|g" \
        -e "s|^User=support|User=$SP_USER|" \
        -e "s|^Group=support|Group=$SP_USER|" \
        "$SRC/systemd/$u" \
        | $SUDO tee /etc/systemd/system/$u >/dev/null
done

# Reap any old supportproxy / udpproxy / webadmin processes (cron
# leftovers, manual nohup launches, the deploy from before this
# migration). systemd-managed processes will get respawned cleanly.
$SUDO pkill -f "$SRC/supportproxy" 2>/dev/null || true
$SUDO pkill -f "$SRC/udpproxy" 2>/dev/null || true
$SUDO pkill -f "$HOMEDIR/udpproxy" 2>/dev/null || true
$SUDO -u "$SP_USER" pkill -f 'webadmin\.wsgi:application' 2>/dev/null || true
sleep 1

$SUDO systemctl daemon-reload
$SUDO systemctl enable --now supportproxy.service supportproxy-webadmin.service

# ----- 9. Verify -----------------------------------------------------
echo
echo "--- step 9/9: verify ---"
sleep 2
$SUDO systemctl --no-pager --lines=0 status supportproxy supportproxy-webadmin || true
echo
echo "listening sockets (expect 127.0.0.1:8080 + the proxy's user/engineer ports):"
$SUDO ss -tlnp 2>/dev/null | grep -E 'supportproxy|gunicorn' || true
echo
echo "external curls:"
curl -sI https://$SP_DOMAIN/                 | head -3 || true
echo "---"
curl -sI https://$SP_DOMAIN/dashboard        | head -3 || true
echo "---"
curl -sI https://$SP_DOMAIN/dashboard/       | head -3 || true
echo "---"
curl -sI https://$SP_DOMAIN/dashboard/login  | head -3 || true

# ----- optional purge ------------------------------------------------
if [ "${SP_PURGE_APACHE:-}" = "1" ]; then
    echo
    echo "--- bonus: apt purge apache2 ---"
    DEBIAN_FRONTEND=noninteractive $SUDO apt-get purge -y -qq \
        apache2 apache2-bin apache2-data apache2-utils libapache2-mod-* \
        python3-certbot-apache 2>/dev/null || true
    $SUDO apt-get autoremove -y -qq
fi

echo
echo "===== done. ====="
echo "rollback: sudo systemctl stop supportproxy supportproxy-webadmin"
echo "          sudo systemctl disable supportproxy supportproxy-webadmin"
echo "          sudo systemctl start apache2 (if you didn't run with SP_PURGE_APACHE=1)"
