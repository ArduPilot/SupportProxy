#!/bin/bash
# script to start SupportProxy from cron
# assumes that keys.tdb is in $HOME/proxy
# assumes that SupportProxy build is in $HOME/SupportProxy
#
# If $HOME/proxy/webui.json exists with "mode":"standalone", we also
# (re)launch the web admin UI on the configured port.

# On hosts that use the systemd units (supportproxy.service /
# supportproxy-webadmin.service), systemd owns the lifecycle —
# Restart=always handles respawns. A copy launched here would race
# systemd for the listening ports ("Address already in use" spam from
# the loser). Bail out: a stray cron entry, or update_server.sh
# calling us, becomes a harmless no-op.
if systemctl is-enabled supportproxy.service >/dev/null 2>&1; then
    exit 0
fi

cd $HOME/proxy

(
    date
    pidof -q supportproxy || {
        nohup $HOME/SupportProxy/supportproxy >> proxy.log 2>&1 &
    }

    if [ -f webui.json ]; then
        webui_mode=$(python3 -c '
import json, sys
try:
    print(json.load(open("webui.json")).get("mode",""))
except Exception:
    pass' 2>/dev/null)
        if [ "$webui_mode" = "standalone" ]; then
            webui_port=$(python3 -c '
import json
print(json.load(open("webui.json")).get("port", 8080))' 2>/dev/null)
            webui_host=$(python3 -c '
import json
print(json.load(open("webui.json")).get("host", "127.0.0.1"))' 2>/dev/null)
            webui_behind_proxy=$(python3 -c '
import json
print("1" if json.load(open("webui.json")).get("behind_proxy") is True else "")' 2>/dev/null)
            if ! pgrep -f 'webadmin\.wsgi:application' >/dev/null; then
                # Per-host stable secret so sessions survive across
                # cron-driven respawns.
                if [ ! -f .webadmin_secret ]; then
                    head -c 32 /dev/urandom | xxd -p -c 64 > .webadmin_secret
                    chmod 600 .webadmin_secret
                fi
                export WEBADMIN_SECRET_KEY="$(cat .webadmin_secret)"
                export WEBADMIN_KEYDB_PATH="$(pwd)/keys.tdb"
                export PYTHONPATH="$HOME/SupportProxy"

                if [ "$webui_behind_proxy" = "1" ]; then
                    # Reverse proxy (nginx/apache) in front of us — it
                    # terminates TLS and forwards plain HTTP over
                    # loopback. Force the no-TLS gunicorn launch even
                    # if fullchain.pem exists (those pem files are for
                    # the supportproxy daemon's WSS, not for us). Tell
                    # Flask to honour X-Forwarded-* via ProxyFix and
                    # keep the session cookie's Secure flag (the proxy
                    # forwards X-Forwarded-Proto: https so
                    # request.is_secure is True).
                    webui_tls_g=()
                    webui_ssl_ctx="None"
                    export WEBADMIN_BEHIND_PROXY=1
                    unset WEBADMIN_INSECURE_COOKIES
                elif [ -r fullchain.pem ] && [ -r privkey.pem ]; then
                    # Standalone HTTPS: reuse the supportproxy WSS cert
                    # (typically a symlink or copy of the host's Let's
                    # Encrypt cert). Leave WEBADMIN_INSECURE_COOKIES
                    # unset so the session cookie keeps its Secure flag.
                    webui_tls_g=(--certfile fullchain.pem --keyfile privkey.pem)
                    webui_ssl_ctx="('fullchain.pem','privkey.pem')"
                    unset WEBADMIN_INSECURE_COOKIES
                else
                    webui_tls_g=()
                    webui_ssl_ctx="None"
                    # plain HTTP fallback for dev: drop Secure-only cookie
                    export WEBADMIN_INSECURE_COOKIES=1
                fi

                if command -v gunicorn >/dev/null 2>&1; then
                    nohup gunicorn -w 1 -b "$webui_host:$webui_port" \
                        "${webui_tls_g[@]}" \
                        webadmin.wsgi:application \
                        >> webui.log 2>&1 &
                else
                    nohup python3 -c "
from webadmin import create_app
create_app().run(host='$webui_host', port=$webui_port,
                 ssl_context=$webui_ssl_ctx,
                 debug=False, use_reloader=False)" \
                        >> webui.log 2>&1 &
                fi
            fi
        fi
    fi
) >> cron.log
