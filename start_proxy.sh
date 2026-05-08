#!/bin/bash
# script to start UDPProxy from cron
# assumes that keys.tdb is in $HOME/proxy
# assumes that UDPProxy build is in $HOME/UDPProxy
#
# If $HOME/proxy/webui.json exists with "mode":"standalone", we also
# (re)launch the web admin UI on the configured port.

cd $HOME/proxy

(
    date
    pidof -q udpproxy || {
        nohup $HOME/UDPProxy/udpproxy >> proxy.log 2>&1 &
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
            if ! pgrep -f 'webadmin\.wsgi:application' >/dev/null; then
                # Per-host stable secret so sessions survive across
                # cron-driven respawns.
                if [ ! -f .webadmin_secret ]; then
                    head -c 32 /dev/urandom | xxd -p -c 64 > .webadmin_secret
                    chmod 600 .webadmin_secret
                fi
                export WEBADMIN_SECRET_KEY="$(cat .webadmin_secret)"
                export WEBADMIN_KEYDB_PATH="$(pwd)/keys.tdb"
                export PYTHONPATH="$HOME/UDPProxy"

                # Reuse the udpproxy WSS cert if it's here (typically a
                # symlink or copy of the host's Let's Encrypt cert).
                # When we have TLS, leave WEBADMIN_INSECURE_COOKIES
                # unset so the session cookie keeps its Secure flag.
                if [ -r fullchain.pem ] && [ -r privkey.pem ]; then
                    webui_tls_g=(--certfile fullchain.pem --keyfile privkey.pem)
                    webui_ssl_ctx="('fullchain.pem','privkey.pem')"
                    unset WEBADMIN_INSECURE_COOKIES
                else
                    webui_tls_g=()
                    webui_ssl_ctx="None"
                    # plain HTTP fallback: drop Secure-only cookie
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
