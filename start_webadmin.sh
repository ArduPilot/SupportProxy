#!/bin/bash
# Foreground launcher for the SupportProxy web admin gunicorn.
# Invoked by the supportproxy-webadmin systemd unit (NOT by cron —
# cron uses the all-in-one start_proxy.sh which backgrounds with
# nohup; under systemd we must stay in the foreground so the service
# lifecycle is correctly tracked).
#
# Reads ~/proxy/webui.json for host/port/behind_proxy (same schema
# start_proxy.sh expects), bootstraps the per-host session secret
# from .webadmin_secret if missing, and execs gunicorn.

set -e
cd "$HOME/proxy"

if [ ! -f webui.json ]; then
    echo "ERROR: $HOME/proxy/webui.json not found" >&2
    exit 1
fi

webui_host=$(python3 -c '
import json
print(json.load(open("webui.json")).get("host", "127.0.0.1"))')
webui_port=$(python3 -c '
import json
print(json.load(open("webui.json")).get("port", 8080))')
webui_behind_proxy=$(python3 -c '
import json
print("1" if json.load(open("webui.json")).get("behind_proxy") is True else "")')

# Per-host stable secret so sessions survive restarts.
if [ ! -f .webadmin_secret ]; then
    head -c 32 /dev/urandom | xxd -p -c 64 > .webadmin_secret
    chmod 600 .webadmin_secret
fi
export WEBADMIN_SECRET_KEY="$(cat .webadmin_secret)"
export WEBADMIN_KEYDB_PATH="$(pwd)/keys.tdb"
export PYTHONPATH="$HOME/SupportProxy"

# Prepend ~/.local/bin for pip user-install gunicorn (the README's
# alternative to a venv). systemd's default PATH doesn't include it,
# so without this exec gunicorn would exit 127.
export PATH="$HOME/.local/bin:$PATH"

gunicorn_args=( -w 1 -k gthread --threads 4
                --timeout 60 --graceful-timeout 30
                -b "$webui_host:$webui_port" )

if [ "$webui_behind_proxy" = "1" ]; then
    # Reverse proxy (nginx/apache) in front. Force plain HTTP even if
    # fullchain.pem exists — those pem files are for the supportproxy
    # daemon's WSS, not for us. Keep the session cookie's Secure flag
    # because the proxy forwards X-Forwarded-Proto: https.
    export WEBADMIN_BEHIND_PROXY=1
    unset WEBADMIN_INSECURE_COOKIES
elif [ -r fullchain.pem ] && [ -r privkey.pem ]; then
    # Standalone HTTPS via the daemon's WSS cert.
    gunicorn_args+=( --certfile fullchain.pem --keyfile privkey.pem )
    unset WEBADMIN_INSECURE_COOKIES
else
    # Plain-HTTP fallback for dev/test: drop Secure-only cookie.
    export WEBADMIN_INSECURE_COOKIES=1
fi

# Activate the project venv if it's set up the way the README
# describes (python3 -m venv --system-site-packages venv + pip
# install pymavlink gunicorn flask flask-wtf). Without this, gunicorn
# isn't on PATH and pymavlink imports fail.
if [ -f "$HOME/SupportProxy/venv/bin/activate" ]; then
    # shellcheck disable=SC1091
    source "$HOME/SupportProxy/venv/bin/activate"
fi

exec gunicorn "${gunicorn_args[@]}" webadmin.wsgi:application
