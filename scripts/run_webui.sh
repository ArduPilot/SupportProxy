#!/bin/bash
# Launch the webadmin Flask app from whatever directory you invoke it in,
# typically test/ during development (where keys.tdb plus the fullchain.pem /
# privkey.pem fixtures live). The current directory becomes WEBADMIN_KEYDB_PATH.
#
#   ../scripts/run_webui.sh              # http  on 127.0.0.1:8080
#   WEBADMIN_PORT=9000 ../scripts/run_webui.sh
#   WEBADMIN_TLS=1 ../scripts/run_webui.sh   # https using fullchain.pem/privkey.pem in cwd
#   WEBADMIN_BIND=0.0.0.0 ../scripts/run_webui.sh
#
# Falls back to Flask's dev server if gunicorn isn't installed.

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

if [ ! -f keys.tdb ]; then
    echo "ERROR: no keys.tdb in $(pwd)" >&2
    echo "Run from a directory that has one (e.g. test/), or initialise one with:" >&2
    echo "    python $REPO_ROOT/keydb.py initialise" >&2
    exit 1
fi

# Activate the project venv if present so Flask/pymavlink/tdb resolve.
if [ -f "$REPO_ROOT/venv/bin/activate" ]; then
    # shellcheck disable=SC1090,SC1091
    source "$REPO_ROOT/venv/bin/activate"
fi

PORT="${WEBADMIN_PORT:-8080}"
BIND="${WEBADMIN_BIND:-127.0.0.1}"

export PYTHONPATH="$REPO_ROOT:$PYTHONPATH"
export WEBADMIN_KEYDB_PATH="$(pwd)/keys.tdb"

# Persist a secret across restarts so sessions don't reset every run.
if [ -z "${WEBADMIN_SECRET_KEY:-}" ]; then
    if [ ! -f .webadmin_secret ]; then
        head -c 32 /dev/urandom | xxd -p -c 64 > .webadmin_secret
        chmod 600 .webadmin_secret
    fi
    WEBADMIN_SECRET_KEY="$(cat .webadmin_secret)"
    export WEBADMIN_SECRET_KEY
fi

USE_TLS=0
if [ "${WEBADMIN_TLS:-0}" = "1" ]; then
    if [ ! -f fullchain.pem ] || [ ! -f privkey.pem ]; then
        echo "ERROR: WEBADMIN_TLS=1 but fullchain.pem/privkey.pem not in $(pwd)" >&2
        exit 1
    fi
    USE_TLS=1
    PROTO="https"
else
    # HTTP dev: drop the Secure flag so the browser sends the session cookie.
    export WEBADMIN_INSECURE_COOKIES=1
    PROTO="http"
fi

echo "webadmin: cwd=$(pwd)"
echo "webadmin: keys.tdb=$WEBADMIN_KEYDB_PATH"
echo "webadmin: $PROTO://$BIND:$PORT/"
echo

if command -v gunicorn >/dev/null 2>&1; then
    # gthread worker (threaded sync) so one stalled TLS connection
    # doesn't block the whole UI. The default sync worker handles one
    # request at a time per worker — fine for low-traffic admin pages,
    # but the 5s auto-refresh from any open tab plus the occasional
    # half-open TLS connection (scanner / slow client / dropped net)
    # is enough to keep the worker pinned and trip gunicorn's
    # WORKER TIMEOUT abort. gthread runs --threads workers per
    # process with IO multiplexed across them.
    GUNICORN_ARGS=(
        -w 1
        -k gthread
        --threads 4
        --timeout 60
        --graceful-timeout 30
        -b "$BIND:$PORT"
    )
    if [ "$USE_TLS" = "1" ]; then
        GUNICORN_ARGS+=( --certfile fullchain.pem --keyfile privkey.pem )
    fi
    exec gunicorn "${GUNICORN_ARGS[@]}" webadmin.wsgi:application
fi

echo "gunicorn not found; falling back to Flask's dev server" >&2
if [ "$USE_TLS" = "1" ]; then
    SSL_EXPR="('fullchain.pem', 'privkey.pem')"
else
    SSL_EXPR="None"
fi
exec python3 - <<PYEOF
from webadmin import create_app
app = create_app()
app.run(host="$BIND", port=$PORT, ssl_context=$SSL_EXPR,
        debug=False, use_reloader=False)
PYEOF
