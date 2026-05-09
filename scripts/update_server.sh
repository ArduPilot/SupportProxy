#!/bin/bash
# Sync the local UDPProxy source to one or more remote servers, rebuild
# in place, and restart the proxy.
#
# Usage: scripts/update_server.sh [user@]host [more-hosts...]
#
# On each server we assume the standard layout:
#   ~/UDPProxy/                  - this repo's checkout (kept in sync
#                                  from the local working tree, including
#                                  the modules/mavlink submodule and any
#                                  uncommitted changes)
#   ~/UDPProxy/start_proxy.sh    - the launcher already in the repo
#   ~/proxy/                     - the data dir; keys.tdb, proxy.log,
#                                  cron.log, the live signing keys live
#                                  here. Untouched by this script.
#
# What runs:
#   1. rsync the local source tree -> remote ~/UDPProxy/, with --delete
#      so removed files go away. Build artifacts and runtime data are
#      excluded so we never clobber the server's keys / logs / certs.
#   2. ssh in and rebuild from clean (make distclean && make).
#   3. kill any running udpproxy and re-run ~/UDPProxy/start_proxy.sh
#      so the new binary takes over immediately. (The cron entry from
#      README would respawn it within a minute anyway, but that leaves
#      a gap.)

set -e

if [ $# -lt 1 ]; then
    echo "usage: $0 [user@]host [more-hosts...]" >&2
    exit 1
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

# Stamp the local source tree with the current git short hash so the web
# UI footer can show it on the server (.git/ is excluded from rsync).
git -C "$REPO_ROOT" rev-parse --short HEAD > "$REPO_ROOT/git-version.txt"

# What rsync should NOT transfer. Build artifacts (rebuilt on the server)
# and data files (server-side state we must not overwrite).
RSYNC_EXCLUDES=(
    --exclude='.git/'
    --exclude='*.o'
    --exclude='udpproxy'
    --exclude='libraries/'
    --exclude='__pycache__/'
    --exclude='*.pyc'
    --exclude='venv/'
    --exclude='.pytest_cache/'
    --exclude='*.tdb'
    --exclude='*.tdb.bak'
    --exclude='*.tlog'
    --exclude='*.tlog.raw'
    --exclude='*.parm'
    --exclude='logs/'
    --exclude='*.orig'
    --exclude='*.rej'
    --exclude='HEAD.tar.gz'
    --exclude='proxy.log'
    --exclude='cron.log'
    --exclude='fullchain.pem'
    --exclude='privkey.pem'
    --exclude='.webadmin_secret'
)

for host in "$@"; do
    echo
    echo "=== $host: syncing source ==="
    rsync -az --delete "${RSYNC_EXCLUDES[@]}" \
        "$REPO_ROOT/" "$host:UDPProxy/"

    echo "=== $host: rebuild + restart ==="
    ssh "$host" bash -se <<'SSH_EOF'
set -e
cd ~/UDPProxy
# Activate the venv if the server's set up the way the README
# describes (python3 -m venv --system-site-packages venv +
# pip install pymavlink). Without this, mavgen.py isn't on PATH and
# regen_headers.sh fails.
if [ -f venv/bin/activate ]; then
    # shellcheck disable=SC1091
    source venv/bin/activate
fi
make distclean >/dev/null
make all
# pkill -f matches the full argv. We anchor on the bin path so we don't
# accidentally kill anything named "udpproxy" run from elsewhere.
pkill -f "$HOME/UDPProxy/udpproxy" 2>/dev/null || true
# Also kill any running webadmin gunicorn so start_proxy.sh respawns it
# against the freshly-rsynced source. Without this, an existing gunicorn
# keeps serving the old code (start_proxy.sh skips relaunching when one
# is already up).
pkill -f 'webadmin\.wsgi:application' 2>/dev/null || true
sleep 1
./start_proxy.sh
sleep 1
echo "running pid:"
pgrep -af udpproxy || echo "  (no udpproxy detected — check ~/proxy/cron.log)"
SSH_EOF
done

echo
echo "All servers updated."
