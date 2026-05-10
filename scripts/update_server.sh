#!/bin/bash
# Sync the local SupportProxy source to one or more remote servers, rebuild
# in place, and restart the proxy.
#
# Usage: scripts/update_server.sh [user@]host [more-hosts...]
#
# On each server we assume the standard layout:
#   ~/SupportProxy/                  - this repo's checkout (kept in sync
#                                  from the local working tree, including
#                                  the modules/mavlink submodule and any
#                                  uncommitted changes)
#   ~/SupportProxy/start_proxy.sh    - the launcher already in the repo
#   ~/proxy/                     - the data dir; keys.tdb, proxy.log,
#                                  cron.log, the live signing keys live
#                                  here. Untouched by this script.
#
# What runs:
#   1. rsync the local source tree -> remote ~/SupportProxy/, with --delete
#      so removed files go away. Build artifacts and runtime data are
#      excluded so we never clobber the server's keys / logs / certs.
#   2. ssh in and rebuild from clean (make distclean && make).
#   3. kill any running supportproxy and re-run ~/SupportProxy/start_proxy.sh
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

# What rsync should NOT transfer. Build artifacts (rebuilt on the server)
# and data files (server-side state we must not overwrite).
RSYNC_EXCLUDES=(
    --exclude='*.o'
    --exclude='supportproxy'
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

if ! command -v git >/dev/null 2>&1; then
    echo "git not found — needed to enumerate the deploy file list" >&2
    exit 1
fi

# Build a clean staging tree of *only* git-tracked files (deny-by-
# default). Anything in the local working tree that isn't tracked —
# pass.dat, x.dat, *.orig from a recent merge, .webadmin_secret,
# fullchain.pem, scratch notes, an unrelated test/ dir — physically
# can't reach the deploy. Uncommitted edits to TRACKED files do go
# through (cp from the working tree), so the existing
# "edit-then-deploy" workflow keeps working; new files have to be
# git add'd before they ship. The .git directory is also copied so
# the deployed build's `git rev-parse --short HEAD` succeeds.
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

(
    cd "$REPO_ROOT"
    # --recurse-submodules so modules/mavlink/* ends up in the list
    # rather than just the submodule pointer. Filter out any path
    # that resolves to a directory — those are uninitialised nested
    # submodules (e.g. modules/mavlink/.../node_modules/...) that we
    # don't have content for locally and the build doesn't need.
    git ls-files -z --recurse-submodules | \
        while IFS= read -r -d '' f; do
            [ -f "$f" ] && printf '%s\0' "$f"
        done | \
        xargs -0 cp --parents -t "$STAGE"
    cp -a .git "$STAGE/.git"
)

for host in "$@"; do
    echo
    echo "=== $host: syncing source ==="
    # RSYNC_EXCLUDES still applies — the staging tree itself is
    # already clean, but the excludes are what stops --delete from
    # clobbering the server's own state (keys.tdb, *.pem, logs/, ...).
    rsync -az --delete "${RSYNC_EXCLUDES[@]}" \
        "$STAGE/" "$host:SupportProxy/"

    echo "=== $host: rebuild + restart ==="
    ssh "$host" bash -se <<'SSH_EOF'
set -e
cd ~/SupportProxy
# Activate the venv if the server's set up the way the README
# describes (python3 -m venv --system-site-packages venv +
# pip install pymavlink). Without this, mavgen.py isn't on PATH and
# regen_headers.sh fails.
if [ -f venv/bin/activate ]; then
    # shellcheck disable=SC1091
    source venv/bin/activate
fi
make distclean >/dev/null
# Run regen_headers explicitly. The Makefile rule for the generated
# headers depends on modules/mavlink/.../all.xml's mtime, but rsync
# preserves source mtimes — so a submodule bump can leave the
# regenerated headers older than the new XML and make won't notice.
# Run regen_headers.sh up-front to be safe.
./regen_headers.sh
make -j all
# pkill -f matches the full argv. We anchor on the bin path so we don't
# accidentally kill anything named "supportproxy" run from elsewhere.
pkill -f "$HOME/SupportProxy/supportproxy" 2>/dev/null || true
# Also kill any running webadmin gunicorn so start_proxy.sh respawns it
# against the freshly-rsynced source. Without this, an existing gunicorn
# keeps serving the old code (start_proxy.sh skips relaunching when one
# is already up).
pkill -f 'webadmin\.wsgi:application' 2>/dev/null || true
sleep 1
./start_proxy.sh
sleep 1
echo "running pid:"
pgrep -af supportproxy || echo "  (no supportproxy detected — check ~/proxy/cron.log)"
SSH_EOF
done

echo
echo "All servers updated."
