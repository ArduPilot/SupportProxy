#!/bin/bash
# Stage the video feature onto a server, alongside whatever else is
# already running there.
#
# Usage:
#   scripts/deploy_video.sh [user@]host                 # pre-flight only
#   scripts/deploy_video.sh [user@]host --apply         # deploy + configure
#   scripts/deploy_video.sh [user@]host --apply --entry 11025 --ports 12001
#
# Deliberately dry-run by default: it restarts the proxy and edits
# keys.tdb, so it should not do either because someone ran it to look.
#
# What it does NOT touch, ever:
#   ~/Video/            mediamtx's install and its recordings. The two
#                       systems run side by side until the new one is
#                       proven, so its ports and its 22 GB of captures
#                       are none of our business.
#   ~/proxy/*.pem       the WSS certs.
#   logs/               existing tlogs and bin logs.
set -u

HOST=""
APPLY=0
ENTRY=""
PORTS=""
RECORD=1
BIDI=0
PUBPASS=""
VIEWPASS=""

while [ $# -gt 0 ]; do
    case "$1" in
        --apply)     APPLY=1 ;;
        --entry)     ENTRY="$2"; shift ;;
        --ports)     PORTS="$2"; shift ;;
        --no-record)    RECORD=0 ;;
        --bidi)         BIDI=1 ;;
        --publish-pass) PUBPASS="$2"; shift ;;
        --viewer-pass)  VIEWPASS="$2"; shift ;;
        -h|--help)   sed -n '2,25p' "$0"; exit 0 ;;
        *)           HOST="$1" ;;
    esac
    shift
done

if [ -z "$HOST" ]; then
    echo "usage: $0 [user@]host [--apply] [--entry PORT2] [--ports P1[,P2,P3]]" >&2
    exit 1
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$SCRIPT_DIR/.." && pwd )"

# Ports for mediamtx, so we can say plainly when a chosen video port
# would collide with it while both systems are running.
MEDIAMTX_PORTS="1935 8322 11002 11032 11033 10002 10003"

say()  { printf '  %s\n' "$*"; }
head2() { printf '\n=== %s ===\n' "$*"; }
fail() { printf '\nABORT: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- pre-flight

head2 "$HOST: pre-flight"

PRE=$(ssh "$HOST" bash -se <<'SSH_EOF' 2>&1
set -u
printf 'os=%s\n' "$( . /etc/os-release && echo "$PRETTY_NAME" )"
printf 'ffmpeg=%s\n' "$(command -v ffmpeg || echo MISSING)"
printf 'freekb=%s\n' "$(df -Pk "$HOME" | awk 'NR==2{print $4}')"
printf 'mediamtx=%s\n' "$(pgrep -x mediamtx >/dev/null && echo running || echo stopped)"
printf 'systemd=%s\n' "$(systemctl is-enabled supportproxy.service 2>/dev/null || echo no)"
# What the build actually needs is mavgen.py on PATH (regen_headers.sh),
# whether that comes from a venv or a --user install. Testing for the
# venv instead would fail on a host where pymavlink is installed
# system-wide, which is how this one is set up.
printf 'mavgen=%s\n' "$(command -v mavgen.py || echo MISSING)"
for p in libtdb-dev libssl-dev; do
    printf 'pkg_%s=%s\n' "$p" "$(dpkg -l "$p" 2>/dev/null | awk '/^ii/{print "ok"}' | head -1)"
done
printf 'bound=%s\n' "$(ss -lntuH 2>/dev/null | awk '{print $5}' | sed 's/.*://' | sort -un | tr '\n' ',')"
SSH_EOF
) || fail "cannot reach $HOST"

get() { echo "$PRE" | sed -n "s/^$1=//p" | head -1; }

say "os:        $(get os)"
say "ffmpeg:    $(get ffmpeg)"
say "free disk: $(( $(get freekb) / 1024 / 1024 )) GiB"
say "mediamtx:  $(get mediamtx)"
say "systemd:   $(get systemd)"
say "mavgen:    $(get mavgen)"

BOUND=",$(get bound)"
FREEKB=$(get freekb)

[ "$(get mavgen)" != MISSING ] || fail "mavgen.py not on PATH; regen_headers.sh needs pymavlink installed"
[ -n "$(get pkg_libtdb-dev)" ] || fail "libtdb-dev missing on the server"
[ -n "$(get pkg_libssl-dev)" ] || fail "libssl-dev missing on the server"

# 4 GiB: the default per-entry video budget is 4 GiB and the recorder
# refuses to open a segment below a 2 GiB floor, so anything less and
# recording would never start.
if [ "$FREEKB" -lt $((6 * 1024 * 1024)) ]; then
    fail "only $(( FREEKB / 1024 / 1024 )) GiB free; want >= 6 GiB (4 GiB video quota + the 2 GiB floor)"
fi

FFMPEG_OK=1
if [ "$(get ffmpeg)" = MISSING ]; then
    FFMPEG_OK=0
    say ""
    say "ffmpeg is NOT installed. MPEG-TS/UDP publish, all viewers and"
    say "recording work without it; only RTSP ingest needs it. There is no"
    say "passwordless sudo here, so install it yourself:"
    say "    ssh $HOST sudo apt install ffmpeg"
fi

# ------------------------------------------------------------------- ports

PORTS="${PORTS:-12001}"
head2 "video ports: $PORTS"
IFS=',' read -ra PORT_LIST <<< "$PORTS"
for p in "${PORT_LIST[@]}"; do
    case "$BOUND" in
        *",$p,"*) fail "port $p is already bound on $HOST" ;;
    esac
    for m in $MEDIAMTX_PORTS; do
        if [ "$p" = "$m" ]; then
            fail "port $p is one of mediamtx's ($MEDIAMTX_PORTS) and both must keep running"
        fi
    done
    say "$p free, and clear of mediamtx"
done

# ------------------------------------------------------------------ entries

head2 "entries on $HOST"
ssh "$HOST" "cd ~/proxy && python3 -c \"
import sys; sys.path.insert(0, '\$HOME/SupportProxy')
import keydb_lib
db = keydb_lib.open_db('keys.tdb'); db.transaction_start()
try:
    for e in keydb_lib.list_entries(db):
        print('  %5d/%-5d %-18s %s' % (e.port1, e.port2, e.name,
                                       ','.join(e.flag_names()) or '(no flags)'))
finally:
    db.transaction_cancel(); db.close()
\"" 2>&1 | head -30

if [ -z "$ENTRY" ]; then
    head2 "no --entry given"
    say "Pre-flight only. Re-run with, for example:"
    say "    $0 $HOST --apply --entry 11025 --ports $PORTS"
    say ""
    say ""
    say "Publisher auth, pick one:"
    say ""
    say "  (a) --publish-pass SECRET   password only, no MAVLink needed."
    say "      Publish with rtsp://HOST:PORT/cam?pw=SECRET."
    say "      NOTE: the password REPLACES the address check, and plain"
    say "      MPEG-TS/UDP cannot carry one -- with a password set, UDP"
    say "      publish is refused. Use RTSP."
    say ""
    say "  (b) nothing                 address must match a recent MAVLink"
    say "      session. Works for UDP and RTSP. But without bidi ANY"
    say "      datagram latches conn1, and this server sees hundreds of"
    say "      distinct scanners doing exactly that -- a scanner holding"
    say "      conn1 makes the aircraft's own publish be refused until it"
    say "      ages out (grace window, 60s default)."
    say ""
    say "  (c) --bidi                  as (b), but only a signature-checked"
    say "      session can latch conn1, so scanners cannot interfere."
    say "      Changes the entry: the aircraft must sign from then on."
    exit 0
fi

if [ "$APPLY" != 1 ]; then
    head2 "dry run"
    say "Would deploy the current working tree to $HOST and then:"
    say "  entry $ENTRY: video ports $PORTS"
    [ "$BIDI" = 1 ]      && say "  entry $ENTRY: bidi_sign ON"
    [ -n "$PUBPASS" ]    && say "  entry $ENTRY: publish password SET (UDP publish will be refused)"
    [ -n "$VIEWPASS" ]   && say "  entry $ENTRY: viewer password SET"
    [ "$RECORD" = 1 ]    && say "  slot 1: record ON"
    if [ "$BIDI" = 0 ] && [ -z "$PUBPASS" ]; then
        say ""
        say "  WARNING: no bidi and no publish password -- a scanner that"
        say "  latches conn1 will block the aircraft's video publish."
    fi
    say "Re-run with --apply to do it."
    exit 0
fi

# ------------------------------------------------------------------- deploy

head2 "$HOST: backing up keys.tdb"
ssh "$HOST" 'cd ~/proxy && cp -a keys.tdb "keys.tdb.before-video.$(date +%Y%m%d%H%M%S)" && ls -1t keys.tdb.before-video.* | head -1' \
    || fail "could not back up keys.tdb"

head2 "$HOST: sync, build, restart"
"$SCRIPT_DIR/update_server.sh" "$HOST" || fail "update_server.sh failed; nothing was reconfigured"

head2 "$HOST: verifying the new build"
ssh "$HOST" '~/SupportProxy/supportproxy --selftest-video' \
    || fail "the deployed binary failed its own self-test"

# ---------------------------------------------------------------- configure

head2 "$HOST: configuring entry $ENTRY"
ssh "$HOST" bash -se <<SSH_EOF
set -e
cd ~/proxy
K=\$HOME/SupportProxy/keydb.py
python3 \$K setvideo $ENTRY ${PORTS//,/ }
python3 \$K setflag $ENTRY video
if [ "$BIDI" = 1 ]; then python3 \$K setflag $ENTRY bidi_sign; fi
if [ -n "$PUBPASS" ]; then python3 \$K setpublishpass $ENTRY '$PUBPASS'; fi
if [ -n "$VIEWPASS" ]; then python3 \$K setviewerpass $ENTRY '$VIEWPASS'; fi
if [ "$RECORD" = 1 ]; then python3 \$K videoflag $ENTRY 0 record; fi
python3 \$K video $ENTRY
SSH_EOF

head2 "$HOST: post-check"
sleep 8
ssh "$HOST" bash -se <<SSH_EOF
for p in ${PORTS//,/ }; do
    if ss -lntu 2>/dev/null | grep -q ":\$p "; then
        echo "  video port \$p is listening"
    else
        echo "  video port \$p NOT listening -- check ~/proxy/proxy.log"
    fi
done
echo "  mediamtx: \$(pgrep -x mediamtx >/dev/null && echo 'still running (untouched)' || echo 'stopped (as it was)')"
grep -E 'video (slot|child)' ~/proxy/proxy.log | tail -4 | sed 's/^/  /'
SSH_EOF

head2 "done"
if [ -n "$PUBPASS" ]; then
    say "Publish to: rtsp://$HOST:${PORT_LIST[0]}/cam?pw=$PUBPASS"
    say "        (UDP publish is refused while a publish password is set)"
else
    say "Publish to: udp://$HOST:${PORT_LIST[0]}   (MPEG-TS, e.g. gstreamer udpsink)"
    if [ "$FFMPEG_OK" = 1 ]; then
        say "        or: rtsp://$HOST:${PORT_LIST[0]}/cam"
    else
        say "        RTSP publish needs ffmpeg installed first."
    fi
fi
# Without the flags ffplay spends its default 5s analyzeduration before
# showing anything, which reads as the proxy being slow.
say "Watch with: ffplay -fflags nobuffer -flags low_delay -framedrop \\"
say "                   -probesize 500000 -analyzeduration 1000000 \\"
say "                   http://$HOST:${PORT_LIST[0]}/v1.ts"
say "        or: the video page in the web admin"
say ""
say "mediamtx is untouched and still on its own ports."
