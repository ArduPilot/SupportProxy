"""Regression tests for the bidi pre-auth gate when video is the only consumer.

conn1 bytes are only parsed when a downstream consumer exists (engineer
forward, tlog, binlog, or -- now -- video). On the TCP path conn1 latches
at accept(), *before* any signature check, and that parse block is the only
thing that ever calls receive_message() and so the only thing that can set
is_authenticated(). A bidi entry whose sole consumer is video therefore
never authenticated, and CONN1_BIDI_PREAUTH_SECONDS killed the session.

The two tests here are a matched pair: with video enabled the session must
survive, and with no consumer at all it must still time out. The second is
what proves the gate is the mechanism rather than something incidental.

(The UDP path validates inside its own latch block, so it authenticates
regardless of the gate -- only TCP was affected.)
"""
import os
import subprocess
import sys
import threading
import time

import pytest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import keydb_lib  # noqa: E402

SUPPORTPROXY_BIN = os.path.join(_REPO_ROOT, 'supportproxy')

_w = os.environ.get('PYTEST_XDIST_WORKER', 'gw0')
_W = int(_w[2:]) if _w.startswith('gw') else 0
# 18100 base: 17500/17600/17700/17800/17900/18000 are taken by other
# test modules, and files sharing a base collide when they run in the
# same phase on the same xdist worker.
PORT_USER = 18100 + _W * 4
PORT_ENG = 18101 + _W * 4

PASSPHRASE = 'bidi_video_pw'

os.environ.setdefault('MAVLINK_DIALECT', 'all')
os.environ.setdefault('MAVLINK20', '1')

# Must exceed CONN1_BIDI_PREAUTH_SECONDS (5) by enough to be unambiguous
# without making the test slow.
OBSERVE_SECONDS = 9.0


def _key(passphrase):
    import hashlib
    return hashlib.sha256(passphrase.encode('ascii')).digest()


def _make_workdir(tmp_path, flags):
    p = tmp_path / 'work'
    p.mkdir()
    db = keydb_lib.init_db(str(p / 'keys.tdb'))
    db.transaction_start()
    keydb_lib.add_entry(db, PORT_USER, PORT_ENG, 'bidi_video', PASSPHRASE)
    for f in flags:
        keydb_lib.set_flag(db, PORT_ENG, f)
    db.transaction_prepare_commit()
    db.transaction_commit()
    db.close()
    return p


def _start_proxy(workdir):
    proc = subprocess.Popen(
        [SUPPORTPROXY_BIN], cwd=str(workdir), env=os.environ.copy(),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1, text=True)
    proc._lines = []
    proc._ready = threading.Event()

    def _drain():
        # Draining matters: a full stdout pipe blocks the child inside
        # printf() and stalls main_loop.
        for line in iter(proc.stdout.readline, ''):
            proc._lines.append(line)
            if 'Added port %d/%d' % (PORT_USER, PORT_ENG) in line:
                proc._ready.set()
        proc.stdout.close()

    proc._thread = threading.Thread(target=_drain, daemon=True)
    proc._thread.start()
    if not proc._ready.wait(timeout=10):
        proc.kill()
        raise RuntimeError('proxy did not start: %r' % (proc._lines,))
    return proc


def _stop(proc):
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
    proc._thread.join(timeout=2)


def _drive_signed_user_tcp(seconds):
    """Hold a signed MAVLink2 TCP user connection open, sending heartbeats.

    Returns once `seconds` have elapsed. Heartbeats keep last_pkt1 fresh so
    the ordinary 10 s idle timeout can't be confused with the pre-auth kill.
    """
    from pymavlink import mavutil
    conn = mavutil.mavlink_connection(
        'tcp:localhost:%d' % PORT_USER, source_system=1,
        source_component=1, use_native=False)
    try:
        conn.setup_signing(_key(PASSPHRASE), sign_outgoing=True)
        deadline = time.time() + seconds
        while time.time() < deadline:
            conn.mav.heartbeat_send(
                mavutil.mavlink.MAV_TYPE_QUADROTOR,
                mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA, 0, 0,
                mavutil.mavlink.MAV_STATE_ACTIVE)
            time.sleep(0.4)
    finally:
        try:
            conn.close()
        except Exception:
            pass


def _log(proc):
    return ''.join(proc._lines)


@pytest.mark.integration
def test_bidi_video_only_authenticates(tmp_path):
    """bidi + video, no engineer/tlog/binlog: the session must survive."""
    workdir = _make_workdir(tmp_path, ['bidi_sign', 'video'])
    proc = _start_proxy(workdir)
    try:
        _drive_signed_user_tcp(OBSERVE_SECONDS)
        time.sleep(0.5)
        out = _log(proc)
    finally:
        _stop(proc)

    assert 'have TCP conn1' in out, \
        'user side never latched; test drove nothing:\n%s' % out
    assert 'pre-auth timeout' not in out, (
        'bidi+video session was killed by the pre-auth deadline -- the parse '
        'gate is not treating video as a consumer:\n%s' % out)


@pytest.mark.integration
def test_bidi_without_any_consumer_still_times_out(tmp_path):
    """Control: bidi with no consumer at all must still hit the deadline.

    Without this, the test above could pass for reasons unrelated to the
    gate (e.g. if something else started authenticating conn1).
    """
    workdir = _make_workdir(tmp_path, ['bidi_sign'])
    proc = _start_proxy(workdir)
    try:
        _drive_signed_user_tcp(OBSERVE_SECONDS)
        time.sleep(0.5)
        out = _log(proc)
    finally:
        _stop(proc)

    assert 'have TCP conn1' in out, \
        'user side never latched; test drove nothing:\n%s' % out
    assert 'pre-auth timeout' in out, (
        'expected the pre-auth deadline to fire with no consumer '
        'configured:\n%s' % out)
