"""Regression test: a drop request must not be silently lost.

The webadmin kill path sets CONN_FLAG_DROP_REQUESTED on the record and
sends SIGUSR1. The child's 5s connections.tdb snapshot used to
delete-and-rewrite every record for its port2 with flags=0, so a flag
that landed while a snapshot was in flight was wiped before the child's
scan ran — the kill silently did nothing, and nothing ever retried.

The fix is twofold: the snapshot rewrite preserves DROP_REQUESTED, and
the child rescans for drop requests on the snapshot cadence so a
request whose SIGUSR1 raced the rewrite is still honoured.

This test simulates the lost-signal case directly: it sets the flag on
an engineer record *without* sending SIGUSR1 and asserts the connection
is dropped anyway within a couple of snapshot cycles.
"""
import hashlib
import os
import signal
import subprocess
import sys
import threading
import time

import pytest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import conntdb_lib  # noqa: E402
import keydb_lib  # noqa: E402

SUPPORTPROXY_BIN = os.path.join(_REPO_ROOT, 'supportproxy')

_W = int(os.environ.get('PYTEST_XDIST_WORKER', 'gw0')[2:]
         if os.environ.get('PYTEST_XDIST_WORKER', 'gw0').startswith('gw') else 0)
PORT_USER = 17900 + _W * 4
PORT_ENG = 17901 + _W * 4

os.environ.setdefault('MAVLINK_DIALECT', 'all')
os.environ.setdefault('MAVLINK20', '1')


@pytest.fixture
def proxy_workdir(tmp_path):
    p = tmp_path / 'work'
    p.mkdir()
    db_path = str(p / 'keys.tdb')
    db = keydb_lib.init_db(db_path)
    db.transaction_start()
    keydb_lib.add_entry(db, PORT_USER, PORT_ENG, 'lostdrop', 'lostpw')
    db.transaction_prepare_commit()
    db.transaction_commit()
    db.close()
    return p


def _start_proxy(workdir):
    proc = subprocess.Popen(
        [SUPPORTPROXY_BIN], cwd=str(workdir),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        bufsize=1, text=True,
    )
    proc._lines = []
    proc._ready = threading.Event()

    def _drain():
        for line in iter(proc.stdout.readline, ''):
            proc._lines.append(line)
            if 'Added port %d/%d' % (PORT_USER, PORT_ENG) in line:
                proc._ready.set()
        proc.stdout.close()

    proc._thread = threading.Thread(target=_drain, daemon=True)
    proc._thread.start()
    if not proc._ready.wait(timeout=10):
        proc.kill()
        proc.wait(timeout=2)
        raise RuntimeError('proxy did not load test port pair')
    return proc


def _terminate(proc):
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)


def _wait(predicate, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return False


def _list_conn_indices(workdir, port2):
    path = str(workdir / 'connections.tdb')
    return sorted(c.conn_index for c in conntdb_lib.list_active(path)
                  if c.port2 == port2)


@pytest.mark.skipif(not os.path.exists(SUPPORTPROXY_BIN),
                    reason='supportproxy binary not built')
class TestDropRequestNotLost:
    def test_flag_without_signal_still_drops(self, proxy_workdir):
        from pymavlink import mavutil
        secret = hashlib.sha256(b'lostpw').digest()

        proc = _start_proxy(proxy_workdir)
        stop_ev = threading.Event()
        user = eng = None
        try:
            # Continuous user traffic keeps the child's loop (and its
            # 5s snapshot/scan cadence) running throughout.
            user = mavutil.mavlink_connection(
                'udpout:127.0.0.1:%d' % PORT_USER,
                source_system=10, source_component=1)

            def _user_stream():
                while not stop_ev.is_set():
                    user.mav.heartbeat_send(0, 0, 0, 0, 0)
                    time.sleep(0.1)

            t = threading.Thread(target=_user_stream, daemon=True)
            t.start()

            # Signed TCP engineer: no idle close, no auto-reconnect, so
            # the slot only goes away if the drop request is honoured.
            eng = mavutil.mavlink_connection(
                'tcp:127.0.0.1:%d' % PORT_ENG,
                source_system=11, source_component=1)
            eng.setup_signing(secret, sign_outgoing=True)
            for _ in range(10):
                eng.mav.heartbeat_send(0, 0, 0, 0, 0)
                time.sleep(0.1)

            assert _wait(lambda: _list_conn_indices(
                proxy_workdir, PORT_ENG) == [0, 1], timeout=10), \
                'expected slots 0,1; got %r' % (
                    _list_conn_indices(proxy_workdir, PORT_ENG),)

            # Set the drop flag but do NOT send SIGUSR1 — this is the
            # state after the signal raced a snapshot rewrite and the
            # child's scan found nothing.
            pid = conntdb_lib._flip_drop_flag(
                str(proxy_workdir / 'connections.tdb'), PORT_ENG, 1)
            assert pid, 'engineer record missing when setting drop flag'

            # The request must still be honoured within a couple of
            # snapshot cycles (5s cadence); the user connection stays.
            assert _wait(lambda: 1 not in _list_conn_indices(
                proxy_workdir, PORT_ENG), timeout=15), \
                'drop request was silently lost; slots: %r\n%s' % (
                    _list_conn_indices(proxy_workdir, PORT_ENG),
                    ''.join(proc._lines[-15:]))
            assert 0 in _list_conn_indices(proxy_workdir, PORT_ENG), \
                'user connection should survive an engineer drop'
        finally:
            stop_ev.set()
            for c in (eng, user):
                if c is not None:
                    c.close()
            _terminate(proc)
