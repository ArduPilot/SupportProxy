"""End-to-end test for per-row 'kill connection'.

Drives a real supportproxy child with a user UDP and two signed
engineer UDP connections, then sets CONN_FLAG_DROP_REQUESTED on one
engineer entry in connections.tdb and sends SIGUSR1 to the child
PID. Asserts that:
  * the requested engineer record disappears from connections.tdb
  * the user + the other engineer remain
  * a follow-up drop on conn_index=0 (user) ends the whole session
    (the proxy's parent reaps the child).
"""
import datetime
import hashlib
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

import pytest
import tdb

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import conntdb_lib  # noqa: E402
import keydb_lib  # noqa: E402

SUPPORTPROXY_BIN = os.path.join(_REPO_ROOT, 'supportproxy')

# Worker-aware ports so xdist runs don't fight over them.
_W = int(os.environ.get('PYTEST_XDIST_WORKER', 'gw0')[2:]
         if os.environ.get('PYTEST_XDIST_WORKER', 'gw0').startswith('gw') else 0)
PORT_USER = 17600 + _W * 4
PORT_ENG = 17601 + _W * 4

os.environ.setdefault('MAVLINK_DIALECT', 'ardupilotmega')
os.environ.setdefault('MAVLINK20', '1')


@pytest.fixture
def proxy_workdir(tmp_path):
    p = tmp_path / 'work'
    p.mkdir()
    db_path = str(p / 'keys.tdb')
    db = keydb_lib.init_db(db_path)
    db.transaction_start()
    keydb_lib.add_entry(db, PORT_USER, PORT_ENG, 'kill_test', 'killpw')
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
    """Return the sorted set of conn_index values present in
    connections.tdb for ``port2`` (filtering by max_age via iter_active)."""
    path = str(workdir / 'connections.tdb')
    return sorted(c.conn_index for c in conntdb_lib.list_active(path)
                  if c.port2 == port2)


def _pid_for(workdir, port2, conn_index):
    path = str(workdir / 'connections.tdb')
    for c in conntdb_lib.list_active(path):
        if c.port2 == port2 and c.conn_index == conn_index:
            return c.pid
    return None


@pytest.mark.skipif(not os.path.exists(SUPPORTPROXY_BIN),
                    reason='supportproxy binary not built')
class TestKillDrop:
    def test_drop_engineer_keeps_others(self, proxy_workdir):
        from pymavlink import mavutil
        secret = hashlib.sha256(b'killpw').digest()

        proc = _start_proxy(proxy_workdir)
        try:
            user = mavutil.mavlink_connection(
                'udpout:127.0.0.1:%d' % PORT_USER,
                source_system=10, source_component=20)
            eng1 = mavutil.mavlink_connection(
                'udpout:127.0.0.1:%d' % PORT_ENG,
                source_system=11, source_component=21)
            eng1.setup_signing(secret, sign_outgoing=True)
            eng2 = mavutil.mavlink_connection(
                'udpout:127.0.0.1:%d' % PORT_ENG,
                source_system=12, source_component=22)
            eng2.setup_signing(secret, sign_outgoing=True)

            # Drive enough traffic to register everyone.
            for _ in range(15):
                user.mav.heartbeat_send(0, 0, 0, 0, 0)
                eng1.mav.heartbeat_send(0, 0, 0, 0, 0)
                eng2.mav.heartbeat_send(0, 0, 0, 0, 0)
                time.sleep(0.1)

            # Wait for both engineer slots to appear in connections.tdb
            # (slots 1 and 2; slot 0 is user).
            assert _wait(lambda: _list_conn_indices(
                proxy_workdir, PORT_ENG) == [0, 1, 2], timeout=5.0), \
                'expected slots 0,1,2; got %r' % (
                    _list_conn_indices(proxy_workdir, PORT_ENG),)

            # Drop engineer #2 via request_drop + SIGUSR1.
            ok = conntdb_lib.request_drop(
                str(proxy_workdir / 'connections.tdb'),
                PORT_ENG, 2)
            assert ok

            # Engineer #2 record should disappear; user + engineer #1 remain.
            assert _wait(lambda: 2 not in _list_conn_indices(
                proxy_workdir, PORT_ENG), timeout=5.0), \
                'engineer #2 not removed; have %r' % (
                    _list_conn_indices(proxy_workdir, PORT_ENG),)
            remaining = _list_conn_indices(proxy_workdir, PORT_ENG)
            assert 0 in remaining and 1 in remaining

            # Pump more traffic so engineer #1 keeps receiving (its TDB
            # heartbeat re-fires) and proves the child is still alive.
            for _ in range(5):
                user.mav.heartbeat_send(0, 0, 0, 0, 0)
                eng1.mav.heartbeat_send(0, 0, 0, 0, 0)
                time.sleep(0.1)
            assert 1 in _list_conn_indices(proxy_workdir, PORT_ENG)

            user.close(); eng1.close(); eng2.close()
        finally:
            _terminate(proc)

    def test_drop_user_ends_session(self, proxy_workdir):
        from pymavlink import mavutil
        secret = hashlib.sha256(b'killpw').digest()

        proc = _start_proxy(proxy_workdir)
        try:
            user = mavutil.mavlink_connection(
                'udpout:127.0.0.1:%d' % PORT_USER,
                source_system=10, source_component=20)
            eng = mavutil.mavlink_connection(
                'udpout:127.0.0.1:%d' % PORT_ENG,
                source_system=11, source_component=21)
            eng.setup_signing(secret, sign_outgoing=True)
            for _ in range(15):
                user.mav.heartbeat_send(0, 0, 0, 0, 0)
                eng.mav.heartbeat_send(0, 0, 0, 0, 0)
                time.sleep(0.1)

            assert _wait(lambda: 0 in _list_conn_indices(
                proxy_workdir, PORT_ENG), timeout=5.0)

            child_pid = _pid_for(proxy_workdir, PORT_ENG, 0)
            assert child_pid is not None and child_pid > 0

            ok = conntdb_lib.request_drop(
                str(proxy_workdir / 'connections.tdb'),
                PORT_ENG, 0)
            assert ok

            # Child should exit; parent reaps via check_children. The
            # log line "[<port2>] Child <pid> exited" appears.
            needle = '[%d] Child %d exited' % (PORT_ENG, child_pid)
            assert _wait(lambda: any(needle in line
                                     for line in proc._lines),
                         timeout=5.0), \
                'child did not exit; recent stdout:\n%s' % (
                    ''.join(proc._lines[-15:]))

            # connections.tdb for that port2 should be empty (parent's
            # check_children removes records after reap).
            assert _wait(
                lambda: not _list_conn_indices(proxy_workdir, PORT_ENG),
                timeout=5.0)

            user.close(); eng.close()
        finally:
            _terminate(proc)
