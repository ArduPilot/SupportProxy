"""Regression test: closing one engineer slot must not orphan the others.

The conn2 close paths used to shrink the scan watermark with
    if (conn2_count == max_conn2_count) max_conn2_count--;
which fires whenever the slot table has no holes, regardless of which
slot closed. With engineers in slots 0 and 1, an EOF on slot 0 dropped
the watermark to 1 and slot 1 fell out of every scan loop (select set,
reads, forwarding, idle close, connections.tdb snapshot): that engineer
silently stopped receiving anything until a third connection happened
to raise the watermark again.

This test connects a user plus two signed TCP engineers, disconnects
engineer #1, and asserts engineer #2 still receives the user's traffic.
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
PORT_USER = 17800 + _W * 4
PORT_ENG = 17801 + _W * 4

os.environ.setdefault('MAVLINK_DIALECT', 'all')
os.environ.setdefault('MAVLINK20', '1')


@pytest.fixture
def proxy_workdir(tmp_path):
    p = tmp_path / 'work'
    p.mkdir()
    db_path = str(p / 'keys.tdb')
    db = keydb_lib.init_db(db_path)
    db.transaction_start()
    keydb_lib.add_entry(db, PORT_USER, PORT_ENG, 'orphan_test', 'orphanpw')
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


def _recv_user_heartbeat(conn, user_sysid, timeout):
    """True if ``conn`` receives a HEARTBEAT originating from the user
    (srcSystem == user_sysid) within ``timeout`` seconds."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        m = conn.recv_match(type='HEARTBEAT', blocking=True, timeout=0.5)
        if m is not None and m.get_srcSystem() == user_sysid:
            return True
    return False


@pytest.mark.skipif(not os.path.exists(SUPPORTPROXY_BIN),
                    reason='supportproxy binary not built')
class TestConn2SlotOrphan:
    def test_engineer2_survives_engineer1_disconnect(self, proxy_workdir):
        from pymavlink import mavutil
        secret = hashlib.sha256(b'orphanpw').digest()

        proc = _start_proxy(proxy_workdir)
        stop_ev = threading.Event()
        user = eng1 = eng2 = None
        try:
            # User side streams continuously in the background so the
            # child keeps iterating and forwarding throughout the test.
            user = mavutil.mavlink_connection(
                'udpout:127.0.0.1:%d' % PORT_USER,
                source_system=10, source_component=1)

            def _user_stream():
                while not stop_ev.is_set():
                    user.mav.heartbeat_send(0, 0, 0, 0, 0)
                    time.sleep(0.1)

            t = threading.Thread(target=_user_stream, daemon=True)
            t.start()

            assert _wait(lambda: 0 in _list_conn_indices(
                proxy_workdir, PORT_ENG), timeout=10), 'user never latched'

            # Engineer #1 into slot 0 (conn_index 1).
            eng1 = mavutil.mavlink_connection(
                'tcp:127.0.0.1:%d' % PORT_ENG,
                source_system=11, source_component=1)
            eng1.setup_signing(secret, sign_outgoing=True)
            for _ in range(10):
                eng1.mav.heartbeat_send(0, 0, 0, 0, 0)
                time.sleep(0.1)
            assert _wait(lambda: 1 in _list_conn_indices(
                proxy_workdir, PORT_ENG), timeout=5), 'engineer #1 missing'

            # Engineer #2 into slot 1 (conn_index 2).
            eng2 = mavutil.mavlink_connection(
                'tcp:127.0.0.1:%d' % PORT_ENG,
                source_system=12, source_component=1)
            eng2.setup_signing(secret, sign_outgoing=True)
            for _ in range(10):
                eng2.mav.heartbeat_send(0, 0, 0, 0, 0)
                time.sleep(0.1)
            assert _wait(lambda: _list_conn_indices(
                proxy_workdir, PORT_ENG) == [0, 1, 2], timeout=5), \
                'expected slots 0,1,2; got %r' % (
                    _list_conn_indices(proxy_workdir, PORT_ENG),)

            # Sanity: engineer #2 sees the user's heartbeats.
            assert _recv_user_heartbeat(eng2, 10, timeout=5), \
                'engineer #2 not receiving user traffic before disconnect'

            # Engineer #1 disconnects abruptly.
            eng1.close()
            eng1 = None
            time.sleep(1.0)  # let the proxy process the EOF

            # Drain anything forwarded before the EOF was processed.
            while eng2.recv_match(blocking=False) is not None:
                pass

            # Engineer #2 must keep receiving the user's traffic.
            assert _recv_user_heartbeat(eng2, 10, timeout=5), \
                'engineer #2 orphaned after engineer #1 disconnect; ' \
                'recent proxy output:\n%s' % ''.join(proc._lines[-15:])
        finally:
            stop_ev.set()
            for c in (eng1, eng2, user):
                if c is not None:
                    c.close()
            _terminate(proc)
