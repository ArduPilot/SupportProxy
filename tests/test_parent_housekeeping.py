"""Regression test: parent housekeeping must not be starved by traffic.

The parent used to run check_children()/reload_ports() only when
epoll_wait() returned 0 (a full second with no events). Because the
per-pair children inherit the listening sockets, the parent's epoll
registrations survive its close() after fork and fire for every UDP
packet on any active session. With one busy session anywhere, the
parent never reaped exited children and never reopened their
listeners: a connection killed via the web UI never came back even
though its user kept sending UDP packets.

This test runs two port pairs: pair A streams continuously, pair B's
user connection is killed via the CONN_FLAG_DROP_REQUESTED + SIGUSR1
path. Pair B's user keeps transmitting; a fresh child must pick the
session up again while pair A's stream never pauses.
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
PORT_A_USER = 17700 + _W * 8
PORT_A_ENG = 17701 + _W * 8
PORT_B_USER = 17702 + _W * 8
PORT_B_ENG = 17703 + _W * 8

os.environ.setdefault('MAVLINK_DIALECT', 'all')
os.environ.setdefault('MAVLINK20', '1')


@pytest.fixture
def proxy_workdir(tmp_path):
    p = tmp_path / 'work'
    p.mkdir()
    db_path = str(p / 'keys.tdb')
    db = keydb_lib.init_db(db_path)
    db.transaction_start()
    keydb_lib.add_entry(db, PORT_A_USER, PORT_A_ENG, 'hk_busy', 'busypw')
    keydb_lib.add_entry(db, PORT_B_USER, PORT_B_ENG, 'hk_victim', 'victimpw')
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
    markers = {
        'Added port %d/%d' % (PORT_A_USER, PORT_A_ENG): False,
        'Added port %d/%d' % (PORT_B_USER, PORT_B_ENG): False,
    }

    def _drain():
        for line in iter(proc.stdout.readline, ''):
            proc._lines.append(line)
            for m in markers:
                if m in line:
                    markers[m] = True
            if all(markers.values()):
                proc._ready.set()
        proc.stdout.close()

    proc._thread = threading.Thread(target=_drain, daemon=True)
    proc._thread.start()
    if not proc._ready.wait(timeout=10):
        proc.kill()
        proc.wait(timeout=2)
        raise RuntimeError('proxy did not load both test port pairs')
    return proc


def _terminate(proc):
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)


def _wait(predicate, timeout=5.0, interval=0.1):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return False


def _pid_for(workdir, port2, conn_index):
    path = str(workdir / 'connections.tdb')
    for c in conntdb_lib.list_active(path):
        if c.port2 == port2 and c.conn_index == conn_index:
            return c.pid
    return None


class _Blaster(threading.Thread):
    """Send heartbeats to a UDP port at a fixed interval until stopped."""

    def __init__(self, port, interval, source_system):
        super().__init__(daemon=True)
        from pymavlink import mavutil
        self.conn = mavutil.mavlink_connection(
            'udpout:127.0.0.1:%d' % port,
            source_system=source_system, source_component=1)
        self.interval = interval
        self.stop_ev = threading.Event()

    def run(self):
        while not self.stop_ev.is_set():
            self.conn.mav.heartbeat_send(0, 0, 0, 0, 0)
            time.sleep(self.interval)

    def stop(self):
        self.stop_ev.set()
        self.join(timeout=2)
        self.conn.close()


@pytest.mark.skipif(not os.path.exists(SUPPORTPROXY_BIN),
                    reason='supportproxy binary not built')
class TestParentHousekeeping:
    def test_killed_pair_recovers_while_other_pair_streams(self, proxy_workdir):
        proc = _start_proxy(proxy_workdir)
        busy = victim = None
        try:
            # Pair A: continuous fast stream, keeps the parent's epoll busy
            # via the stale registrations of the forked child's sockets.
            busy = _Blaster(PORT_A_USER, interval=0.005, source_system=10)
            busy.start()
            # Pair B: normal-rate user, keeps transmitting through the kill.
            victim = _Blaster(PORT_B_USER, interval=0.1, source_system=20)
            victim.start()

            # Both children latch their user connection.
            assert _wait(lambda: _pid_for(proxy_workdir, PORT_A_ENG, 0),
                         timeout=10), 'pair A user never registered'
            assert _wait(lambda: _pid_for(proxy_workdir, PORT_B_ENG, 0),
                         timeout=10), 'pair B user never registered'
            old_pid = _pid_for(proxy_workdir, PORT_B_ENG, 0)

            # Kill pair B's user connection via the web UI mechanism.
            ok = conntdb_lib.request_drop(
                str(proxy_workdir / 'connections.tdb'), PORT_B_ENG, 0)
            assert ok

            # Pair B's user is still sending; the parent must reap the
            # exited child, reopen the listeners and fork a fresh child
            # even though pair A's stream never pauses.
            assert _wait(
                lambda: _pid_for(proxy_workdir, PORT_B_ENG, 0)
                not in (None, old_pid),
                timeout=20), \
                'killed pair never came back while other pair streamed; ' \
                'recent proxy output:\n%s' % ''.join(proc._lines[-15:])
        finally:
            if busy:
                busy.stop()
            if victim:
                victim.stop()
            _terminate(proc)
