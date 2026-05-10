"""End-to-end test for tlog capture.

Sets up an isolated workdir with keys.tdb (KEY_FLAG_TLOG enabled),
starts supportproxy there, drives a few HEARTBEATs in each direction,
kills the proxy, and asserts:

  * logs/<port2>/<today>/session1.tlog exists, is non-empty, and parses
    with pymavlink.mavutil.mavlink_connection
  * a second connection (after the first child idles out) produces
    session2.tlog
  * timestamps in the tlog are monotonic
  * messages from BOTH directions appear (at minimum, both sides'
    HEARTBEATs are seen)
"""
import datetime
import os
import signal
import socket
import struct
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

# Worker-aware ports so xdist runs don't fight over them.
_W = int(os.environ.get('PYTEST_XDIST_WORKER', 'gw0')[2:]
         if os.environ.get('PYTEST_XDIST_WORKER', 'gw0').startswith('gw') else 0)
PORT_USER = 17500 + _W * 4
PORT_ENG  = 17501 + _W * 4

os.environ.setdefault('MAVLINK_DIALECT', 'ardupilotmega')
os.environ.setdefault('MAVLINK20', '1')


def _today_str():
    """Match the proxy's localtime-based directory naming."""
    return datetime.datetime.now().strftime('%Y-%m-%d')


@pytest.fixture
def proxy_workdir(tmp_path):
    p = tmp_path / 'work'
    p.mkdir()
    db_path = str(p / 'keys.tdb')
    db = keydb_lib.init_db(db_path)
    db.transaction_start()
    keydb_lib.add_entry(db, PORT_USER, PORT_ENG, 'tlog_test', 'tlogpw')
    keydb_lib.set_flag(db, PORT_ENG, 'tlog')
    keydb_lib.set_tlog_retention(db, PORT_ENG, 7.0)
    db.transaction_prepare_commit()
    db.transaction_commit()
    db.close()
    return p


def _start_proxy(workdir, env_extra=None):
    """Spawn supportproxy and drain its stdout in a background thread.

    The drain is essential: the proxy logs per-connection events to
    stdout, and if the pipe fills (~64 KiB) the child blocks on write
    inside printf(), which stalls main_loop and stops the tlog tap.
    """
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    proc = subprocess.Popen(
        [SUPPORTPROXY_BIN], cwd=str(workdir), env=env,
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
        raise RuntimeError(
            'proxy did not load test port pair; stdout: '
            + ''.join(proc._lines))
    return proc


def _wait_for_log(proc, needle, timeout=10.0):
    """Spin until any line in proc._lines contains `needle`, or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if any(needle in line for line in proc._lines):
            return True
        time.sleep(0.1)
    return False


def _terminate(proc):
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)
    if hasattr(proc, '_thread'):
        proc._thread.join(timeout=2)


def _drive_traffic(passphrase, duration=2.5):
    """Open a user UDP and a signed engineer UDP and pump HEARTBEATs in
    both directions. We return after `duration` seconds."""
    from pymavlink import mavutil

    user = mavutil.mavlink_connection('udpout:127.0.0.1:%d' % PORT_USER,
                                      source_system=10, source_component=20)
    eng = mavutil.mavlink_connection('udpout:127.0.0.1:%d' % PORT_ENG,
                                     source_system=11, source_component=21)
    # Engineer side requires signing.
    import hashlib
    secret = hashlib.sha256(passphrase.encode('utf-8')).digest()
    eng.setup_signing(secret, sign_outgoing=True)

    # Send the user's HEARTBEAT first so the proxy registers conn1, then
    # alternate directions for ~duration.
    user.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_QUADROTOR,
                            mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
                            0, 0, 0)
    time.sleep(0.2)

    deadline = time.time() + duration
    user_count = 0
    eng_count = 0
    while time.time() < deadline:
        user.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_QUADROTOR,
                                mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
                                0, 0, 0)
        user_count += 1
        eng.mav.heartbeat_send(mavutil.mavlink.MAV_TYPE_GCS,
                               mavutil.mavlink.MAV_AUTOPILOT_INVALID,
                               0, 0, 0)
        eng_count += 1
        time.sleep(0.1)

    user.close()
    eng.close()
    return user_count, eng_count


def _read_tlog_records(path):
    """Yield (timestamp_us, frame_bytes) tuples from a MAVProxy tlog.

    We don't try to MAVLink-parse the frame here; we just walk records
    by reading the 8-byte timestamp + length-from-header. This avoids
    pulling pymavlink into the assertion loop and lets us validate the
    raw on-disk shape directly.
    """
    with open(path, 'rb') as f:
        data = f.read()
    i = 0
    while i + 8 <= len(data):
        ts = struct.unpack('>Q', data[i:i+8])[0]
        i += 8
        if i + 1 > len(data):
            break
        stx = data[i]
        if stx == 0xFD:
            if i + 10 > len(data):
                break
            payload_len = data[i+1]
            incompat = data[i+2]
            sig = 13 if (incompat & 0x01) else 0
            frame_len = 10 + payload_len + 2 + sig
        elif stx == 0xFE:
            if i + 6 > len(data):
                break
            payload_len = data[i+1]
            frame_len = 6 + payload_len + 2
        else:
            break  # desync
        if i + frame_len > len(data):
            break
        yield ts, data[i:i+frame_len]
        i += frame_len


def _parse_tlog_with_pymavlink(path):
    """Open the tlog with pymavlink and pull a few messages out so we
    confirm mavlogdump-equivalent readers can consume it."""
    from pymavlink import mavutil
    m = mavutil.mavlink_connection(path)
    msgs = []
    while True:
        msg = m.recv_match(blocking=False)
        if msg is None:
            break
        msgs.append(msg)
    m.close()
    return msgs


@pytest.mark.skipif(not os.path.exists(SUPPORTPROXY_BIN),
                    reason='supportproxy binary not built')
class TestTlogCapture:
    def test_session1_created_with_bidirectional_traffic(self, proxy_workdir):
        proc = _start_proxy(proxy_workdir)
        try:
            _drive_traffic('tlogpw', duration=2.0)
            # give the proxy a moment to flush any buffered writes
            time.sleep(0.5)
        finally:
            _terminate(proc)

        tlog = (proxy_workdir / 'logs' / str(PORT_ENG)
                / _today_str() / 'session1.tlog')
        assert tlog.exists(), 'expected %s to exist; proxy stdout: %s' % (
            tlog, ''.join(getattr(proc, '_lines', [])))
        assert tlog.stat().st_size > 0

        # Validate every record has a sane framed packet behind its 8-byte ts.
        records = list(_read_tlog_records(str(tlog)))
        assert len(records) > 0, 'tlog had no records'

        # Timestamps should be monotonic.
        prev = 0
        for ts, _ in records:
            assert ts >= prev, 'timestamps regressed: %d < %d' % (ts, prev)
            prev = ts

        # Both directions must show up. We track sysid (10 = user, 11 = eng).
        sysids = set()
        for _, frame in records:
            if frame[0] == 0xFD:
                # v2: header at [0..10), payload at [10..10+len), sysid at byte 5
                sysids.add(frame[5])
            elif frame[0] == 0xFE:
                # v1: sysid at byte 3
                sysids.add(frame[3])
        proxy_log = ''.join(getattr(proc, '_lines', []))
        assert 10 in sysids, 'no user frames (sysid 10); have %r\nproxy log:\n%s' % (
            sysids, proxy_log)
        assert 11 in sysids, 'no engineer frames (sysid 11); have %r\nproxy log:\n%s' % (
            sysids, proxy_log)

    def test_pymavlink_can_read_tlog(self, proxy_workdir):
        proc = _start_proxy(proxy_workdir)
        try:
            _drive_traffic('tlogpw', duration=1.5)
            time.sleep(0.5)
        finally:
            _terminate(proc)

        tlog = (proxy_workdir / 'logs' / str(PORT_ENG)
                / _today_str() / 'session1.tlog')
        assert tlog.exists()
        msgs = _parse_tlog_with_pymavlink(str(tlog))
        # We sent at minimum a few HEARTBEATs each way; pymavlink should
        # decode at least one of them.
        types = {m.get_type() for m in msgs}
        assert 'HEARTBEAT' in types, (
            'pymavlink did not decode any HEARTBEAT; saw %r' % types)

    def test_second_connection_creates_session2(self, proxy_workdir):
        proc = _start_proxy(proxy_workdir)
        try:
            _drive_traffic('tlogpw', duration=1.5)
            # The per-port-pair child idles out after 10s of conn1 silence,
            # then the parent reaps it and reopens the listening sockets.
            # Those sockets aren't re-added to the parent's epoll set until
            # the next 5s reload tick, so we wait for "Child ... exited" and
            # then a further ~6s before sending the second batch — anything
            # tighter races the rebuild cadence.
            assert _wait_for_log(proc, 'exited', timeout=15.0), \
                'first child never exited'
            time.sleep(6.0)
            _drive_traffic('tlogpw', duration=1.5)
            time.sleep(0.5)
        finally:
            _terminate(proc)

        date_dir = proxy_workdir / 'logs' / str(PORT_ENG) / _today_str()
        proxy_log = ''.join(getattr(proc, '_lines', []))
        assert (date_dir / 'session1.tlog').exists(), proxy_log
        assert (date_dir / 'session2.tlog').exists(), (
            'expected session2.tlog after second connection; have %r\n'
            'proxy log:\n%s' % (
                sorted(p.name for p in date_dir.iterdir()), proxy_log))
