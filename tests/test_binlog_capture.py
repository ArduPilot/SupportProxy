"""End-to-end tests for the ArduPilot binary-log capture feature.

We launch the real supportproxy binary against a fresh keys.tdb that
has KEY_FLAG_BINLOG (and optionally KEY_FLAG_TLOG) set on a test
entry, drive synthetic REMOTE_LOG_DATA_BLOCK packets through the
user-side UDP port via pymavlink (using the ardupilotmega dialect),
and assert:

  * a sessionN.bin file appears at the expected sparse-file path,
  * its contents match what we sent at each seqno*200 offset,
  * REMOTE_LOG_BLOCK_STATUS=ACK comes back through the user-side
    socket for each block,
  * a connected "engineer" pymavlink instance on port2 sees
    *zero* msgid-184/185 messages (they're stripped from the
    forward path),
  * a forced gap (skip seqno N, then send N+1..) results in a
    REMOTE_LOG_BLOCK_STATUS=NACK for the missing seqno,
  * with both KEY_FLAG_TLOG and KEY_FLAG_BINLOG set, the resulting
    .tlog and .bin files share the same N (paired-N invariant).
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

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import keydb_lib  # noqa: E402

SUPPORTPROXY_BIN = os.path.join(_REPO_ROOT, 'supportproxy')

# Worker-aware ports so xdist runs don't fight over them.
_W = int(os.environ.get('PYTEST_XDIST_WORKER', 'gw0')[2:]
         if os.environ.get('PYTEST_XDIST_WORKER', 'gw0').startswith('gw') else 0)
PORT_USER = 17800 + _W * 4
PORT_ENG = 17801 + _W * 4
PORT_USER_PAIR = 17900 + _W * 4
PORT_ENG_PAIR = 17901 + _W * 4

os.environ.setdefault('MAVLINK_DIALECT', 'ardupilotmega')
os.environ.setdefault('MAVLINK20', '1')


def _today_str():
    return datetime.datetime.now().strftime('%Y-%m-%d')


@pytest.fixture
def proxy_workdir(tmp_path):
    p = tmp_path / 'work'
    p.mkdir()
    return p


def _setup_db(workdir, port_user, port_eng, name, passphrase, *flags):
    db_path = str(workdir / 'keys.tdb')
    db = keydb_lib.init_db(db_path)
    db.transaction_start()
    keydb_lib.add_entry(db, port_user, port_eng, name, passphrase)
    for f in flags:
        keydb_lib.set_flag(db, port_eng, f)
    db.transaction_prepare_commit()
    db.transaction_commit()
    db.close()


def _start_proxy(workdir, port_eng):
    proc = subprocess.Popen(
        [SUPPORTPROXY_BIN], cwd=str(workdir),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        bufsize=1, text=True,
    )
    proc._lines = []
    proc._ready = threading.Event()
    needle = 'Added port'

    def _drain():
        for line in iter(proc.stdout.readline, ''):
            proc._lines.append(line)
            if needle in line and str(port_eng) in line:
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


def _terminate(proc):
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)
    if hasattr(proc, '_thread'):
        proc._thread.join(timeout=2)


def _bin_path(workdir, port_eng, n=1):
    return (workdir / 'logs' / str(port_eng) / _today_str()
            / ('session%d.bin' % n))


def _wait_for(predicate, timeout=5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def _send_data_block(sock, dest, seqno, payload):
    """Build + send a REMOTE_LOG_DATA_BLOCK from a fake vehicle.
    payload is padded/truncated to 200 bytes."""
    from pymavlink.dialects.v20 import ardupilotmega as mav
    mav_obj = mav.MAVLink(file=None, srcSystem=1, srcComponent=1)
    data = (payload + b'\x00' * 200)[:200]
    msg = mav.MAVLink_remote_log_data_block_message(
        target_system=255, target_component=mav.MAV_COMP_ID_LOG,
        seqno=seqno, data=list(data))
    buf = msg.pack(mav_obj)
    sock.sendto(buf, dest)


def _recv_block_statuses(sock, timeout=2.0):
    """Drain incoming UDP packets, decode REMOTE_LOG_BLOCK_STATUS,
    return list of (seqno, status) seen within `timeout`."""
    from pymavlink.dialects.v20 import ardupilotmega as mav
    mav_obj = mav.MAVLink(file=None)
    sock.settimeout(0.1)
    out = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data, _ = sock.recvfrom(2048)
        except socket.timeout:
            continue
        try:
            msgs = mav_obj.parse_buffer(data) or []
        except mav.MAVError:
            continue
        for m in msgs:
            if m.get_type() == 'REMOTE_LOG_BLOCK_STATUS':
                out.append((m.seqno, m.status))
    return out


@pytest.mark.skipif(not os.path.exists(SUPPORTPROXY_BIN),
                    reason='supportproxy binary not built')
class TestBinlogCapture:

    def test_data_blocks_land_in_bin_file(self, proxy_workdir):
        _setup_db(proxy_workdir, PORT_USER, PORT_ENG, 'bintest', 'bp',
                  'binlog')
        proc = _start_proxy(proxy_workdir, PORT_ENG)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('127.0.0.1', 0))
            dest = ('127.0.0.1', PORT_USER)
            # Send seqnos 0..4 with distinguishable payloads.
            payloads = [bytes([(seq % 250) + 1]) * 50 for seq in range(5)]
            for seq, p in enumerate(payloads):
                _send_data_block(sock, dest, seq, p)
            # Allow proxy time to flush.
            assert _wait_for(
                lambda: _bin_path(proxy_workdir, PORT_ENG).exists()
                        and _bin_path(proxy_workdir, PORT_ENG).stat().st_size
                        >= 1000,
                timeout=5.0), \
                'bin file not written; proxy log:\n%s' % (
                    ''.join(getattr(proc, '_lines', [])))

            with open(_bin_path(proxy_workdir, PORT_ENG), 'rb') as f:
                content = f.read()
            assert len(content) == 5 * 200
            for seq, p in enumerate(payloads):
                expect = (p + b'\x00' * 200)[:200]
                got = content[seq * 200:(seq + 1) * 200]
                assert got == expect, 'mismatch at seq %d' % seq

            # ACKs should have come back for each block.
            statuses = _recv_block_statuses(sock, timeout=1.5)
            ack_seqnos = sorted(s for s, st in statuses if st == 1)
            assert set(ack_seqnos) >= set(range(5)), \
                'missing ACKs; saw %r' % statuses
            sock.close()
        finally:
            _terminate(proc)

    def test_engineer_does_not_see_remote_log_msgs(self, proxy_workdir):
        from pymavlink import mavutil
        _setup_db(proxy_workdir, PORT_USER, PORT_ENG, 'bintest', 'bp',
                  'binlog')
        proc = _start_proxy(proxy_workdir, PORT_ENG)
        try:
            # Connect "engineer" first (signed) — the proxy needs at least
            # one engineer slot occupied to route the user→engineer path.
            secret = hashlib.sha256(b'bp').digest()
            eng = mavutil.mavlink_connection(
                'udpout:127.0.0.1:%d' % PORT_ENG,
                source_system=11, source_component=21)
            eng.setup_signing(secret, sign_outgoing=True)
            # Send a HEARTBEAT to register the engineer slot.
            eng.mav.heartbeat_send(0, 0, 0, 0, 0)
            time.sleep(0.4)

            # Non-blocking so recv_match returns None on no data instead
            # of throwing TimeoutError (which pymavlink doesn't catch).
            eng.port.setblocking(False)

            # Now drive REMOTE_LOG_DATA_BLOCKs from the "vehicle".
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('127.0.0.1', 0))
            for seq in range(3):
                _send_data_block(sock, ('127.0.0.1', PORT_USER), seq,
                                 b'\x42' * 50)
                time.sleep(0.1)
            time.sleep(0.5)

            # Drain anything on the engineer side and check no REMOTE_LOG_*
            # messages got through.
            seen = set()
            deadline = time.time() + 1.5
            while time.time() < deadline:
                try:
                    m = eng.recv_match(blocking=False)
                except (BlockingIOError, OSError):
                    m = None
                if m is None:
                    time.sleep(0.05)
                    continue
                seen.add(m.get_type())
            assert 'REMOTE_LOG_DATA_BLOCK' not in seen, \
                'engineer saw stripped msg; types=%r' % seen
            assert 'REMOTE_LOG_BLOCK_STATUS' not in seen
            sock.close()
            eng.close()
        finally:
            _terminate(proc)

    def test_gap_triggers_nack(self, proxy_workdir):
        _setup_db(proxy_workdir, PORT_USER, PORT_ENG, 'bintest', 'bp',
                  'binlog')
        proc = _start_proxy(proxy_workdir, PORT_ENG)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('127.0.0.1', 0))
            dest = ('127.0.0.1', PORT_USER)

            # Send 0, then jump to 2, 3, 4 — leaving 1 missing.
            _send_data_block(sock, dest, 0, b'\x01' * 50)
            time.sleep(0.2)
            for seq in [2, 3, 4]:
                _send_data_block(sock, dest, seq, b'\x02' * 50)
            # Wait for the proxy's tick to fire NACK(s) for seq 1.
            statuses = _recv_block_statuses(sock, timeout=2.5)
            nack_seqnos = [s for s, st in statuses if st == 0]
            assert 1 in nack_seqnos, 'no NACK for missing seq 1; saw %r' % statuses

            # Now fill the gap; subsequent NACK pump should drop the
            # state.
            _send_data_block(sock, dest, 1, b'\x03' * 50)
            time.sleep(0.7)
            statuses_after = _recv_block_statuses(sock, timeout=1.0)
            # Once filled, no further NACK for seq 1.
            assert all(not (s == 1 and st == 0) for s, st in statuses_after)
            sock.close()
        finally:
            _terminate(proc)

    def test_proxy_sends_remote_log_start_when_idle(self, proxy_workdir):
        """ArduPilot's mavlink-backend logger sits in
        _sending_to_client = false until it receives a STATUS message
        with seqno=MAV_REMOTE_LOG_DATA_BLOCK_START (2147483646) +
        status=ACK. While in that state, logging_failed() returns
        true and pre-arm rejects the vehicle. The proxy must
        therefore send START periodically (1 Hz) any time
        KEY_FLAG_BINLOG is set and no DATA_BLOCK has arrived yet.

        Test: drive a single user-side packet (HEARTBEAT) so the
        proxy registers conn1, then wait and assert the proxy emits
        REMOTE_LOG_BLOCK_STATUS(seqno=START_MAGIC, status=ACK) back
        through the user-side socket."""
        START_MAGIC = 2147483646
        _setup_db(proxy_workdir, PORT_USER, PORT_ENG, 'bintest', 'bp',
                  'binlog')
        proc = _start_proxy(proxy_workdir, PORT_ENG)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('127.0.0.1', 0))
            dest = ('127.0.0.1', PORT_USER)

            # Drive HEARTBEATs the way a real ArduPilot does (~1 Hz) so
            # the proxy's select() keeps waking and main_loop.tick()
            # has a chance to fire. A single quiet HEARTBEAT would
            # only trigger one tick before main_loop's idle-timeout
            # kicks in.
            from pymavlink.dialects.v20 import ardupilotmega as mav
            hb_mav = mav.MAVLink(file=None, srcSystem=1, srcComponent=1)
            hb_msg = mav.MAVLink_heartbeat_message(
                type=0, autopilot=0, base_mode=0, custom_mode=0,
                system_status=0, mavlink_version=3)
            hb_bytes = hb_msg.pack(hb_mav)
            collected = []
            sock.settimeout(0.1)
            deadline = time.time() + 3.0
            while time.time() < deadline:
                sock.sendto(hb_bytes, dest)
                # Drain whatever's queued in the kernel buffer.
                try:
                    while True:
                        data, _ = sock.recvfrom(2048)
                        collected.append(data)
                except socket.timeout:
                    pass
            from pymavlink.dialects.v20 import ardupilotmega as mav2
            decoder = mav2.MAVLink(file=None)
            start_seqnos = []
            for blob in collected:
                try:
                    msgs = decoder.parse_buffer(blob) or []
                except mav2.MAVError:
                    continue
                for m in msgs:
                    if m.get_type() == 'REMOTE_LOG_BLOCK_STATUS' \
                       and m.seqno == START_MAGIC and m.status == 1:
                        start_seqnos.append(m.seqno)
            assert len(start_seqnos) >= 2, \
                'expected ≥ 2 START messages in 3s, got %d' % len(start_seqnos)
            sock.close()
        finally:
            _terminate(proc)

    def test_proxy_stops_sending_start_after_first_data_block(self, proxy_workdir):
        """Once the vehicle starts streaming (any DATA_BLOCK arrives),
        the proxy no longer needs to nudge it — the continuous ACK
        traffic from the proxy's data path keeps ArduPilot's 10 s
        client-timeout from firing. Verify START stops once a real
        DATA_BLOCK arrives."""
        START_MAGIC = 2147483646
        _setup_db(proxy_workdir, PORT_USER, PORT_ENG, 'bintest', 'bp',
                  'binlog')
        proc = _start_proxy(proxy_workdir, PORT_ENG)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('127.0.0.1', 0))
            dest = ('127.0.0.1', PORT_USER)

            # Vehicle starts streaming right away.
            _send_data_block(sock, dest, 0, b'\x10' * 50)
            _send_data_block(sock, dest, 1, b'\x11' * 50)
            time.sleep(0.5)
            # Drain the ACKs we expect for the data blocks.
            _recv_block_statuses(sock, timeout=0.5)
            # Now wait 2 s and confirm NO new START messages.
            statuses = _recv_block_statuses(sock, timeout=2.0)
            assert not any(s == START_MAGIC for s, _ in statuses), \
                'unexpected START after data flowing; saw %r' % statuses
            sock.close()
        finally:
            _terminate(proc)

    def test_strict_start_gate_discards_pre_seqno_0(self, proxy_workdir):
        """A vehicle that was already streaming when SupportProxy
        activated will have a non-zero seqno on its first DATA_BLOCK.
        Writing at offset seqno*200 would sparse-extend the file out
        to GB and produce a bin that doesn't start with FMT records
        (which DFReader requires). The strict-start gate: drop any
        DATA_BLOCK with seqno != 0 until a fresh seqno=0 arrives."""
        _setup_db(proxy_workdir, PORT_USER, PORT_ENG, 'bintest', 'bp',
                  'binlog')
        proc = _start_proxy(proxy_workdir, PORT_ENG)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('127.0.0.1', 0))
            dest = ('127.0.0.1', PORT_USER)

            # Mid-stream seqnos: pretend the vehicle has been logging
            # since seqno=1000.
            for seq in (1000, 1001, 1002, 1003):
                _send_data_block(sock, dest, seq, b'\x99' * 50)
            time.sleep(0.7)

            # No file should exist yet — strict gate.
            date_dir = (proxy_workdir / 'logs' / str(PORT_ENG)
                        / _today_str())
            if date_dir.exists():
                files = sorted(p.name for p in date_dir.iterdir())
                assert not any(f.endswith('.bin') for f in files), \
                    'file created from mid-stream seqno; have %r' % files

            # Also: no ACKs sent (the proxy hasn't latched onto the
            # session, so even pending_acks should be empty).
            statuses = _recv_block_statuses(sock, timeout=0.5)
            assert all(s != 1000 and s != 1001 and s != 1002 and s != 1003
                       for s, _ in statuses), \
                'pre-seqno-0 blocks should not be ACKed; saw %r' % statuses

            # Now the vehicle restarts and we see seqno=0. File opens.
            _send_data_block(sock, dest, 0, b'\x11' * 50)
            _send_data_block(sock, dest, 1, b'\x22' * 50)
            assert _wait_for(
                lambda: _bin_path(proxy_workdir, PORT_ENG).exists()
                        and _bin_path(proxy_workdir, PORT_ENG).stat().st_size
                        >= 400,
                timeout=5.0), \
                'file not opened after seqno=0; proxy log:\n%s' % (
                    ''.join(getattr(proc, '_lines', [])))
            with open(_bin_path(proxy_workdir, PORT_ENG), 'rb') as f:
                content = f.read()
            # File is exactly 400 bytes (seqno 0 + 1), no sparse extension.
            assert len(content) == 400
            assert content[:50] == b'\x11' * 50
            assert content[200:250] == b'\x22' * 50
            sock.close()
        finally:
            _terminate(proc)

    def test_bin_parses_with_dfreader(self, proxy_workdir):
        """End-to-end: pack a minimal-but-valid ArduPilot bin payload
        (one FMT-of-FMT record) into DATA_BLOCKs, drive them through
        the proxy with strict seqno-0 start, then open the resulting
        sessionN.bin with pymavlink.DFReader.DFReader_binary and
        assert it parses without error and yields the FMT record back.

        This is the test that would have caught the FireVPS
        session22.bin corruption — without it, the proxy could write
        any garbage into the file and we'd never notice."""
        from pymavlink import DFReader
        _setup_db(proxy_workdir, PORT_USER, PORT_ENG, 'bintest', 'bp',
                  'binlog')

        # Minimal valid bin: a single FMT-of-FMT record (89 bytes),
        # padded with zero bytes to 200 to fill one DATA_BLOCK slot.
        # DFReader_binary's record framer skips the zero padding by
        # scanning for the next 0xA3 0x95 marker, so this layout is
        # parseable.
        HEAD = bytes([0xA3, 0x95])
        FMT_MSG_TYPE = 0x80
        fmt_body = (HEAD + bytes([FMT_MSG_TYPE]) +
                    bytes([FMT_MSG_TYPE, 89]) +
                    b'FMT\x00' +
                    b'BBnNZ'.ljust(16, b'\x00') +
                    b'Type,Length,Name,Format,Columns'.ljust(64, b'\x00'))
        assert len(fmt_body) == 89
        block0 = fmt_body + b'\x00' * (200 - len(fmt_body))

        proc = _start_proxy(proxy_workdir, PORT_ENG)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('127.0.0.1', 0))
            dest = ('127.0.0.1', PORT_USER)
            _send_data_block(sock, dest, 0, block0)
            assert _wait_for(
                lambda: _bin_path(proxy_workdir, PORT_ENG).exists()
                        and _bin_path(proxy_workdir, PORT_ENG).stat().st_size
                        >= 200,
                timeout=5.0)
            sock.close()

            # Parse with DFReader.
            log = DFReader.DFReader_binary(
                str(_bin_path(proxy_workdir, PORT_ENG)))
            types_seen = set()
            while True:
                m = log.recv_match()
                if m is None:
                    break
                types_seen.add(m.get_type())
            assert 'FMT' in types_seen, \
                "DFReader didn't parse a FMT record; saw %r" % types_seen
        finally:
            _terminate(proc)

    def test_paired_session_n_with_tlog(self, proxy_workdir):
        """tlog + binlog flags both set on one entry should produce
        sessionN.tlog and sessionN.bin sharing the same N. We drive
        traffic from a single raw socket (sending DATA_BLOCKs) so the
        proxy's connect() on first peer doesn't lock us out of
        subsequent sends.

        DATA_BLOCK frames are valid MAVLink, so they trip the tlog tap
        before the binlog tap consumes them — both writers light up
        from the same stream of frames."""
        from pymavlink import mavutil
        _setup_db(proxy_workdir, PORT_USER_PAIR, PORT_ENG_PAIR,
                  'bintest_pair', 'pp', 'tlog', 'binlog')
        proc = _start_proxy(proxy_workdir, PORT_ENG_PAIR)
        try:
            # Engineer needs to be connected so the user-side parser
            # also feeds tlog (tlog tap is inside the conn2_count>0
            # branch — pre-existing constraint).
            secret = hashlib.sha256(b'pp').digest()
            eng = mavutil.mavlink_connection(
                'udpout:127.0.0.1:%d' % PORT_ENG_PAIR,
                source_system=11, source_component=21)
            eng.setup_signing(secret, sign_outgoing=True)
            eng.mav.heartbeat_send(0, 0, 0, 0, 0)
            time.sleep(0.3)

            # Single user socket — sends DATA_BLOCKs which are valid
            # MAVLink frames. Tlog tap fires, then binlog tap consumes
            # and writes to sessionN.bin.
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('127.0.0.1', 0))
            for seq in range(3):
                _send_data_block(sock, ('127.0.0.1', PORT_USER_PAIR),
                                 seq, b'\x55' * 50)
                time.sleep(0.05)
            time.sleep(0.7)
            sock.close(); eng.close()

            date_dir = (proxy_workdir / 'logs' / str(PORT_ENG_PAIR)
                        / _today_str())
            files = sorted(p.name for p in date_dir.iterdir())
            assert (date_dir / 'session1.tlog').exists(), \
                'no session1.tlog; have %r' % files
            assert (date_dir / 'session1.bin').exists(), \
                'no session1.bin; have %r\nproxy log:\n%s' % (
                    files, ''.join(getattr(proc, '_lines', [])))
        finally:
            _terminate(proc)
