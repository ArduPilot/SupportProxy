"""Exercise full-width identities and explicit targets through the real proxy."""
import hashlib
import os
from pathlib import Path
import signal
import socket
import subprocess
import time

import pytest
from pymavlink import mavutil

import keydb_lib
from test_config import SUPPORTPROXY_BIN
from test_binlog_capture import (_send_data_block, _send_system_time,
                                 _recv_block_status_msgs, _wait_bin, _bin_path)

KEY = hashlib.sha256(b'sysid32-test').digest()
WORKER = int(os.environ.get('PYTEST_XDIST_WORKER', 'gw0').removeprefix('gw'))
PORT_USER = 24000 + WORKER * 2
PORT_ENG = PORT_USER + 1


@pytest.fixture
def wide_proxy(tmp_path, request):
    flags, sysid = getattr(request, 'param', (['tlog'], 0))
    db = keydb_lib.init_db(str(tmp_path / 'keys.tdb'))
    db.transaction_start()
    keydb_lib.add_entry(db, PORT_USER, PORT_ENG, 'wide', 'sysid32-test')
    for flag in flags:
        keydb_lib.set_flag(db, PORT_ENG, flag)
    keydb_lib.set_fc_sysid(db, PORT_ENG, sysid)
    db.transaction_prepare_commit()
    db.transaction_commit()
    db.close()
    log = (tmp_path / 'proxy.log').open('w')
    proc = subprocess.Popen([SUPPORTPROXY_BIN], cwd=tmp_path, stdout=log,
                            stderr=subprocess.STDOUT, start_new_session=True)
    try:
        want = {'%04X' % port for port in (PORT_USER, PORT_ENG)}
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            lines = Path('/proc/net/tcp').read_text().splitlines()[1:]
            listening = {line.split()[1].split(':')[1] for line in lines
                         if line.split()[3] == '0A'}
            if want <= listening:
                break
            assert proc.poll() is None, (tmp_path / 'proxy.log').read_text()
            time.sleep(0.02)
        else:
            pytest.fail('Proxy did not start: ' + (tmp_path / 'proxy.log').read_text())
        yield tmp_path
    finally:
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=10)
        log.close()


def heartbeat(tag):
    return mavutil.mavlink.MAVLink_heartbeat_message(
        mavutil.mavlink.MAV_TYPE_QUADROTOR,
        mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA, 0, tag, 0, 3)


def receive(link, kind, predicate, timeout=4):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        msg = link.recv_match(type=kind, blocking=True, timeout=0.1)
        if msg is not None and predicate(msg):
            return msg
    pytest.fail('No matching %s received' % kind)


@pytest.mark.parametrize('transport', ['udpout', 'tcp', 'ws'])
@pytest.mark.parametrize('wide_proxy', [(['tlog'], 0), (['tlog', 'bidi_sign'], 0)], indirect=True)
def test_forward_wide_ids_and_targets(wide_proxy, transport, request):
    bidi = 'bidi_sign' in request.node.callspec.params['wide_proxy'][0]
    def connect(port, source):
        endpoint = (transport + ':127.0.0.1:%d') % port
        return mavutil.mavlink_connection(endpoint, source_system=source, source_component=11)
    user = connect(PORT_USER, 0xFEDCBA98)
    if bidi:
        user.setup_signing(KEY, sign_outgoing=True)
    user.mav.send(heartbeat(100))
    eng = connect(PORT_ENG, 0xFFFFFFFF)
    eng.setup_signing(KEY, sign_outgoing=True)
    try:
        eng.mav.send(heartbeat(101))
        receive(user, 'HEARTBEAT', lambda m: m.custom_mode == 101)
        cases = [(42, None), (0xFFFFFFFF, None), (42, 7), (42, 0),
                 (42, 0xFFFFFFFF), (0xFEDCBA98, 0x80000000)]
        expected = set()
        tag = 200
        for sender, receiver, signed in [(user, eng, True), (eng, user, bidi)]:
            for source, target in cases:
                sender.mav.srcSystem = source
                if target is None:
                    msg = heartbeat(tag)
                    predicate = lambda m: m.custom_mode == tag
                else:
                    msg = mavutil.mavlink.MAVLink_command_long_message(target, 250, 300, 1,
                                                                      tag, 2, 3, 4, 5, 6, 7)
                    predicate = lambda m: m.param1 == tag
                sender.mav.send(msg)
                got = receive(receiver, msg.get_type(), predicate)
                assert got.get_srcSystem() == source
                assert got.get_srcComponent() == 11
                assert got.get_seq() == msg.get_seq()
                assert got.get_target_system() == target
                assert bool(got.get_header().incompat_flags & 1) == signed
                if target is not None:
                    assert got.get_target_component() == 250
                expected.add((source, target, tag))
                tag += 1
            # Maximum-size targeted payloads must retain their contents.
            msg = mavutil.mavlink.MAVLink_file_transfer_protocol_message(0, 0x87654321, 250, list(range(251)))
            sender.mav.send(msg)
            got = receive(receiver, 'FILE_TRANSFER_PROTOCOL', lambda m: m.get_target_system() == 0x87654321)
            assert got.get_payload() == msg.get_payload()
            assert got.get_payload()[1:3] == bytes([255, 250])
            assert list(got.payload) == list(range(251))
            # A future extension byte fills the 255-byte payload: the relay
            # must retain it even though its dialect only knows 254 bytes.
            payload = bytes(msg.get_payload()) + b'\xa5'
            sender.write(msg._pack(sender.mav, msg.crc_extra, payload))
            got = receive(receiver, 'FILE_TRANSFER_PROTOCOL', lambda m: len(m.get_payload()) == 255)
            assert got.get_payload() == payload
            assert got.get_target_system() == 0x87654321
            assert len(got.get_msgbuf()) == (287 if signed else 274)
        if not bidi:
            # Legacy MAVLink1 user traffic still forwards with signing.
            user.mav.srcSystem = 42
            user.mav.send(heartbeat(998), force_mavlink1=True)
            got = receive(eng, 'HEARTBEAT', lambda m: m.custom_mode == 998)
            assert got.get_srcSystem() == 42
            assert got.get_target_system() is None
        # Incoming signatures must still be checked for full-width sources.
        eng.mav.srcSystem = 0xFFFFFFFF
        invalid = bytearray(heartbeat(999).pack(eng.mav))
        invalid[-1] ^= 1
        eng.write(invalid)
        assert user.recv_match(type='HEARTBEAT', blocking=True, timeout=0.3) is None
        eng.mav.send(heartbeat(1000))
        receive(user, 'HEARTBEAT', lambda m: m.custom_mode == 1000)
        # Proxy-generated signing warnings use the full remembered vehicle ID.
        user.mav.srcSystem = 0xFEDCBA98
        user.mav.send(heartbeat(1001))
        receive(eng, 'HEARTBEAT', lambda m: m.custom_mode == 1001)
        eng.mav.signing.sign_outgoing = False
        deadline = time.monotonic() + 3
        warning = None
        while time.monotonic() < deadline:
            eng.mav.send(heartbeat(1002))
            warning = eng.recv_match(type='STATUSTEXT', blocking=True, timeout=0.2)
            if warning is not None:
                break
        assert warning is not None
        assert warning.get_srcSystem() == 0xFEDCBA98
        assert warning.get_srcComponent() == 11
        assert warning.text == 'Need to use support signing key'
    finally:
        eng.close()
        user.close()
    logs = list(wide_proxy.rglob('*.tlog'))
    assert logs
    recorded = set()
    for path in logs:
        # The mmap indexer still assumes fixed-size MAVLink2 headers.
        reader = mavutil.mavlogfile(str(path))
        try:
            while (msg := reader.recv_match(type=['HEARTBEAT', 'COMMAND_LONG'])) is not None:
                tag = msg.custom_mode if msg.get_type() == "HEARTBEAT" else int(msg.param1)
                recorded.add((msg.get_srcSystem(), msg.get_target_system(), tag))
        finally:
            reader.close()
    assert expected <= recorded


@pytest.mark.parametrize('wide_proxy', [(['binlog'], 257), (['binlog'], 0x80000001),
                                       (['binlog'], 0xFFFFFFFF)], indirect=True)
def test_wide_binlog_ack_and_reboot_filter(wide_proxy, request):
    sysid = request.node.callspec.params['wide_proxy'][1]
    dest = ('127.0.0.1', PORT_USER)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('127.0.0.1', 0))
        _send_system_time(sock, dest, 60000, sysid=sysid)
        _send_data_block(sock, dest, 0, b'A' * 200, sysid=sysid)
        assert _wait_bin(wide_proxy, PORT_ENG, min_size=200)
        replies = _recv_block_status_msgs(sock, timeout=0.5)
        assert any(m.seqno == 0 and m.get_target_system() == sysid for m in replies)
        # Same low byte is a different vehicle and must not trigger rotation.
        _send_system_time(sock, dest, 1000, sysid=sysid & 255)
        _send_data_block(sock, dest, 1, b'B' * 200, sysid=sysid)
        assert _wait_bin(wide_proxy, PORT_ENG, min_size=400)
        assert not _bin_path(wide_proxy, PORT_ENG, 2).exists()
        # The matching full-width source must trigger rotation.
        _send_system_time(sock, dest, 1000, sysid=sysid)
        _send_data_block(sock, dest, 0, b'C' * 200, sysid=sysid)
        second = _wait_bin(wide_proxy, PORT_ENG, n=2, min_size=200)
        assert second
        assert second.read_bytes()[:200] == b'C' * 200
