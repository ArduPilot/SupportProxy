"""WebSocket framing tests for the cases the MAVLink path never exercised.

MAVLink frames are under 300 bytes and arrive one per segment, so the
original implementation could get away with a fixed 1 KiB buffer, no
fragmentation handling and no control-frame handling. Video traffic hits
all three. These tests pin the corrected behaviour.

Each test uses a ping/pong round trip as the liveness probe. That is a
deliberately strong assertion: a pong only comes back if the proxy
consumed *exactly* the right number of bytes for everything sent before
it, so it detects framing desync as well as connection loss.
"""
import base64
import os
import socket
import struct
import time

import pytest

from test_config import TEST_PORT_ENGINEER
from test_connections import BaseConnectionTest

# Server->client frames are never masked, so a mask of zero is only used
# on the client->server side here, where the RFC requires one.
_ZERO_MASK = b"\x00\x00\x00\x00"


def _ws_handshake(s, target="/"):
    key = base64.b64encode(b"x" * 16).decode()
    req = (
        f"GET {target} HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ).encode()
    s.sendall(req)
    s.settimeout(5.0)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    assert b"101" in buf, f"no 101 Switching Protocols: {buf!r}"


def _frame(opcode, payload=b"", fin=True, masked=True):
    """Build a client->server frame with a zero mask (payload unchanged)."""
    b0 = (0x80 if fin else 0x00) | opcode
    n = len(payload)
    mask_bit = 0x80 if masked else 0x00
    if n <= 125:
        hdr = bytes([b0, mask_bit | n])
    elif n <= 0xFFFF:
        hdr = bytes([b0, mask_bit | 126]) + struct.pack(">H", n)
    else:
        hdr = bytes([b0, mask_bit | 127]) + struct.pack(">Q", n)
    if masked:
        hdr += _ZERO_MASK
    return hdr + payload


def _read_frame(s, timeout=5.0):
    """Read one server->client frame. Returns (opcode, payload) or None."""
    s.settimeout(timeout)
    buf = b""

    def _need(k):
        nonlocal buf
        while len(buf) < k:
            chunk = s.recv(4096)
            if not chunk:
                return False
            buf += chunk
        return True

    if not _need(2):
        return None
    opcode = buf[0] & 0x0F
    ln = buf[1] & 0x7F
    pos = 2
    if ln == 126:
        if not _need(4):
            return None
        ln = struct.unpack(">H", buf[2:4])[0]
        pos = 4
    elif ln == 127:
        if not _need(10):
            return None
        ln = struct.unpack(">Q", buf[2:10])[0]
        pos = 10
    # server->client frames must not be masked
    assert (buf[1] & 0x80) == 0, "server masked a frame"
    if not _need(pos + ln):
        return None
    return opcode, buf[pos:pos + ln]


def _connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect(("127.0.0.1", TEST_PORT_ENGINEER))
    return s


def _assert_alive(s, token):
    """Ping/pong round trip: proves the link is up AND framing is in sync."""
    s.sendall(_frame(0x9, token))
    got = _read_frame(s)
    assert got is not None, "no pong: connection closed"
    assert got[0] == 0xA, f"expected pong (0xA), got opcode 0x{got[0]:x}"
    assert got[1] == token, f"pong payload mismatch: {got[1]!r} != {token!r}"


class TestWebSocketFraming(BaseConnectionTest):

    def test_ping_gets_pong(self, test_server):
        """Control frames are answered rather than passed to MAVLink."""
        s = _connect()
        try:
            _ws_handshake(s)
            _assert_alive(s, b"probe-1")
        finally:
            s.close()

    @pytest.mark.parametrize("size", [2000, 16384, 65536],
                             ids=["2k", "16k", "64k"])
    def test_large_frame_does_not_kill_connection(self, test_server, size):
        """Frames beyond the old 1 KiB pending[] used to fail the link.

        The payload is not valid MAVLink -- it gets parsed and discarded.
        What matters is that the connection survives and stays in sync.
        """
        s = _connect()
        try:
            _ws_handshake(s)
            s.sendall(_frame(0x2, b"\x00" * size))
            _assert_alive(s, b"after-large")
        finally:
            s.close()

    def test_fragmented_message_reassembled(self, test_server):
        """A message split across continuation frames must be consumed whole."""
        s = _connect()
        try:
            _ws_handshake(s)
            part = b"\x11" * 4096
            s.sendall(_frame(0x2, part, fin=False))       # first fragment
            s.sendall(_frame(0x0, part, fin=False))       # continuation
            s.sendall(_frame(0x0, part, fin=True))        # final
            _assert_alive(s, b"after-frag")
        finally:
            s.close()

    def test_interleaved_ping_during_fragments(self, test_server):
        """A control frame may arrive between fragments (RFC 6455 s5.4)."""
        s = _connect()
        try:
            _ws_handshake(s)
            s.sendall(_frame(0x2, b"\x22" * 1000, fin=False))
            _assert_alive(s, b"mid-frag")
            s.sendall(_frame(0x0, b"\x22" * 1000, fin=True))
            _assert_alive(s, b"post-frag")
        finally:
            s.close()

    def test_unmasked_client_frame_rejected(self, test_server):
        """RFC 6455 s5.1 requires client->server frames to be masked."""
        s = _connect()
        try:
            _ws_handshake(s)
            s.sendall(_frame(0x2, b"unmasked payload", masked=False))
            time.sleep(0.3)
            # The proxy must drop us; a pong would mean it accepted it.
            s.settimeout(3.0)
            try:
                data = s.recv(4096)
            except socket.timeout:
                pytest.fail("proxy neither closed nor responded to an "
                            "unmasked frame")
            assert data == b"", \
                f"expected connection close, got {data!r}"
        finally:
            s.close()

        self.assert_with_proxy_log(
            test_server, test_server.proc.poll() is None,
            "supportproxy died on an unmasked frame (should just drop the "
            "connection)")

    def test_handshake_accepts_path_and_query(self, test_server):
        """detect()/handshake must not require the literal 'GET / HTTP/1.1'.

        Video viewers connect to targets like /v1?token=... -- the old
        exact-prefix match rejected those outright.
        """
        s = _connect()
        try:
            _ws_handshake(s, target="/v1?token=abc123")
            _assert_alive(s, b"pathy")
        finally:
            s.close()
