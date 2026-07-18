"""Regression test for the WebSocket extended-payload-length overflow
(Codex security scan finding #1). Pre-fix, a crafted 0x7f-length frame
with payload_len near UINT64_MAX wrapped the completeness check in
WebSocket::decode() and let the unmask loop / memmove walk over the
fixed 1024-byte pending[] buffer. The fix bounds payload_len before
any addition; the proxy now drops the frame and stays up.
"""
import base64
import socket
import struct
import time

import pytest

from test_config import TEST_PORT_ENGINEER
from test_connections import BaseConnectionTest


def _ws_handshake(s):
    """Minimal Sec-WebSocket-Key handshake. We only need the proxy to
    switch into WebSocket framing mode; we don't validate the Accept
    value on our end."""
    key = base64.b64encode(b"x" * 16).decode()
    req = (
        "GET / HTTP/1.1\r\n"
        "Host: localhost\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    ).encode()
    s.sendall(req)
    s.settimeout(3.0)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf += chunk
    assert b"101" in buf, f"no 101 Switching Protocols: {buf!r}"


def _craft_127_frame(payload_len, payload=b""):
    """Build a binary WS frame using the 64-bit extended length encoding,
    masked (clients must mask). Zero mask leaves the payload unchanged."""
    hdr = bytes([0x82, 0x80 | 127]) + struct.pack(">Q", payload_len)
    hdr += b"\x00\x00\x00\x00"
    return hdr + payload


class TestWebSocketDecodeOverflow(BaseConnectionTest):

    @pytest.mark.parametrize("payload_len", [
        0xFFFFFFFFFFFFFFFF,   # UINT64_MAX: wraps the pre-fix add to ~14
        1 << 63,              # high bit set
        2048,                 # just over pending[1024]
    ], ids=["uint64_max", "msb_set", "just_over_buffer"])
    def test_oversized_127_frame_does_not_crash(self, test_server, payload_len):
        # use the engineer port: it supports multiple parallel TCP
        # connections, so parametrized cases don't fight over conn1.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect(("127.0.0.1", TEST_PORT_ENGINEER))
        try:
            _ws_handshake(s)
            s.sendall(_craft_127_frame(payload_len))
            # let the proxy reach decode() and reject
            time.sleep(0.3)
        finally:
            s.close()

        self.assert_with_proxy_log(
            test_server,
            test_server.proc.poll() is None,
            "supportproxy died after crafted 0x7f frame with "
            f"payload_len=0x{payload_len:x}",
        )


class TestWebSocketHandshakeOrdering(BaseConnectionTest):
    """The proxy must not forward MAVLink frames to a WebSocket peer
    before it has sent the HTTP upgrade (101) response. If it does, the
    frame lands ahead of the "HTTP/1.1 101" status line and corrupts
    the handshake — the peer's WS parser chokes on binary garbage.

    Reproduced deterministically: a raw-socket "user" sends just enough
    of the HTTP request for the proxy to detect WebSocket and create the
    server object (so done_headers is false), a signed engineer streams
    data that the proxy tries to forward to that user, and only then is
    the handshake completed. The 101 response must arrive uncorrupted.
    """

    def test_no_forward_before_handshake(self, test_server):
        from pymavlink import mavutil
        from test_config import TEST_PORT_USER, TEST_PASSPHRASE
        from test_connections import passphrase_to_key

        secret = passphrase_to_key(TEST_PASSPHRASE)

        # Raw user socket: send the request line + a header, but NOT the
        # Sec-WebSocket-Key line, so WebSocket::detect matches (opening
        # the server object) while check_headers leaves done_headers
        # false — the exact window where a forwarded frame corrupts the
        # stream.
        u = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        u.settimeout(5.0)
        u.connect(("127.0.0.1", TEST_PORT_USER))
        u.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\n")
        time.sleep(0.3)

        # Signed engineer streams heartbeats; the proxy forwards them to
        # the (mid-handshake) user via WebSocket::send.
        eng = mavutil.mavlink_connection(
            'udpout:127.0.0.1:%d' % TEST_PORT_ENGINEER,
            source_system=11, source_component=21)
        eng.setup_signing(secret, sign_outgoing=True)
        for _ in range(10):
            eng.mav.heartbeat_send(0, 0, 0, 0, 0)
            time.sleep(0.1)

        # Now finish the handshake.
        key = base64.b64encode(b"y" * 16).decode()
        u.sendall(("Sec-WebSocket-Key: %s\r\n\r\n" % key).encode())

        # Read the start of the server's response. It must begin with
        # the HTTP status line — no forwarded MAVLink frame (which would
        # start with a MAVLink magic byte, 0xFD or 0xFE) ahead of it.
        buf = b""
        deadline = time.time() + 5
        while b"\r\n\r\n" not in buf and time.time() < deadline:
            try:
                chunk = u.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk

        eng.close()
        u.close()

        assert buf.startswith(b"HTTP/1.1 101"), \
            ("handshake corrupted by a pre-handshake forward; "
             "first bytes: %r" % buf[:64])
