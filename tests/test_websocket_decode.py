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

