"""Regression test: the proxy must not write MAVLink frames to a
would-be WebSocket user before it has sent the HTTP upgrade (101)
response. If it does, the frame lands ahead of the "HTTP/1.1 101"
status line and corrupts the handshake — the peer's WS parser chokes
on binary garbage where the status line should be (observed in the
field as `illegal status line: bytearray(b'\\xfd\\t...HTTP/1.1 101')`,
0xfd being the MAVLink2 magic).

Two windows are covered, each with its own fresh proxy so a sticky
conn1 can't couple the cases:

  1. TCP accepted, transport not yet known: conn1 is latched but no
     user data has been seen, so WebSocket hasn't been detected and
     mav1 is still raw-TCP. An engineer frame forwarded now goes out
     as plain MAVLink on the raw socket. (Fixed by gating the
     engineer->user forward on count1>0.)
  2. WebSocket detected but handshake unfinished: mav1 wraps the
     WebSocket but done_headers is false, so a frame would be WS-framed
     and written before the 101. (Fixed by WebSocket::send dropping
     until done_headers.)
"""
import hashlib
import os
import signal
import socket
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

_W = int(os.environ.get('PYTEST_XDIST_WORKER', 'gw0')[2:]
         if os.environ.get('PYTEST_XDIST_WORKER', 'gw0').startswith('gw') else 0)
PORT_USER = 18000 + _W * 4
PORT_ENG = 18001 + _W * 4

os.environ.setdefault('MAVLINK_DIALECT', 'all')
os.environ.setdefault('MAVLINK20', '1')


@pytest.fixture
def proxy_workdir(tmp_path):
    p = tmp_path / 'work'
    p.mkdir()
    db = keydb_lib.init_db(str(p / 'keys.tdb'))
    db.transaction_start()
    keydb_lib.add_entry(db, PORT_USER, PORT_ENG, 'wshs', 'wshspw')
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


def _drive(split_at, hold_s=1.0):
    """Connect a raw user and send the WebSocket upgrade request in two
    parts split at byte ``split_at``: the first part, then (while a
    signed engineer streams forwardable data) the rest. Returns the
    server's first response bytes.

      split_at == 0  -> send nothing first: proxy still in raw-TCP mode
                        when it tries to forward (transport undecided).
      0 < split_at < 14 -> first read is a partial handshake prefix
                        (< the 14-byte "GET / HTTP/1.1" needed to
                        classify): must not be mistaken for raw MAVLink.
      split_at past the request line, before the key -> WebSocket
                        detected but handshake not yet complete.
    """
    from pymavlink import mavutil
    import base64
    secret = hashlib.sha256(b'wshspw').digest()

    key = base64.b64encode(b"z" * 16).decode()
    req = ("GET / HTTP/1.1\r\nHost: localhost\r\n"
           "Upgrade: websocket\r\nConnection: Upgrade\r\n"
           "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n"
           % key).encode()

    u = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    u.settimeout(5.0)
    u.connect(("127.0.0.1", PORT_USER))
    if split_at:
        u.sendall(req[:split_at])
    time.sleep(0.3)

    eng = mavutil.mavlink_connection(
        'udpout:127.0.0.1:%d' % PORT_ENG,
        source_system=11, source_component=21)
    eng.setup_signing(secret, sign_outgoing=True)
    deadline = time.time() + hold_s
    while time.time() < deadline:
        eng.mav.heartbeat_send(0, 0, 0, 0, 0)
        time.sleep(0.1)

    u.sendall(req[split_at:])

    buf = b""
    rd = time.time() + 5
    while b"\r\n\r\n" not in buf and time.time() < rd:
        try:
            chunk = u.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk

    eng.close()
    u.close()
    return buf


@pytest.mark.skipif(not os.path.exists(SUPPORTPROXY_BIN),
                    reason='supportproxy binary not built')
class TestWSHandshakeOrdering:
    def _check(self, proc, split_at, why):
        buf = _drive(split_at=split_at)
        assert buf.startswith(b"HTTP/1.1 101"), \
            ("%s; first bytes: %r\nproxy log:\n%s"
             % (why, buf[:64], ''.join(proc._lines[-12:])))

    def test_no_raw_forward_before_ws_detect(self, proxy_workdir):
        # Transport undecided: send nothing before the engineer streams,
        # so the proxy is still in raw-TCP mode when it tries to forward.
        proc = _start_proxy(proxy_workdir)
        try:
            self._check(proc, 0,
                        "handshake corrupted by a raw pre-detect forward")
        finally:
            _terminate(proc)

    def test_fragmented_prefix_not_misclassified(self, proxy_workdir):
        # First read is a 9-byte prefix of "GET / HTTP/1.1" (< the 14
        # needed to classify). It must be held as "maybe WebSocket", not
        # committed to raw — otherwise the engineer's forwarded frame
        # goes out as raw MAVLink ahead of the eventual 101.
        proc = _start_proxy(proxy_workdir)
        try:
            self._check(proc, 9,
                        "fragmented GET prefix misclassified as raw")
        finally:
            _terminate(proc)

    def test_no_ws_forward_before_handshake(self, proxy_workdir):
        # WebSocket detected (full request line sent) but Sec-WebSocket-
        # Key withheld, so done_headers stays false while the engineer
        # streams.
        proc = _start_proxy(proxy_workdir)
        try:
            self._check(proc, len(b"GET / HTTP/1.1\r\nHost: localhost\r\n"),
                        "handshake corrupted by a pre-handshake WS forward")
        finally:
            _terminate(proc)
