"""Video viewers: fan-out, join point, credentials and the drop policy.

The two properties worth testing hardest:

  * fan-out is byte-exact. Both recording and viewing promise the
    publisher's own bytes, so a viewer's stream has to appear verbatim
    in what was published -- not merely "be valid MPEG-TS".

  * one slow viewer cannot hurt anyone else. That is meant to be true
    by construction (the publisher never inspects viewer state), so the
    test drives a viewer that never reads until it is lapped and checks
    the others are untouched.
"""
import os
import socket
import subprocess
import sys
import threading
import time

import pytest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import keydb_lib  # noqa: E402
import tsgen  # noqa: E402
from test_video_child import (Proxy, Publisher, _Mav, PORT_ENG,  # noqa: E402
                              PORT_USER, PASSPHRASE, VPORT)


def _workdir(tmp_path, raw_tcp=False, viewer_pass=None):
    p = tmp_path / 'work'
    p.mkdir()
    db = keydb_lib.init_db(str(p / 'keys.tdb'))
    db.transaction_start()
    keydb_lib.add_entry(db, PORT_USER, PORT_ENG, 'vid', PASSPHRASE)
    keydb_lib.set_flag(db, PORT_ENG, 'video')
    keydb_lib.set_video_ports(db, PORT_ENG, [VPORT])
    if raw_tcp:
        keydb_lib.set_video_slot_flag(db, PORT_ENG, 0, 'raw_tcp')
    if viewer_pass:
        keydb_lib.set_video_viewer_pass(db, PORT_ENG, viewer_pass)
    db.transaction_prepare_commit()
    db.transaction_commit()
    db.close()
    return p


class Feed:
    """Publishes continuously in the background, recording every byte sent."""

    def __init__(self, port, gen=None):
        self.port = port
        self.gen = gen or tsgen.TSGen()
        self.pub = Publisher(port)
        self.sent = bytearray()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._t = None

    def burst(self, packets=200):
        data = self.gen.stream(packets, gop=10, psi_every=20)
        for dg in self.gen.datagrams(data):
            self.pub.sock.sendto(dg, ('127.0.0.1', self.port))
            with self._lock:
                self.sent += dg
            time.sleep(0.002)

    def start(self, packets=200, pause=0.05):
        def _run():
            while not self._stop.is_set():
                self.burst(packets)
                time.sleep(pause)
        self._t = threading.Thread(target=_run, daemon=True)
        self._t.start()

    def snapshot(self):
        with self._lock:
            return bytes(self.sent)

    def stop(self):
        self._stop.set()
        if self._t:
            self._t.join(timeout=5)
        self.pub.close()


class Session:
    def __init__(self, workdir, env=None):
        self.workdir = workdir
        backup = os.environ.copy()
        os.environ.update(env or {})
        try:
            self.proxy = Proxy(workdir)
        finally:
            os.environ.clear()
            os.environ.update(backup)
        assert self.proxy.wait_for(r'video slot 0 listening'), self.proxy.log
        self.mav = _Mav()
        assert self.proxy.wait_for(r'have UDP conn1'), self.proxy.log
        time.sleep(1.2)
        self.feed = Feed(VPORT)

    def wait_ready(self, timeout=25):
        """Wait until the scanner reports a joinable stream."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.feed.burst(120)
            if 'join=ready' in self.proxy.log:
                return True
            time.sleep(0.3)
        return 'join=ready' in self.proxy.log

    def stop(self):
        try:
            self.feed.stop()
        except Exception:
            pass
        self.mav.stop()
        self.proxy.stop()


@pytest.fixture
def session(tmp_path):
    made = {}

    def _start(env=None, **kw):
        wd = _workdir(tmp_path, **kw)
        made['s'] = Session(wd, env=env)
        return made['s']

    yield _start
    if 's' in made:
        made['s'].stop()


def http_get(port, path='/v1.ts', headers='', timeout=5.0):
    """Open an HTTP viewer and return (socket, response_head)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(('127.0.0.1', port))
    s.sendall(('GET %s HTTP/1.1\r\nHost: localhost\r\n%s\r\n'
               % (path, headers)).encode())
    head = b''
    while b'\r\n\r\n' not in head:
        chunk = s.recv(4096)
        if not chunk:
            break
        head += chunk
    sep = head.find(b'\r\n\r\n')
    body = head[sep + 4:] if sep >= 0 else b''
    return s, head[:sep if sep >= 0 else len(head)], body


def read_for(sock, seconds, initial=b''):
    """Drain a socket for a while and return what arrived."""
    out = bytearray(initial)
    deadline = time.time() + seconds
    sock.settimeout(0.5)
    while time.time() < deadline:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            continue
        except OSError:
            break
        if not chunk:
            break
        out += chunk
    return bytes(out)


@pytest.mark.integration
class TestHttpViewer:
    def test_stream_is_served_and_byte_exact(self, session):
        s = session()
        assert s.wait_ready(), s.proxy.log
        s.feed.start()
        sock, head, body = http_get(VPORT)
        try:
            assert b'200 OK' in head, head
            assert b'video/mp2t' in head, head
            data = read_for(sock, 4, body)
        finally:
            sock.close()
        assert len(data) > 10000, 'viewer got almost nothing: %d' % len(data)
        assert data[0] == 0x47, 'viewer stream does not start at a packet'
        sent = s.feed.snapshot()
        assert data in sent, \
            'viewer stream is not a verbatim span of what was published'

    def test_join_starts_at_a_decodable_point(self, session):
        """First bytes must be a PAT, with a PMT before any video payload.

        Serving from an arbitrary point looks exactly like a broken
        stream to the client, so this is the property that decides
        whether the feature seems to work at all.
        """
        s = session()
        assert s.wait_ready(), s.proxy.log
        s.feed.start()
        sock, head, body = http_get(VPORT)
        try:
            data = read_for(sock, 3, body)
        finally:
            sock.close()
        assert len(data) >= 188 * 4, len(data)

        def pid_of(pkt):
            return ((pkt[1] & 0x1F) << 8) | pkt[2]

        pkts = [data[i:i + 188] for i in range(0, len(data) - 187, 188)]
        assert pkts[0][0] == 0x47
        assert pid_of(pkts[0]) == 0, \
            'first packet is PID 0x%x, expected the PAT' % pid_of(pkts[0])

        saw_pmt = False
        for pkt in pkts[:40]:
            pid = pid_of(pkt)
            if pid == tsgen.DEFAULT_PMT_PID:
                saw_pmt = True
            if pid == tsgen.DEFAULT_VIDEO_PID:
                assert saw_pmt, 'video payload arrived before any PMT'
                break
        assert saw_pmt, 'no PMT near the start of the viewer stream'

    def test_two_viewers_agree_on_overlapping_bytes(self, session):
        s = session()
        assert s.wait_ready(), s.proxy.log
        s.feed.start()
        a, _, abody = http_get(VPORT)
        time.sleep(0.5)
        b, _, bbody = http_get(VPORT)
        try:
            da = read_for(a, 4, abody)
            db = read_for(b, 4, bbody)
        finally:
            a.close()
            b.close()
        assert len(da) > 5000 and len(db) > 5000, (len(da), len(db))
        # b joined no earlier than a, so b's opening run must appear
        # verbatim somewhere in a
        probe = db[:4096]
        assert probe in da or da[:4096] in db, \
            'the two viewers disagree on the same stream'

    def test_404_for_a_wrong_path(self, session):
        s = session()
        assert s.wait_ready(), s.proxy.log
        sock, head, _ = http_get(VPORT, path='/nope')
        sock.close()
        assert b'404' in head, head

    def test_503_before_the_stream_is_joinable(self, session):
        """No keyframe yet means no decodable start point; say so."""
        s = session()
        g = tsgen.TSGen()
        out = bytearray()
        for i in range(80):
            if i % 20 == 0:
                out += g.pat()
                out += g.pmt()
            out += g.video(key=False)
        for dg in g.datagrams(bytes(out)):
            s.feed.pub.sock.sendto(dg, ('127.0.0.1', VPORT))
            time.sleep(0.003)
        time.sleep(1.0)
        sock, head, _ = http_get(VPORT)
        sock.close()
        assert b'503' in head, head


@pytest.mark.integration
class TestViewerCredentials:
    def test_password_required_when_set(self, session):
        s = session(viewer_pass='watchme')
        assert s.wait_ready(), s.proxy.log
        sock, head, _ = http_get(VPORT)
        sock.close()
        assert b'401' in head, head

    def test_password_accepted_in_query(self, session):
        s = session(viewer_pass='watchme')
        assert s.wait_ready(), s.proxy.log
        sock, head, _ = http_get(VPORT, path='/v1.ts?pw=watchme')
        sock.close()
        assert b'200 OK' in head, head

    def test_password_accepted_via_basic_auth(self, session):
        import base64
        s = session(viewer_pass='watchme')
        assert s.wait_ready(), s.proxy.log
        cred = base64.b64encode(b'viewer:watchme').decode()
        sock, head, _ = http_get(VPORT,
                                 headers='Authorization: Basic %s\r\n' % cred)
        sock.close()
        assert b'200 OK' in head, head

    def test_wrong_password_refused(self, session):
        s = session(viewer_pass='watchme')
        assert s.wait_ready(), s.proxy.log
        sock, head, _ = http_get(VPORT, path='/v1.ts?pw=nope')
        sock.close()
        assert b'401' in head, head


@pytest.mark.integration
class TestRawTcpViewer:
    def test_raw_viewer_served_when_enabled(self, session):
        s = session(raw_tcp=True)
        assert s.wait_ready(), s.proxy.log
        s.feed.start()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(8)
        sock.connect(('127.0.0.1', VPORT))
        try:
            data = read_for(sock, 6)      # says nothing; detected on silence
        finally:
            sock.close()
        assert len(data) > 5000, 'raw viewer got %d bytes' % len(data)
        assert data[0] == 0x47
        assert data in s.feed.snapshot(), 'raw stream is not verbatim'

    def test_raw_viewer_refused_when_flag_off(self, session):
        s = session(raw_tcp=False)
        assert s.wait_ready(), s.proxy.log
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(8)
        sock.connect(('127.0.0.1', VPORT))
        try:
            data = read_for(sock, 5)
        finally:
            sock.close()
        assert data == b'', 'raw viewer served with the flag off'
        # wait for the line rather than reading the log straight away:
        # the proxy's stdout is drained by a separate thread
        assert s.proxy.wait_for(r'raw-TCP viewers not enabled'), s.proxy.log

    def test_raw_viewer_refused_when_a_password_is_set(self, session):
        """Raw TCP has nowhere to carry a credential, so it must not be
        a way around the viewer password."""
        s = session(raw_tcp=True, viewer_pass='watchme')
        assert s.wait_ready(), s.proxy.log
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(8)
        sock.connect(('127.0.0.1', VPORT))
        try:
            data = read_for(sock, 5)
        finally:
            sock.close()
        assert data == b'', 'raw viewer bypassed the viewer password'
        assert s.proxy.wait_for(r'cannot carry the viewer password'), \
            s.proxy.log


@pytest.mark.integration
class TestSlowViewer:
    def test_slow_viewer_dropped_without_disturbing_others(self, session):
        """A viewer that never reads must be dropped, and must not cost
        the other viewers a single byte.

        The ring is shrunk so lapping is reachable without pushing tens
        of megabytes through the test.
        """
        s = session(env={'SUPPORTPROXY_VIDEO_RING_BYTES': str(256 * 1024)})
        assert s.wait_ready(), s.proxy.log

        # A: connects, never reads.
        slow, _, _ = http_get(VPORT)
        # B: connects and reads continuously.
        fast, _, fbody = http_get(VPORT)

        got = bytearray(fbody)
        stop = threading.Event()

        def drain():
            fast.settimeout(0.5)
            while not stop.is_set():
                try:
                    c = fast.recv(65536)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not c:
                    break
                got.extend(c)

        t = threading.Thread(target=drain, daemon=True)
        t.start()
        try:
            # push well past the ring so the idle viewer is lapped
            deadline = time.time() + 30
            while time.time() < deadline:
                s.feed.burst(300)
                if 'lapped' in s.proxy.log or 'chronically behind' in s.proxy.log:
                    break
            time.sleep(1.0)
        finally:
            stop.set()
            t.join(timeout=5)
            slow.close()
            fast.close()

        assert ('lapped' in s.proxy.log
                or 'chronically behind' in s.proxy.log), \
            'the idle viewer was never dropped:\n%s' % s.proxy.log[-3000:]

        data = bytes(got)
        assert len(data) > 50000, 'the healthy viewer got %d bytes' % len(data)
        # the surviving viewer's stream must still be a contiguous,
        # verbatim run -- no hole where the other viewer was dropped
        sent = s.feed.snapshot()
        assert data in sent, \
            "the healthy viewer's stream has a gap or reordering"

    def test_viewer_cap_is_enforced(self, session):
        s = session()
        assert s.wait_ready(), s.proxy.log
        socks = []
        try:
            refused = None
            for _ in range(40):
                sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sk.settimeout(5)
                try:
                    sk.connect(('127.0.0.1', VPORT))
                except OSError:
                    sk.close()
                    break
                sk.sendall(b'GET /v1.ts HTTP/1.1\r\nHost: x\r\n\r\n')
                socks.append(sk)
            time.sleep(1.5)
            for sk in socks:
                sk.settimeout(1.0)
                try:
                    head = sk.recv(256)
                except (socket.timeout, OSError):
                    continue
                if b'503' in head and b'too many' in head.lower():
                    refused = True
                    break
            assert refused, \
                'no viewer was refused past the cap:\n%s' % s.proxy.log[-2000:]
        finally:
            for sk in socks:
                sk.close()

    def test_per_address_caps_pin_loopback_and_others(self, session):
        """127.0.0.1 is the web UI proxying HLS for every bystander, so it
        gets 24 of the 32 entries; any other address gets 8. Neither can
        take the whole table, which would deny publishing."""
        s = session()
        assert s.wait_ready(), s.proxy.log
        socks = []

        def silent(src, n):
            for _ in range(n):
                c = socket.socket()
                c.bind((src, 0))
                c.settimeout(5)
                c.connect(('127.0.0.1', VPORT))
                socks.append(c)
            return socks[len(socks) - n:]

        def refused(held):
            count = 0
            for c in held:
                c.setblocking(False)
                try:
                    if b'503' in c.recv(256):
                        count += 1
                except OSError:
                    pass     # silent: accepted and waiting
            return count

        try:
            # A silent connection is dropped after VIDEO_DETECT_SILENCE_S
            # (2 s), so both batches are opened and counted inside that
            # window to be held together.
            loopback = silent('127.0.0.1', 40)
            other = silent('127.0.0.2', 12)
            time.sleep(0.5)
            assert refused(loopback) == 40 - 24
            # 24 of the 32 entries are held by 127.0.0.1, which leaves 8
            # for the other address (also exactly its own cap)
            assert refused(other) == 12 - 8
        finally:
            for c in socks:
                c.close()

    def test_other_addresses_are_capped_at_eight_each(self, session):
        """On its own, a non-loopback address gets exactly 8 entries. The
        loopback test cannot show this: with 24 entries already held
        only 8 are free, which a cap of 12 or 16 would also leave."""
        s = session()
        assert s.wait_ready(), s.proxy.log
        socks = []
        try:
            for _ in range(12):
                c = socket.socket()
                c.bind(('127.0.0.2', 0))
                c.settimeout(5)
                c.connect(('127.0.0.1', VPORT))
                socks.append(c)
            time.sleep(0.5)          # inside the 2 s silent-drop window
            refused = 0
            for c in socks:
                c.setblocking(False)
                try:
                    if b'503' in c.recv(256):
                        refused += 1
                except OSError:
                    pass
            assert refused == 12 - 8
        finally:
            for c in socks:
                c.close()


@pytest.mark.integration
class TestViewerCpu:
    def test_idle_viewer_does_not_busy_spin(self, session):
        """A caught-up viewer on a quiet stream must cost no CPU.

        EPOLLOUT armed permanently makes epoll_wait return immediately
        for any writable socket. Measured before this was fixed: one
        idle viewer burned a full core, which on a single-core VPS is
        the whole machine.
        """
        s = session()
        assert s.wait_ready(), s.proxy.log
        vpid = s.proxy.video_pid()
        assert vpid is not None, s.proxy.log

        def ticks():
            with open('/proc/%d/stat' % vpid) as f:
                parts = f.read().split()
            return int(parts[13]) + int(parts[14])   # utime + stime

        sock, head, _ = http_get(VPORT)
        assert b'200 OK' in head, head
        try:
            time.sleep(2)          # let it settle and catch up
            t0 = ticks()
            time.sleep(4)          # publisher is quiet throughout
            t1 = ticks()
        finally:
            sock.close()

        # 400 ticks would be a full core over 4s; anything above a small
        # fraction of that means we are spinning rather than sleeping.
        used = t1 - t0
        assert used < 40, \
            'idle viewer burned %d ticks in 4s (400 = one core)' % used


def ws_connect(port, target, timeout=8.0):
    """Minimal WebSocket client: handshake, then read binary frames."""
    import base64
    key = base64.b64encode(b'v' * 16).decode()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(('127.0.0.1', port))
    s.sendall((
        'GET %s HTTP/1.1\r\n'
        'Host: localhost\r\n'
        'Upgrade: websocket\r\n'
        'Connection: Upgrade\r\n'
        'Sec-WebSocket-Key: %s\r\n'
        'Sec-WebSocket-Version: 13\r\n\r\n' % (target, key)).encode())
    head = b''
    try:
        while b'\r\n\r\n' not in head:
            c = s.recv(4096)
            if not c:
                break
            head += c
    except socket.timeout:
        pass
    sep = head.find(b'\r\n\r\n')
    rest = head[sep + 4:] if sep >= 0 else b''
    return s, head[:sep if sep >= 0 else len(head)], rest


def ws_read_payload(sock, seconds, initial=b''):
    """Read server->client frames and return the concatenated payload."""
    buf = bytearray(initial)
    out = bytearray()
    deadline = time.time() + seconds
    sock.settimeout(0.5)
    while time.time() < deadline:
        try:
            c = sock.recv(65536)
            if not c:
                break
            buf += c
        except socket.timeout:
            pass
        # decode as many complete frames as we have
        while len(buf) >= 2:
            ln = buf[1] & 0x7F
            pos = 2
            if ln == 126:
                if len(buf) < 4:
                    break
                ln = int.from_bytes(buf[2:4], 'big')
                pos = 4
            elif ln == 127:
                if len(buf) < 10:
                    break
                ln = int.from_bytes(buf[2:10], 'big')
                pos = 10
            if (buf[1] & 0x80) != 0:
                raise AssertionError('server masked a frame')
            if len(buf) < pos + ln:
                break
            opcode = buf[0] & 0x0F
            if opcode == 0x2:            # binary: stream data
                out += buf[pos:pos + ln]
            del buf[:pos + ln]
    return bytes(out)


def mint_token(workdir, port2, slot):
    import sys as _sys
    if _REPO_ROOT not in _sys.path:
        _sys.path.insert(0, _REPO_ROOT)
    from webadmin import videotoken
    db = keydb_lib.open_db(str(workdir / 'keys.tdb'))
    db.transaction_start()
    try:
        ke = keydb_lib.KeyEntry(port2)
        assert ke.fetch(db)
        return videotoken.mint(ke.secret_key, port2, slot)
    finally:
        db.transaction_cancel()
        db.close()


@pytest.mark.integration
class TestWebSocketViewer:
    def test_ws_viewer_receives_the_stream(self, session):
        s = session()
        assert s.wait_ready(), s.proxy.log
        s.feed.start()
        tok = mint_token(s.workdir, PORT_ENG, 0)
        sock, head, rest = ws_connect(VPORT, '/v1?t=%s' % tok)
        try:
            assert b'101' in head, head
            data = ws_read_payload(sock, 5, rest)
        finally:
            sock.close()
        assert len(data) > 10000, 'ws viewer got %d bytes' % len(data)
        assert data[0] == 0x47, 'ws payload does not start at a TS packet'
        assert data in s.feed.snapshot(), \
            'ws payload is not a verbatim span of what was published'

    def test_ws_requires_a_credential_when_a_password_is_set(self, session):
        s = session(viewer_pass='watchme')
        assert s.wait_ready(), s.proxy.log
        sock, head, _ = ws_connect(VPORT, '/v1')
        sock.close()
        assert b'101' not in head, \
            'websocket upgraded without a credential: %r' % head
        assert b'401' in head, head

    def test_ws_accepts_a_valid_token(self, session):
        s = session(viewer_pass='watchme')
        assert s.wait_ready(), s.proxy.log
        tok = mint_token(s.workdir, PORT_ENG, 0)
        sock, head, _ = ws_connect(VPORT, '/v1?t=%s' % tok)
        sock.close()
        assert b'101' in head, head

    def test_ws_rejects_a_tampered_token(self, session):
        s = session(viewer_pass='watchme')
        assert s.wait_ready(), s.proxy.log
        tok = mint_token(s.workdir, PORT_ENG, 0)
        bad = tok[:-1] + ('0' if tok[-1] != '0' else '1')
        sock, head, _ = ws_connect(VPORT, '/v1?t=%s' % bad)
        sock.close()
        assert b'101' not in head, 'tampered token was accepted'

    def test_ws_accepts_the_viewer_password_too(self, session):
        s = session(viewer_pass='watchme')
        assert s.wait_ready(), s.proxy.log
        sock, head, _ = ws_connect(VPORT, '/v1?pw=watchme')
        sock.close()
        assert b'101' in head, head


def http_fetch(port, path, timeout=5.0):
    """GET a short response and return (head, body)."""
    sock, head, body = http_get(port, path, timeout=timeout)
    try:
        want = 0
        for line in head.split(b'\r\n'):
            if line.lower().startswith(b'content-length:'):
                want = int(line.split(b':')[1])
        while len(body) < want:
            c = sock.recv(65536)
            if not c:
                break
            body += c
    finally:
        sock.close()
    return head, body


@pytest.mark.integration
class TestHlsViewer:
    GOPS = 6
    GOP_S = 4

    def _publish(self, s):
        """Timestamped keyframes GOP_S seconds apart, sent as fast as
        the socket takes them (the PTS is what segments are cut by)."""
        gen = s.feed.gen
        sent = bytearray()
        for i in range(self.GOPS):
            for dg in gen.datagrams(gen.hls_gop(i * self.GOP_S * 90000)):
                s.feed.pub.sock.sendto(dg, ('127.0.0.1', VPORT))
                sent += dg
                time.sleep(0.002)
        time.sleep(0.5)
        return bytes(sent)

    def test_playlist_spans_three_targets_and_segments_play(self, session):
        s = session()
        assert s.wait_ready(), s.proxy.log
        sent = self._publish(s)
        tok = mint_token(s.workdir, PORT_ENG, 0)

        head, body = http_fetch(VPORT, '/v1.m3u8?t=%s' % tok)
        assert b'200' in head.split(b'\r\n')[0], head
        assert b'application/vnd.apple.mpegurl' in head
        pl = body.decode()
        assert '#EXT-X-TARGETDURATION:6\n' in pl, pl

        # RFC 8216 6.2.2: a live playlist spans at least 3 target durations,
        # which the default ring has to be able to hold.
        durs = [float(l[len('#EXTINF:'):].rstrip(',')) for l in pl.split('\n')
                if l.startswith('#EXTINF:')]
        assert sum(durs) >= 18, pl

        # The child's start is a discontinuity, and the counters start
        # from its launch time so a restart can't make them fall back.
        assert '#EXT-X-DISCONTINUITY\n' in pl, pl
        dseq = int(pl.split('#EXT-X-DISCONTINUITY-SEQUENCE:')[1].split('\n')[0])
        mseq = int(pl.split('#EXT-X-MEDIA-SEQUENCE:')[1].split('\n')[0])
        assert dseq > 0 and mseq > 0, pl

        # Segments carry the token, and are byte spans of the publish.
        uris = [l for l in pl.split('\n') if l.endswith('?t=%s' % tok)]
        assert len(uris) == len(durs), pl
        head, seg = http_fetch(VPORT, '/' + uris[0])
        assert b'200' in head.split(b'\r\n')[0], head
        assert b'video/mp2t' in head
        assert len(seg) > 0 and len(seg) % 188 == 0 and seg[0] == 0x47
        assert seg in sent, 'segment is not a verbatim span of what was published'

    def _last_seq(self, pl):
        names = [l for l in pl.split('\n') if l.startswith('v1-')]
        return int(names[-1].split('?')[0].rsplit('-', 1)[1][:-3])

    def test_counters_do_not_fall_back_when_the_child_is_replaced(self,
                                                                  session):
        """Each child starts its counters at its launch time. A publisher
        that outruns the wall clock pushes them past it, and the
        successor must carry on from there, not drop back."""
        import os
        import re
        s = session()
        assert s.wait_ready(), s.proxy.log
        tok = mint_token(s.workdir, PORT_ENG, 0)
        gen = s.feed.gen
        # 40 keyframe groups, sent flat out: far more segments than
        # seconds have passed since this child launched.
        for i in range(40):
            for dg in gen.datagrams(gen.hls_gop(i * 4 * 90000)):
                s.feed.pub.sock.sendto(dg, ('127.0.0.1', VPORT))
                time.sleep(0.001)
        # The child records its counters on its 5 s tick.
        time.sleep(6)
        head, body = http_fetch(VPORT, '/v1.m3u8?t=%s' % tok)
        assert b'200' in head.split(b'\r\n')[0], head
        before = self._last_seq(body.decode())

        first = s.proxy.video_pid()
        assert first is not None
        os.kill(first, 9)
        assert s.proxy.wait_for(r'video child %d exited' % first), \
            s.proxy.log
        assert s.proxy.wait_for(r'video child (?!%d\b)\d+ ready' % first), \
            s.proxy.log

        deadline = time.time() + 40
        after = None
        while time.time() < deadline and after is None:
            for i in range(4):
                for dg in gen.datagrams(gen.hls_gop(i * 4 * 90000)):
                    s.feed.pub.sock.sendto(dg, ('127.0.0.1', VPORT))
                    time.sleep(0.002)
            time.sleep(0.5)
            try:
                head, body = http_fetch(VPORT, '/v1.m3u8?t=%s' % tok)
            except OSError:
                continue
            if b'200' in head.split(b'\r\n')[0]:
                after = self._last_seq(body.decode())
        assert after is not None, s.proxy.log
        assert after > before, \
            'media sequence fell back from %d to %d' % (before, after)

    def test_playlist_needs_a_credential_when_a_password_is_set(self, session):
        s = session(viewer_pass='watchme')
        assert s.wait_ready(), s.proxy.log
        self._publish(s)
        head, _ = http_fetch(VPORT, '/v1.m3u8')
        assert b'401' in head.split(b'\r\n')[0], head
        head, _ = http_fetch(VPORT, '/v1.m3u8?pw=watchme')
        assert b'200' in head.split(b'\r\n')[0], head


def _make_cert(workdir):
    """Self-signed cert the proxy picks up from its cwd for TLS."""
    subprocess.run([
        'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', 'privkey.pem', '-out', 'fullchain.pem',
        '-days', '2', '-subj', '/CN=localhost',
    ], cwd=str(workdir), check=True, capture_output=True)


@pytest.mark.integration
class TestSecureWebSocketViewer:
    def test_wss_viewer_receives_the_stream(self, tmp_path):
        """A browser on an HTTPS admin page can only open wss://, so the
        TLS path has to work, not just ws://."""
        import ssl
        wd = _workdir(tmp_path)
        _make_cert(wd)
        s = Session(wd)
        try:
            assert s.wait_ready(), s.proxy.log
            s.feed.start()
            tok = mint_token(wd, PORT_ENG, 0)

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(10)
            raw.connect(('127.0.0.1', VPORT))
            sock = ctx.wrap_socket(raw, server_hostname='localhost')
            try:
                import base64
                key = base64.b64encode(b'w' * 16).decode()
                sock.sendall((
                    'GET /v1?t=%s HTTP/1.1\r\n'
                    'Host: localhost\r\n'
                    'Upgrade: websocket\r\n'
                    'Connection: Upgrade\r\n'
                    'Sec-WebSocket-Key: %s\r\n'
                    'Sec-WebSocket-Version: 13\r\n\r\n' % (tok, key)).encode())
                head = b''
                deadline = time.time() + 8
                while b'\r\n\r\n' not in head and time.time() < deadline:
                    try:
                        c = sock.recv(4096)
                    except (socket.timeout, ssl.SSLWantReadError):
                        continue
                    if not c:
                        break
                    head += c
                assert b'101' in head, head
                sep = head.find(b'\r\n\r\n')
                data = ws_read_payload(sock, 5, head[sep + 4:])
            except Exception:
                raise AssertionError('wss failed; proxy log:\n%s' % s.proxy.log)
            finally:
                sock.close()
            assert len(data) > 5000, \
                'wss viewer got %d bytes; proxy log:\n%s' % (len(data),
                                                             s.proxy.log)
            assert data[0] == 0x47
            assert data in s.feed.snapshot(), 'wss payload not verbatim'
        finally:
            s.stop()


def mint_bound_token(workdir, port2, slot, until):
    """A viewer token bound to a share link that expires at `until`."""
    from webadmin import videotoken
    db = keydb_lib.open_db(str(workdir / 'keys.tdb'))
    db.transaction_start()
    try:
        ke = keydb_lib.KeyEntry(port2)
        assert ke.fetch(db)
        return videotoken.mint(ke.secret_key, port2, slot, until=until)
    finally:
        db.transaction_cancel()
        db.close()


def wss_connect(port, target, timeout=8.0):
    """ws_connect over TLS (the proxy's cert is self-signed)."""
    import base64
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    raw.connect(('127.0.0.1', port))
    sock = ctx.wrap_socket(raw, server_hostname='localhost')
    key = base64.b64encode(b'w' * 16).decode()
    sock.sendall((
        'GET %s HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n'
        'Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n'
        'Sec-WebSocket-Version: 13\r\n\r\n' % (target, key)).encode())
    head = b''
    deadline = time.time() + timeout
    while b'\r\n\r\n' not in head and time.time() < deadline:
        try:
            c = sock.recv(4096)
        except (socket.timeout, ssl.SSLWantReadError):
            continue
        except (ssl.SSLError, OSError):
            break
        if not c:
            break
        head += c
    sep = head.find(b'\r\n\r\n')
    return sock, head[:sep if sep >= 0 else len(head)], \
        head[sep + 4:] if sep >= 0 else b''


def closed_within(sock, seconds):
    """True if the peer ends the connection within `seconds`. Frames the
    server is still sending are read and thrown away."""
    deadline = time.time() + seconds
    sock.settimeout(1.0)
    while time.time() < deadline:
        try:
            if not sock.recv(65536):
                return True
        except socket.timeout:
            continue
        except OSError:
            return True
    return False


@pytest.mark.integration
class TestLinkBoundViewer:
    """A viewer admitted with a share link's token lives only as long as
    the link, and only as long as the entry's key."""

    def test_stream_ends_when_the_link_expires(self, session):
        s = session(viewer_pass='watchme')
        assert s.wait_ready(), s.proxy.log
        s.feed.start()
        until = int(time.time()) + 4
        tok = mint_bound_token(s.workdir, PORT_ENG, 0, until)
        sock, head, _ = ws_connect(VPORT, '/v1?t=%s' % tok)
        try:
            assert b'101' in head, head
            # Checked on the child's 5 s tick, so allow a couple of them.
            assert closed_within(sock, 20), \
                'viewer outlived its link:\n%s' % s.proxy.log
        finally:
            sock.close()
        # And the expired token buys nothing new.
        sock, head, _ = ws_connect(VPORT, '/v1?t=%s' % tok)
        sock.close()
        assert b'101' not in head, head

    def test_an_already_expired_link_is_refused(self, session):
        s = session(viewer_pass='watchme')
        assert s.wait_ready(), s.proxy.log
        tok = mint_bound_token(s.workdir, PORT_ENG, 0, int(time.time()) - 5)
        sock, head, _ = ws_connect(VPORT, '/v1?t=%s' % tok)
        sock.close()
        assert b'101' not in head, head

    def test_changing_the_key_ends_the_stream(self, session):
        s = session(viewer_pass='watchme')
        assert s.wait_ready(), s.proxy.log
        s.feed.start()
        tok = mint_bound_token(s.workdir, PORT_ENG, 0,
                               int(time.time()) + 3600)
        sock, head, _ = ws_connect(VPORT, '/v1?t=%s' % tok)
        try:
            assert b'101' in head, head
            db = keydb_lib.open_db(str(s.workdir / 'keys.tdb'))
            db.transaction_start()
            keydb_lib.set_pass(db, PORT_ENG, 'a-different-passphrase')
            db.transaction_prepare_commit()
            db.transaction_commit()
            db.close()
            assert closed_within(sock, 20), \
                'viewer survived a key change:\n%s' % s.proxy.log
        finally:
            sock.close()
        # The old link no longer opens a new stream either.
        sock, head, _ = ws_connect(VPORT, '/v1?t=%s' % tok)
        sock.close()
        assert b'101' not in head, head


@pytest.mark.integration
class TestSecureLinkBoundViewer:
    def _session(self, tmp_path):
        wd = _workdir(tmp_path, viewer_pass='watchme')
        _make_cert(wd)
        s = Session(wd)
        assert s.wait_ready(), s.proxy.log
        s.feed.start()
        return wd, s

    def test_wss_upgrade_needs_a_credential(self, tmp_path):
        """Over TLS the request is unreadable until the handshake has
        been answered, so a refusal is a close rather than a 401. What
        matters is that no media ever flows."""
        wd, s = self._session(tmp_path)
        try:
            for target in ('/v1', '/v1?pw=wrong'):
                sock, head, rest = wss_connect(VPORT, target)
                try:
                    got = bytearray(rest)
                    deadline = time.time() + 10
                    sock.settimeout(1.0)
                    closed = False
                    while time.time() < deadline:
                        try:
                            c = sock.recv(65536)
                        except socket.timeout:
                            continue
                        except OSError:
                            closed = True
                            break
                        if not c:
                            closed = True
                            break
                        got += c
                    assert closed, 'unauthorised wss viewer left open'
                    # At most a close frame: no stream payload.
                    assert len(got) < 100, \
                        'unauthorised wss viewer received %d bytes' % len(got)
                finally:
                    sock.close()
            assert 'unauthorized' in s.proxy.log, s.proxy.log
        finally:
            s.stop()

    def test_wss_stream_ends_when_the_link_expires(self, tmp_path):
        wd, s = self._session(tmp_path)
        try:
            tok = mint_bound_token(wd, PORT_ENG, 0, int(time.time()) + 4)
            sock, head, _ = wss_connect(VPORT, '/v1?t=%s' % tok)
            try:
                assert b'101' in head, head
                assert closed_within(sock, 20), \
                    'wss viewer outlived its link:\n%s' % s.proxy.log
            finally:
                sock.close()
        finally:
            s.stop()


@pytest.mark.integration
class TestFragmentedRequest:
    def test_http_request_split_across_packets(self, session):
        """A viewer request may arrive in pieces; the parser has to
        wait for the rest rather than give up or re-classify."""
        s = session()
        assert s.wait_ready(), s.proxy.log
        s.feed.start()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(8)
        sock.connect(('127.0.0.1', VPORT))
        try:
            req = b'GET /v1.ts HTTP/1.1\r\nHost: localhost\r\n\r\n'
            for i in range(0, len(req), 7):     # dribble it out
                sock.sendall(req[i:i + 7])
                time.sleep(0.05)
            head = b''
            deadline = time.time() + 6
            while b'\r\n\r\n' not in head and time.time() < deadline:
                try:
                    c = sock.recv(4096)
                except socket.timeout:
                    continue
                if not c:
                    break
                head += c
            assert b'200 OK' in head, \
                'fragmented request not served: %r\n%s' % (head[:200],
                                                           s.proxy.log)
        finally:
            sock.close()


@pytest.mark.integration
class TestPublisherRestart:
    """Killing and restarting the publisher.

    Reported from a real session: the browser showed a gap and then
    never resumed. A new publisher is a new stream -- PSI, continuity
    counters and PTS all restart -- so appending its bytes to what a
    viewer has already been given makes time jump backwards, and a
    Media Source player stalls permanently rather than recovering. The
    stream has to be *ended* so the client reconnects and rejoins.
    """

    def test_viewer_is_ended_when_the_publisher_goes(self, session):
        s = session()
        assert s.wait_ready(), s.proxy.log
        sock, head, body = http_get(VPORT)
        assert b'200' in head, head
        assert read_for(sock, 1.5, body), 'viewer got no bytes at all'

        s.feed.stop()
        # The slot releases after VIDEO_PUB_IDLE_S (10s); allow the tick.
        assert s.proxy.wait_for(r'publisher idle, releasing', timeout=25), \
            s.proxy.log

        # A clean end of stream: recv returns b'' rather than hanging or
        # silently continuing into the next publisher's bytes.
        sock.settimeout(10)
        deadline = time.time() + 10
        closed = False
        while time.time() < deadline:
            try:
                if sock.recv(65536) == b'':
                    closed = True
                    break
            except socket.timeout:
                break
            except OSError:
                closed = True
                break
        sock.close()
        assert closed, 'viewer was left attached to a stream that ended'

    def test_the_reason_is_logged(self, session):
        s = session()
        assert s.wait_ready(), s.proxy.log
        sock, head, body = http_get(VPORT)
        read_for(sock, 1.0, body)
        s.feed.stop()
        assert s.proxy.wait_for(r'publisher gone', timeout=25), s.proxy.log
        sock.close()

    def test_a_new_viewer_can_join_the_restarted_stream(self, session):
        """The point of the whole thing: after a restart, watching
        works again."""
        s = session()
        assert s.wait_ready(), s.proxy.log
        first, head, body = http_get(VPORT)
        read_for(first, 1.0, body)

        s.feed.stop()
        assert s.proxy.wait_for(r'publisher idle, releasing', timeout=25), \
            s.proxy.log
        first.close()

        # Restart the publisher exactly as a user re-running the tool
        # would: a fresh socket, a fresh stream.
        s.feed = Feed(VPORT)
        assert s.wait_ready(), s.proxy.log
        second, head2, body2 = http_get(VPORT)
        assert b'200' in head2, head2
        got = read_for(second, 3.0, body2)
        second.close()
        assert got, 'no bytes from the restarted stream'
        assert got[0] == 0x47, 'restarted stream did not begin on a TS packet'

    def test_restarted_stream_is_not_spliced_onto_the_old_one(self, session):
        """The ring restarts with the stream, so a viewer joining after
        a restart must not be served bytes from before it."""
        s = session()
        assert s.wait_ready(), s.proxy.log
        before = s.feed.snapshot()
        assert before

        s.feed.stop()
        assert s.proxy.wait_for(r'publisher idle, releasing', timeout=25), \
            s.proxy.log

        s.feed = Feed(VPORT)
        assert s.wait_ready(), s.proxy.log
        sock, head, body = http_get(VPORT)
        got = read_for(sock, 3.0, body)
        sock.close()
        assert got
        # Everything served must come from the new publisher's bytes.
        new_bytes = s.feed.snapshot()
        assert got in new_bytes, \
            'served bytes are not a span of the restarted stream'
