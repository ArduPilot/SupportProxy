"""RTSP viewers share the TS ring without acquiring a publisher slot."""
import base64
import shutil
import socket
import struct
import subprocess
import time

import pytest

from test_video_child import VPORT, PORT_ENG
from test_video_view import session, http_get, read_for  # noqa: F401
from test_video_rtsp import clip, RtspSession, _workdir  # noqa: F401


class Client:
    def __init__(self, suffix=''):
        self.sock = socket.create_connection(('127.0.0.1', VPORT), timeout=5)
        self.url = 'rtsp://127.0.0.1:%d/view/v1%s' % (VPORT, suffix)
        self.cseq = 0
        self.pending = b''
        self.session = None
        self.media = []

    def close(self):
        self.sock.close()

    def more(self):
        data = self.sock.recv(65536)
        if not data:
            raise EOFError()
        self.pending += data

    def frame(self):
        while len(self.pending) < 4:
            self.more()
        channel, size = struct.unpack('!BH', self.pending[1:4])
        while len(self.pending) < size + 4:
            self.more()
        data, self.pending = self.pending[4:size+4], self.pending[size+4:]
        return channel, data

    def request(self, method, extra='', url=None, fragmented=False):
        self.cseq += 1
        if self.session:
            extra += 'Session: %s\r\n' % self.session
        data = ('%s %s RTSP/1.0\r\nCSeq: %d\r\n%s\r\n' %
                (method, url or self.url, self.cseq, extra)).encode()
        if fragmented:
            # Split inside the request target, before classification.
            split = data.index(b'/view/') + 8
            self.sock.sendall(data[:split])
            time.sleep(0.1)
            self.sock.sendall(data[split:])
        else:
            self.sock.sendall(data)
        return self.response()

    def response(self):
        while True:
            if not self.pending:
                self.more()
            if self.pending[0] == ord('$'):
                self.media.append(self.frame())
                continue
            end = self.pending.find(b'\r\n\r\n')
            if end < 0:
                self.more()
                continue
            lines = self.pending[:end].decode().split('\r\n')
            headers = dict(line.lower().split(': ', 1) for line in lines[1:])
            size = int(headers.get('content-length', 0))
            while len(self.pending) < end + 4 + size:
                self.more()
            body = self.pending[end+4:end+4+size]
            self.pending = self.pending[end+4+size:]
            return int(lines[0].split()[1]), headers, body

    def play(self, channel=0):
        assert self.request('OPTIONS')[0] == 200
        code, _, sdp = self.request('DESCRIBE')
        assert code == 200
        assert b'MP2T/90000' in sdp
        code, headers, _ = self.request('SETUP',
            'Transport: RTP/AVP/TCP;unicast;interleaved=%d-%d\r\n' %
            (channel, channel+1), url=self.url.split('?')[0]+'/trackID=0')
        assert code == 200
        self.session = headers['session'].split(';')[0]
        assert self.request('PLAY')[0] == 200


@pytest.mark.integration
def test_rtsp_payload_is_verbatim_and_http_stays_live(session):
    s = session()
    assert s.wait_ready(), s.proxy.log
    s.feed.start()
    c = Client()
    try:
        c.play(channel=4)
        payloads, seqs, reports = [], [], []
        for _ in range(35):
            channel, packet = c.frame()
            if channel == 5:
                reports.append(packet)
                continue
            assert channel == 4 and packet[:2] == b'\x80\x21'
            seqs.append(struct.unpack('!H', packet[2:4])[0])
            payloads.append(packet[12:])
        data = b''.join(payloads)
        assert len(data) > 10000
        assert data in s.feed.snapshot()
        assert all(b == (a+1) % 65536 for a, b in zip(seqs, seqs[1:]))
        assert reports and reports[0][1] == 200
        assert data[0] == 0x47
        assert ((data[1] & 31) << 8) | data[2] == 0  # join starts at PAT
        http, headers, body = http_get(VPORT)
        try:
            assert b'200 OK' in headers
            assert len(read_for(http, 0.5, body)) > 1000
        finally:
            http.close()
        # Receiver reports share the TCP connection with RTSP controls.
        c.sock.sendall(b'$\x05\x00\x08\x80\xc9\x00\x01\x00\x00\x00\x01')
        assert c.request('GET_PARAMETER')[0] == 200
        assert c.request('PAUSE')[0] == 200
        assert c.request('PLAY')[0] == 200
        assert c.request('TEARDOWN')[0] == 200
    finally:
        c.close()


@pytest.mark.integration
@pytest.mark.parametrize('credential', ['query', 'basic', 'token'])
def test_viewer_credentials_and_fragmented_request(session, credential):
    s = session(viewer_pass='viewer-secret')
    assert s.wait_ready(), s.proxy.log
    c = Client()
    try:
        assert c.request('DESCRIBE', fragmented=True)[0] == 401
        assert c.request('DESCRIBE', url=c.url+'?pw=wrong')[0] == 401
        if credential == 'query':
            extra, url = '', c.url+'?pw=viewer-secret'
        elif credential == 'basic':
            extra = 'Authorization: Basic %s\r\n' % base64.b64encode(
                b'viewer:viewer-secret').decode()
            url = c.url
        else:
            import keydb_lib
            from webadmin.videotoken import mint
            db = keydb_lib.open_db(str(s.workdir / 'keys.tdb'))
            ke = keydb_lib.KeyEntry(PORT_ENG)
            assert ke.fetch(db)
            db.close()
            url, extra = c.url+'?t='+mint(ke.secret_key, ke.port2, 0), ''
        code, headers, body = c.request('DESCRIBE', extra, url=url)
        assert code == 200 and b'MP2T' in body
        assert '?' not in headers['content-base']
        # This connection retains authorisation for the relative track URI.
        assert c.request('SETUP', 'Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\n')[0] == 200
        assert 'viewer-secret' not in s.proxy.log
        assert 'RTSP publisher' not in s.proxy.log
    finally:
        c.close()


@pytest.mark.integration
def test_not_ready_paths_transport_and_session(session):
    s = session()
    c = Client()
    try:
        assert c.request('DESCRIBE')[0] == 503
        assert s.wait_ready(), s.proxy.log
        assert c.request('DESCRIBE', url=c.url.replace('v1', 'v2'))[0] == 404
        assert c.request('SETUP', 'Transport: RTP/AVP;unicast;client_port=6000-6001\r\n')[0] == 461
        assert c.request('SETUP', 'Transport: RTP/AVP/TCP;interleaved=255-256\r\n')[0] == 461
        assert c.request('PLAY')[0] == 454
        c.play()
        assert c.request('PLAY', 'Scale: 1.000\r\n')[0] == 200
        assert c.request('PLAY', 'Scale: 2.0\r\n')[0] == 457
        assert c.request('PLAY', 'Scale: nan\r\n')[0] == 457
        c.session = 'wrong'
        assert c.request('TEARDOWN')[0] == 454
        assert c.request('GET_PARAMETER')[0] == 454
    finally:
        c.close()


@pytest.mark.integration
def test_selects_tcp_from_transport_alternatives(session):
    s = session()
    assert s.wait_ready(), s.proxy.log
    c = Client()
    try:
        code, headers, _ = c.request('SETUP',
            'Transport: RTP/AVP;unicast;client_port=6000-6001, '
            'RTP/AVP/TCP;unicast;interleaved=6-7\r\n')
        assert code == 200
        assert headers['transport'] == 'rtp/avp/tcp;unicast;interleaved=6-7'
        c.session = headers['session'].split(';')[0]
        assert c.request('PLAY')[0] == 200
        while True:
            channel, _ = c.frame()
            if channel == 6:
                break
            assert channel == 7
    finally:
        c.close()


@pytest.mark.integration
@pytest.mark.slow
def test_unauthenticated_options_cannot_extend_admission_deadline(session):
    s = session(viewer_pass='viewer-secret')
    c = Client()
    try:
        start = time.monotonic()
        disconnected = False
        while time.monotonic()-start < 20:
            try:
                assert c.request('OPTIONS')[0] == 200
            except (EOFError, ConnectionError):
                disconnected = True
                break
            time.sleep(1)
        assert disconnected, s.proxy.log
        assert s.proxy.wait_for('RTSP authentication timeout'), s.proxy.log
        healthy = Client('?pw=viewer-secret')
        try:
            assert healthy.request('DESCRIBE')[0] == 503
        finally:
            healthy.close()
    finally:
        c.close()


@pytest.mark.integration
def test_repeated_authentication_failures_close_connection(session):
    s = session(viewer_pass='viewer-secret')
    c = Client('?pw=wrong')
    try:
        for _ in range(3):
            assert c.request('DESCRIBE')[0] == 401
        assert c.sock.recv(1024) == b''
        assert 'RTSP publisher' not in s.proxy.log
    finally:
        c.close()


@pytest.mark.integration
@pytest.mark.slow
def test_rtcp_receiver_reports_keep_session_alive(session):
    s = session()
    c = Client()
    try:
        # SETUP without PLAY keeps output quiet, isolating the session
        # timer from write progress and the independent publisher timer.
        code, headers, _ = c.request('SETUP',
            'Transport: RTP/AVP/TCP;interleaved=0-1\r\n')
        assert code == 200
        c.session = headers['session'].split(';')[0]
        start = time.monotonic()
        while time.monotonic()-start < 70:
            c.sock.sendall(b'$\x01\x00\x08\x80\xc9\x00\x01\x00\x00\x00\x01')
            time.sleep(5)
        assert c.request('GET_PARAMETER')[0] == 200
    finally:
        c.close()


@pytest.mark.integration
@pytest.mark.parametrize('packet', [
    b'',                                      # no RTCP header
    b'\x40\xc9\x00\x01\x00\x00\x00\x01',  # wrong version
    b'\x81\xc9\x00\x01\x00\x00\x00\x01',  # RR report block missing
    b'\xa0\xc9\x00\x01\x00\x00\x00\x00',  # zero padding count
])
def test_invalid_rtcp_is_rejected(session, packet):
    session()
    c = Client()
    try:
        code, _, _ = c.request('SETUP',
            'Transport: RTP/AVP/TCP;interleaved=0-1\r\n')
        assert code == 200
        c.sock.sendall(b'$\x01'+struct.pack('!H', len(packet))+packet)
        assert c.sock.recv(1024) == b''
    finally:
        c.close()


@pytest.mark.integration
@pytest.mark.parametrize('wire_request', [
    b'DESCRIBE {url} RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 999999999\r\n\r\n',
    b'DESCRIBE {url} RTSP/1.0\r\nCSeq: 1\r\nContent-Length: 0\r\nContent-Length: 1\r\n\r\n',
    b'DESCRIBE {url} RTSP/1.0\r\nCSeq: 1\r\nTransfer-Encoding: chunked\r\n\r\n',
    b'DESCRIBE {url} RTSP/1.0\r\nCSeq: bad\r\n\r\n',
])
def test_malformed_control_cannot_disturb_publisher(session, wire_request):
    s = session()
    assert s.wait_ready(), s.proxy.log
    c = Client()
    try:
        c.sock.sendall(wire_request.replace(b'{url}', c.url.encode()))
        assert c.sock.recv(1024) == b''
        healthy = Client()
        try:
            assert healthy.request('DESCRIBE')[0] == 200
        finally:
            healthy.close()
    finally:
        c.close()


@pytest.mark.integration
def test_slow_rtsp_viewer_is_dropped_without_stalling_http(session):
    s = session(env={'SUPPORTPROXY_VIDEO_RING_BYTES': str(256 * 1024)})
    assert s.wait_ready(), s.proxy.log
    c = Client()
    try:
        c.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        c.play()
        s.feed.start()
        assert s.proxy.wait_for(r'viewer disconnected .*\(fell too far behind', timeout=25), s.proxy.log
        healthy, headers, body = http_get(VPORT)
        try:
            assert b'200 OK' in headers
            data = read_for(healthy, 1, body)
            assert len(data) > 10000 and data in s.feed.snapshot()
        finally:
            healthy.close()
    finally:
        c.close()


@pytest.mark.integration
@pytest.mark.skipif(shutil.which('ffmpeg') is None, reason='real media needs ffmpeg')
@pytest.mark.parametrize('player', ['ffmpeg', 'ffmpeg_basic', 'gstreamer', 'vlc'])
def test_real_rtsp_publisher_can_be_decoded_by_rtsp_viewer(tmp_path, clip, player):
    if player == 'gstreamer' and shutil.which('gst-launch-1.0') is None:
        pytest.skip('GStreamer is not installed')
    if player == 'vlc' and shutil.which('cvlc') is None:
        pytest.skip('VLC is not installed')
    if player == 'vlc':
        modules = subprocess.run(['cvlc', '--list'], capture_output=True, timeout=10)
        if b'live555' not in modules.stdout:
            pytest.skip('VLC build has no live555 RTSP plugin')
    import keydb_lib
    wd = _workdir(tmp_path)
    db = keydb_lib.open_db(str(wd / 'keys.tdb'))
    keydb_lib.set_video_viewer_pass(db, PORT_ENG, 'viewer-secret')
    db.close()
    s = RtspSession(wd)
    try:
        s.publish(clip)
        assert s.proxy.wait_for(r'join=ready', timeout=40), s.proxy.log
        url = 'rtsp://127.0.0.1:%d/view/v1?pw=viewer-secret' % VPORT
        if player == 'ffmpeg_basic':
            url = 'rtsp://viewer:viewer-secret@127.0.0.1:%d/view/v1' % VPORT
        if player.startswith('ffmpeg'):
            argv = [
                'ffmpeg', '-hide_banner', '-loglevel', 'error',
                '-rtsp_transport', 'tcp', '-i', url,
                '-frames:v', '5', '-f', 'framemd5', '-',
            ]
        elif player == 'gstreamer':
            argv = [
                # Mission Planner's documented pipeline. The identity
                # ends it after decoded frames arrive; without an MP
                # consumer, appsink must not wait for its queue at EOS.
                'gst-launch-1.0', '-q', 'rtspsrc', 'location='+url,
                'protocols=tcp', 'latency=100', '!', 'application/x-rtp', '!',
                'decodebin3', '!', 'queue', 'max-size-buffers=1', 'leaky=2', '!',
                'videoconvert', '!', 'video/x-raw,format=BGRA', '!',
                'identity', 'eos-after=6', '!', 'appsink',
                'name=outsink', 'wait-on-eos=false', 'sync=false',
            ]
        else:
            argv = [
                'cvlc', '--ignore-config', '--no-media-library', '-vv',
                '--rtsp-tcp', '--vout=dummy', '--aout=dummy', '--no-audio',
                '--avcodec-hw=none', '--run-time=2', url, 'vlc://quit',
            ]
        result = subprocess.run(argv, capture_output=True, timeout=25)
        assert result.returncode == 0, result.stderr.decode()
        if player.startswith('ffmpeg'):
            frames = [line for line in result.stdout.splitlines() if line and not line.startswith(b'#')]
            assert len(frames) == 5, result.stdout
        elif player == 'vlc':
            assert b'using video decoder module' in result.stderr, result.stderr.decode()
        c = Client('?pw=viewer-secret')
        try:
            c.play()
            s.stop_publisher()
            assert s.proxy.wait_for(r'viewer disconnected .*\(publisher gone\)', timeout=30), s.proxy.log
        finally:
            c.close()
    finally:
        s.stop()
