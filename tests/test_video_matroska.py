"""Matroska relay: admission, fragmented input, late joins, rotation and loss."""
import socket
import time
from urllib.parse import quote

import keydb_lib
from test_video_child import Proxy, _make_workdir, PORT_ENG, VPORT
from test_video_view import http_get, ws_connect, ws_read_payload, mint_token

PASSWORD = 'raw&publish?=test'


def element(eid, payload):
    width = max(1, (eid.bit_length()+7)//8)
    n = next(n for n in range(1, 9) if len(payload) < (1 << (7*n))-1)
    return eid.to_bytes(width, 'big') + ((1 << (7*n)) | len(payload)).to_bytes(n, 'big') + payload


# Transport fixtures deliberately contain EBML-looking bytes inside frames:
# scanning for a magic Cluster signature instead of parsing sizes would fail.
HEADER = (element(0x1A45DFA3, b'matroska') + bytes.fromhex('1853806701ffffffffffffff') +
          element(0x1549A966, b'info') + element(0x1654AE6B, b'V_FFV1'))


def cluster(i, size=128):
    return element(0x1F43B675, i.to_bytes(4, 'big') + bytes.fromhex('1f43b675') + bytes([i % 256])*size)


def publish(password=PASSWORD, fragmented=False):
    s = socket.create_connection(('127.0.0.1', VPORT), timeout=4)
    target = '/v1.mkv' + ('' if password is None else '?pw='+quote(password, safe=''))
    request = ('PUT %s HTTP/1.1\r\nHost: localhost\r\nContent-Type: video/x-matroska\r\n'
               'Transfer-Encoding: chunked\r\nExpect: 100-continue\r\n\r\n' % target).encode()
    if fragmented:
        for byte in request:
            s.sendall(bytes([byte]))
            time.sleep(.001)
    else:
        s.sendall(request)
    response = b''
    while b'\r\n\r\n' not in response:
        part = s.recv(1024)
        if not part: break
        response += part
    return s, response


def send(s, data, fragment=0):
    chunk = ('%x\r\n' % len(data)).encode()+data+b'\r\n'
    if fragment:
        for offset in range(0, len(chunk), fragment): s.sendall(chunk[offset:offset+fragment])
    else:
        s.sendall(chunk)


def receive(s, data, count):
    while len(data) < count:
        part = s.recv(count-len(data))
        assert part, 'unexpected disconnect'
        data += part
    return data


def start(tmp_path, viewer=False):
    wd = _make_workdir(tmp_path, publish_pass=PASSWORD)
    db = keydb_lib.init_db(str(wd/'keys.tdb'))
    db.transaction_start()
    keydb_lib.set_video_slot_flag(db, PORT_ENG, 0, 'record')
    if viewer: keydb_lib.set_video_viewer_pass(db, PORT_ENG, 'viewer')
    db.transaction_prepare_commit(); db.transaction_commit(); db.close()
    proxy = Proxy(wd)
    assert proxy.wait_for('video slot 0 listening'), proxy.log
    return wd, proxy


def test_auth_fragmentation_late_join_and_reconnect(tmp_path):
    wd, proxy = start(tmp_path, viewer=True)
    try:
        for wrong in ('wrong', '', None):
            s, response = publish(wrong)
            s.close()
            assert b'403' in response
        pub, response = publish(fragmented=True)
        assert b'100 Continue' in response
        send(pub, HEADER, fragment=1)
        send(pub, cluster(1), fragment=3)
        send(pub, cluster(2), fragment=7)
        assert proxy.wait_for('join=ready'), proxy.log
        bad, response, _ = http_get(VPORT, '/v1.mkv')
        bad.close()
        assert b'401' in response
        view, response, body = http_get(VPORT, '/v1.mkv?pw=viewer')
        assert b'video/x-matroska' in response
        expected = HEADER+cluster(2)
        assert receive(view, body, len(expected)) == expected
        busy, response = publish()
        busy.close()
        assert b'409' in response
        send(pub, cluster(3), fragment=11)
        assert receive(view, b'', len(cluster(3))) == cluster(3)
        pub.close()
        assert view.recv(1024) == b''
        view.close()
        pub, response = publish()
        assert b'100 Continue' in response
        send(pub, HEADER+cluster(10))
        time.sleep(.15)
        view, response, body = http_get(VPORT, '/v1.mkv?pw=viewer')
        expected = HEADER+cluster(10)
        assert receive(view, body, len(expected)) == expected
        view.close(); pub.close()
        assert list(wd.rglob('*.mkv'))
    finally:
        proxy.stop()


def test_record_rotates_at_cluster_boundaries(tmp_path, monkeypatch):
    monkeypatch.setenv('SUPPORTPROXY_VIDEO_SEGMENT_BYTES', '300')
    wd, proxy = start(tmp_path)
    try:
        pub, response = publish()
        assert b'100 Continue' in response
        send(pub, HEADER)
        frames = [cluster(i, 220) for i in range(12)]
        for frame in frames: send(pub, frame, fragment=17)
        time.sleep(.4)
        pub.close()
        time.sleep(.4)
        files = sorted(wd.rglob('*.mkv'), key=lambda p:p.stat().st_mtime_ns)
        assert len(files) >= 6
        recovered = b''
        for path in files:
            data = path.read_bytes()
            assert data.startswith(HEADER)
            recovered += data[len(HEADER):]
        assert recovered == b''.join(frames)
    finally:
        proxy.stop()


def test_bad_sizes_release_slot_and_slow_viewer_isolated(tmp_path, monkeypatch):
    monkeypatch.setenv('SUPPORTPROXY_VIDEO_RING_BYTES', '65536')
    _, proxy = start(tmp_path)
    try:
        pub, response = publish()
        assert b'100' in response
        send(pub, b'\x00')  # invalid EBML ID
        assert pub.recv(1024) == b''
        pub.close()
        pub, response = publish()
        assert b'100' in response
        pub.sendall(b'fffffffffff\r\n')  # reject without allocating payload
        assert pub.recv(1024) == b''
        pub.close()
        pub, response = publish()
        assert b'100' in response
        send(pub, HEADER+cluster(1, 12000))
        assert proxy.wait_for('join=ready'), proxy.log
        slow, response, _ = http_get(VPORT, '/v1.mkv')
        for i in range(2, 500): send(pub, cluster(i, 12000))
        send(pub, cluster(500, 12000))
        time.sleep(.3)
        fast, response, body = http_get(VPORT, '/v1.mkv')
        expected = HEADER+cluster(500, 12000)
        assert receive(fast, body, len(expected)) == expected
        assert proxy.wait_for('lapped|chronically behind'), proxy.log
        fast.close(); slow.close(); pub.close()
    finally:
        proxy.stop()


def test_websocket_prefix_and_http_token(tmp_path):
    wd, proxy = start(tmp_path, viewer=True)
    try:
        pub, response = publish()
        assert b'100' in response
        send(pub, HEADER+cluster(4))
        assert proxy.wait_for('join=ready'), proxy.log
        token = mint_token(wd, PORT_ENG, 0)
        http, response, body = http_get(VPORT, '/v1.mkv?t='+token)
        expected = HEADER+cluster(4)
        assert b'200' in response
        assert receive(http, body, len(expected)) == expected
        http.close()
        ws, response, body = ws_connect(VPORT, '/v1?t='+token)
        assert b'101' in response
        assert ws_read_payload(ws, 2, body) == expected
        ws.close(); pub.close()
    finally:
        proxy.stop()
