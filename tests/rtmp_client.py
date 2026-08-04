"""A minimal RTMP publisher, for the cases ffmpeg's client never sends.

ffmpeg publishes politely: it waits for onStatus before streaming, and
its writes happen to align with chunk boundaries. Two defects in our
server were invisible to it -- media pipelined into the same segment as
publish, and a chunk header split from its payload -- so the tests need
a client that can be told to do both.

It replays the tags of a real FLV file rather than synthesising H.264,
so the bitstream, the avcC and the frame types are genuine.
"""
import os
import socket
import struct


def _amf_str(s):
    b = s.encode()
    return b'\x02' + struct.pack('>H', len(b)) + b


def _amf_num(v):
    return b'\x00' + struct.pack('>d', v)


def _amf_null():
    return b'\x05'


def _amf_obj(d):
    out = b'\x03'
    for k, v in d.items():
        kb = k.encode()
        out += struct.pack('>H', len(kb)) + kb
        out += _amf_str(v) if isinstance(v, str) else _amf_num(v)
    return out + b'\x00\x00\x09'


def read_flv_tags(path):
    """[(tag_type, timestamp, payload)] for audio/video/script tags."""
    d = open(path, 'rb').read()
    i = 9 + 4                      # header + PreviousTagSize0
    tags = []
    while i + 11 <= len(d):
        ttype = d[i] & 0x1f
        sz = int.from_bytes(d[i + 1:i + 4], 'big')
        ts = int.from_bytes(d[i + 4:i + 7], 'big') | (d[i + 7] << 24)
        body = d[i + 11:i + 11 + sz]
        if len(body) < sz:
            break
        if ttype in (8, 9, 18):
            tags.append((ttype, ts, body))
        i += 11 + sz + 4
    return tags


class RtmpPublisher:
    """Publishes to a SupportProxy video port, byte layout under test control."""

    def __init__(self, host, port, app='PhoenixFPV', stream='FPV',
                 timeout=10):
        self.s = socket.create_connection((host, port), timeout)
        self.s.settimeout(timeout)
        self.app = app
        self.stream = stream
        self.out_chunk = 4096

    # -- framing ---------------------------------------------------

    def _chunk(self, csid, mtype, sid, ts, payload, fmt=0):
        if fmt == 0:
            hdr = (bytes([csid]) + ts.to_bytes(3, 'big')
                   + len(payload).to_bytes(3, 'big') + bytes([mtype])
                   + struct.pack('<I', sid))
        elif fmt == 1:
            hdr = (bytes([0x40 | csid]) + ts.to_bytes(3, 'big')
                   + len(payload).to_bytes(3, 'big') + bytes([mtype]))
        else:
            raise ValueError('fmt %d not needed here' % fmt)
        out = bytearray(hdr)
        at = 0
        while at < len(payload):
            if at:
                out += bytes([0xc0 | csid])
            out += payload[at:at + self.out_chunk]
            at += self.out_chunk
        return bytes(out)

    def _command(self, payload):
        return self._chunk(3, 20, 0, 0, payload)

    def _drain(self, seconds=0.4):
        self.s.settimeout(seconds)
        got = b''
        try:
            while True:
                b = self.s.recv(65536)
                if not b:
                    break
                got += b
        except socket.timeout:
            pass
        self.s.settimeout(10)
        return got

    # -- protocol --------------------------------------------------

    def handshake(self):
        self.s.sendall(b'\x03' + bytes(1536))       # C0 + C1
        want = 1 + 1536 + 1536
        got = b''
        while len(got) < want:
            b = self.s.recv(want - len(got))
            if not b:
                raise AssertionError('server closed during handshake')
            got += b
        self.s.sendall(got[1:1537])                 # C2 echoes S1
        return got

    def connect(self, password=None):
        stream = self.stream
        if password:
            stream = '%s?pw=%s' % (stream, password)
        tc = 'rtmp://127.0.0.1/%s' % self.app
        # Announce our outbound chunk size before sending anything that
        # needs splitting; the peer assumes the 128-byte default until
        # told otherwise.
        self.s.sendall(self._chunk(2, 1, 0, 0,
                                   self.out_chunk.to_bytes(4, 'big')))
        self.s.sendall(self._command(
            _amf_str('connect') + _amf_num(1) +
            _amf_obj({'app': self.app, 'tcUrl': tc, 'flashVer': 'test'})))
        self._drain()
        self.s.sendall(self._command(
            _amf_str('createStream') + _amf_num(2) + _amf_null()))
        self._drain()
        self._publish_cmd = (self._command(
            _amf_str('publish') + _amf_num(3) + _amf_null() +
            _amf_str(stream) + _amf_str('live')))

    def publish(self, first_tags=(), pipeline=False):
        """Send publish. With pipeline, media rides the same write.

        Pipelining is what a publisher that does not wait for onStatus
        does, and it is where the sequence header used to be dropped.
        """
        buf = self._publish_cmd
        for ttype, ts, body in first_tags:
            buf += self._chunk(6, ttype, 1, ts, body)
        self.s.sendall(buf)
        if not pipeline:
            self._drain()

    def send_tag(self, ttype, ts, body, fmt=0, split=False):
        """One media message. split writes header and payload separately.

        That is the shape that made the parser apply a chunk's timestamp
        delta twice: the header arrives, the payload does not, and the
        header is re-parsed on the next read.
        """
        frame = self._chunk(6, ttype, 1, ts, body, fmt=fmt)
        if split:
            head = 8 if fmt == 1 else 12
            self.s.sendall(frame[:head])
            self.s.sendall(frame[head:])
        else:
            self.s.sendall(frame)

    def close(self):
        try:
            self.s.close()
        except OSError:
            pass
