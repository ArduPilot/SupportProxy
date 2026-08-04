#!/usr/bin/env python3
"""Generate a test video stream for a SupportProxy video port, and pull it
back to check what arrived.

The picture carries a test pattern plus a running wall clock and elapsed
timer burned into the frame, so a viewer anywhere can see at a glance
whether the stream is live, how far behind it is, and whether it froze.

  # publish a 720p H.264 test pattern over MPEG-TS/UDP
  scripts/test_video.py publish --host neon --port 40001

  # publish over RTSP with a publish password
  scripts/test_video.py publish --host neon --port 40001 \
      --transport rtsp --publish-pass secret

  # pull it back and report on what arrived
  scripts/test_video.py view --host neon --port 40001 --viewer-pass hunter2

  # do both and print a pass/fail
  scripts/test_video.py check --host neon --port 40001

  # what can this machine do?
  scripts/test_video.py caps

Publish transports are the ones the proxy actually accepts: MPEG-TS over
UDP, and RTSP. A plain TCP connection to a video port is treated as a
viewer, so there is no raw-TCP publish; SRT is not implemented yet.
"""
import argparse
import base64
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time

TS_PACKET = 188
# What a well-behaved MPEG-TS/UDP sender emits: 7 packets per datagram,
# which is also SRT's default payload size for the same reason.
TS_UDP_PAYLOAD = 7 * TS_PACKET

# Stream types we recognise in a PMT, for reporting.
STREAM_TYPES = {
    0x02: 'MPEG-2 video', 0x03: 'MP2 audio', 0x04: 'MP3 audio',
    0x0F: 'AAC', 0x1B: 'H.264', 0x24: 'HEVC', 0x81: 'AC-3',
    0x06: 'private data',
}


def log(msg):
    sys.stderr.write('%s\n' % msg)
    sys.stderr.flush()


def die(msg, code=2):
    log('error: %s' % msg)
    sys.exit(code)


# ----------------------------------------------------------------- caps

def have(prog):
    return shutil.which(prog) is not None


def ffmpeg_has_filter(name):
    if not have('ffmpeg'):
        return False
    try:
        out = subprocess.run(['ffmpeg', '-hide_banner', '-filters'],
                             capture_output=True, text=True,
                             timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return re.search(r'^\s*\S+\s+%s\s' % re.escape(name), out, re.M) is not None


def gst_has(element):
    if not have('gst-inspect-1.0'):
        return False
    return subprocess.run(['gst-inspect-1.0', element],
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL).returncode == 0


def capabilities():
    caps = {
        'ffmpeg': have('ffmpeg'),
        'ffprobe': have('ffprobe'),
        'ffplay': have('ffplay'),
        'gstreamer': have('gst-launch-1.0'),
    }
    caps['ffmpeg_drawtext'] = ffmpeg_has_filter('drawtext')
    caps['ffmpeg_testsrc2'] = ffmpeg_has_filter('testsrc2')
    caps['gst_clockoverlay'] = gst_has('clockoverlay')
    caps['gst_rtspclientsink'] = gst_has('rtspclientsink')
    return caps


def pick_encoder(want, transport):
    """Resolve --encoder auto against what is installed and what the
    transport needs."""
    caps = capabilities()
    ff_ok = caps['ffmpeg'] and caps['ffmpeg_testsrc2']
    gst_ok = caps['gstreamer'] and caps['gst_clockoverlay']
    # GStreamer can only publish RTSP with rtspclientsink, which lives in
    # the -bad plugin set and is often absent.
    if transport == 'rtsp':
        gst_ok = gst_ok and caps['gst_rtspclientsink']

    if want == 'ffmpeg':
        if not ff_ok:
            die('ffmpeg not usable here (need ffmpeg with testsrc2); '
                'run "%s caps"' % sys.argv[0])
        return 'ffmpeg'
    if want == 'gst':
        if not gst_ok:
            die('gstreamer not usable for %s here; run "%s caps"'
                % (transport, sys.argv[0]))
        return 'gst'
    if ff_ok:
        return 'ffmpeg'
    if gst_ok:
        return 'gst'
    die('neither ffmpeg nor gstreamer is usable here; run "%s caps"'
        % sys.argv[0])


# ------------------------------------------------------------- publisher

def publish_url(a):
    if a.transport == 'udp':
        # pkt_size makes ffmpeg emit 7-packet datagrams rather than
        # splitting a TS packet across two, which the proxy rejects.
        return 'udp://%s:%d?pkt_size=%d' % (a.host, a.port, TS_UDP_PAYLOAD)
    # The publish password rides in the request-line query. It is the only
    # place RTSP can carry one without us parsing the session, and ffmpeg
    # passes the query through untouched.
    url = 'rtsp://%s:%d/%s' % (a.host, a.port, a.rtsp_path.lstrip('/'))
    if a.publish_pass:
        url += '?pw=%s' % a.publish_pass
    return url


def ffmpeg_publish_cmd(a):
    vcodec = {'h264': 'libx264', 'hevc': 'libx265'}[a.codec]
    # The clock is the point of the exercise: wall time proves the stream
    # is live, the elapsed timer proves it is not looping or stalled.
    #
    # The text needs BOTH single quotes around it AND a backslash on the
    # colon in %{pts:hms} -- measured, not guessed. Quotes alone still
    # split the filter arg at that colon, and the backslash alone does
    # too. %{localtime} takes no argument so has no colon to escape.
    fs = _font_size(a)
    # x is clamped rather than plain (w-text_w)/2: a line wider than the
    # frame would otherwise centre to a negative x and lose characters
    # off BOTH edges, which is how the clock ends up unreadable at small
    # sizes. The comma in max() is a filter-arg separator, so it escapes.
    common = ('fontcolor=white:fontsize=%d:box=1:boxcolor=black@0.6:'
              'boxborderw=6:x=max(0\\,(w-text_w)/2)' % fs)
    filters = ["drawtext=text='%s':%s:y=h-text_h-%d"
               % ("%{localtime}  +%{pts\\:hms}", common, max(8, fs // 3))]
    if a.label:
        # Its own line, so a long label cannot push the clock off-frame.
        filters.append("drawtext=text='%s':%s:y=%d"
                       % (_ff_escape(a.label), common, max(8, fs // 3)))
    drawtext = ','.join(filters)

    cmd = ['ffmpeg', '-hide_banner', '-nostdin', '-loglevel', a.loglevel,
           '-re',
           '-f', 'lavfi', '-i',
           'testsrc2=size=%s:rate=%d' % (a.size, a.fps)]
    if a.audio:
        # A tone, so an audio track exists to exercise the audio path.
        cmd += ['-f', 'lavfi', '-i',
                'sine=frequency=440:sample_rate=48000']
    vf = drawtext
    if ffmpeg_has_filter('drawtext'):
        cmd += ['-vf', vf]
    else:
        log('note: ffmpeg has no drawtext filter (needs libfreetype); '
            'publishing the pattern without a clock overlay')
    cmd += ['-c:v', vcodec, '-preset', 'ultrafast', '-tune', 'zerolatency',
            '-b:v', a.bitrate, '-maxrate', a.bitrate,
            '-bufsize', a.bitrate,
            # A short GOP means a viewer joining late finds an anchor
            # quickly; the proxy needs a keyframe to start anyone.
            '-g', str(a.fps * a.gop_seconds),
            '-pix_fmt', 'yuv420p']
    if a.audio:
        cmd += ['-c:a', 'aac', '-b:a', '96k']
    else:
        cmd += ['-an']
    if a.duration:
        cmd += ['-t', str(a.duration)]

    if a.transport == 'udp':
        cmd += ['-f', 'mpegts', '-muxdelay', '0', '-flush_packets', '1']
    else:
        cmd += ['-f', 'rtsp', '-rtsp_transport', 'tcp']
    cmd += [publish_url(a)]
    return cmd


def _font_size(a):
    """--font-size 0 means scale to the frame: the clock has to stay
    readable at 320x180 and not fill the screen at 1080p."""
    if a.font_size:
        return a.font_size
    try:
        height = int(a.size.split('x')[1])
    except (IndexError, ValueError):
        return 24
    return max(12, height // 20)


def _ff_escape(s):
    """Escape --label for use inside the single-quoted drawtext value.

    A single quote cannot be escaped inside a single-quoted section of an
    ffmpeg filter argument -- it has to close the quote, escape, reopen.
    Not worth it for a caption on a test pattern, so those are dropped.
    """
    s = s.replace("'", '')
    return s.replace('\\', r'\\').replace(':', r'\:').replace(',', r'\,')


def gst_publish_cmd(a):
    enc = {'h264': 'x264enc tune=zerolatency speed-preset=ultrafast '
                   'key-int-max=%d bitrate=%d' % (a.fps * a.gop_seconds,
                                                  _kbits(a.bitrate)),
           'hevc': 'x265enc tune=zerolatency speed-preset=ultrafast '
                   'key-int-max=%d bitrate=%d' % (a.fps * a.gop_seconds,
                                                  _kbits(a.bitrate))}[a.codec]
    w, h = a.size.split('x')
    src = 'videotestsrc is-live=true pattern=smpte'
    if a.duration:
        src += ' num-buffers=%d' % (a.fps * a.duration)
    fs = _font_size(a)
    parts = [
        src,
        'video/x-raw,width=%s,height=%s,framerate=%d/1' % (w, h, a.fps),
        'clockoverlay time-format="%H:%M:%S" font-desc="Sans {}" '
        'valignment=bottom halignment=center'.format(fs),
        'timeoverlay font-desc="Sans {}" valignment=top '
        'halignment=center'.format(fs),
        'videoconvert',
        enc,
        'mpegtsmux alignment=7 name=mux',
    ]
    if a.transport == 'udp':
        parts.append('udpsink host=%s port=%d' % (a.host, a.port))
    else:
        parts.append('rtspclientsink location=%s' % publish_url(a))
    # gst-launch takes each argv element as one pipeline token -- it does
    # NOT split them on spaces -- so "videotestsrc is-live=true" as a
    # single argument is a syntax error. shlex.split gives one word per
    # argument while keeping "Sans 18" together as the quoted value it is.
    return ['gst-launch-1.0', '-q'] + shlex.split(' ! '.join(parts))


def _kbits(bitrate):
    m = re.match(r'^(\d+)([kKmM]?)$', bitrate)
    if not m:
        die('bad --bitrate %r (try 2M or 2000k)' % bitrate)
    n = int(m.group(1))
    return n * 1000 if m.group(2).lower() == 'm' else (n if m.group(2)
                                                       else n // 1000)


def cmd_publish(a):
    encoder = pick_encoder(a.encoder, a.transport)
    cmd = (ffmpeg_publish_cmd(a) if encoder == 'ffmpeg'
           else gst_publish_cmd(a))

    log('publishing to %s' % publish_url(a))
    log('  %s %s %s @ %dfps, %s, audio=%s, encoder=%s'
        % (a.codec, a.size, a.transport, a.fps, a.bitrate,
           'on' if a.audio else 'off', encoder))
    if a.dry_run:
        print(' '.join(_shquote(c) for c in cmd))
        return 0
    if a.verbose:
        log('  $ %s' % ' '.join(_shquote(c) for c in cmd))

    try:
        p = _spawn(cmd)
    except OSError as e:
        die('cannot start %s: %s' % (cmd[0], e))
    try:
        return p.wait()
    except KeyboardInterrupt:
        p.send_signal(signal.SIGINT)
        try:
            return p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()
            return 130
    finally:
        # Covers every other way this process can end: a signal, an
        # exception, or the shell going away.
        _reap(p)


def _pdeathsig():
    """Ask the kernel to SIGTERM this child when its parent dies.

    Without it, killing the wrapper leaves ffmpeg publishing forever --
    and because one publisher holds a slot, that orphan then refuses the
    *next* publisher as slot-busy. A leaked test publisher can quietly
    take over a real video port, which is exactly what it did.
    """
    try:
        import ctypes
        libc = ctypes.CDLL('libc.so.6', use_errno=True)
        libc.prctl(1, signal.SIGTERM, 0, 0, 0)   # PR_SET_PDEATHSIG
    except Exception:
        pass                                     # best effort; the
                                                 # finally: below still
                                                 # covers a clean exit


def _spawn(cmd, **kw):
    return subprocess.Popen(cmd, preexec_fn=_pdeathsig, **kw)


def _reap(p):
    """Stop a publisher and make sure it is really gone."""
    if p is None or p.poll() is not None:
        return
    p.terminate()
    try:
        p.wait(timeout=5)
    except subprocess.TimeoutExpired:
        p.kill()
        p.wait()


def _shquote(s):
    return s if re.match(r'^[\w@%+=:,./-]+$', s) else "'%s'" % s.replace(
        "'", "'\\''")


# ---------------------------------------------------------------- viewer

def viewer_query(a):
    """Credential for a viewer URL. A token beats a password: it is
    short-lived and does not land in logs or history as a reusable
    secret."""
    if a.token:
        return 't=%s' % a.token
    if a.viewer_pass:
        return 'pw=%s' % a.viewer_pass
    return ''


def http_view(a, sink, deadline):
    path = a.path
    q = viewer_query(a)
    if q:
        path += ('&' if '?' in path else '?') + q
    req = ('GET %s HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: supportproxy-test\r\n'
           'Connection: close\r\n\r\n' % (path, a.host, a.port))
    s = socket.create_connection((a.host, a.port), timeout=a.connect_timeout)
    s.sendall(req.encode())
    return _read_after_headers(s, sink, deadline, a)


def tcp_view(a, sink, deadline):
    """Raw TCP viewer: connect, say nothing, read. Only works when the
    slot has 'open TCP viewers' enabled -- there is nowhere in a raw
    stream to carry a credential."""
    s = socket.create_connection((a.host, a.port), timeout=a.connect_timeout)
    return _read_body(s, sink, deadline, a)


def ws_view(a, sink, deadline):
    key = base64.b64encode(os.urandom(16)).decode()
    path = a.path
    q = viewer_query(a)
    if q:
        path += ('&' if '?' in path else '?') + q
    req = ('GET %s HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n'
           'Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n'
           'Sec-WebSocket-Version: 13\r\n\r\n'
           % (path, a.host, a.port, key))
    s = socket.create_connection((a.host, a.port), timeout=a.connect_timeout)
    s.sendall(req.encode())
    head, rest = _read_headers(s, a)
    if '101' not in head.split('\r\n')[0]:
        raise ViewError('websocket upgrade refused: %s'
                        % head.split('\r\n')[0])
    return _read_ws_frames(s, rest, sink, deadline, a)


class ViewError(Exception):
    pass


def _read_headers(s, a):
    buf = b''
    while b'\r\n\r\n' not in buf:
        if len(buf) > 65536:
            raise ViewError('no end of headers after 64 KiB')
        chunk = s.recv(4096)
        if not chunk:
            raise ViewError('connection closed during headers')
        buf += chunk
    head, _, rest = buf.partition(b'\r\n\r\n')
    return head.decode('latin-1'), rest


def _read_after_headers(s, sink, deadline, a):
    head, rest = _read_headers(s, a)
    status = head.split('\r\n')[0]
    if ' 200' not in status:
        raise ViewError('server said: %s\n%s' % (status, head))
    if rest:
        sink(rest)
    return _read_body(s, sink, deadline, a, primed=True)


def _read_body(s, sink, deadline, a, primed=False):
    s.settimeout(1.0)
    while time.time() < deadline:
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            continue
        if not chunk:
            break
        sink(chunk)
    s.close()
    return True


def _read_ws_frames(s, rest, sink, deadline, a):
    """Enough of RFC 6455 to read a binary stream from the server.
    Server-to-client frames are never masked."""
    buf = bytearray(rest)
    s.settimeout(1.0)
    while time.time() < deadline:
        # Parse whatever complete frames are buffered.
        while True:
            frame, used = _ws_parse(buf)
            if frame is None:
                break
            del buf[:used]
            opcode, payload = frame
            if opcode == 0x8:            # close
                s.close()
                return True
            if opcode in (0x1, 0x2, 0x0):
                sink(payload)
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            continue
        if not chunk:
            break
        buf += chunk
    s.close()
    return True


def _ws_parse(buf):
    if len(buf) < 2:
        return None, 0
    b0, b1 = buf[0], buf[1]
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    ln = b1 & 0x7F
    off = 2
    if ln == 126:
        if len(buf) < off + 2:
            return None, 0
        ln = int.from_bytes(buf[off:off + 2], 'big')
        off += 2
    elif ln == 127:
        if len(buf) < off + 8:
            return None, 0
        ln = int.from_bytes(buf[off:off + 8], 'big')
        off += 8
    if masked:
        if len(buf) < off + 4:
            return None, 0
        mask = buf[off:off + 4]
        off += 4
    if len(buf) < off + ln:
        return None, 0
    payload = bytes(buf[off:off + ln])
    if masked:
        payload = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
    return (opcode, payload), off + ln


# ------------------------------------------------------------ TS analysis

class TSAnalyser:
    """Just enough MPEG-TS to say whether what arrived is a real stream.

    Deliberately independent of the proxy's own scanner: a bug shared
    between the thing under test and the thing checking it would be
    invisible.
    """

    def __init__(self):
        self.buf = bytearray()
        self.bytes = 0
        self.packets = 0
        self.unsynced = 0
        self.pids = {}
        self.cc = {}
        self.cc_errors = 0
        self.rai = 0
        self.pat_seen = 0
        self.pmt_pids = set()
        self.streams = {}
        self.first_byte_at = None
        self.last_byte_at = None

    def feed(self, data):
        now = time.time()
        if self.first_byte_at is None:
            self.first_byte_at = now
        self.last_byte_at = now
        self.bytes += len(data)
        self.buf += data
        # Resync to a sync byte if we are not on one.
        while self.buf and self.buf[0] != 0x47:
            del self.buf[0]
            self.unsynced += 1
        while len(self.buf) >= TS_PACKET:
            pkt = bytes(self.buf[:TS_PACKET])
            if pkt[0] != 0x47:
                del self.buf[0]
                self.unsynced += 1
                continue
            del self.buf[:TS_PACKET]
            self._packet(pkt)

    def _packet(self, pkt):
        self.packets += 1
        pid = ((pkt[1] & 0x1F) << 8) | pkt[2]
        self.pids[pid] = self.pids.get(pid, 0) + 1
        pusi = bool(pkt[1] & 0x40)
        afc = (pkt[3] >> 4) & 0x3
        cc = pkt[3] & 0x0F

        # Continuity counter only advances on packets that carry payload.
        if afc in (1, 3):
            prev = self.cc.get(pid)
            if prev is not None and cc != (prev + 1) % 16:
                self.cc_errors += 1
            self.cc[pid] = cc
        payload = 4
        if afc in (2, 3):
            af_len = pkt[4]
            if afc == 2:
                payload = TS_PACKET
            else:
                payload = 5 + af_len
            if af_len > 0 and len(pkt) > 5 and (pkt[5] & 0x40):
                self.rai += 1
        if afc in (1, 3) and payload < TS_PACKET:
            if pid == 0 and pusi:
                self.pat_seen += 1
                self._parse_pat(pkt[payload:])
            elif pid in self.pmt_pids and pusi:
                self._parse_pmt(pkt[payload:])

    def _section(self, data):
        if not data:
            return None
        ptr = data[0]
        body = data[1 + ptr:]
        if len(body) < 3:
            return None
        length = ((body[1] & 0x0F) << 8) | body[2]
        if len(body) < 3 + length:
            return None          # spans packets; the next copy will do
        return body[:3 + length]

    def _parse_pat(self, data):
        sec = self._section(data)
        if not sec or sec[0] != 0x00:
            return
        # header 8 bytes, then 4-byte entries, then 4-byte CRC
        body = sec[8:-4]
        for i in range(0, len(body) - 3, 4):
            prog = (body[i] << 8) | body[i + 1]
            pid = ((body[i + 2] & 0x1F) << 8) | body[i + 3]
            if prog != 0:
                self.pmt_pids.add(pid)

    def _parse_pmt(self, data):
        sec = self._section(data)
        if not sec or sec[0] != 0x02:
            return
        if len(sec) < 12:
            return
        info_len = ((sec[10] & 0x0F) << 8) | sec[11]
        i = 12 + info_len
        end = len(sec) - 4
        while i + 4 < end:
            stype = sec[i]
            epid = ((sec[i + 1] & 0x1F) << 8) | sec[i + 2]
            es_len = ((sec[i + 3] & 0x0F) << 8) | sec[i + 4]
            self.streams[epid] = stype
            i += 5 + es_len

    def report(self):
        span = 0.0
        if self.first_byte_at and self.last_byte_at:
            span = self.last_byte_at - self.first_byte_at
        return {
            'bytes': self.bytes,
            'ts_packets': self.packets,
            'seconds': round(span, 2),
            'megabits_per_sec': round(self.bytes * 8 / span / 1e6, 2)
            if span > 0.5 else None,
            'discarded_unsynced_bytes': self.unsynced,
            'continuity_errors': self.cc_errors,
            'random_access_points': self.rai,
            'pat_sections': self.pat_seen,
            'pids': dict(sorted(self.pids.items())),
            'elementary_streams': {
                pid: STREAM_TYPES.get(t, 'type 0x%02X' % t)
                for pid, t in sorted(self.streams.items())},
        }

    def verdict(self, want_seconds):
        """(ok, [problems]) -- what a human would call a working stream."""
        bad = []
        if self.packets == 0:
            bad.append('no MPEG-TS packets arrived at all')
            return False, bad
        if self.pat_seen == 0:
            bad.append('no PAT: a viewer cannot discover the video PID')
        if not self.streams:
            bad.append('no PMT: no elementary streams declared')
        if self.rai == 0:
            bad.append('no random-access point: a late viewer has no '
                       'anchor to start from')
        if self.cc_errors:
            bad.append('%d continuity errors (packet loss or interleaving)'
                       % self.cc_errors)
        if self.unsynced:
            bad.append('%d bytes discarded resyncing' % self.unsynced)
        span = (self.last_byte_at - self.first_byte_at) if self.first_byte_at \
            else 0
        if want_seconds and span < want_seconds * 0.5:
            bad.append('stream stopped after %.1fs of %ds requested'
                       % (span, want_seconds))
        return (not bad), bad


def cmd_view(a):
    an = TSAnalyser()
    out = open(a.save, 'wb') if a.save else None

    def sink(data):
        an.feed(data)
        if out:
            out.write(data)

    log('viewing %s://%s:%d%s (%s) for %ds'
        % (a.via, a.host, a.port, a.path if a.via != 'tcp' else '',
           'token' if a.token else ('password' if a.viewer_pass else
                                    'no credential'),
           a.duration))
    reader = {'http': http_view, 'tcp': tcp_view, 'ws': ws_view}[a.via]
    deadline = time.time() + a.duration
    try:
        reader(a, sink, deadline)
    except ViewError as e:
        if out:
            out.close()
        die(str(e), 1)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        if out:
            out.close()
        die('%s://%s:%d: %s' % (a.via, a.host, a.port, e), 1)
    finally:
        if out:
            out.close()
            log('wrote %s' % a.save)

    rep = an.report()
    if a.json:
        print(json.dumps(rep, indent=2))
    else:
        _print_report(rep)
    ok, problems = an.verdict(a.duration)
    for p in problems:
        log('  ! %s' % p)
    return 0 if ok else 1


def _print_report(rep):
    print('bytes            %d' % rep['bytes'])
    print('TS packets       %d' % rep['ts_packets'])
    print('duration         %ss' % rep['seconds'])
    if rep['megabits_per_sec'] is not None:
        print('rate             %s Mbit/s' % rep['megabits_per_sec'])
    print('PAT sections     %d' % rep['pat_sections'])
    print('random access    %d' % rep['random_access_points'])
    print('continuity errs  %d' % rep['continuity_errors'])
    print('resync discards  %d' % rep['discarded_unsynced_bytes'])
    if rep['elementary_streams']:
        print('streams')
        for pid, name in rep['elementary_streams'].items():
            print('  PID %-5d %s' % (pid, name))
    else:
        print('streams          (none declared)')


# ----------------------------------------------------------------- check

def cmd_check(a):
    """Publish and view at once, then say whether it worked."""
    encoder = pick_encoder(a.encoder, a.transport)

    # The publisher has to outlive the viewer: the viewer only starts
    # after --settle, so publishing for exactly --duration would cut the
    # stream off early and be reported as "stream stopped".
    view_seconds = a.duration
    pub_args = argparse.Namespace(**vars(a))
    pub_args.duration = int(a.duration + a.settle + 2) if a.duration else 0

    cmd = (ffmpeg_publish_cmd(pub_args) if encoder == 'ffmpeg'
           else gst_publish_cmd(pub_args))
    if a.verbose:
        log('  $ %s' % ' '.join(_shquote(c) for c in cmd))

    log('publishing to %s (%s, %s)' % (publish_url(a), a.codec, encoder))
    pub = _spawn(cmd, stdout=subprocess.DEVNULL,
                 stderr=(None if a.verbose else subprocess.DEVNULL))
    result = {}

    def run_view():
        try:
            result['rc'] = cmd_view(a)
        except SystemExit as e:
            result['rc'] = e.code

    try:
        # Give the publisher a moment to be admitted and start a GOP,
        # otherwise the viewer arrives before there is any anchor to
        # join at and reports a stream that is in fact fine.
        time.sleep(a.settle)
        if pub.poll() is not None:
            die('publisher exited immediately (rc=%d); re-run with '
                '--verbose to see why' % pub.returncode, 1)
        t = threading.Thread(target=run_view)
        t.start()
        t.join()
    finally:
        _reap(pub)

    rc = result.get('rc', 1)
    log('RESULT: %s' % ('PASS' if rc == 0 else 'FAIL'))
    return rc


def cmd_caps(a):
    caps = capabilities()
    if a.json:
        print(json.dumps(caps, indent=2))
        return 0
    for k, v in caps.items():
        print('%-22s %s' % (k, 'yes' if v else 'NO'))
    print()
    print('publish transports: udp (MPEG-TS), rtsp')
    print('                    SRT is not implemented in the proxy yet')
    print('view transports:    http, tcp (raw), ws')
    return 0


# ------------------------------------------------------------------ main

def add_common(p):
    p.add_argument('--host', default='127.0.0.1',
                   help='proxy host (default 127.0.0.1)')
    p.add_argument('--port', type=int, required=True,
                   help='the entry\'s video port')
    p.add_argument('-v', '--verbose', action='store_true')


def add_publish_opts(p):
    p.add_argument('--transport', choices=['udp', 'rtsp'], default='udp',
                   help='udp = MPEG-TS datagrams (cannot carry a password); '
                        'rtsp = publish over RTSP (can)')
    p.add_argument('--publish-pass', default='',
                   help='publish password, RTSP only -- it rides in the '
                        'request-line query as ?pw=')
    p.add_argument('--rtsp-path', default='cam',
                   help='RTSP path (cosmetic; the port selects the slot)')
    p.add_argument('--codec', choices=['h264', 'hevc'], default='h264',
                   help='h264 plays in a browser; hevc does not')
    p.add_argument('--size', default='1280x720')
    p.add_argument('--fps', type=int, default=25)
    p.add_argument('--bitrate', default='2M')
    p.add_argument('--gop-seconds', type=int, default=2,
                   help='keyframe interval; a late viewer waits up to this '
                        'long for an anchor (default 2)')
    p.add_argument('--audio', action='store_true',
                   help='include an AAC tone (off by default, like the '
                        'proxy)')
    p.add_argument('--duration', type=int, default=0,
                   help='seconds to publish, 0 = until interrupted')
    p.add_argument('--encoder', choices=['auto', 'ffmpeg', 'gst'],
                   default='auto')
    p.add_argument('--label', default='',
                   help='extra text to burn into the frame, e.g. which '
                        'host is sending')
    p.add_argument('--font-size', type=int, default=0,
                   help='0 = scale to the frame height (default)')
    p.add_argument('--loglevel', default='warning',
                   help='ffmpeg -loglevel (default warning)')
    p.add_argument('--dry-run', action='store_true',
                   help='print the encoder command and exit')


def add_view_opts(p):
    p.add_argument('--via', choices=['http', 'tcp', 'ws'], default='http')
    p.add_argument('--path', default='/stream.ts',
                   help='/stream.ts and / always work; /v1.ts../v3.ts name '
                        'a slot explicitly')
    p.add_argument('--viewer-pass', default='')
    p.add_argument('--token', default='',
                   help='short-lived HMAC token from the web admin video '
                        'page; preferred over --viewer-pass')
    p.add_argument('--save', default='',
                   help='also write the received stream to this file')
    p.add_argument('--json', action='store_true')
    p.add_argument('--connect-timeout', type=float, default=10.0)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)

    p = sub.add_parser('publish', help='send a test pattern to a video port')
    add_common(p)
    add_publish_opts(p)
    p.set_defaults(func=cmd_publish)

    p = sub.add_parser('view', help='pull a stream back and report on it')
    add_common(p)
    add_view_opts(p)
    p.add_argument('--duration', type=int, default=10,
                   help='seconds to watch (default 10)')
    p.set_defaults(func=cmd_view)

    p = sub.add_parser('check', help='publish and view together, pass/fail')
    add_common(p)
    add_publish_opts(p)
    add_view_opts(p)
    p.add_argument('--settle', type=float, default=3.0,
                   help='seconds to let the publisher establish before '
                        'the viewer joins (default 3)')
    p.set_defaults(func=cmd_check)

    p = sub.add_parser('caps', help='what this machine can generate')
    p.add_argument('--json', action='store_true')
    p.set_defaults(func=cmd_caps)

    a = ap.parse_args(argv)
    # 'check' takes both option sets; its --duration comes from the view
    # side and doubles as how long to publish.
    if a.cmd == 'check' and not a.duration:
        a.duration = 10
    return a.func(a)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
