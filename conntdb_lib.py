"""
Reader for connections.tdb — the live per-connection state the
supportproxy children mirror out via the heartbeat fork-and-write idiom.

This module has no Flask dependency so the keydb.py CLI and the
webadmin Flask app can both use it. webadmin/connections.py is the
thin Flask wrapper that resolves the path from app config and
delegates here.

Schema mirrors `struct ConnEntry` in conntdb.h. Forward-compatible:
records of size >= CONNENTRY_MIN_SIZE are accepted; trailing bytes
from a newer C++ schema are ignored on read.
"""
import errno
import os
import signal
import socket
import struct
import time

import keydb_lib

# Name reported by /proc/<pid>/comm for a live supportproxy process.
# request_drop cross-checks this so we don't accidentally signal a PID
# that died and got recycled by an unrelated process.
SUPPORTPROXY_COMM = 'supportproxy'

# ConnEntry.flags bits — keep in sync with conntdb.h.
CONN_FLAG_DROP_REQUESTED = 1 << 0

CONN_FILE = 'connections.tdb'
CONN_MAGIC = 0x436f6e6e45424553  # "ConnEBES"

# Pre-flags layout was 64 bytes (matches sizeof(ConnEntry) at the time
# of this writing). Anything smaller is invalid; trailing bytes from a
# newer schema are ignored.
CONNENTRY_MIN_SIZE = 64

# struct ConnEntry layout (little-endian, natural alignment):
#   QQQ   magic, connected_at, last_update            (24)
#   ii    port2, conn_index                           ( 8)
#   III   pid, rx_msgs, tx_msgs                       (12)
#   I     peer_ip_be                                  ( 4)
#   HBB   peer_port_be, transport, is_user            ( 4)
#   I     flags                                       ( 4)
#   I     _pad                                        ( 4)
#   4x    _pad2 (was implicit C++ tail padding)       ( 4)  -> 64
#   BBBB  role, stream_idx, app_proto, authenticated  ( 4)
#   4x    _pad3                                       ( 4)  -> 72
#
# The video fields start at 64, not 60. Bytes 60..63 were implicit tail
# padding in C++ (the struct is 8-aligned) which this format spells out
# as "4x" -- so a field placed there would be zeroed by any writer using
# the older format, while sizeof() stayed 64 and no size check caught it.
PACK_FORMAT = "<QQQiiIIIIHBBII4xBBBB4x"
CONNENTRY_CURRENT_SIZE = struct.calcsize(PACK_FORMAT)
assert CONNENTRY_CURRENT_SIZE == 72, CONNENTRY_CURRENT_SIZE

# ConnEntry.role / .app_proto — keep in sync with conntdb.h.
CONN_ROLE_MAVLINK = 0
CONN_ROLE_VIDEO_PUB = 1
CONN_ROLE_VIDEO_SUB = 2

ROLE_NAMES = {
    CONN_ROLE_MAVLINK: 'mavlink',
    CONN_ROLE_VIDEO_PUB: 'video-pub',
    CONN_ROLE_VIDEO_SUB: 'video-sub',
}

CONN_APP_MAVLINK = 0
CONN_APP_MPEGTS = 1
CONN_APP_RTSP = 2
CONN_APP_HTTP = 3
CONN_APP_SRT = 4
CONN_APP_RTMP = 5
CONN_APP_RTP = 6

APP_NAMES = {
    CONN_APP_MAVLINK: 'mavlink',
    CONN_APP_MPEGTS: 'mpegts',
    CONN_APP_RTSP: 'rtsp',
    CONN_APP_HTTP: 'http',
    CONN_APP_SRT: 'srt',
    CONN_APP_RTMP: 'rtmp',
    CONN_APP_RTP: 'rtp',
}

# Video rows occupy a conn_index range disjoint from the MAVLink ones so
# the two writers can snapshot independently.
VIDEO_CONN_INDEX_BASE = 1000
VIDEO_CONN_STRIDE = 256

# struct ConnKey { int port2; int conn_index; }
KEY_FORMAT = "<ii"

TRANSPORT_NAMES = {
    0: 'udp',
    1: 'tcp',
    2: 'ws',
    3: 'wss',
}


class ConnEntry:
    __slots__ = ('magic', 'connected_at', 'last_update',
                 'port2', 'conn_index', 'pid',
                 'rx_msgs', 'tx_msgs',
                 'peer_ip_be', 'peer_port_be',
                 'transport', 'is_user', 'flags',
                 'role', 'stream_idx', 'app_proto', 'authenticated')

    def __init__(self):
        for s in self.__slots__:
            setattr(self, s, 0)

    @classmethod
    def unpack(cls, data):
        if len(data) < CONNENTRY_MIN_SIZE:
            raise ValueError("record too small: %d bytes" % len(data))
        if len(data) < CONNENTRY_CURRENT_SIZE:
            data = data + b'\x00' * (CONNENTRY_CURRENT_SIZE - len(data))
        body = data[:CONNENTRY_CURRENT_SIZE]
        ce = cls()
        (ce.magic, ce.connected_at, ce.last_update,
         ce.port2, ce.conn_index, ce.pid,
         ce.rx_msgs, ce.tx_msgs,
         ce.peer_ip_be, ce.peer_port_be,
         ce.transport, ce.is_user,
         ce.flags, _pad,
         ce.role, ce.stream_idx, ce.app_proto,
         ce.authenticated) = struct.unpack(PACK_FORMAT, body)
        return ce

    @property
    def transport_name(self):
        return TRANSPORT_NAMES.get(self.transport, str(self.transport))

    @property
    def role_name(self):
        return ROLE_NAMES.get(self.role, str(self.role))

    @property
    def app_name(self):
        return APP_NAMES.get(self.app_proto, str(self.app_proto))

    @property
    def is_video(self):
        return self.role in (CONN_ROLE_VIDEO_PUB, CONN_ROLE_VIDEO_SUB)

    @property
    def peer_ip(self):
        return socket.inet_ntoa(struct.pack("<I", self.peer_ip_be))

    @property
    def peer_port(self):
        return socket.ntohs(self.peer_port_be)

    @property
    def peer(self):
        return "%s:%d" % (self.peer_ip, self.peer_port)

    def uptime_s(self, now=None):
        if now is None:
            now = time.time()
        return max(0, int(now) - int(self.connected_at))

    def age_s(self, now=None):
        if now is None:
            now = time.time()
        return int(now) - int(self.last_update)


def conn_path_for(keydb_path):
    """connections.tdb sits in the same directory as keys.tdb."""
    keydb_dir = os.path.dirname(os.path.abspath(keydb_path)) or '.'
    return os.path.join(keydb_dir, CONN_FILE)


def iter_active(path, now=None, max_age_s=30):
    """Yield ConnEntry records currently in connections.tdb at ``path``.

    Records older than ``max_age_s`` (last_update too far in the past)
    are skipped — defence in depth against orphans the supportproxy parent
    failed to clean up. Returns nothing if the file is missing.
    """
    if not os.path.exists(path):
        return
    try:
        db = keydb_lib.open_db(path)
    except OSError as e:
        if e.errno in (errno.ENOENT, errno.EACCES):
            return
        raise
    try:
        if now is None:
            now = time.time()
        k = db.firstkey()
        while k is not None:
            v = db.get(k)
            if (v is not None and len(v) >= CONNENTRY_MIN_SIZE
                    and len(k) == struct.calcsize(KEY_FORMAT)):
                try:
                    ce = ConnEntry.unpack(v)
                except (ValueError, struct.error):
                    ce = None
                if ce is not None and ce.magic == CONN_MAGIC:
                    if int(now) - int(ce.last_update) <= max_age_s:
                        yield ce
            k = db.nextkey(k)
    finally:
        db.close()


def list_active(path, **kw):
    """Sorted list of active records (by port2, conn_index)."""
    out = list(iter_active(path, **kw))
    out.sort(key=lambda c: (c.port2, c.conn_index))
    return out


def _proc_comm(pid):
    """Read /proc/<pid>/comm; return None on any error (file missing,
    permission denied, etc). Module-level so tests can monkeypatch."""
    try:
        with open('/proc/%d/comm' % pid) as f:
            return f.read().strip()
    except OSError:
        return None


def _flip_drop_flag(path, port2, conn_index):
    """Set CONN_FLAG_DROP_REQUESTED on the (port2, conn_index) record.

    Returns the PID stored in that record, or None when the record is
    missing. Caller is responsible for signalling the PID afterwards.
    """
    if not os.path.exists(path):
        return None
    try:
        db = keydb_lib.open_db(path)
    except OSError:
        return None
    pid = None
    try:
        db.transaction_start()
        try:
            key = struct.pack(KEY_FORMAT, port2, conn_index)
            v = db.get(key)
            if v is None or len(v) < CONNENTRY_MIN_SIZE:
                return None
            ce = ConnEntry.unpack(v)
            if ce.magic != CONN_MAGIC:
                return None
            ce.flags |= CONN_FLAG_DROP_REQUESTED
            pid = ce.pid if ce.pid > 0 else None
            # rebuild record bytes preserving any forward-compat tail
            tail = v[CONNENTRY_CURRENT_SIZE:] if len(v) > CONNENTRY_CURRENT_SIZE else b''
            new_body = struct.pack(
                PACK_FORMAT,
                ce.magic, ce.connected_at, ce.last_update,
                ce.port2, ce.conn_index, ce.pid,
                ce.rx_msgs, ce.tx_msgs,
                ce.peer_ip_be, ce.peer_port_be,
                ce.transport, ce.is_user,
                ce.flags, 0,  # _pad
                ce.role, ce.stream_idx, ce.app_proto, ce.authenticated,
            )
            import tdb as _tdb
            db.store(key, new_body + tail, _tdb.REPLACE)
            db.transaction_prepare_commit()
            db.transaction_commit()
        except Exception:
            db.transaction_cancel()
            raise
    finally:
        db.close()
    return pid


def request_drop(path, port2, conn_index, exec_name=SUPPORTPROXY_COMM):
    """Ask the per-port-pair child to drop a single connection.

    Sets CONN_FLAG_DROP_REQUESTED on the (port2, conn_index) record so
    the child can find it after the signal, then sends SIGUSR1 to the
    child PID (validated against /proc/<pid>/comm so we don't hit a
    recycled PID). Returns True if the signal was sent.

    A user-side row (conn_index=0) ends the whole session because the
    child has nothing left to proxy without conn1; an engineer row
    (conn_index>=1) drops just that engineer slot.
    """
    pid = _flip_drop_flag(path, port2, conn_index)
    if pid is None:
        return False
    if _proc_comm(pid) != exec_name:
        return False
    try:
        os.kill(pid, signal.SIGUSR1)
    except OSError:
        return False
    return True
