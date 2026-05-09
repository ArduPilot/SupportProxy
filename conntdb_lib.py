"""
Reader for connections.tdb — the live per-connection state the
udpproxy children mirror out via the heartbeat fork-and-write idiom.

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
import socket
import struct
import time

import keydb_lib

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
# Raw: 60 bytes. C++ rounds sizeof() up to 64 to align the next
# instance at an 8-byte boundary (alignof(uint64_t)). Add 4 explicit
# pad bytes here so the on-disk size matches.
PACK_FORMAT = "<QQQiiIIIIHBBII4x"
CONNENTRY_CURRENT_SIZE = struct.calcsize(PACK_FORMAT)
assert CONNENTRY_CURRENT_SIZE == 64, CONNENTRY_CURRENT_SIZE

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
                 'transport', 'is_user', 'flags')

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
         ce.flags, _pad) = struct.unpack(PACK_FORMAT, body)
        return ce

    @property
    def transport_name(self):
        return TRANSPORT_NAMES.get(self.transport, str(self.transport))

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
    are skipped — defence in depth against orphans the udpproxy parent
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
