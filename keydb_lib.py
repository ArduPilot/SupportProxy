"""
Library for the SupportProxy keys.tdb.

The on-disk record layout is append-only and forward-compatible. Readers
accept any record of size >= KEYENTRY_MIN_SIZE; bytes beyond what the
reader's struct format covers are preserved verbatim on write so older code
never truncates fields added by newer code.

Used by the keydb.py CLI shim and the webadmin app. All mutations require
the caller to hold an open TDB transaction.
"""
import errno
import hashlib
import hmac
import math
import os
import struct
import time

import tdb

KEY_MAGIC = 0x6b73e867a72cdd1f

# Pre-flags layout was 96 bytes. Anything smaller is invalid; anything bigger
# is acceptable (extra trailing bytes belong to a newer schema we ignore).
#
# The current C++ struct ends with the video fields -- ports, flags, the
# viewer and publish keys, the quota, the MAVLink grace window, the per-slot
# RTMP paths -- and `uint32_t reserved[12]`. All are 4-byte aligned and slot in
# cleanly after the existing fields, so the struct is 344 bytes with no
# trailing pad. When a future field is added, claim
# another `reserved[]` slot (renumber: shrink reserved by 1, add a named field)
# so the on-disk byte layout stays compatible — the zero-init paths in
# db_load_key (C++) and unpack() (Python) handle older records transparently.
# tz_offset_hours took a slot that was previously a zeroed reserved word, so
# older records read back as 0.0 with the KEY_FLAG_USE_TZ bit clear — i.e.
# server-local naming (the flag, not the value, decides whether the offset
# is used), needing no conversion.
KEYENTRY_MIN_SIZE = 96
PACK_FORMAT = "<QQ32siIII32sIfIf3II32s32sII32s32s32s12I"
KEYENTRY_CURRENT_SIZE = struct.calcsize(PACK_FORMAT)
# The C++ side asserts sizeof(KeyEntry) == 344 in keydb.h. Assert the same
# here so a PACK_FORMAT edit that drifts from the struct fails at import
# rather than by writing records the C++ reader misparses.
assert KEYENTRY_CURRENT_SIZE == 344, KEYENTRY_CURRENT_SIZE

# Flag bits — keep in sync with KEY_FLAG_* in keydb.h.
FLAG_ADMIN     = 1 << 0
FLAG_BIDI_SIGN = 1 << 1   # require signed MAVLink on the user side too
FLAG_TLOG      = 1 << 2   # record per-connection MAVProxy-format tlogs
FLAG_BINLOG    = 1 << 3   # record ArduPilot bin logs over MAVLink
FLAG_USE_TZ    = 1 << 4   # name logs with tz_offset_hours; else server local
FLAG_VIDEO     = 1 << 5   # video proxying enabled for this entry

FLAG_NAMES = {
    "admin":     FLAG_ADMIN,
    "bidi_sign": FLAG_BIDI_SIGN,
    "tlog":      FLAG_TLOG,
    "binlog":    FLAG_BINLOG,
    "use_tz":    FLAG_USE_TZ,
    "video":     FLAG_VIDEO,
}

DEFAULT_LOG_RETENTION_DAYS = 7.0
RESERVED_WORDS = 12

# Video. Keep in sync with the KEY_MAX_VIDEO_PORTS / VIDEO_* block in keydb.h.
MAX_VIDEO_PORTS = 3

# video_flags carries one byte of options per slot plus a byte of
# entry-wide options:
#   bits 0-7 slot 0, 8-15 slot 1, 16-23 slot 2, 24-31 entry-wide
VIDEO_SLOT_BITS = 8
VIDEO_SLOT_SRT     = 1 << 0   # UDP side speaks SRT, not plain MPEG-TS
VIDEO_SLOT_RECORD  = 1 << 1   # write .ts segments under logs/
VIDEO_SLOT_RAW_TCP = 1 << 2   # allow raw-TCP viewers (no credential)

VIDEO_SLOT_FLAG_NAMES = {
    "srt":     VIDEO_SLOT_SRT,
    "record":  VIDEO_SLOT_RECORD,
    "raw_tcp": VIDEO_SLOT_RAW_TCP,
}

VIDEO_OPT_SHIFT = 24
VIDEO_OPT_AUDIO = 1 << 0      # carry audio from RTSP ingest as AAC (default off)

VIDEO_OPT_FLAG_NAMES = {
    "audio": VIDEO_OPT_AUDIO,
}

# Publisher grace after the MAVLink session drops, so video rides through
# an outage instead of being revoked. 0 in the record means this default.
VIDEO_MAV_GRACE_DEFAULT_S = 60
VIDEO_MAV_GRACE_MAX_S = 3600

# Video ports use the same range the web UI allows for port1/port2.
VIDEO_PORT_MIN = 1024
VIDEO_PORT_MAX = 65535

# Where automatic video port allocation starts. Deliberately well clear
# of the 10000/11000/20000/21000 blocks the MAVLink port pairs use, so a
# suggested video port never sits in the middle of a run of port1/port2
# and a whole entry's ports stay recognisable at a glance.
VIDEO_PORT_BASE = 40001


def video_slot_opts(video_flags, slot):
    """The option byte for one slot."""
    if not 0 <= slot < MAX_VIDEO_PORTS:
        return 0
    return (video_flags >> (slot * VIDEO_SLOT_BITS)) & 0xFF


def video_set_slot_opts(video_flags, slot, opts):
    """Return video_flags with slot's option byte replaced."""
    if not 0 <= slot < MAX_VIDEO_PORTS:
        raise ValueError("slot out of range: %r" % (slot,))
    shift = slot * VIDEO_SLOT_BITS
    return (video_flags & ~(0xFF << shift)) | ((opts & 0xFF) << shift)


def video_entry_opts(video_flags):
    """The entry-wide option byte."""
    return (video_flags >> VIDEO_OPT_SHIFT) & 0xFF


def video_set_entry_opts(video_flags, opts):
    return ((video_flags & ~(0xFF << VIDEO_OPT_SHIFT))
            | ((opts & 0xFF) << VIDEO_OPT_SHIFT))


# Timezone offset is a plain GMT offset in hours (fractional allowed, e.g.
# 5.5 for IST, -3.75 for Chatham). We deliberately store an offset rather
# than a named zone: a fixed offset is unambiguous and DST-free, which is
# what a log-naming convention wants (a name would need the full tz
# database plus DST handling that shifts mid-session). The offset drives
# both the YYYY-MM-DD date subdir and the YYYY_MM_DD_HH:MM:SS filename.
#
# The offset is only used when the KEY_FLAG_USE_TZ flag is set; otherwise
# logs are named in the server's own local timezone (the default, and
# what legacy records — flag clear — get, matching the pre-timestamp
# behaviour). 0 with the flag set is a genuine GMT offset.
TZ_MIN_OFFSET = -12.0
TZ_MAX_OFFSET = 14.0


def format_tz_offset(hours):
    """Render a GMT offset as e.g. 'GMT+05:30', 'GMT-03:45', 'GMT'."""
    if not math.isfinite(hours):
        return 'invalid'
    if not hours:
        return 'GMT'
    sign = '+' if hours >= 0 else '-'
    total_min = int(round(abs(hours) * 60.0))
    return 'GMT%s%02d:%02d' % (sign, total_min // 60, total_min % 60)


class CLIError(Exception):
    """Raised by helpers below when input is invalid or the entry is missing."""


def _video_key(passphrase):
    """sha256 of a video password; all-zero when unset.

    All-zero is the 'no password' sentinel, so an empty passphrase must
    hash to zeros rather than to sha256(b'') -- otherwise clearing a
    password would set one that the empty string matches.
    """
    if not passphrase:
        return bytearray(32)
    if isinstance(passphrase, str):
        passphrase = passphrase.encode('utf-8')
    return bytearray(hashlib.sha256(passphrase).digest())


def _video_key_matches(stored, passphrase):
    if not any(stored):
        return False        # no password set: callers decide what that means
    if not passphrase:
        return False
    if isinstance(passphrase, str):
        passphrase = passphrase.encode('utf-8')
    return hmac.compare_digest(bytes(stored),
                               hashlib.sha256(passphrase).digest())


class KeyEntry:
    def __init__(self, port2):
        self.magic = KEY_MAGIC
        self.timestamp = 0
        self.secret_key = bytearray(32)
        self.port1 = 0
        self.connections = 0
        self.count1 = 0
        self.count2 = 0
        self.name = ''
        self.flags = 0
        self.log_retention_days = 0.0
        self.fc_sysid = 0
        self.tz_offset_hours = 0.0
        self.video_ports = [0] * MAX_VIDEO_PORTS
        self.video_flags = 0
        self.video_viewer_key = bytearray(32)
        self.video_publish_key = bytearray(32)
        self.video_quota_mb = 0
        self.video_mav_grace_s = 0
        self.video_rtmp_path = [''] * MAX_VIDEO_PORTS
        self.reserved = [0] * RESERVED_WORDS
        self.port2 = port2
        # opaque trailing bytes from a record written by a future schema
        self._tail = b''

    def pack(self):
        name = self.name.encode('UTF-8').ljust(32, b'\x00')[:32]
        reserved = list(self.reserved) + [0] * (RESERVED_WORDS - len(self.reserved))
        vports = list(self.video_ports) + [0] * (MAX_VIDEO_PORTS - len(self.video_ports))
        body = struct.pack(PACK_FORMAT,
                           self.magic, self.timestamp, bytes(self.secret_key),
                           self.port1, self.connections, self.count1,
                           self.count2, name, self.flags,
                           self.log_retention_days,
                           self.fc_sysid,
                           self.tz_offset_hours,
                           *vports[:MAX_VIDEO_PORTS],
                           self.video_flags,
                           bytes(self.video_viewer_key),
                           bytes(self.video_publish_key),
                           self.video_quota_mb,
                           self.video_mav_grace_s,
                           *[self._rtmp_bytes(i)
                             for i in range(MAX_VIDEO_PORTS)],
                           *reserved[:RESERVED_WORDS])
        return body + self._tail

    def unpack(self, data):
        if len(data) < KEYENTRY_MIN_SIZE:
            raise ValueError("record too small: %d bytes" % len(data))
        if len(data) < KEYENTRY_CURRENT_SIZE:
            # legacy record: zero-extend so newer fields default to 0
            body = data + b'\x00' * (KEYENTRY_CURRENT_SIZE - len(data))
            self._tail = b''
        else:
            body = data[:KEYENTRY_CURRENT_SIZE]
            self._tail = data[KEYENTRY_CURRENT_SIZE:]
        unpacked = struct.unpack(PACK_FORMAT, body)
        (self.magic, self.timestamp, secret_key, self.port1,
         self.connections, self.count1, self.count2, name,
         self.flags, self.log_retention_days,
         self.fc_sysid, self.tz_offset_hours) = unpacked[:12]
        n = 12
        self.video_ports = list(unpacked[n:n + MAX_VIDEO_PORTS])
        n += MAX_VIDEO_PORTS
        (self.video_flags, viewer_key, publish_key,
         self.video_quota_mb, self.video_mav_grace_s) = unpacked[n:n + 5]
        n += 5
        self.video_rtmp_path = [
            b.decode('utf-8', errors='ignore').rstrip('\0')
            for b in unpacked[n:n + MAX_VIDEO_PORTS]]
        n += MAX_VIDEO_PORTS
        self.reserved = list(unpacked[n:n + RESERVED_WORDS])
        self.video_viewer_key = bytearray(viewer_key)
        self.video_publish_key = bytearray(publish_key)
        self.secret_key = bytearray(secret_key)
        self.name = name.decode('utf-8', errors='ignore').rstrip('\0')

    def fetch(self, db):
        v = db.get(struct.pack('<i', self.port2))
        if v is None or len(v) < KEYENTRY_MIN_SIZE:
            return False
        self.unpack(v)
        return self.magic == KEY_MAGIC

    def store(self, db):
        # preserve trailing bytes from any existing record we don't recognise
        key = struct.pack('<i', self.port2)
        existing = db.get(key)
        if existing is not None and len(existing) > KEYENTRY_CURRENT_SIZE:
            self._tail = existing[KEYENTRY_CURRENT_SIZE:]
        db.store(key, self.pack(), tdb.REPLACE)

    def remove(self, db):
        db.delete(struct.pack('<i', self.port2))

    def set_passphrase(self, passphrase):
        if isinstance(passphrase, str):
            passphrase = passphrase.encode('utf-8')
        self.secret_key = bytearray(hashlib.sha256(passphrase).digest())

    def passphrase_matches(self, passphrase):
        if isinstance(passphrase, str):
            passphrase = passphrase.encode('utf-8')
        return hmac.compare_digest(bytes(self.secret_key),
                                   hashlib.sha256(passphrase).digest())

    def is_admin(self):
        return bool(self.flags & FLAG_ADMIN)

    # --- video ---------------------------------------------------------

    def video_enabled(self):
        return bool(self.flags & FLAG_VIDEO)

    def active_video_ports(self):
        """(slot, port) for each configured slot, in slot order."""
        return [(i, p) for i, p in enumerate(self.video_ports[:MAX_VIDEO_PORTS])
                if p]

    def video_port_count(self):
        """How many video slots this entry uses.

        Derived from the ports rather than stored, so there is no second
        source of truth to disagree with them. It is the highest
        allocated slot, not the number allocated, so an entry with a gap
        still accounts for every port it owns. Never 0: an entry with no
        ports yet is presented as wanting one.
        """
        highest = 0
        for slot in range(MAX_VIDEO_PORTS):
            if self.video_ports[slot]:
                highest = slot + 1
        return highest or 1

    def _rtmp_bytes(self, slot):
        """One slot's path as a fixed 32-byte field."""
        paths = list(self.video_rtmp_path) + [''] * MAX_VIDEO_PORTS
        return paths[slot].encode('utf-8')[:31]

    def rtmp_path(self, slot):
        paths = list(self.video_rtmp_path) + [''] * MAX_VIDEO_PORTS
        return paths[slot] if 0 <= slot < MAX_VIDEO_PORTS else ''

    def set_rtmp_path(self, slot, path):
        """Set (or clear) the RTMP app/stream for one slot.

        Stored as the camera spells it -- "PhoenixFPV/FPV" -- because
        that is the form it is compared against when a publisher names
        its app and stream.
        """
        if not 0 <= slot < MAX_VIDEO_PORTS:
            raise CLIError("slot must be 0..%d" % (MAX_VIDEO_PORTS - 1))
        path = (path or '').strip().strip('/')
        if len(path.encode('utf-8')) > 31:
            raise CLIError("RTMP path too long (max 31 bytes): %r" % path)
        # A path is pasted from a camera's config page, so reject the
        # characters that would change the URL's meaning rather than
        # silently building a different one.
        bad = set(path) & set(' ?#@\\"\'<>')
        if bad:
            raise CLIError("RTMP path may not contain %s"
                           % ' '.join(sorted(bad)))
        paths = list(self.video_rtmp_path) + [''] * MAX_VIDEO_PORTS
        paths[slot] = path
        self.video_rtmp_path = paths[:MAX_VIDEO_PORTS]

    def slot_opts(self, slot):
        return video_slot_opts(self.video_flags, slot)

    def set_slot_opts(self, slot, opts):
        self.video_flags = video_set_slot_opts(self.video_flags, slot, opts)

    def slot_opt_names(self, slot):
        opts = self.slot_opts(slot)
        return [n for n, b in VIDEO_SLOT_FLAG_NAMES.items() if opts & b]

    def entry_opt_names(self):
        opts = video_entry_opts(self.video_flags)
        return [n for n, b in VIDEO_OPT_FLAG_NAMES.items() if opts & b]

    def set_video_viewer_pass(self, passphrase):
        """Empty/None clears the password (open viewing)."""
        self.video_viewer_key = _video_key(passphrase)

    def set_video_publish_pass(self, passphrase):
        """Empty/None clears it, leaving the MAVLink check as the only gate."""
        self.video_publish_key = _video_key(passphrase)

    def video_viewer_pass_set(self):
        return any(self.video_viewer_key)

    def video_publish_pass_set(self):
        return any(self.video_publish_key)

    def video_viewer_pass_matches(self, passphrase):
        return _video_key_matches(self.video_viewer_key, passphrase)

    def video_publish_pass_matches(self, passphrase):
        return _video_key_matches(self.video_publish_key, passphrase)

    def mav_grace_seconds(self):
        """Effective grace window; 0 in the record means the default."""
        return self.video_mav_grace_s or VIDEO_MAV_GRACE_DEFAULT_S

    def flag_names(self):
        on = [n for n, b in FLAG_NAMES.items() if self.flags & b]
        unknown = self.flags & ~sum(FLAG_NAMES.values())
        if unknown:
            on.append("0x%x" % unknown)
        return on

    def __str__(self):
        flagstr = ''
        if self.flags:
            flagstr = ' flags=' + ','.join(self.flag_names())
        retstr = ''
        if self.flags & (FLAG_TLOG | FLAG_BINLOG):
            if self.log_retention_days == 0.0:
                retstr = ' log_retention=forever'
            else:
                retstr = ' log_retention=%.4g days' % self.log_retention_days
        sysstr = ''
        if self.fc_sysid:
            sysstr = ' fc_sysid=%u' % self.fc_sysid
        tzstr = ''
        if self.flags & FLAG_USE_TZ:
            tzstr = ' tz=%s' % format_tz_offset(self.tz_offset_hours)
        elif self.tz_offset_hours:
            # offset stored but not active — show it parenthesised so it
            # is clear the server-local default is in effect
            tzstr = ' tz=local(%s off)' % format_tz_offset(self.tz_offset_hours)
        return ("%u/%u '%s' counts=%u/%u connections=%u ts=%u%s%s%s%s"
                % (self.port1, self.port2, self.name,
                   self.count1, self.count2, self.connections,
                   self.timestamp, flagstr, retstr, sysstr, tzstr))


def open_db(path='keys.tdb'):
    # tdb.open can return EBUSY under heavy concurrent open contention
    # (another process holds an exclusive lock through tdb_transaction_start
    # while we try to open). Retry with a short backoff: TDB's own locking
    # serializes the actual transactions, but bare open() racing with that
    # can spuriously fail. 5 attempts is enough for the test harness; for
    # the production CLI / web app it absorbs the rare collision with the
    # live supportproxy's reload tick.
    last = None
    for delay in (0.0, 0.01, 0.05, 0.1, 0.25):
        if delay:
            time.sleep(delay)
        try:
            return tdb.open(path, hash_size=1024, tdb_flags=0,
                            flags=os.O_RDWR, mode=0o600)
        except OSError as e:
            if e.errno != errno.EBUSY:
                raise
            last = e
    raise last


def init_db(path='keys.tdb'):
    return tdb.open(path, hash_size=1024, tdb_flags=0,
                    flags=os.O_RDWR | os.O_CREAT, mode=0o600)


def list_entries(db):
    """Return all KeyEntry records sorted by port2.

    Caller must hold a transaction so the multi-record traversal sees a
    consistent snapshot.
    """
    entries = []
    k = db.firstkey()
    while k is not None:
        v = db.get(k)
        if v is not None and len(v) >= KEYENTRY_MIN_SIZE and len(k) == 4:
            try:
                port2, = struct.unpack('<i', k)
                ke = KeyEntry(port2)
                ke.unpack(v)
                if ke.magic == KEY_MAGIC:
                    entries.append(ke)
            except (ValueError, struct.error):
                pass
        k = db.nextkey(k)
    entries.sort(key=lambda e: e.port2)
    return entries


def get_port_sets(db):
    """(port1s, port2s, video_ports) across every entry.

    Video ports share the same listening-port namespace as port1/port2,
    so every uniqueness check has to consider all three sets. Prefer
    ports_in_use() for new code; this stays for callers that need the
    split.
    """
    ports1 = set()
    ports2 = set()
    portsv = set()
    for e in list_entries(db):
        ports1.add(e.port1)
        ports2.add(e.port2)
        portsv.update(p for p in e.video_ports[:MAX_VIDEO_PORTS] if p)
    return ports1, ports2, portsv


def ports_in_use(db, exclude_port2=None):
    """Every port bound by any entry, as one set.

    exclude_port2 drops that entry's own ports, so an edit doesn't
    collide with itself.
    """
    used = set()
    for e in list_entries(db):
        if exclude_port2 is not None and e.port2 == exclude_port2:
            continue
        used.add(e.port1)
        used.add(e.port2)
        used.update(p for p in e.video_ports[:MAX_VIDEO_PORTS] if p)
    used.discard(0)
    return used


def suggest_video_ports(db, ke, count, keep=None):
    """Pick `count` free video ports for `ke`, counting up from
    VIDEO_PORT_BASE.

    `keep` is the entry's current ports; an already-allocated slot keeps
    its port rather than being renumbered, so opening the edit page and
    saving it does not silently move a running stream to a new port.
    Returns a MAX_VIDEO_PORTS-long list, 0 for slots beyond `count`.
    """
    keep = list(keep or [])
    keep += [0] * (MAX_VIDEO_PORTS - len(keep))

    used = ports_in_use(db, exclude_port2=ke.port2)
    used.update(p for p in (ke.port1, ke.port2) if p)
    # A kept port must not be handed to another slot as well.
    used.update(p for p in keep[:count] if p)

    out = []
    nxt = VIDEO_PORT_BASE
    for slot in range(MAX_VIDEO_PORTS):
        if slot >= count:
            out.append(0)
            continue
        if keep[slot]:
            out.append(keep[slot])
            continue
        while nxt in used and nxt <= VIDEO_PORT_MAX:
            nxt += 1
        if nxt > VIDEO_PORT_MAX:
            # Nothing free above the base. Leave it for the operator to
            # fill in rather than suggesting a port that cannot be used.
            out.append(0)
            continue
        out.append(nxt)
        used.add(nxt)
        nxt += 1
    return out


def find_by_port(db, port):
    """Find an entry by port1 OR port2. Caller holds a transaction.

    Tries port2 (direct fetch) first, then scans port1.
    """
    ke = KeyEntry(port)
    if ke.fetch(db) and ke.magic == KEY_MAGIC:
        return ke
    for e in list_entries(db):
        if e.port1 == port:
            return e
    return None


def count_admins(db):
    """Caller holds a transaction."""
    return sum(1 for e in list_entries(db) if e.is_admin())


# Mutation helpers. Caller must hold a transaction; commit/cancel is the
# caller's responsibility so multiple mutations can share one transaction.

def add_entry(db, port1, port2, name, passphrase):
    used = ports_in_use(db)
    if port1 in used:
        raise CLIError("Port %d is already in use" % port1)
    if port2 in used:
        raise CLIError("Port %d is already in use" % port2)
    if port1 == port2:
        raise CLIError("port1 and port2 must differ")
    ke = KeyEntry(port2)
    ke.port1 = port1
    ke.name = name
    ke.set_passphrase(passphrase)
    ke.store(db)
    return ke


def remove_entry(db, port2):
    ke = KeyEntry(port2)
    if not ke.fetch(db):
        raise CLIError("Entry for port2 %d not found" % port2)
    ke.remove(db)
    return ke


def set_name(db, port2, name):
    ke = KeyEntry(port2)
    if not ke.fetch(db):
        raise CLIError("Failed to find ID with port2 %d" % port2)
    ke.name = name
    ke.store(db)
    return ke


def set_pass(db, port2, passphrase):
    ke = KeyEntry(port2)
    if not ke.fetch(db):
        raise CLIError("No entry for port2 %d" % port2)
    ke.set_passphrase(passphrase)
    ke.store(db)
    return ke


def reset_timestamp(db, port2):
    ke = KeyEntry(port2)
    if not ke.fetch(db):
        raise CLIError("No entry for port2 %d" % port2)
    ke.timestamp = 0
    ke.store(db)
    return ke


def set_port1(db, port2, port1):
    ke = KeyEntry(port2)
    if not ke.fetch(db):
        raise CLIError("No entry for port2 %d" % port2)
    ke.port1 = port1
    ke.store(db)
    return ke


def _flag_bit(flag_name):
    if flag_name not in FLAG_NAMES:
        raise CLIError("Unknown flag '%s'. Known: %s"
                       % (flag_name, ', '.join(sorted(FLAG_NAMES))))
    return FLAG_NAMES[flag_name]


def set_flag(db, port2, flag_name):
    bit = _flag_bit(flag_name)
    ke = KeyEntry(port2)
    if not ke.fetch(db):
        raise CLIError("No entry for port2 %d" % port2)
    was_set = bool(ke.flags & bit)
    ke.flags |= bit
    # Auto-default the shared log retention on first enable from a
    # fresh-zero state. Applies to either tlog or binlog — both file
    # types share the same per-entry retention.
    if (bit == FLAG_TLOG or bit == FLAG_BINLOG) \
            and not was_set and ke.log_retention_days == 0.0:
        ke.log_retention_days = DEFAULT_LOG_RETENTION_DAYS
    ke.store(db)
    return ke


def clear_flag(db, port2, flag_name):
    bit = _flag_bit(flag_name)
    ke = KeyEntry(port2)
    if not ke.fetch(db):
        raise CLIError("No entry for port2 %d" % port2)
    ke.flags &= ~bit
    ke.store(db)
    return ke


def set_log_retention(db, port2, days):
    """Set the per-entry log retention (days). Applies to both .tlog
    and .bin files — they share one retention value per entry."""
    ke = KeyEntry(port2)
    if not ke.fetch(db):
        raise CLIError("No entry for port2 %d" % port2)
    if days < 0.0:
        raise CLIError("retention days must be >= 0 (got %r)" % days)
    ke.log_retention_days = float(days)
    ke.store(db)
    return ke


def set_timezone(db, port2, hours):
    """Set the per-entry log-naming GMT offset (hours, fractional) and
    enable its use (KEY_FLAG_USE_TZ). Setting a timezone means you want
    it applied; clear the 'use_tz' flag to revert to server-local naming
    without discarding the stored offset."""
    ke = KeyEntry(port2)
    if not ke.fetch(db):
        raise CLIError("No entry for port2 %d" % port2)
    if not math.isfinite(hours):
        raise CLIError("timezone offset must be a finite number (got %r)"
                       % hours)
    if hours < TZ_MIN_OFFSET or hours > TZ_MAX_OFFSET:
        raise CLIError("timezone offset must be in %g..%g hours (got %r)"
                       % (TZ_MIN_OFFSET, TZ_MAX_OFFSET, hours))
    ke.tz_offset_hours = float(hours)
    ke.flags |= FLAG_USE_TZ
    ke.store(db)
    return ke


def set_fc_sysid(db, port2, sysid):
    """Set the MAVLink sysid filter for this entry. 0 = match any (default);
    non-zero restricts binlog reboot detection to packets from that sysid."""
    ke = KeyEntry(port2)
    if not ke.fetch(db):
        raise CLIError("No entry for port2 %d" % port2)
    if sysid < 0 or sysid > 255:
        raise CLIError("fc_sysid must be in 0..255 (got %r)" % sysid)
    ke.fc_sysid = int(sysid)
    ke.store(db)
    return ke


def validate_video_ports(db, ke, ports):
    """Normalise `ports` to a MAX_VIDEO_PORTS-long list, or raise CLIError.

    Video ports share the listening-port namespace with port1/port2, so
    each is checked against every port any *other* entry binds, against
    this entry's own port1/port2, and against the others in this list.

    Split out from set_video_ports() so the web UI can validate against
    an entry it has already fetched and is about to store itself, rather
    than going through a second fetch/store.
    """
    if len(ports) > MAX_VIDEO_PORTS:
        raise CLIError("at most %d video ports (got %d)"
                       % (MAX_VIDEO_PORTS, len(ports)))

    vports = [int(p or 0) for p in ports]
    vports += [0] * (MAX_VIDEO_PORTS - len(vports))
    used = ports_in_use(db, exclude_port2=ke.port2)
    seen = set()
    for p in vports:
        if p == 0:
            continue
        if p < VIDEO_PORT_MIN or p > VIDEO_PORT_MAX:
            raise CLIError("video port %d out of range %d..%d"
                           % (p, VIDEO_PORT_MIN, VIDEO_PORT_MAX))
        if p in (ke.port1, ke.port2):
            raise CLIError("video port %d collides with this entry's "
                           "own port1/port2" % p)
        if p in seen:
            raise CLIError("video port %d is listed twice" % p)
        if p in used:
            raise CLIError("Port %d is already in use" % p)
        seen.add(p)
    return vports


def set_video_ports(db, port2, ports):
    """Set this entry's video ports. `ports` is a list of up to 3 ints;
    0 (or a short list) leaves the remaining slots unused."""
    ke = KeyEntry(port2)
    if not ke.fetch(db):
        raise CLIError("No entry for port2 %d" % port2)
    ke.video_ports = validate_video_ports(db, ke, ports)
    ke.store(db)
    return ke


def set_video_rtmp_path(db, port2, slot, path):
    """Set the RTMP app/stream a slot accepts, e.g. 'PhoenixFPV/FPV'.

    Optional, and an access control rather than a requirement: the
    publisher's app and stream are read off the wire, so a blank path
    accepts whatever the camera publishes.
    """
    ke = KeyEntry(port2)
    if not ke.fetch(db):
        raise CLIError("No entry for port2 %d" % port2)
    if not 0 <= slot < MAX_VIDEO_PORTS:
        raise CLIError("video slot must be 0..%d (got %r)"
                       % (MAX_VIDEO_PORTS - 1, slot))
    ke.set_rtmp_path(slot, path)
    ke.store(db)
    return ke


def set_video_slot_flag(db, port2, slot, flag_name, on=True):
    """Set or clear one per-slot video option (srt / record / raw_tcp)."""
    ke = KeyEntry(port2)
    if not ke.fetch(db):
        raise CLIError("No entry for port2 %d" % port2)
    if not 0 <= slot < MAX_VIDEO_PORTS:
        raise CLIError("video slot must be 0..%d (got %r)"
                       % (MAX_VIDEO_PORTS - 1, slot))
    bit = VIDEO_SLOT_FLAG_NAMES.get(flag_name)
    if bit is None:
        raise CLIError("unknown video slot flag '%s' (known: %s)"
                       % (flag_name, ', '.join(sorted(VIDEO_SLOT_FLAG_NAMES))))
    opts = ke.slot_opts(slot)
    ke.set_slot_opts(slot, (opts | bit) if on else (opts & ~bit))
    ke.store(db)
    return ke


def set_video_entry_flag(db, port2, flag_name, on=True):
    """Set or clear one entry-wide video option (audio)."""
    ke = KeyEntry(port2)
    if not ke.fetch(db):
        raise CLIError("No entry for port2 %d" % port2)
    bit = VIDEO_OPT_FLAG_NAMES.get(flag_name)
    if bit is None:
        raise CLIError("unknown video option '%s' (known: %s)"
                       % (flag_name, ', '.join(sorted(VIDEO_OPT_FLAG_NAMES))))
    opts = video_entry_opts(ke.video_flags)
    ke.video_flags = video_set_entry_opts(
        ke.video_flags, (opts | bit) if on else (opts & ~bit))
    ke.store(db)
    return ke


def set_video_viewer_pass(db, port2, passphrase):
    """Set (or clear, with an empty passphrase) the video viewer password."""
    ke = KeyEntry(port2)
    if not ke.fetch(db):
        raise CLIError("No entry for port2 %d" % port2)
    ke.set_video_viewer_pass(passphrase)
    ke.store(db)
    return ke


def set_video_publish_pass(db, port2, passphrase):
    """Set (or clear) the video publish password.

    Cleared is the normal case: publish is then gated only by a MAVLink
    session from the same address within the grace window.
    """
    ke = KeyEntry(port2)
    if not ke.fetch(db):
        raise CLIError("No entry for port2 %d" % port2)
    ke.set_video_publish_pass(passphrase)
    ke.store(db)
    return ke


def set_video_quota(db, port2, quota_mb):
    """Per-entry video disk budget in MB. 0 = use the server default."""
    ke = KeyEntry(port2)
    if not ke.fetch(db):
        raise CLIError("No entry for port2 %d" % port2)
    q = int(quota_mb)
    if q < 0:
        raise CLIError("video quota must be >= 0 (got %r)" % quota_mb)
    ke.video_quota_mb = q
    ke.store(db)
    return ke


def set_video_grace(db, port2, seconds):
    """Publisher grace after the MAVLink session drops. 0 = default."""
    ke = KeyEntry(port2)
    if not ke.fetch(db):
        raise CLIError("No entry for port2 %d" % port2)
    s = int(seconds)
    if s < 0 or s > VIDEO_MAV_GRACE_MAX_S:
        raise CLIError("video grace must be 0..%d seconds (got %r)"
                       % (VIDEO_MAV_GRACE_MAX_S, seconds))
    ke.video_mav_grace_s = s
    ke.store(db)
    return ke


def convert_db(db):
    """Convert legacy 48-byte records to the current layout."""
    count = 0
    for k in db.keys():
        if len(k) != 4:
            continue
        port2, = struct.unpack('<i', k)
        v = db.get(k)
        if v is not None and len(v) == 48:
            magic, timestamp, secret_key = struct.unpack("<QQ32s", v)
            ke = KeyEntry(port2)
            ke.magic = magic
            ke.timestamp = timestamp
            ke.secret_key = bytearray(secret_key)
            if port2 != 0:
                ke.port1 = port2 - 1000
            ke.store(db)
            count += 1
    return count
