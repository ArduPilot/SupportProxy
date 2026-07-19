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
# The current C++ struct ends with `uint32_t flags`, `float log_retention_days`,
# `uint32_t fc_sysid`, `float tz_offset_hours`, and `uint32_t reserved[14]`. All
# are 4-byte aligned and slot in cleanly after the existing fields, so the
# struct is 168 bytes with no trailing pad. When a future field is added, claim
# another `reserved[]` slot (renumber: shrink reserved by 1, add a named field)
# so the on-disk byte layout stays compatible — the zero-init paths in
# db_load_key (C++) and unpack() (Python) handle older records transparently.
# tz_offset_hours took a slot that was previously a zeroed reserved word, so
# older records read back as 0.0 with the KEY_FLAG_USE_TZ bit clear — i.e.
# server-local naming (the flag, not the value, decides whether the offset
# is used), needing no conversion.
KEYENTRY_MIN_SIZE = 96
PACK_FORMAT = "<QQ32siIII32sIfIf14I"
KEYENTRY_CURRENT_SIZE = struct.calcsize(PACK_FORMAT)  # 168

# Flag bits — keep in sync with KEY_FLAG_* in keydb.h.
FLAG_ADMIN     = 1 << 0
FLAG_BIDI_SIGN = 1 << 1   # require signed MAVLink on the user side too
FLAG_TLOG      = 1 << 2   # record per-connection MAVProxy-format tlogs
FLAG_BINLOG    = 1 << 3   # record ArduPilot bin logs over MAVLink
FLAG_USE_TZ    = 1 << 4   # name logs with tz_offset_hours; else server local

FLAG_NAMES = {
    "admin":     FLAG_ADMIN,
    "bidi_sign": FLAG_BIDI_SIGN,
    "tlog":      FLAG_TLOG,
    "binlog":    FLAG_BINLOG,
    "use_tz":    FLAG_USE_TZ,
}

DEFAULT_LOG_RETENTION_DAYS = 7.0
RESERVED_WORDS = 14


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
        self.reserved = [0] * RESERVED_WORDS
        self.port2 = port2
        # opaque trailing bytes from a record written by a future schema
        self._tail = b''

    def pack(self):
        name = self.name.encode('UTF-8').ljust(32, b'\x00')[:32]
        reserved = list(self.reserved) + [0] * (RESERVED_WORDS - len(self.reserved))
        body = struct.pack(PACK_FORMAT,
                           self.magic, self.timestamp, bytes(self.secret_key),
                           self.port1, self.connections, self.count1,
                           self.count2, name, self.flags,
                           self.log_retention_days,
                           self.fc_sysid,
                           self.tz_offset_hours,
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
        self.reserved = list(unpacked[12:12 + RESERVED_WORDS])
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
    ports1 = set()
    ports2 = set()
    for e in list_entries(db):
        ports1.add(e.port1)
        ports2.add(e.port2)
    return ports1, ports2


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
    ports1, ports2 = get_port_sets(db)
    if port1 in ports1 or port1 in ports2:
        raise CLIError("Entry already exists for port1 %d" % port1)
    if port2 in ports2 or port2 in ports1:
        raise CLIError("Entry already exists for port2 %d" % port2)
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
