/*
  key database structure
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <tdb.h>

#define KEY_FILE "keys.tdb"

#define KEY_MAGIC 0x6b73e867a72cdd1fULL

/*
  Append-only forward-compatible record layout.

  - New fields are appended at the end. Existing field offsets/sizes never change.
  - Readers accept any record of size >= KEYENTRY_MIN_SIZE (the size of the
    pre-flags layout). Bytes beyond what the reader's sizeof(KeyEntry) covers
    are ignored on read; bytes missing from the on-disk record are zero-padded.
  - Writers preserve any trailing bytes the on-disk record had beyond their
    sizeof(KeyEntry), so older code never truncates fields added by newer code.
 */
#define KEYENTRY_MIN_SIZE 96

/*
  flag bits
 */
#define KEY_FLAG_ADMIN     (1u << 0)
#define KEY_FLAG_BIDI_SIGN (1u << 1)  // require signed MAVLink on the user side too
#define KEY_FLAG_TLOG      (1u << 2)  // record per-connection MAVProxy-format tlogs
#define KEY_FLAG_BINLOG    (1u << 3)  // record ArduPilot bin logs over MAVLink
#define KEY_FLAG_USE_TZ    (1u << 4)  // name logs with tz_offset_hours; else server local
#define KEY_FLAG_VIDEO     (1u << 5)  // video proxying enabled for this entry
#define KEY_FLAG_LOG_LOGIN (1u << 6)  // any authenticated web user may read logs
#define KEY_FLAG_LOG_PUBLIC (1u << 7) // anyone with the URL may read logs

#define KEY_MAX_VIDEO_PORTS 5

/*
  How many slots the original layout carried inline.

  Slots 0..2 live in video_ports/video_flags/video_rtmp_path where they
  always did; 3 and 4 are in fields appended after reserved[]. The split
  is not elegant, but those three are middle fields: growing any of them
  shifts every field after it, so every record already on disk would be
  misparsed and an older binary would read garbage. The append-only
  contract at the top of this file is what makes that unnecessary, and
  the accessors below keep the seam out of callers' way.
 */
#define KEY_VIDEO_PORTS_INLINE 3

/*
  KeyEntry.video_flags: one byte of options per video slot, plus a
  byte of entry-wide options. A byte per slot (rather than packing bits
  tightly) keeps the shift arithmetic obvious and leaves room to grow
  without another schema change.

    bits  0-7   slot 0
    bits  8-15  slot 1
    bits 16-23  slot 2
    bits 24-31  entry-wide

  That is the whole word, which is why slots 3 and 4 have their own
  video_flags_hi (byte 0 = slot 3, byte 1 = slot 4). Widening this field
  was not an option: it sits in the middle of the record.
 */
#define VIDEO_SLOT_BITS 8
#define VIDEO_SLOT_SHIFT(slot) ((slot) * VIDEO_SLOT_BITS)

// per-slot bits
#define VIDEO_SLOT_SRT     (1u << 0)  // UDP side speaks SRT, not plain MPEG-TS
#define VIDEO_SLOT_RECORD  (1u << 1)  // write .ts segments under logs/
#define VIDEO_SLOT_RAW_TCP (1u << 2)  // allow raw-TCP viewers (no credential)
/*
  Accept a publisher on this slot that its MAVLink session authorises,
  even though the entry has a publish password.

  Some publishers cannot present one: a camera speaking RTMP straight
  out of its own firmware has nowhere to put a credential unless its
  stream-key field tolerates a query, and plain MPEG-TS over UDP never
  does. Without this the choice was all-or-nothing per entry -- set a
  password and those streams stop, or leave it off and every stream is
  admitted on its source address.

  Opt-in, and per slot, so an entry that already has a password keeps
  password-only publishing everywhere until someone deliberately widens
  one slot. The fallback applies only when no credential was offered at
  all: a wrong password is still a wrong password, so a typo does not
  quietly succeed on the strength of the address.
 */
#define VIDEO_SLOT_SESSION_OK (1u << 3)
/*
  Admit a publisher that offers no credential without any check at all:
  no MAVLink session, no publish password. Anyone who can reach the port
  can publish, so this is off by default and per slot. A password that
  is offered and wrong is still refused.
 */
#define VIDEO_SLOT_OPEN_PUB (1u << 4)

// entry-wide bits, stored in the top byte
#define VIDEO_OPT_SHIFT 24
#define VIDEO_OPT_AUDIO (1u << 0)     // carry audio from RTSP ingest as AAC.
                                      // Default off: audio is rarely useful
                                      // from an aircraft, and dropping it
                                      // keeps the muxed TS video-only.

/*
  Per-slot options, from whichever word holds the slot. Callers that
  keep their own copy of the two words (supportproxy's listen_port) use
  this directly; everything else uses the KeyEntry overload below.
 */
static inline uint32_t video_slot_opts_split(uint32_t lo, uint32_t hi,
                                             unsigned slot)
{
    if (slot >= KEY_MAX_VIDEO_PORTS) {
        return 0;
    }
    if (slot < KEY_VIDEO_PORTS_INLINE) {
        return (lo >> VIDEO_SLOT_SHIFT(slot)) & 0xFFu;
    }
    return (hi >> VIDEO_SLOT_SHIFT(slot - KEY_VIDEO_PORTS_INLINE)) & 0xFFu;
}

static inline uint32_t video_slot_opts_set(uint32_t word, unsigned index,
                                           uint32_t opts)
{
    const uint32_t mask = 0xFFu << VIDEO_SLOT_SHIFT(index);
    return (word & ~mask) | ((opts & 0xFFu) << VIDEO_SLOT_SHIFT(index));
}

static inline uint32_t video_entry_opts(uint32_t video_flags)
{
    return (video_flags >> VIDEO_OPT_SHIFT) & 0xFFu;
}

// A publisher with no credential is accepted when a MAVLink session for
// the same entry was seen from the same address within this window, so
// video rides through a MAVLink dropout instead of being revoked.
#define VIDEO_MAV_GRACE_DEFAULT_S 60u

struct KeyEntry {
    uint64_t magic;
    uint64_t timestamp;
    uint8_t secret_key[32];
    int port1;
    uint32_t connections;
    uint32_t count1;
    uint32_t count2;
    char name[32];
    uint32_t flags;
    float    log_retention_days;    // tlog + bin; 0.0 = forever; fractional values allowed for tests
    uint32_t fc_sysid;              // 0 = match any; otherwise only monitor packets from this MAVLink sysid (binlog reboot detection)
    float    tz_offset_hours;       // log naming: GMT offset in hours (fractional allowed), used only when KEY_FLAG_USE_TZ is set
    uint32_t video_ports[KEY_VIDEO_PORTS_INLINE];  // 0 = slot unused
    uint32_t video_flags;           // VIDEO_SLOT_* / VIDEO_OPT_*, see above
    uint8_t  video_viewer_key[32];  // sha256(viewer password); all-zero = open
    uint8_t  video_publish_key[32]; // sha256(publish password); all-zero = the
                                    // MAVLink-session check is the only gate
    uint32_t video_quota_mb;        // per-entry video disk budget; 0 = default
    uint32_t video_mav_grace_s;     // publisher grace after MAVLink drops;
                                    // 0 = VIDEO_MAV_GRACE_DEFAULT_S
    /*
      RTMP publish path for each slot, "app/stream" as configured on the
      camera, e.g. "PhoenixFPV/FPV". Empty = accept whatever is
      published.

      Optional, and an access control rather than a requirement: RTMP is
      parsed here now (videortmp.cpp), so the app and stream are read off
      the wire. Set, only that path is admitted on the slot.
     */
    char video_rtmp_path[KEY_VIDEO_PORTS_INLINE][32];
    uint32_t reserved[12];

    /*
      Slots 3 and 4. Appended rather than grown into the arrays above,
      which are middle fields -- see KEY_VIDEO_PORTS_INLINE. A record
      written before these existed zero-extends, which reads as two
      unused slots, so nothing needs converting.
     */
    uint32_t video_ports_hi[KEY_MAX_VIDEO_PORTS - KEY_VIDEO_PORTS_INLINE];
    uint32_t video_flags_hi;        // byte 0 = slot 3, byte 1 = slot 4
    char video_rtmp_path_hi[KEY_MAX_VIDEO_PORTS - KEY_VIDEO_PORTS_INLINE][32];
    uint32_t reserved2[9];
};

/* Unified views over the split. Slot indices are 0..KEY_MAX_VIDEO_PORTS-1. */
static inline uint32_t video_port_of(const struct KeyEntry &ke, unsigned slot)
{
    if (slot < KEY_VIDEO_PORTS_INLINE) {
        return ke.video_ports[slot];
    }
    if (slot < KEY_MAX_VIDEO_PORTS) {
        return ke.video_ports_hi[slot - KEY_VIDEO_PORTS_INLINE];
    }
    return 0;
}

static inline const char *video_rtmp_path_of(const struct KeyEntry &ke,
                                             unsigned slot)
{
    if (slot < KEY_VIDEO_PORTS_INLINE) {
        return ke.video_rtmp_path[slot];
    }
    if (slot < KEY_MAX_VIDEO_PORTS) {
        return ke.video_rtmp_path_hi[slot - KEY_VIDEO_PORTS_INLINE];
    }
    return "";
}

static inline uint32_t video_slot_opts_of(const struct KeyEntry &ke,
                                          unsigned slot)
{
    return video_slot_opts_split(ke.video_flags, ke.video_flags_hi, slot);
}

/*
  The on-disk layout is an ABI shared with keydb_lib.py's PACK_FORMAT
  ("<QQ32siIII32sIfIf3II32s32sII32s32s32s12I2II32s32s9I"). Nothing enforced that
  agreement until these asserts: a padding change or a differently-sized
  int/float would silently produce records the Python side misparses.

  The record grew 168 -> 248 -> 344 -> 456 as video fields were added,
  the last step to carry video slots 3 and 4. That is
  allowed by the append-only contract at the top of this file: readers
  zero-extend a short record and writers preserve any tail they don't
  understand, so old and new binaries interoperate in both directions.
 */
static_assert(sizeof(int) == 4, "KeyEntry ABI assumes 32-bit int");
static_assert(sizeof(float) == 4, "KeyEntry ABI assumes 32-bit float");
static_assert(sizeof(struct KeyEntry) == 456, "KeyEntry size changed");
static_assert(offsetof(struct KeyEntry, magic) == 0, "KeyEntry layout");
static_assert(offsetof(struct KeyEntry, timestamp) == 8, "KeyEntry layout");
static_assert(offsetof(struct KeyEntry, secret_key) == 16, "KeyEntry layout");
static_assert(offsetof(struct KeyEntry, port1) == 48, "KeyEntry layout");
static_assert(offsetof(struct KeyEntry, connections) == 52, "KeyEntry layout");
static_assert(offsetof(struct KeyEntry, count1) == 56, "KeyEntry layout");
static_assert(offsetof(struct KeyEntry, count2) == 60, "KeyEntry layout");
static_assert(offsetof(struct KeyEntry, name) == 64, "KeyEntry layout");
static_assert(offsetof(struct KeyEntry, flags) == 96, "KeyEntry layout");
static_assert(offsetof(struct KeyEntry, log_retention_days) == 100, "KeyEntry layout");
static_assert(offsetof(struct KeyEntry, fc_sysid) == 104, "KeyEntry layout");
static_assert(offsetof(struct KeyEntry, tz_offset_hours) == 108, "KeyEntry layout");
static_assert(offsetof(struct KeyEntry, video_ports) == 112, "KeyEntry layout");
static_assert(offsetof(struct KeyEntry, video_flags) == 124, "KeyEntry layout");
static_assert(offsetof(struct KeyEntry, video_viewer_key) == 128, "KeyEntry layout");
static_assert(offsetof(struct KeyEntry, video_publish_key) == 160, "KeyEntry layout");
static_assert(offsetof(struct KeyEntry, video_quota_mb) == 192, "KeyEntry layout");
static_assert(offsetof(struct KeyEntry, video_mav_grace_s) == 196, "KeyEntry layout");
// Slots 3 and 4 start after every field the 344-byte record had, so an
// old record zero-extends into them and an old writer preserves them.
static_assert(offsetof(struct KeyEntry, video_ports_hi) == 344, "KeyEntry layout");
static_assert(offsetof(struct KeyEntry, video_flags_hi) == 352, "KeyEntry layout");
static_assert(offsetof(struct KeyEntry, video_rtmp_path_hi) == 356, "KeyEntry layout");
static_assert(offsetof(struct KeyEntry, reserved2) == 420, "KeyEntry layout");
static_assert(offsetof(struct KeyEntry, video_rtmp_path) == 200,
              "KeyEntry layout");
static_assert(sizeof(((struct KeyEntry *)nullptr)->video_rtmp_path) == 96,
              "KeyEntry layout");
static_assert(offsetof(struct KeyEntry, reserved) == 296, "KeyEntry layout");
// No implicit tail padding, so appending a field trips the size assert.
static_assert(offsetof(struct KeyEntry, reserved2) + 9*sizeof(uint32_t)
              == sizeof(struct KeyEntry), "KeyEntry must have no tail padding");
// KEYENTRY_MIN_SIZE is the pre-flags layout: everything through name[].
static_assert(KEYENTRY_MIN_SIZE == offsetof(struct KeyEntry, flags),
              "KEYENTRY_MIN_SIZE must be the offset of the first post-legacy field");

/*
  open DB with or without a transaction
 */
TDB_CONTEXT *db_open(void);
void db_close(TDB_CONTEXT *db);
TDB_CONTEXT *db_open_transaction(void);
void db_close_cancel(TDB_CONTEXT *db);
void db_close_commit(TDB_CONTEXT *db);
bool db_load_key(TDB_CONTEXT *tdb, int port2, struct KeyEntry &key);
bool db_save_key(TDB_CONTEXT *tdb, int port2, const struct KeyEntry &key);
