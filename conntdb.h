/*
  Per-connection live state, persisted to connections.tdb so the web
  admin UI can render who is currently connected to each port pair
  without poking into the running children.

  Layout matches the keys.tdb forward-compat pattern:
    - Append-only fields. Existing offsets/sizes never change.
    - Readers accept records of size >= CONNENTRY_MIN_SIZE; trailing
      bytes beyond what they understand are preserved on write.

  Each per-port-pair child writes its own records here, on connect/
  disconnect events and on a 10s heartbeat snapshot driven by the
  same fork-and-write idiom mavlink.cpp uses for save_signing_timestamp().
  The supportproxy parent wipes the file at startup and clears
  records for exiting / removed children.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <tdb.h>

#define CONN_FILE "connections.tdb"

#define CONN_MAGIC 0x436f6e6e45424553ULL  // "ConnEBES"

#define CONN_TRANSPORT_UDP 0
#define CONN_TRANSPORT_TCP 1
#define CONN_TRANSPORT_WS  2
#define CONN_TRANSPORT_WSS 3

// Pre-flags layout was 64 bytes; bump CONNENTRY_MIN_SIZE only if we
// ever decide to drop a field (we shouldn't).
#define CONNENTRY_MIN_SIZE 64

// flag bits on ConnEntry.flags
//
// CONN_FLAG_DROP_REQUESTED:  the web admin has asked the per-port-pair
//   child to drop this specific connection. The webadmin sets the bit
//   in TDB and sends SIGUSR1 to the child; the child's main_loop scans
//   for entries matching its port2 with this bit set, closes the
//   matching slot, and deletes the record.
#define CONN_FLAG_DROP_REQUESTED (1u << 0)

// ConnEntry.role
#define CONN_ROLE_MAVLINK   0
#define CONN_ROLE_VIDEO_PUB 1
#define CONN_ROLE_VIDEO_SUB 2

// ConnEntry.app_proto — the application protocol on top of .transport
#define CONN_APP_MAVLINK 0
#define CONN_APP_MPEGTS  1
#define CONN_APP_RTSP    2
#define CONN_APP_HTTP    3
#define CONN_APP_SRT     4
#define CONN_APP_RTMP    5

/*
  Video rows live in a conn_index range disjoint from the MAVLink ones
  (0 = user, 1..MAX_COMM2_LINKS = engineer slots), because the two
  writers snapshot independently: each deletes and rewrites only its own
  range, so neither erases the other's rows.
 */
#define VIDEO_CONN_INDEX_BASE 1000
#define VIDEO_CONN_STRIDE     256
#define VIDEO_PUB_INDEX(slot)      (VIDEO_CONN_INDEX_BASE + (slot)*VIDEO_CONN_STRIDE)
#define VIDEO_SUB_INDEX(slot, i)   (VIDEO_PUB_INDEX(slot) + 1 + (i))

struct ConnEntry {
    uint64_t magic;            // CONN_MAGIC
    uint64_t connected_at;     // unix seconds
    uint64_t last_update;      // unix seconds
    int      port2;            // owning entry's primary key
    int      conn_index;       // 0 = mav1 (user); 1..MAX_COMM2_LINKS = conn2[i-1]
    uint32_t pid;              // owning child pid (parent uses this for cleanup)
    uint32_t rx_msgs;          // mavlink messages parsed FROM this peer
    uint32_t tx_msgs;          // mavlink messages forwarded TO this peer
    uint32_t peer_ip_be;       // sockaddr_in.sin_addr.s_addr (network order)
    uint16_t peer_port_be;     // network order
    uint8_t  transport;        // CONN_TRANSPORT_*
    uint8_t  is_user;          // 1 if this is mav1, 0 if engineer-side
    uint32_t flags;            // reserved (forward-compat)
    uint32_t _pad;             // keep total a multiple of 8
    uint32_t _pad2;            // was implicit tail padding; see below
    // Fields below are the video extension. They start at offset 64,
    // after _pad2, for the reason spelled out in the comment below.
    uint8_t  role;             // CONN_ROLE_*
    uint8_t  stream_idx;       // video slot 0..KEY_MAX_VIDEO_PORTS-1
    uint8_t  app_proto;        // CONN_APP_*
    uint8_t  authenticated;    // 1 = MAVLink signature validated. Only the
                               // session child ever sets this; the video
                               // child requires it on bidi entries.
    uint32_t _pad3;
};

/*
  ABI shared with conntdb_lib.py's PACK_FORMAT ("<QQQiiIIIIHBBII4x").

  _pad2 covers bytes 60..63, which used to be *implicit* tail padding
  (the struct is 8-aligned, so sizeof was already 64) and which the
  Python format spells out as its trailing "4x". Naming it matters:
  while it was implicit, appending a field in C++ silently placed that
  field at offset 60 without changing sizeof, so no size assert could
  catch it — yet an older Python writer zeroes those bytes on every
  rewrite. Now any appended field pushes sizeof past 64 and trips the
  assert below. New fields go after _pad2, at offset 64.

  Both sides agree these bytes are zero: Python emits "4x", and every
  C++ construction site value-initialises (ConnEntry e {}).
 */
static_assert(sizeof(int) == 4, "ConnEntry ABI assumes 32-bit int");
static_assert(sizeof(struct ConnEntry) == 72, "ConnEntry size changed");
static_assert(offsetof(struct ConnEntry, magic) == 0, "ConnEntry layout");
static_assert(offsetof(struct ConnEntry, connected_at) == 8, "ConnEntry layout");
static_assert(offsetof(struct ConnEntry, last_update) == 16, "ConnEntry layout");
static_assert(offsetof(struct ConnEntry, port2) == 24, "ConnEntry layout");
static_assert(offsetof(struct ConnEntry, conn_index) == 28, "ConnEntry layout");
static_assert(offsetof(struct ConnEntry, pid) == 32, "ConnEntry layout");
static_assert(offsetof(struct ConnEntry, rx_msgs) == 36, "ConnEntry layout");
static_assert(offsetof(struct ConnEntry, tx_msgs) == 40, "ConnEntry layout");
static_assert(offsetof(struct ConnEntry, peer_ip_be) == 44, "ConnEntry layout");
static_assert(offsetof(struct ConnEntry, peer_port_be) == 48, "ConnEntry layout");
static_assert(offsetof(struct ConnEntry, transport) == 50, "ConnEntry layout");
static_assert(offsetof(struct ConnEntry, is_user) == 51, "ConnEntry layout");
static_assert(offsetof(struct ConnEntry, flags) == 52, "ConnEntry layout");
static_assert(offsetof(struct ConnEntry, _pad) == 56, "ConnEntry layout");
static_assert(offsetof(struct ConnEntry, _pad2) == 60, "ConnEntry layout");
// The video extension starts here. It had to begin at 64 rather than 60:
// while bytes 60..63 were implicit tail padding, a field placed there did
// not change sizeof (so no size assert could catch it) yet an older
// Python writer zeroes them on every rewrite via its trailing "4x".
static_assert(offsetof(struct ConnEntry, role) == 64, "ConnEntry layout");
static_assert(offsetof(struct ConnEntry, stream_idx) == 65, "ConnEntry layout");
static_assert(offsetof(struct ConnEntry, app_proto) == 66, "ConnEntry layout");
static_assert(offsetof(struct ConnEntry, authenticated) == 67, "ConnEntry layout");
static_assert(offsetof(struct ConnEntry, _pad3) == 68, "ConnEntry layout");
// No implicit tail padding, so appending a field trips the size assert.
static_assert(offsetof(struct ConnEntry, _pad3) + sizeof(uint32_t)
              == sizeof(struct ConnEntry),
              "ConnEntry must have no implicit tail padding");
// Old records are 64 bytes; readers zero-extend them, which leaves
// authenticated == 0 and so fails closed for bidi entries.
static_assert(CONNENTRY_MIN_SIZE == 64,
              "CONNENTRY_MIN_SIZE is the pre-video record size");

struct ConnKey {
    int port2;
    int conn_index;
};

// Keyed lookups depend on this being a bare 8-byte pair with no padding.
static_assert(sizeof(struct ConnKey) == 8, "ConnKey layout");
static_assert(offsetof(struct ConnKey, conn_index) == 4, "ConnKey layout");

TDB_CONTEXT *conn_db_open(void);
TDB_CONTEXT *conn_db_open_transaction(void);
void conn_db_close(TDB_CONTEXT *db);
void conn_db_close_cancel(TDB_CONTEXT *db);
void conn_db_close_commit(TDB_CONTEXT *db);

// individual record write/delete (caller holds an open transaction)
bool conn_write(TDB_CONTEXT *db, const struct ConnEntry &ce);
bool conn_delete(TDB_CONTEXT *db, int port2, int conn_index);

// Wipe every record whose port2 matches. Caller holds a transaction.
// Returns the number of records removed.
int conn_delete_for_port2(TDB_CONTEXT *db, int port2);

// Bitmask of conn_index values (0..31) whose record for this port2 has
// CONN_FLAG_DROP_REQUESTED set. Used by the heartbeat snapshot so its
// delete+rewrite can't wipe a drop request that raced it.
uint32_t conn_drop_mask(TDB_CONTEXT *db, int port2);

// Fetch the user-side record (conn_index 0) for this port2. Returns
// false if there is none. Used by the video child to decide whether a
// publisher's address matches a recent MAVLink session.
bool conn_get_user(TDB_CONTEXT *db, int port2, struct ConnEntry &out);

// Delete every record for this port2 whose conn_index is in [lo,hi].
// The MAVLink child and the video child snapshot independently, so each
// must only clear its own range or they erase each other's rows.
// Returns the number removed.
int conn_delete_index_range(TDB_CONTEXT *db, int port2, int lo, int hi);

// One-shot helpers used by the parent (open + transaction internally).
void conn_recreate_empty(void);
void conn_remove_port2(int port2);
// Remove only the video rows for this port2 (index >= VIDEO_CONN_INDEX_BASE).
void conn_remove_video(int port2);
