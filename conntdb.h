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
};

struct ConnKey {
    int port2;
    int conn_index;
};

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

// One-shot helpers used by the parent (open + transaction internally).
void conn_recreate_empty(void);
void conn_remove_port2(int port2);
