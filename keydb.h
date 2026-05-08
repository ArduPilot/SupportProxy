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
};

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
