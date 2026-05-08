#include "keydb.h"
#include <string.h>
#include <stdlib.h>

TDB_CONTEXT *db_open(void)
{
    return tdb_open(KEY_FILE, 1000, 0, O_RDWR | O_CREAT, 0600);
}

TDB_CONTEXT *db_open_transaction(void)
{
    auto *db = db_open();
    if (db == nullptr) {
        return db;
    }
    tdb_transaction_start(db);
    return db;
}

void db_close(TDB_CONTEXT *db)
{
    tdb_close(db);
}

void db_close_cancel(TDB_CONTEXT *db)
{
    tdb_transaction_cancel(db);
    db_close(db);
}

void db_close_commit(TDB_CONTEXT *db)
{
    tdb_transaction_prepare_commit(db);
    tdb_transaction_commit(db);
    db_close(db);
}

bool db_load_key(TDB_CONTEXT *db, int port2, struct KeyEntry &key)
{
    TDB_DATA k;
    k.dptr = (uint8_t *)&port2;
    k.dsize = sizeof(int);

    auto d = tdb_fetch(db, k);
    if (d.dptr == nullptr || d.dsize < KEYENTRY_MIN_SIZE) {
        if (d.dptr) {
            free(d.dptr);
        }
        return false;
    }
    // zero-init so fields not present in older on-disk layouts default to 0
    memset(&key, 0, sizeof(key));
    size_t copy = d.dsize < sizeof(key) ? d.dsize : sizeof(key);
    memcpy(&key, d.dptr, copy);
    free(d.dptr);
    return key.magic == KEY_MAGIC;
}

bool db_save_key(TDB_CONTEXT *tdb, int port2, const struct KeyEntry &ke)
{
    TDB_DATA k;
    k.dptr = (uint8_t*)&port2;
    k.dsize = sizeof(int);

    // preserve any trailing bytes the on-disk record has beyond our struct
    auto orig = tdb_fetch(tdb, k);
    size_t tail = 0;
    if (orig.dptr != nullptr && orig.dsize > sizeof(ke)) {
        tail = orig.dsize - sizeof(ke);
    }

    size_t total = sizeof(ke) + tail;
    uint8_t *buf = (uint8_t*)malloc(total);
    if (buf == nullptr) {
        if (orig.dptr) {
            free(orig.dptr);
        }
        return false;
    }
    memcpy(buf, &ke, sizeof(ke));
    if (tail > 0) {
        memcpy(buf + sizeof(ke), orig.dptr + sizeof(ke), tail);
    }
    if (orig.dptr) {
        free(orig.dptr);
    }

    TDB_DATA d;
    d.dptr = buf;
    d.dsize = total;
    bool ok = tdb_store(tdb, k, d, TDB_REPLACE) == 0;
    free(buf);
    return ok;
}
