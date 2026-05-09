#include "conntdb.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <vector>

/*
  Open connections.tdb (cwd-relative, like keys.tdb). EBUSY can happen
  briefly when a concurrent transaction holds the open lock; retry with
  a short backoff so heartbeat grandchildren don't drop their snapshot
  for a transient lock collision.
 */
TDB_CONTEXT *conn_db_open(void)
{
    static const struct timespec backoffs[] = {
        {0, 0},
        {0, 10  * 1000 * 1000},   // 10ms
        {0, 50  * 1000 * 1000},
        {0, 100 * 1000 * 1000},
        {0, 250 * 1000 * 1000},
    };
    TDB_CONTEXT *db = nullptr;
    for (size_t i = 0; i < sizeof(backoffs) / sizeof(backoffs[0]); i++) {
        if (i > 0) {
            nanosleep(&backoffs[i], nullptr);
        }
        db = tdb_open(CONN_FILE, 1000, 0, O_RDWR | O_CREAT, 0600);
        if (db != nullptr) {
            return db;
        }
        if (errno != EBUSY) {
            return nullptr;
        }
    }
    return nullptr;
}

TDB_CONTEXT *conn_db_open_transaction(void)
{
    auto *db = conn_db_open();
    if (db == nullptr) {
        return nullptr;
    }
    if (tdb_transaction_start(db) != 0) {
        tdb_close(db);
        return nullptr;
    }
    return db;
}

void conn_db_close(TDB_CONTEXT *db)
{
    tdb_close(db);
}

void conn_db_close_cancel(TDB_CONTEXT *db)
{
    tdb_transaction_cancel(db);
    tdb_close(db);
}

void conn_db_close_commit(TDB_CONTEXT *db)
{
    tdb_transaction_prepare_commit(db);
    tdb_transaction_commit(db);
    tdb_close(db);
}

static TDB_DATA make_key(struct ConnKey &k, int port2, int conn_index)
{
    k.port2 = port2;
    k.conn_index = conn_index;
    TDB_DATA d;
    d.dptr = (uint8_t *)&k;
    d.dsize = sizeof(k);
    return d;
}

bool conn_write(TDB_CONTEXT *db, const struct ConnEntry &ce)
{
    struct ConnKey k;
    auto kd = make_key(k, ce.port2, ce.conn_index);

    // preserve any trailing bytes from a record written by newer code
    auto orig = tdb_fetch(db, kd);
    size_t tail = 0;
    if (orig.dptr != nullptr && orig.dsize > sizeof(ce)) {
        tail = orig.dsize - sizeof(ce);
    }

    size_t total = sizeof(ce) + tail;
    uint8_t *buf = (uint8_t *)malloc(total);
    if (buf == nullptr) {
        if (orig.dptr) {
            free(orig.dptr);
        }
        return false;
    }
    memcpy(buf, &ce, sizeof(ce));
    if (tail > 0) {
        memcpy(buf + sizeof(ce), orig.dptr + sizeof(ce), tail);
    }
    if (orig.dptr) {
        free(orig.dptr);
    }

    TDB_DATA d;
    d.dptr = buf;
    d.dsize = total;
    bool ok = tdb_store(db, kd, d, TDB_REPLACE) == 0;
    free(buf);
    return ok;
}

bool conn_delete(TDB_CONTEXT *db, int port2, int conn_index)
{
    struct ConnKey k;
    auto kd = make_key(k, port2, conn_index);
    return tdb_delete(db, kd) == 0;
}

struct port2_filter {
    int port2;
    std::vector<struct ConnKey> matches;
};

static int collect_port2(struct tdb_context *db, TDB_DATA key,
                         TDB_DATA data, void *ptr)
{
    (void)db;
    (void)data;
    auto *f = (struct port2_filter *)ptr;
    if (key.dsize != sizeof(struct ConnKey)) {
        return 0;
    }
    struct ConnKey k {};
    memcpy(&k, key.dptr, sizeof(k));
    if (k.port2 == f->port2) {
        f->matches.push_back(k);
    }
    return 0;
}

int conn_delete_for_port2(TDB_CONTEXT *db, int port2)
{
    struct port2_filter f { port2, {} };
    tdb_traverse(db, collect_port2, &f);
    int n = 0;
    for (auto &k : f.matches) {
        TDB_DATA kd;
        kd.dptr = (uint8_t *)&k;
        kd.dsize = sizeof(k);
        if (tdb_delete(db, kd) == 0) {
            n++;
        }
    }
    return n;
}

void conn_recreate_empty(void)
{
    // Easiest way to nuke all records is to remove the file. tdb_open
    // with O_CREAT will recreate it on next access.
    if (unlink(CONN_FILE) != 0 && errno != ENOENT) {
        perror("unlink connections.tdb");
    }
    auto *db = conn_db_open();
    if (db != nullptr) {
        tdb_close(db);
    }
}

void conn_remove_port2(int port2)
{
    auto *db = conn_db_open_transaction();
    if (db == nullptr) {
        return;
    }
    conn_delete_for_port2(db, port2);
    conn_db_close_commit(db);
}
