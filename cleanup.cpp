/*
  hourly session-log cleanup worker (covers .tlog and .bin)
 */
#include "cleanup.h"
#include "keydb.h"

#include <algorithm>
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <vector>
#include <string>
#include <tdb.h>

namespace {

// Per-port-pair on-disk quota: matches BinlogWriter::MAX_PER_PORT2_BYTES
// in binlog.h. Kept in sync there. Total .tlog + .bin under logs/<port2>/
// across all date dirs may not exceed this; oldest files are deleted
// first.
constexpr off_t MAX_PER_PORT2_BYTES = off_t(1024) * 1024 * 1024;  // 1 GiB

struct PassCtx {
    const char *base_dir;
    time_t now;
};

/*
  Predicate for "this is a session file we should age out under
  log_retention_days". Covers both .tlog (raw MAVLink frames) and
  .bin (ArduPilot dataflash logs) so the retention rule is uniform —
  per spec, both file types share the entry's retention setting.
 */
static bool is_session_file(const char *name)
{
    size_t n = strlen(name);
    return (n > 5 && strcmp(name + n - 5, ".tlog") == 0) ||
           (n > 4 && strcmp(name + n - 4, ".bin")  == 0);
}

/*
  Enforce the per-port2 disk quota by deleting oldest session files
  until total bytes <= MAX_PER_PORT2_BYTES. Runs after the retention
  pass so the operator's per-entry retention dictates *when* a file
  can go; this dictates *whether one must go anyway* because we're
  about to overflow. Walks every date dir under logs/<port2>/, sorts
  files by mtime ascending, deletes from the head.
 */
static void enforce_port2_quota(uint32_t port2, const char *base_dir)
{
    char port_dir[768];
    snprintf(port_dir, sizeof(port_dir), "%s/%u", base_dir, port2);
    DIR *d = opendir(port_dir);
    if (d == nullptr) {
        return;
    }

    struct Item {
        std::string path;
        off_t       size;
        time_t      mtime;
        std::string date_dir;
    };
    std::vector<Item> items;
    off_t total = 0;

    struct dirent *ent;
    while ((ent = readdir(d)) != nullptr) {
        if (ent->d_name[0] == '.') {
            continue;
        }
        char date_dir[1024];
        snprintf(date_dir, sizeof(date_dir), "%s/%s", port_dir, ent->d_name);
        struct stat st;
        if (stat(date_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
            continue;
        }
        DIR *dd = opendir(date_dir);
        if (dd == nullptr) {
            continue;
        }
        struct dirent *fent;
        while ((fent = readdir(dd)) != nullptr) {
            if (fent->d_name[0] == '.' || !is_session_file(fent->d_name)) {
                continue;
            }
            char fpath[1280];
            snprintf(fpath, sizeof(fpath), "%s/%s", date_dir, fent->d_name);
            struct stat fst;
            if (stat(fpath, &fst) != 0) {
                continue;
            }
            items.push_back({fpath, fst.st_size, fst.st_mtime, date_dir});
            total += fst.st_size;
        }
        closedir(dd);
    }
    closedir(d);

    if (total <= MAX_PER_PORT2_BYTES) {
        return;
    }

    // Sort oldest-first and delete until under quota.
    std::sort(items.begin(), items.end(),
              [](const Item &a, const Item &b) { return a.mtime < b.mtime; });
    for (const auto &it : items) {
        if (total <= MAX_PER_PORT2_BYTES) {
            break;
        }
        if (unlink(it.path.c_str()) == 0) {
            ::printf("log cleanup: removed %s for quota "
                     "(port2=%u total %lld > %lld)\n",
                     it.path.c_str(), unsigned(port2),
                     (long long)total, (long long)MAX_PER_PORT2_BYTES);
            total -= it.size;
            // Try rmdir on the date dir in case this was its last file;
            // harmless if it isn't.
            (void)rmdir(it.date_dir.c_str());
        }
    }
}

static void retention_pass(uint32_t port2, double retention_days,
                           const char *base_dir, time_t now)
{
    if (retention_days <= 0.0) {
        return;  // 0 = keep forever (per-entry); quota pass still runs below
    }
    double cutoff_age_s = retention_days * 86400.0;

    char port_dir[768];
    snprintf(port_dir, sizeof(port_dir), "%s/%u", base_dir, port2);

    DIR *d = opendir(port_dir);
    if (d == nullptr) {
        return;
    }
    struct dirent *ent;
    while ((ent = readdir(d)) != nullptr) {
        if (ent->d_name[0] == '.') {
            continue;
        }
        char date_dir[1024];
        snprintf(date_dir, sizeof(date_dir), "%s/%s", port_dir, ent->d_name);

        struct stat st;
        if (stat(date_dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
            continue;
        }

        DIR *dd = opendir(date_dir);
        if (dd == nullptr) {
            continue;
        }
        unsigned remaining = 0;
        struct dirent *fent;
        while ((fent = readdir(dd)) != nullptr) {
            if (fent->d_name[0] == '.') {
                continue;
            }
            char fpath[1280];
            snprintf(fpath, sizeof(fpath), "%s/%s", date_dir, fent->d_name);
            if (is_session_file(fent->d_name)) {
                struct stat fst;
                if (stat(fpath, &fst) == 0) {
                    double age = double(now - fst.st_mtime);
                    if (age > cutoff_age_s) {
                        if (unlink(fpath) == 0) {
                            ::printf("log cleanup: removed %s (age %.0fs > %.0fs)\n",
                                     fpath, age, cutoff_age_s);
                            continue;
                        }
                    }
                }
            }
            remaining++;
        }
        closedir(dd);

        if (remaining == 0) {
            if (rmdir(date_dir) == 0) {
                ::printf("log cleanup: removed empty %s\n", date_dir);
            }
        }
    }
    closedir(d);
}

static void cleanup_for_port2(uint32_t port2, double retention_days,
                              const char *base_dir, time_t now)
{
    // Two passes per port2:
    //   1. retention_pass: per-entry "delete files older than the
    //      configured retention". Skipped when retention=0 (keep
    //      forever).
    //   2. enforce_port2_quota: hard 1 GiB cap. Runs even if
    //      retention=0, so even a "keep forever" entry can't fill
    //      the disk.
    retention_pass(port2, retention_days, base_dir, now);
    enforce_port2_quota(port2, base_dir);
}

static int traverse_cb(struct tdb_context *db, TDB_DATA key, TDB_DATA data, void *ptr)
{
    (void)db;
    auto *ctx = static_cast<PassCtx *>(ptr);
    if (key.dsize != sizeof(int) || data.dsize < KEYENTRY_MIN_SIZE) {
        return 0;
    }
    int port2 = 0;
    memcpy(&port2, key.dptr, sizeof(int));
    if (port2 <= 0) {
        return 0;
    }
    struct KeyEntry k {};
    size_t copy = data.dsize < sizeof(KeyEntry) ? data.dsize : sizeof(KeyEntry);
    memcpy(&k, data.dptr, copy);
    if (k.magic != KEY_MAGIC) {
        return 0;
    }
    cleanup_for_port2(uint32_t(port2), double(k.log_retention_days),
                      ctx->base_dir, ctx->now);
    return 0;
}

static double cleanup_interval_seconds()
{
    const char *env = getenv("SUPPORTPROXY_CLEANUP_INTERVAL");
    if (env != nullptr && *env != '\0') {
        char *endp = nullptr;
        double v = strtod(env, &endp);
        if (endp != env && v > 0.0) {
            return v;
        }
    }
    return 3600.0;
}

static void sleep_seconds(double s)
{
    if (s <= 0.0) {
        return;
    }
    struct timespec ts;
    ts.tv_sec = time_t(s);
    ts.tv_nsec = long((s - double(ts.tv_sec)) * 1e9);
    nanosleep(&ts, nullptr);
}

}  // namespace

void log_cleanup_once(const char *base_dir)
{
    auto *db = db_open();
    if (db == nullptr) {
        return;
    }
    PassCtx ctx { base_dir, time(nullptr) };
    tdb_traverse(db, traverse_cb, &ctx);
    db_close(db);
}

void log_cleanup_loop(const char *base_dir)
{
    // Run an immediate pass on startup so a fresh restart still cleans up.
    log_cleanup_once(base_dir);
    double interval = cleanup_interval_seconds();
    while (true) {
        sleep_seconds(interval);
        log_cleanup_once(base_dir);
    }
}
