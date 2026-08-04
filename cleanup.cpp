/*
  hourly session-log cleanup worker (covers .tlog and .bin)
 */
#include "cleanup.h"
#include "keydb.h"

#include <algorithm>
#include <errno.h>
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <vector>
#include <string>
#include <tdb.h>

off_t port2_quota_bytes(void)
{
    static off_t cached = -1;
    if (cached >= 0) {
        return cached;
    }
    cached = off_t(1024) * 1024 * 1024;  // 1 GiB default
    const char *env = getenv("SUPPORTPROXY_PORT2_QUOTA_BYTES");
    if (env != nullptr && *env != '\0') {
        // strict: plain positive bytes only. A prefix parse would turn
        // a well-meant "1GB" into a 1-byte quota and let the cleanup
        // pass delete nearly the whole log tree.
        char *endp = nullptr;
        errno = 0;
        long long v = strtoll(env, &endp, 10);
        if (errno == 0 && endp != env && *endp == '\0' && v > 0) {
            cached = off_t(v);
        } else {
            ::printf("ignoring invalid SUPPORTPROXY_PORT2_QUOTA_BYTES "
                     "'%s' (want plain bytes); using %lld\n",
                     env, (long long)cached);
        }
    }
    return cached;
}

static off_t parse_quota_env(const char *name, off_t dflt)
{
    const char *env = getenv(name);
    if (env == nullptr || *env == '\0') {
        return dflt;
    }
    // strict: plain positive bytes only. A prefix parse would turn a
    // well-meant "1GB" into a 1-byte quota and let the cleanup pass
    // delete nearly the whole log tree.
    char *endp = nullptr;
    errno = 0;
    long long v = strtoll(env, &endp, 10);
    if (errno == 0 && endp != env && *endp == '\0' && v > 0) {
        return off_t(v);
    }
    ::printf("ignoring invalid %s '%s' (want plain bytes); using %lld\n",
             name, env, (long long)dflt);
    return dflt;
}

off_t port2_video_quota_bytes(void)
{
    static off_t cached = -1;
    if (cached < 0) {
        cached = parse_quota_env("SUPPORTPROXY_PORT2_VIDEO_QUOTA_BYTES",
                                 off_t(4) * 1024 * 1024 * 1024);
    }
    return cached;
}

bool video_have_free_space(const char *base_dir)
{
    struct statvfs vfs;
    if (statvfs(base_dir, &vfs) != 0) {
        return true;    // can't tell; don't block recording on it
    }
    const uint64_t free_bytes = uint64_t(vfs.f_bavail) * vfs.f_frsize;
    const uint64_t total = uint64_t(vfs.f_blocks) * vfs.f_frsize;
    const uint64_t floor_abs = uint64_t(2) * 1024 * 1024 * 1024;
    const uint64_t floor_pct = total / 20;      // 5%
    const uint64_t want = floor_abs > floor_pct ? floor_abs : floor_pct;
    return free_bytes > want;
}

namespace {

struct PassCtx {
    const char *base_dir;
    time_t now;
};

/*
  What kind of session file this is.

  Retention treats both kinds identically -- one per-entry setting
  covers everything -- but the quota does not: video and telemetry get
  independent budgets, because a shared pool sorted by mtime would let
  a few minutes of video evict a whole flight's telemetry.
 */
enum session_kind {
    SESSION_NONE = 0,
    SESSION_TELEM,      // .tlog, .bin
    SESSION_VIDEO,      // .vN.ts
};

static session_kind session_file_kind(const char *name)
{
    const size_t n = strlen(name);
    if (n > 5 && strcmp(name + n - 5, ".tlog") == 0) {
        return SESSION_TELEM;
    }
    if (n > 4 && strcmp(name + n - 4, ".bin") == 0) {
        return SESSION_TELEM;
    }
    // "<session>.v<slot>.ts" -- the slot is part of the name so the
    // three slots of one entry never collide.
    if (n > 6 && strcmp(name + n - 3, ".ts") == 0
        && name[n - 6] == '.' && name[n - 5] == 'v'
        && name[n - 4] >= '1' && name[n - 4] <= '9') {
        return SESSION_VIDEO;
    }
    return SESSION_NONE;
}

static bool is_session_file(const char *name)
{
    return session_file_kind(name) != SESSION_NONE;
}

/*
  Enforce the per-port2 disk quota by deleting oldest session files
  until total bytes <= MAX_PER_PORT2_BYTES. Runs after the retention
  pass so the operator's per-entry retention dictates *when* a file
  can go; this dictates *whether one must go anyway* because we're
  about to overflow. Walks every date dir under logs/<port2>/, sorts
  files by mtime ascending, deletes from the head.
 */
// Files whose mtime is within this window are treated as belonging to
// a live session and are never deleted by the quota pass: on Linux the
// unlink would succeed while the writer keeps appending to an
// invisible unlinked inode — the log is lost on close and the disk
// usage stops being counted.
//
// mtime is a heuristic, not ownership: the hourly pass runs in the
// cleanup child and cannot know which files other children hold open.
// An open file idle for longer than the grace (a stalled stream) can
// still be unlinked, and a just-closed session is protected slightly
// longer than needed. Both are acceptable: a healthy binlog/tlog
// writes many times per second.
// Overridable for tests: with the default 60s, every segment a short
// test writes is still "live" and none is evictable, so the quota pass
// correctly frees nothing and the behaviour cannot be observed at all.
static time_t active_file_grace_s(void)
{
    static time_t cached = -1;
    if (cached >= 0) {
        return cached;
    }
    cached = 60;
    const char *env = getenv("SUPPORTPROXY_ACTIVE_FILE_GRACE");
    if (env != nullptr && *env != '\0') {
        char *endp = nullptr;
        errno = 0;
        long v = strtol(env, &endp, 10);
        if (errno == 0 && endp != env && *endp == '\0' && v >= 0) {
            cached = time_t(v);
        }
    }
    return cached;
}

static void enforce_quota(uint32_t port2, const char *base_dir,
                          session_kind kind, off_t quota,
                          off_t needed)
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
            if (fent->d_name[0] == '.'
                || session_file_kind(fent->d_name) != kind) {
                continue;
            }
            char fpath[1280];
            snprintf(fpath, sizeof(fpath), "%s/%s", date_dir, fent->d_name);
            struct stat fst;
            if (stat(fpath, &fst) != 0) {
                continue;
            }
            // allocated size, not apparent: .bin files are sparse and
            // st_size wildly overstates what they cost on disk
            const off_t alloc = off_t(fst.st_blocks) * 512;
            total += alloc;
            if (time(nullptr) - fst.st_mtime < active_file_grace_s()) {
                // live session file: count it, never delete it
                continue;
            }
            items.push_back({fpath, alloc, fst.st_mtime, date_dir});
        }
        closedir(dd);
    }
    closedir(d);

    // `needed` is the caller's prospective growth: a write-time breach
    // can happen with total still at or just under the quota, and
    // without accounting for it here the pass would free nothing and
    // the caller's write would be dropped forever.
    if (total + needed <= quota) {
        return;
    }

    // Sort oldest-first and delete down to 80% of quota, not just
    // under it: freeing to the brim meant an active session's growth
    // re-breached the cap within minutes and blocked binlog writes
    // until the next hourly pass.
    const off_t target = quota - quota / 5;
    std::sort(items.begin(), items.end(),
              [](const Item &a, const Item &b) { return a.mtime < b.mtime; });
    for (const auto &it : items) {
        if (total + needed <= target) {
            break;
        }
        if (unlink(it.path.c_str()) == 0) {
            ::printf("log cleanup: removed %s for %s quota "
                     "(port2=%u total %lld > %lld)\n",
                     it.path.c_str(),
                     kind == SESSION_VIDEO ? "video" : "telemetry",
                     unsigned(port2),
                     (long long)total, (long long)quota);
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
                              uint32_t video_quota_mb,
                              const char *base_dir, time_t now)
{
    // Passes per port2:
    //   1. retention_pass: per-entry "delete files older than the
    //      configured retention", covering both kinds. Skipped when
    //      retention=0 (keep forever).
    //   2. one quota pass per kind, with independent budgets. Both run
    //      even if retention=0, so even a "keep forever" entry cannot
    //      fill the disk -- and video can never evict telemetry,
    //      because it is never a candidate in the telemetry pass.
    retention_pass(port2, retention_days, base_dir, now);
    enforce_quota(port2, base_dir, SESSION_TELEM, port2_quota_bytes(), 0);
    const off_t vquota = video_quota_mb != 0
        ? off_t(video_quota_mb) * 1024 * 1024
        : port2_video_quota_bytes();
    enforce_quota(port2, base_dir, SESSION_VIDEO, vquota, 0);
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
                      k.video_quota_mb, ctx->base_dir, ctx->now);
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

void log_cleanup_port2_quota(unsigned port2, const char *base_dir,
                             off_t needed)
{
    // binlog's write-time gate: telemetry budget only. Freeing video
    // here would let a .bin write delete a recording, which is exactly
    // the cross-eviction the split budgets exist to prevent.
    enforce_quota(port2, base_dir, SESSION_TELEM, port2_quota_bytes(), needed);
}

void log_cleanup_port2_video_quota(unsigned port2, const char *base_dir,
                                   off_t quota, off_t needed)
{
    enforce_quota(port2, base_dir, SESSION_VIDEO,
                  quota > 0 ? quota : port2_video_quota_bytes(), needed);
}

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
