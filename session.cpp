/*
  Shared timestamp-naming + mkdir-p helpers for TlogWriter / BinlogWriter.
 */
#include "session.h"

#include <dirent.h>
#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

int mkpath_0700(const char *path)
{
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s", path);
    size_t n = strlen(tmp);
    for (size_t i = 1; i <= n; i++) {
        if (tmp[i] == '/' || tmp[i] == 0) {
            char saved = tmp[i];
            tmp[i] = 0;
            if (mkdir(tmp, 0700) != 0 && errno != EEXIST) {
                return -1;
            }
            tmp[i] = saved;
        }
    }
    return 0;
}

void session_time_strings(time_t utc, bool use_offset, double tz_offset_hours,
                          char *datedir, size_t datedir_len,
                          char *name, size_t name_len)
{
    struct tm tm {};
    struct tm *r;
    if (use_offset && isfinite(tz_offset_hours)) {
        // Explicit fixed GMT offset: apply it then format with gmtime so
        // the machine's own timezone plays no part. No DST — a fixed
        // offset by design.
        time_t shifted = utc + (time_t)llround(tz_offset_hours * 3600.0);
        r = gmtime_r(&shifted, &tm);
    } else {
        // Default (KEY_FLAG_USE_TZ clear, or a non-finite offset): name
        // in the server's local timezone, as configured on the host —
        // the least-surprising default and what the pre-timestamp
        // naming did.
        r = localtime_r(&utc, &tm);
    }
    if (r == nullptr) {
        // gmtime_r/localtime_r only fail on absurd inputs; format a
        // zeroed tm rather than uninitialised stack.
        memset(&tm, 0, sizeof(tm));
    }

    snprintf(datedir, datedir_len, "%04d-%02d-%02d",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    snprintf(name, name_len, "%04d_%02d_%02d_%02d:%02d:%02d",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec);
}

void session_unique_basename(const char *base_dir, uint32_t port2,
                             const char *datedir,
                             char *name, size_t name_len)
{
    char base[64];
    snprintf(base, sizeof(base), "%s", name);

    char dir[1024];
    snprintf(dir, sizeof(dir), "%s/%u/%s", base_dir, unsigned(port2), datedir);

    for (int suffix = 1; suffix < 1000; suffix++) {
        char candidate[80];
        if (suffix == 1) {
            snprintf(candidate, sizeof(candidate), "%s", base);
        } else {
            snprintf(candidate, sizeof(candidate), "%s-%d", base, suffix);
        }
        char p_tlog[2048], p_bin[2048];
        snprintf(p_tlog, sizeof(p_tlog), "%s/%s.tlog", dir, candidate);
        snprintf(p_bin, sizeof(p_bin), "%s/%s.bin", dir, candidate);
        struct stat st;
        if (stat(p_tlog, &st) != 0 && stat(p_bin, &st) != 0) {
            snprintf(name, name_len, "%s", candidate);
            return;
        }
    }
    // 1000 collisions in one second/dir cannot happen in practice, but
    // never return an occupied basename (that would truncate/append into
    // another session's log). A pid+nanosecond suffix can't match any of
    // the "-N" candidates above, so it stays unique.
    struct timespec ts {};
    clock_gettime(CLOCK_REALTIME, &ts);
    snprintf(name, name_len, "%s-%d-%09ld",
             base, int(getpid()), long(ts.tv_nsec));
}
