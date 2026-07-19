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
        // offset by design. Clamp to the valid range before the
        // arithmetic so a malformed stored value (e.g. use_tz set on a
        // hand-edited record) can't overflow time_t in llround/add.
        double off = tz_offset_hours;
        if (off < -12.0) off = -12.0;
        if (off > 14.0)  off = 14.0;
        time_t shifted = utc + (time_t)llround(off * 3600.0);
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

// True if neither <dir>/<candidate>.tlog nor <dir>/<candidate>.bin exists.
static bool basename_free(const char *dir, const char *candidate)
{
    char p_tlog[2048], p_bin[2048];
    snprintf(p_tlog, sizeof(p_tlog), "%s/%s.tlog", dir, candidate);
    snprintf(p_bin, sizeof(p_bin), "%s/%s.bin", dir, candidate);
    struct stat st;
    return stat(p_tlog, &st) != 0 && stat(p_bin, &st) != 0;
}

void session_unique_basename(const char *base_dir, uint32_t port2,
                             const char *datedir,
                             char *name, size_t name_len)
{
    char base[64];
    snprintf(base, sizeof(base), "%s", name);

    char dir[1024];
    snprintf(dir, sizeof(dir), "%s/%u/%s", base_dir, unsigned(port2), datedir);

    // Plain basename, then "-2", "-3", … — every candidate is checked
    // for occupancy across BOTH extensions, so we never hand back a name
    // that would truncate (.bin) or append into (.tlog) another session's
    // log. A single "-N" suffix keeps the name browsable by the web UI.
    // The cap is a safety bound; the first free slot is normally "-2".
    for (int suffix = 1; suffix < 100000; suffix++) {
        char candidate[96];
        if (suffix == 1) {
            snprintf(candidate, sizeof(candidate), "%s", base);
        } else {
            snprintf(candidate, sizeof(candidate), "%s-%d", base, suffix);
        }
        if (basename_free(dir, candidate)) {
            snprintf(name, name_len, "%s", candidate);
            return;
        }
    }
    // 100000 files in one second/dir cannot happen; as an absolute last
    // resort append the pid+nanoseconds as ONE numeric suffix (still a
    // single "-N" the web UI accepts) and still check occupancy, so we
    // never return an occupied name.
    for (int i = 0; i < 100; i++) {
        struct timespec ts {};
        clock_gettime(CLOCK_REALTIME, &ts);
        char candidate[96];
        snprintf(candidate, sizeof(candidate), "%s-%d%09ld",
                 base, int(getpid()), long(ts.tv_nsec));
        if (basename_free(dir, candidate)) {
            snprintf(name, name_len, "%s", candidate);
            return;
        }
    }
    // Unreachable: there is genuinely no free name. Leave `name` as the
    // plain base (its value on entry) — no worse than the impossible
    // exhaustion above.
    snprintf(name, name_len, "%s", base);
}
