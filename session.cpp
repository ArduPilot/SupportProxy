/*
  Shared sessionN + mkdir-p helpers for TlogWriter / BinlogWriter.
 */
#include "session.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

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

unsigned next_session_n(uint32_t port2, const char *base_dir)
{
    time_t now = time(nullptr);
    struct tm tm_now;
    localtime_r(&now, &tm_now);

    char dir[768];
    snprintf(dir, sizeof(dir), "%s/%u/%04d-%02d-%02d",
             base_dir, port2,
             tm_now.tm_year + 1900,
             tm_now.tm_mon + 1,
             tm_now.tm_mday);

    DIR *d = opendir(dir);
    if (d == nullptr) {
        // No dir yet -> first session of the day.
        return 1;
    }
    unsigned highest = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != nullptr) {
        unsigned n = 0;
        // Match either sessionN.tlog or sessionN.bin so paired N stays
        // paired across both extensions.
        if (sscanf(ent->d_name, "session%u.tlog", &n) == 1
            || sscanf(ent->d_name, "session%u.bin", &n) == 1) {
            if (n > highest) {
                highest = n;
            }
        }
    }
    closedir(d);
    return highest + 1;
}
