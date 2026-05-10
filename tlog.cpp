/*
  per-connection MAVProxy-format tlog writer
 */
#include "tlog.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

/*
  mkdir -p for a relative or absolute path. Modes default to 0700 because
  tlogs may contain sensitive telemetry; admins can chgrp the parent if
  they want a wider audience.
 */
static int mkpath(const char *path)
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

TlogWriter::~TlogWriter()
{
    close();
}

bool TlogWriter::open(uint32_t port2, const char *base_dir)
{
    if (fp != nullptr) {
        return true;
    }

    time_t now = time(nullptr);
    struct tm tm_now;
    localtime_r(&now, &tm_now);

    char dir[768];
    snprintf(dir, sizeof(dir), "%s/%u/%04d-%02d-%02d",
             base_dir, port2,
             tm_now.tm_year + 1900,
             tm_now.tm_mon + 1,
             tm_now.tm_mday);

    if (mkpath(dir) < 0) {
        ::printf("tlog: mkdir %s failed: %s\n", dir, strerror(errno));
        return false;
    }

    DIR *d = opendir(dir);
    if (d == nullptr) {
        ::printf("tlog: opendir %s failed: %s\n", dir, strerror(errno));
        return false;
    }
    unsigned highest = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != nullptr) {
        unsigned n = 0;
        if (sscanf(ent->d_name, "session%u.tlog", &n) == 1 && n > highest) {
            highest = n;
        }
    }
    closedir(d);

    char path[1024];
    snprintf(path, sizeof(path), "%s/session%u.tlog", dir, highest + 1);

    fp = fopen(path, "ab");
    if (fp == nullptr) {
        ::printf("tlog: fopen %s failed: %s\n", path, strerror(errno));
        return false;
    }
    // Unbuffered: each frame goes straight to write() so the file is
    // readable in real-time (e.g. during a live download) and survives
    // a child crash without losing the stdio buffer.
    setvbuf(fp, nullptr, _IONBF, 0);
    ::printf("tlog: %s\n", path);
    return true;
}

void TlogWriter::write_frame(const uint8_t *frame, size_t len)
{
    if (fp == nullptr || frame == nullptr || len == 0) {
        return;
    }
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    uint64_t us = uint64_t(tv.tv_sec) * 1000000ULL + uint64_t(tv.tv_usec);

    uint8_t hdr[8];
    for (int i = 0; i < 8; i++) {
        hdr[i] = uint8_t((us >> ((7 - i) * 8)) & 0xff);
    }
    fwrite(hdr, 1, 8, fp);
    fwrite(frame, 1, len, fp);
}

void TlogWriter::close()
{
    if (fp != nullptr) {
        fflush(fp);
        fsync(fileno(fp));
        fclose(fp);
        fp = nullptr;
    }
}
