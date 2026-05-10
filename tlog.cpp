/*
  per-connection MAVProxy-format tlog writer
 */
#include "tlog.h"
#include "session.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>

TlogWriter::~TlogWriter()
{
    close();
}

bool TlogWriter::open(uint32_t port2, unsigned session_n, const char *base_dir)
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

    if (mkpath_0700(dir) < 0) {
        ::printf("tlog: mkdir %s failed: %s\n", dir, strerror(errno));
        return false;
    }

    char path[1024];
    snprintf(path, sizeof(path), "%s/session%u.tlog", dir, session_n);

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
