/*
  Video segment recording. See videorec.h.
 */
#include "videorec.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "cleanup.h"
#include "session.h"

// Drop written pages from the page cache after this much. A few GB of
// video would otherwise evict everything useful on a small VPS.
#define VIDEO_FADVISE_CHUNK (8u * 1024 * 1024)

uint32_t video_segment_seconds(void)
{
    static uint32_t cached = 0;
    if (cached == 0) {
        cached = VIDEO_SEGMENT_SECONDS_DEFAULT;
        const char *env = getenv("SUPPORTPROXY_VIDEO_SEGMENT_SECONDS");
        if (env != nullptr && *env != '\0') {
            char *endp = nullptr;
            errno = 0;
            long v = strtol(env, &endp, 10);
            if (errno == 0 && endp != env && *endp == '\0' && v > 0) {
                cached = uint32_t(v);
            }
        }
    }
    return cached;
}

uint64_t video_segment_bytes(void)
{
    static uint64_t cached = 0;
    if (cached == 0) {
        cached = VIDEO_SEGMENT_BYTES_DEFAULT;
        const char *env = getenv("SUPPORTPROXY_VIDEO_SEGMENT_BYTES");
        if (env != nullptr && *env != '\0') {
            char *endp = nullptr;
            errno = 0;
            long long v = strtoll(env, &endp, 10);
            if (errno == 0 && endp != env && *endp == '\0' && v > 0) {
                cached = uint64_t(v);
            }
        }
    }
    return cached;
}

VideoWriter::~VideoWriter(void)
{
    close_segment();
}

void VideoWriter::configure(uint32_t port2, int slot, bool use_tz,
                            float tz_offset, const char *base_dir,
                            uint32_t quota_mb)
{
    port2_ = port2;
    slot_ = slot;
    use_tz_ = use_tz;
    tz_offset_ = tz_offset;
    base_dir_ = base_dir != nullptr ? base_dir : "logs";
    quota_mb_ = quota_mb;
}

bool VideoWriter::open_segment(time_t now)
{
    if (stopped_) {
        return false;
    }
    if (!video_have_free_space(base_dir_.c_str())) {
        printf("[%u] video slot %d: filesystem too full, recording stopped\n",
               unsigned(port2_), slot_);
        stopped_ = true;
        return false;
    }

    // Make room before writing rather than after: the quota pass would
    // otherwise only notice on its hourly tick, by which point the
    // budget has been exceeded for most of an hour.
    log_cleanup_port2_video_quota(port2_, base_dir_.c_str(),
                                  quota_mb_ != 0
                                  ? off_t(quota_mb_) * 1024 * 1024 : 0,
                                  off_t(video_segment_bytes()));

    char datedir[16];
    char name[64];
    session_time_strings(now, use_tz_, tz_offset_,
                         datedir, sizeof(datedir), name, sizeof(name));

    char dir[1024];
    snprintf(dir, sizeof(dir), "%s/%u/%s", base_dir_.c_str(),
             unsigned(port2_), datedir);
    // mkpath_0700 returns 0 on success and -1 on failure, like mkdir --
    // not a bool. The other callers all test "< 0".
    if (mkpath_0700(dir) < 0) {
        printf("[%u] video slot %d: cannot create %s - %s\n",
               unsigned(port2_), slot_, dir, strerror(errno));
        return false;
    }

    /*
      session_unique_basename() picks a free name, but it checks with
      stat() and then hands the name back -- and after exhausting its
      fallbacks it returns the plain base, occupied or not. Neither is
      safe here, so the name is only a starting point: the open is
      O_EXCL and a collision just tries again.
     */
    for (int attempt = 0; attempt < 8; attempt++) {
        char base[64];
        snprintf(base, sizeof(base), "%s", name);
        session_unique_basename(base_dir_.c_str(), port2_, datedir,
                                base, sizeof(base));
        char path[1200];
        snprintf(path, sizeof(path), "%s/%s.v%d.ts", dir, base, slot_ + 1);
        const int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd >= 0) {
            fd_ = fd;
            path_ = path;
            date_dir_ = dir;
            seg_start_ = now;
            seg_bytes_ = 0;
            fadvise_mark_ = 0;
            rotate_wanted_ = 0;
            segments_++;
            printf("[%u] video slot %d recording to %s\n",
                   unsigned(port2_), slot_, path);
            return true;
        }
        if (errno != EEXIST) {
            printf("[%u] video slot %d: cannot open %s - %s\n",
                   unsigned(port2_), slot_, path, strerror(errno));
            if (errno == ENOSPC || errno == EDQUOT) {
                stopped_ = true;
            }
            return false;
        }
        // Someone took the name between the check and the open. Nudge
        // the timestamp so the next candidate differs.
        now++;
        session_time_strings(now, use_tz_, tz_offset_,
                             datedir, sizeof(datedir), name, sizeof(name));
    }
    printf("[%u] video slot %d: no free segment name\n",
           unsigned(port2_), slot_);
    return false;
}

bool VideoWriter::write(const uint8_t *buf, size_t n, time_t now)
{
    if (stopped_) {
        return false;
    }
    if (fd_ < 0 && !open_segment(now)) {
        return false;
    }

    size_t off = 0;
    while (off < n) {
        const ssize_t w = ::write(fd_, buf + off, n - off);
        if (w < 0) {
            if (errno == EINTR) {
                continue;
            }
            printf("[%u] video slot %d: write failed - %s; "
                   "recording stopped (the live stream is unaffected)\n",
                   unsigned(port2_), slot_, strerror(errno));
            // A full disk must not take the stream down with it: stop
            // recording, keep relaying.
            close_segment();
            stopped_ = true;
            return false;
        }
        off += size_t(w);
    }
    seg_bytes_ += n;
    total_bytes_ += n;

    if (seg_bytes_ - fadvise_mark_ >= VIDEO_FADVISE_CHUNK) {
        // Written data is never read back here, so let the kernel drop
        // it rather than evict everything else on a small box.
        posix_fadvise(fd_, off_t(fadvise_mark_),
                      off_t(seg_bytes_ - fadvise_mark_), POSIX_FADV_DONTNEED);
        fadvise_mark_ = seg_bytes_;
    }
    return true;
}

bool VideoWriter::rotation_due(time_t now)
{
    if (fd_ < 0) {
        return false;
    }
    const bool due = (now - seg_start_) >= time_t(video_segment_seconds())
        || seg_bytes_ >= video_segment_bytes();
    if (due && rotate_wanted_ == 0) {
        // Remember when we first wanted to cut. Without this the
        // overshoot fallback never fires, and a stream whose muxer
        // never signals a random access point grows one segment
        // without bound -- which the quota pass can never evict,
        // because it is the file being written.
        rotate_wanted_ = now;
    }
    return due;
}

bool VideoWriter::rotation_overdue(time_t now) const
{
    return rotate_wanted_ != 0
        && (now - rotate_wanted_) >= VIDEO_ROTATE_OVERSHOOT_S;
}

void VideoWriter::rotate(time_t now, bool clean)
{
    if (fd_ < 0) {
        return;
    }
    printf("[%u] video slot %d rotating after %llu bytes (%s cut)\n",
           unsigned(port2_), slot_, (unsigned long long)seg_bytes_,
           clean ? "clean" : "forced");
    close_segment();
    rotate_wanted_ = 0;
    (void)now;
}

void VideoWriter::close_segment(void)
{
    if (fd_ < 0) {
        return;
    }
    const int fd = fd_;
    fd_ = -1;

    /*
      fsync off the event loop. A 512 MiB segment can take a long time
      to flush, and doing it inline would stall every stream and viewer
      in this process. The fd is shared with the child across fork, so
      the child's fsync covers our writes; we close our copy at once.
     */
    const pid_t pid = fork();
    if (pid == 0) {
        fsync(fd);
        close(fd);
        _exit(0);
    }
    if (pid < 0) {
        // Couldn't fork: better a stall than an unflushed segment.
        fsync(fd);
    }
    close(fd);
}
