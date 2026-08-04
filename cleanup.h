/*
  hourly session-log cleanup worker (covers .tlog and .bin)
 */
#pragma once

#include <sys/types.h>

/*
  Per-port-pair on-disk quota (bytes) for logs/<port2>/. Default 1 GiB;
  override with SUPPORTPROXY_PORT2_QUOTA_BYTES (integer bytes). Shared
  by the cleanup quota pass and binlog's write-time gate so the two
  always agree.
 */
off_t port2_quota_bytes(void);

/*
  Per-port-pair on-disk quota (bytes) for video segments. Separate from
  the telemetry budget on purpose: video is orders of magnitude larger
  per second than a tlog, and a single shared pool sorted by mtime would
  let a few minutes of video evict a flight's telemetry. The two are
  enforced independently so that cannot happen.

  Default 4 GiB; override with SUPPORTPROXY_PORT2_VIDEO_QUOTA_BYTES.
  A non-zero KeyEntry.video_quota_mb overrides both, per entry.

  Sizing rule: the quota pass cannot delete the segment currently being
  written (see ACTIVE_FILE_GRACE_S), so with segment duration S, grace G
  and aggregate bitrate B the un-evictable working set is (S+G)*B, and
  the budget needs to clear that with room to spare:
      quota >= (S + G) * B / 0.8
 */
off_t port2_video_quota_bytes(void);

/*
  Refuse to start a new segment when the filesystem holding base_dir has
  less than max(2 GiB, 5%) free. Per-entry quotas bound one entry; they
  do nothing about N entries x 3 slots filling a disk between them.
 */
bool video_have_free_space(const char *base_dir);

/*
  Video equivalent of log_cleanup_port2_quota: free video segments for
  this entry ahead of a write of `needed` bytes. `quota` of 0 means the
  server default.
 */
void log_cleanup_port2_video_quota(unsigned port2, const char *base_dir,
                                   off_t quota, off_t needed);

/*
  Run forever: every SUPPORTPROXY_CLEANUP_INTERVAL seconds (default 3600,
  env var override accepts a float for tests), traverse keys.tdb and
  remove .tlog / .bin files in logs/<port2>/ whose age in seconds
  exceeds log_retention_days * 86400. Removes empty date subdirs as a
  follow-up. Entries with retention_days == 0.0 are skipped (keep
  forever). Records on disk for entries no longer in keys.tdb are NOT
  auto-deleted.
 */
void log_cleanup_loop(const char *base_dir = "logs");

/*
  Run a single cleanup pass synchronously and return. Exposed for the
  test suite so it can drive cleanup without the sleep loop.
 */
void log_cleanup_once(const char *base_dir = "logs");

/*
  Run just the quota pass for a single port pair, synchronously.
  Used by the binlog writer when a write-time quota breach needs
  relief now rather than at the next hourly pass. `needed` is extra
  headroom (bytes) the caller wants on top of what's on disk: the
  pass frees when total+needed exceeds the quota, so a prospective
  breach at total == quota still gets relief.
 */
void log_cleanup_port2_quota(unsigned port2, const char *base_dir = "logs",
                             off_t needed = 0);
