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
