/*
  Helpers shared by TlogWriter and BinlogWriter.

  Both writers store files at logs/<port2>/<YYYY-MM-DD>/sessionN.<ext>
  with paired N — when a child fork records both kinds of session
  files, sessionN.tlog and sessionN.bin sit next to each other, which
  makes the per-day file list in the web UI read naturally.
 */
#pragma once

#include <stdint.h>

/*
  mkdir -p with mode 0700 for every component of `path` (logs may
  contain sensitive telemetry — admins can chgrp the parent if they
  want a wider audience). Returns 0 on success, -1 on the first
  unrecoverable mkdir() error.
 */
int mkpath_0700(const char *path);

/*
  Scan logs/<port2>/<YYYY-MM-DD>/ for sessionN.tlog and sessionN.bin,
  return max(N) + 1 (so the first call against a fresh dir returns 1).
  Considers BOTH extensions so a tlog-then-bin or bin-then-tlog open
  ordering yields the same N for both writers in one child fork.
 */
unsigned next_session_n(uint32_t port2, const char *base_dir);
