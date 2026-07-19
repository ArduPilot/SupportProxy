/*
  Helpers shared by TlogWriter and BinlogWriter.

  Both writers store files at logs/<port2>/<YYYY-MM-DD>/<name>.<ext>,
  where <name> is a timestamp "YYYY_MM_DD_HH:MM:SS" of the session
  start. A child fork that records both kinds computes one <name> and
  passes it to both writers, so the .tlog and .bin sit next to each
  other with matching names. The date subdir and the filename are both
  formed in the entry's log-naming timezone: an explicit GMT offset in
  hours, or — when the offset is 0/unset (the default) — the server's
  own local timezone.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <time.h>

/*
  mkdir -p with mode 0700 for every component of `path` (logs may
  contain sensitive telemetry — admins can chgrp the parent if they
  want a wider audience). Returns 0 on success, -1 on the first
  unrecoverable mkdir() error.
 */
int mkpath_0700(const char *path);

/*
  Format the date subdir ("YYYY-MM-DD") and the log basename
  ("YYYY_MM_DD_HH:MM:SS") for the UTC time `utc`. When `use_offset` is
  true the finite tz_offset_hours (fractional allowed) is applied and
  formatted with gmtime, so the host timezone never affects naming (a
  fixed offset, no DST). When false, the time is formatted in the
  server's own local timezone — the default when KEY_FLAG_USE_TZ is
  clear.
 */
void session_time_strings(time_t utc, bool use_offset, double tz_offset_hours,
                          char *datedir, size_t datedir_len,
                          char *name, size_t name_len);

/*
  Make `name` (a basename from session_time_strings) unique within
  logs/<port2>/<datedir>/ across BOTH the .tlog and .bin extensions: if
  a file with that base already exists (a same-second session start, or
  a reboot rotation landing in the same second), append "-2", "-3", …
  until free. Modifies `name` in place. Cheap — only touched once per
  file open.
 */
void session_unique_basename(const char *base_dir, uint32_t port2,
                             const char *datedir,
                             char *name, size_t name_len);
