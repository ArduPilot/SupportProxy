/*
  The per-entry video child.

  Unlike the per-port-pair MAVLink child, this is a long-lived direct
  child of the parent, forked from reload_ports() and respawned by
  check_children(). Its lifetime is deliberately independent of any
  MAVLink session: the MAVLink child idles out after 10 s, and video has
  to survive that, and has to work with no MAVLink session at all when
  the entry has a publish password.

  Because the *child* binds the video ports, a video port simply does not
  exist unless the entry has video enabled -- the enable is structural
  rather than a policy check somewhere in a packet path.
 */
#pragma once

#include <stdint.h>
#include <sys/types.h>

#include "keydb.h"

// Number of listening fds a video child opens per configured slot
// (one UDP, one TCP).
#define VIDEO_FDS_PER_SLOT 2

/*
  Entry point for the video child. Called after the caller has done fd
  sanitation in the forked child. Never returns: it _exit()s.

  ready_fd is the write end of a pipe the parent reads once to learn
  whether every configured port bound. A single byte is written: 0 for
  success, or errno for the first failure. The fd is closed either way,
  so the parent's read never blocks if the child dies first.
 */
void video_child_main(int port2, int ready_fd) __attribute__((noreturn));

// True if this entry should have a video child: video enabled and at
// least one port configured.
bool video_entry_wants_child(uint32_t flags, const uint32_t *video_ports);
