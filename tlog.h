/*
  per-connection MAVProxy-format tlog writer

  on-disk format: a sequence of records, each
      8-byte big-endian uint64 timestamp (microseconds since epoch)
      raw MAVLink frame bytes
  matches what pymavlink's mavlogfile reader and mavlogdump.py expect.
 */
#pragma once

#include <stdint.h>
#include <stdio.h>
#include <stddef.h>

class TlogWriter {
public:
    TlogWriter() = default;
    ~TlogWriter();
    TlogWriter(const TlogWriter &) = delete;
    TlogWriter &operator=(const TlogWriter &) = delete;

    /*
      open logs/<port2>/<YYYY-MM-DD>/sessionN.tlog. The caller supplies
      session_n via the shared next_session_n() helper so the paired
      .tlog / .bin files for one child fork share their N. Creates parent
      dirs as needed. Returns true on success.
     */
    bool open(uint32_t port2, unsigned session_n,
              const char *base_dir = "logs");

    /*
      write a complete MAVLink frame, prefixed with an 8-byte big-endian
      microsecond timestamp from gettimeofday().
     */
    void write_frame(const uint8_t *frame, size_t len);

    /*
      close: fflush + fsync + fclose. Safe to call multiple times; called
      from the destructor.
     */
    void close();

    bool is_open() const { return fp != nullptr; }

private:
    FILE *fp = nullptr;
};
