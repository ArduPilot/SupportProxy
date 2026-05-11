/*
  ArduPilot binary-log writer over the "dataflash over MAVLink" protocol.

  Vehicle pushes REMOTE_LOG_DATA_BLOCK (msgid 184), 200 bytes per
  block, indexed by seqno. We write each block at offset
  seqno * 200 in logs/<port2>/<YYYY-MM-DD>/sessionN.bin (sparse file
  if there are gaps), ACK each received block with a
  REMOTE_LOG_BLOCK_STATUS=ACK back through the user-side MAVLink
  channel, and NACK gaps in the seqno stream with the same message
  type but status=NACK. NACKs are throttled to ~10 Hz per missing
  seqno; we abandon a missing block after 60 s elapsed or once the
  highest-seen seqno is 200 ahead — both numbers match MAVProxy's
  mavproxy_dataflash_logger.py.

  Strip behaviour (REMOTE_LOG_* messages don't reach the support
  engineer) lives in supportproxy.cpp; this class just owns the
  file + ACK/NACK state.
 */
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#include <deque>
#include <unordered_map>
#include <vector>

class MAVLink;
struct __mavlink_message;
typedef struct __mavlink_message mavlink_message_t;

class BinlogWriter {
public:
    BinlogWriter() = default;
    ~BinlogWriter();
    BinlogWriter(const BinlogWriter &) = delete;
    BinlogWriter &operator=(const BinlogWriter &) = delete;

    /*
      open logs/<port2>/<YYYY-MM-DD>/sessionN.bin. Caller supplies
      session_n via the shared next_session_n() helper so the .bin
      and .tlog for one child fork share their N.
     */
    bool open(uint32_t port2, unsigned session_n,
              const char *base_dir = "logs");
    bool is_open() const { return fp != nullptr; }

    /*
      Decode a REMOTE_LOG_DATA_BLOCK message and process it.

      Strict-start gate: the file is opened lazily ONLY when we see a
      block with seqno == 0. Any DATA_BLOCK arriving before that is
      silently discarded — the vehicle was already mid-log when
      SupportProxy activated, and writing at offset seqno*200 from
      mid-stream produces a multi-gigabyte sparse file that doesn't
      begin with the FMT records ArduPilot's .bin format requires,
      so DFReader_binary / mavlogdump.py reject it. This may relax
      later (e.g. by sending REMOTE_LOG_BLOCK_STATUS=START to nudge
      the vehicle into restarting its stream), but the strict gate
      is the simplest correctness anchor for now.

      After the file is open: write the 200 bytes at offset
      seqno*200, mark the seqno seen, queue an ACK. On a forward
      jump (seqno > highest_seen + 1) the gap is recorded for NACK
      in tick().

      port2 + session_n are used only on the (lazy) open. They're
      passed every call rather than stored so BinlogWriter doesn't
      need to copy strings.
     */
    void handle_block(uint32_t port2, unsigned session_n,
                      const mavlink_message_t &msg);

    /*
      Periodic pump. Called once per main_loop iteration whenever
      KEY_FLAG_BINLOG is set on the entry (regardless of whether the
      file has been opened yet).

      Two phases:

      * Before any DATA_BLOCK has arrived: emit a
        REMOTE_LOG_BLOCK_STATUS(status=ACK, seqno=START_MAGIC) at 1 Hz.
        That magic seqno (MAV_REMOTE_LOG_DATA_BLOCK_START) flips
        ArduPilot's AP_Logger_MAVLink::_sending_to_client to true,
        which is what makes logging_failed() return false (and so
        ArduPilot pre-arm pass) — see
        AP_Logger_MAVLink::handle_ack in libraries/AP_Logger. The
        side-effect on the vehicle is that it resets its seqno
        counter to 0 and starts streaming, which dovetails with our
        strict seqno==0 file-open gate.

      * After the first DATA_BLOCK (any_block_seen = true): drain
        pending ACKs and emit NACKs for gaps, rate-limited (NACK at
        ≤ 10 Hz per missing seqno, ACKs as fast as the caller drives
        us, capped at MAX_ACKS_PER_TICK so a backlog can't starve
        other work). The continuous ACK traffic also keeps the
        vehicle's 10-second client-timeout from firing.
     */
    void tick(MAVLink &user_link);

    void close();

private:
    static constexpr size_t BLOCK_BYTES = 200;
    // Mirrors MAVProxy's "10 ACK/NACK per idle loop" throttle.
    static constexpr unsigned MAX_ACKS_PER_TICK  = 10;
    static constexpr unsigned MAX_NACKS_PER_TICK = 10;
    // NACK throttle: minimum 100 ms between re-NACKs of the same seqno.
    static constexpr double   NACK_REPEAT_S      = 0.1;
    // Give up on a missing block after this much wall time, OR once the
    // highest-seen seqno is this many blocks ahead — whichever first.
    static constexpr double   NACK_GIVEUP_S      = 60.0;
    static constexpr uint32_t NACK_GIVEUP_BLOCKS = 200;
    // How often to re-send START until the vehicle starts streaming.
    // ArduPilot's client-timeout is 10 s so 1 Hz is comfortable.
    static constexpr double   START_REPEAT_S     = 1.0;

    FILE *fp = nullptr;

    // Bit-per-block "have I seen this seqno?" bitmap. Grown on demand
    // in handle_block (~125 KiB per 1 M blocks = ~200 MB log).
    std::vector<uint8_t> seen_bitmap;
    bool seqno_seen(uint32_t seqno) const;
    void mark_seqno_seen(uint32_t seqno);

    uint32_t highest_seen = 0;
    bool any_block_seen = false;
    // Monotonic timestamp of the most recent START we sent. Used by
    // tick() to throttle the 1 Hz start-loop while the vehicle hasn't
    // begun streaming yet.
    double last_start_sent_s = 0.0;

    // First-seen sysid/compid of the vehicle on this log session,
    // used as target_{system,component} when we send ACK/NACK back.
    uint8_t target_system = 0;
    uint8_t target_component = 0;

    // Pending ACK queue (seqnos to ACK, FIFO).
    std::deque<uint32_t> pending_acks;

    // NACK state per missing seqno: when we first noticed it (for the
    // 60 s give-up), and when we last sent a NACK (for the 100 ms
    // throttle).
    struct NackState {
        double first_seen_s;
        double last_sent_s;     // 0.0 = never sent yet
    };
    std::unordered_map<uint32_t, NackState> nack_state;

    // Helpers used by handle_block / tick.
    void queue_gap_nacks(uint32_t prev_highest, uint32_t new_seqno,
                         double now_s);
    void drop_stale_nack_state(double now_s);
    bool send_status(MAVLink &user_link, uint32_t seqno, uint8_t status);
};
