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
#include <string>
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
      Observe an arbitrary user-side MAVLink message for FC-reboot
      detection. Called for *every* user→engineer message (cheap;
      early-returns on non-SYSTEM_TIME). Watches SYSTEM_TIME packets
      sourced from MAV_COMP_ID_AUTOPILOT1 (and optionally filtered by
      fc_sysid_filter_) for a >= 10 s backward jump in time_boot_ms,
      which is the unambiguous signature of an FC reboot —
      time_boot_ms is monotonic from boot, GPS sync corrections only
      affect time_unix_usec. On a detected reboot the current
      sessionN.bin is closed, the per-log state is reset, and a fresh
      sessionN+1.bin is opened so the new log writes from offset 0.
     */
    void observe(const mavlink_message_t &msg);

    /*
      Per-entry MAVLink sysid filter. 0 (the default) accepts
      SYSTEM_TIME from any sysid; non-zero restricts reboot detection
      to packets with msg.sysid == sysid. Sourced from
      KeyEntry.fc_sysid at fork start.
     */
    void set_fc_sysid_filter(uint8_t sysid) { fc_sysid_filter_ = sysid; }

    /*
      Periodic pump. Called once per main_loop iteration whenever
      KEY_FLAG_BINLOG is set on the entry (regardless of whether the
      file has been opened yet).

      Three phases:

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
        pending ACKs and emit NACKs for gaps. ACKs are uncapped per
        tick — freeing the vehicle's pending-block queue faster
        reduces its drop rate, and one UDP send per ACK is cheap.
        NACKs are throttled to ~10 Hz per missing seqno and capped
        at MAX_NACKS_PER_TICK per call so a wide gap can't bury
        legitimate ACKs. The continuous ACK traffic also keeps the
        vehicle's 10-second client-timeout from firing.

      * Defence-in-depth re-START: while streaming, emit a low-rate
        START every START_KEEPALIVE_S so a post-reboot vehicle (whose
        _sending_to_client got cleared) resumes streaming within a
        few seconds. rotate_for_reboot() zeroes last_start_sent_s so
        the next tick() iteration fires START immediately.
     */
    void tick(MAVLink &user_link);

    void close();

private:
    static constexpr size_t BLOCK_BYTES = 200;
    // NACK throttle from MAVProxy's "10/loop". ACKs are unlimited
    // per tick — see the comment in tick() — because freeing the
    // vehicle's pending queue faster reduces drop rate.
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
    // Keep-alive START cadence after streaming has begun: defence in
    // depth so a post-reboot vehicle (whose _sending_to_client got
    // cleared) resumes streaming within ~5 s of the next keepalive.
    // ArduPilot ignores a redundant START on an already-streaming
    // vehicle (it just sets _sending_to_client = true again).
    static constexpr double   START_KEEPALIVE_S  = 5.0;
    // Backward jump in SYSTEM_TIME.time_boot_ms that we treat as an
    // FC reboot. 10 s is well above any plausible timer-correction
    // wobble and well below the multi-second pause a real reboot
    // creates.
    static constexpr uint32_t REBOOT_TIME_BACKWARD_MS = 10000;
    // Caps to limit the damage from an attacker (or a buggy vehicle)
    // sending a giant seqno on the unsigned-by-default user-side port.
    // A bare seqno=0 followed by seqno=2^32-1 would otherwise sparse-
    // extend the file to ~800 GB and grow the bitmap to 512 MB. Both
    // caps are enforced in handle_block(); on breach the block is
    // silently dropped without ACK so the vehicle (if legitimate) can
    // retry, and so the cleanup loop can age-out other sessions
    // before retrying eventually succeeds.
    // 1. Per-write expansion cap: the file may grow by at most 100 MB
    //    in a single seqno step. Covers ~30 minutes of streaming at
    //    400 blocks/s; anything bigger is unambiguously bogus.
    static constexpr off_t MAX_FORWARD_JUMP_BYTES = off_t(100) * 1024 * 1024;
    // 2. Per-port-pair on-disk quota: total size of all .tlog + .bin
    //    files under logs/<port2>/ may not exceed 1 GiB. The hourly
    //    cleanup loop also enforces this by deleting oldest files.
    static constexpr off_t MAX_PER_PORT2_BYTES   = off_t(1024) * 1024 * 1024;

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
    // The magic START packet emit, factored out so both the pre-stream
    // 1 Hz loop and the streaming-mode keepalive call it.
    bool send_start_packet(MAVLink &user_link);

    // Captured on the first successful open() so rotate_for_reboot()
    // can re-scan the per-day dir for a fresh session N without
    // dragging port2/base_dir through every observe() / handle_block()
    // signature.
    uint32_t    port2_   = 0;
    std::string base_dir_;

    // Current size of fp (= the largest seqno+1 we've written * 200).
    // Tracked locally rather than fstat'ing on every write.
    off_t current_file_size_ = 0;
    // Bytes consumed by all .tlog/.bin files under logs/<port2>/
    // *other than* fp. Computed at open() and refreshed periodically
    // (the cleanup child can delete files while we're writing). Used
    // alongside current_file_size_ to enforce MAX_PER_PORT2_BYTES.
    off_t other_sessions_bytes_ = 0;
    unsigned writes_since_quota_refresh_ = 0;
    void refresh_other_sessions_bytes();

    // Per-entry MAVLink sysid filter for SYSTEM_TIME-based reboot
    // detection. 0 = match any (default). Set from KeyEntry.fc_sysid
    // by the per-port-pair child at fork.
    uint8_t fc_sysid_filter_ = 0;

    // Most-recently-seen SYSTEM_TIME.time_boot_ms from the autopilot.
    // 0 = nothing seen yet (used as a guard so the very first
    // SYSTEM_TIME can't trigger a spurious reboot).
    uint32_t last_system_time_boot_ms_ = 0;

    // Close + reset per-log state + arm pending_session_n_ for the
    // NEXT open. Used when observe() decides the FC has rebooted.
    // Does NOT re-open here — the new file is only opened when a
    // fresh seqno=0 arrives, so the existing strict-start gate keeps
    // protecting the rotated file from delayed pre-reboot blocks.
    // Does NOT reset per-vehicle state (target_system/component,
    // fc_sysid_filter_).
    bool rotate_for_reboot();

    // Session N to use on the NEXT open(), set by rotate_for_reboot()
    // and consumed on the gate-triggered open in handle_block.
    // 0 = no pending rotation; use the caller's session_n argument.
    unsigned pending_session_n_ = 0;
};
