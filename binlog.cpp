/*
  ArduPilot binary-log writer over MAVLink.
 */
#include "binlog.h"
#include "session.h"
#include "mavlink.h"
#include "util.h"

#include "libraries/mavlink2/generated/ardupilotmega/mavlink.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

namespace {

// Stable proxy-side identity used as src sysid/compid on outgoing
// ACK/NACK messages. Matches MAVProxy's defaults closely enough that
// vehicle-side filters don't reject us. Vehicle accepts the message
// based on target_{system,component}, not source.
constexpr uint8_t PROXY_SYSID  = 255;
constexpr uint8_t PROXY_COMPID = MAV_COMP_ID_LOG;

}  // namespace

BinlogWriter::~BinlogWriter()
{
    close();
}

bool BinlogWriter::open(uint32_t port2, unsigned session_n, const char *base_dir)
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
        ::printf("binlog: mkdir %s failed: %s\n", dir, strerror(errno));
        return false;
    }

    char path[1024];
    snprintf(path, sizeof(path), "%s/session%u.bin", dir, session_n);

    // O_RDWR via "rb+"-then-"wb+" dance: blocks arrive out of order so
    // we need to seek + write to arbitrary offsets. fopen "ab" forces
    // every write to the end. Use "wb+" to truncate and create, or
    // "rb+" to keep an existing file (rare — child crashed mid-session
    // and a new fork is reusing the same N? next_session_n() rules
    // that out, but defensively allow it).
    fp = fopen(path, "wb+");
    if (fp == nullptr) {
        ::printf("binlog: fopen %s failed: %s\n", path, strerror(errno));
        return false;
    }
    // Unbuffered: each block + each ACK/NACK gets a syscall, but the
    // file is readable in real time (matching TlogWriter behaviour)
    // and a child crash doesn't lose buffered bytes.
    setvbuf(fp, nullptr, _IONBF, 0);
    ::printf("binlog: %s\n", path);
    return true;
}

void BinlogWriter::close()
{
    if (fp != nullptr) {
        fflush(fp);
        fsync(fileno(fp));
        fclose(fp);
        fp = nullptr;
    }
}

bool BinlogWriter::seqno_seen(uint32_t seqno) const
{
    size_t byte = seqno >> 3;
    if (byte >= seen_bitmap.size()) {
        return false;
    }
    return (seen_bitmap[byte] & (1u << (seqno & 7))) != 0;
}

void BinlogWriter::mark_seqno_seen(uint32_t seqno)
{
    size_t byte = seqno >> 3;
    if (byte >= seen_bitmap.size()) {
        // Grow in chunks so we don't realloc per-block. 64 KiB chunk
        // covers 524288 blocks (~100 MB log) per resize.
        size_t want = byte + 1;
        size_t round = (want + 65535) & ~(size_t)65535;
        seen_bitmap.resize(round, 0);
    }
    seen_bitmap[byte] |= uint8_t(1u << (seqno & 7));
}

void BinlogWriter::handle_block(uint32_t port2, unsigned session_n,
                                 const mavlink_message_t &msg)
{
    mavlink_remote_log_data_block_t blk {};
    mavlink_msg_remote_log_data_block_decode(&msg, &blk);

    // Strict-start gate. Without this we sparse-extend the file out
    // to whatever the vehicle's current seqno is — a vehicle that
    // was already streaming when SupportProxy activated will have
    // seqnos in the millions, producing a multi-GB hole-y file that
    // doesn't start at byte 0 with FMT records and so won't parse
    // with DFReader_binary / mavlogdump.py.
    if (fp == nullptr) {
        if (blk.seqno != 0) {
            return;
        }
        if (!open(port2, session_n)) {
            return;
        }
    }

    // Latch the vehicle's sysid/compid on first block so subsequent
    // ACKs/NACKs go to the right target. We also use the source
    // sysid/compid from the MAVLink header rather than the message
    // body's target_* fields (which point at the GCS, not the vehicle).
    if (!any_block_seen) {
        target_system = msg.sysid;
        target_component = msg.compid;
        any_block_seen = true;
    }

    // Sparse write. fseeko + fwrite at seqno * 200; if seqno < highest
    // we just fill an old gap.
    off_t offset = off_t(blk.seqno) * off_t(BLOCK_BYTES);
    if (fseeko(fp, offset, SEEK_SET) != 0) {
        ::printf("binlog: seek seqno=%u failed: %s\n",
                 unsigned(blk.seqno), strerror(errno));
        return;
    }
    size_t wrote = fwrite(blk.data, 1, BLOCK_BYTES, fp);
    if (wrote != BLOCK_BYTES) {
        ::printf("binlog: short write seqno=%u wrote=%zu: %s\n",
                 unsigned(blk.seqno), wrote, strerror(errno));
        // Don't ACK a partial write — let the vehicle re-send.
        return;
    }

    bool was_seen = seqno_seen(blk.seqno);
    mark_seqno_seen(blk.seqno);

    // If this block fills a previously-NACKed gap, drop its NACK state
    // so tick() stops chasing it.
    nack_state.erase(blk.seqno);

    // Forward jump → record gap NACKs. Only counts as a "new" forward
    // when seqno is strictly greater than the previous highest.
    double now_s = time_seconds();
    if (any_block_seen && blk.seqno > highest_seen + 1
        && !(highest_seen == 0 && !was_seen && blk.seqno == 0)) {
        queue_gap_nacks(highest_seen, blk.seqno, now_s);
    }
    if (blk.seqno >= highest_seen) {
        highest_seen = blk.seqno;
    }

    // Always queue an ACK for any successfully-written block, even one
    // we'd seen before (the vehicle's still re-sending because it
    // didn't get our previous ACK).
    pending_acks.push_back(blk.seqno);
    (void)was_seen;
}

void BinlogWriter::queue_gap_nacks(uint32_t prev_highest,
                                    uint32_t new_seqno,
                                    double now_s)
{
    // Walk [prev_highest+1, new_seqno-1] and seed NACK state. Skip
    // seqnos we've already filled (e.g. an out-of-order recovery that
    // happened before this block).
    for (uint32_t s = prev_highest + 1; s < new_seqno; s++) {
        if (seqno_seen(s)) {
            continue;
        }
        if (nack_state.find(s) == nack_state.end()) {
            // last_sent_s = 0 means "never sent yet"; tick() will
            // emit the first NACK on its next call.
            nack_state[s] = NackState { now_s, 0.0 };
        }
    }
}

void BinlogWriter::drop_stale_nack_state(double now_s)
{
    for (auto it = nack_state.begin(); it != nack_state.end(); ) {
        bool drop = false;
        if (seqno_seen(it->first)) {
            drop = true;
        } else if (now_s - it->second.first_seen_s > NACK_GIVEUP_S) {
            drop = true;
        } else if (highest_seen >= it->first
                   && highest_seen - it->first > NACK_GIVEUP_BLOCKS) {
            drop = true;
        }
        if (drop) {
            it = nack_state.erase(it);
        } else {
            ++it;
        }
    }
}

bool BinlogWriter::send_status(MAVLink &user_link, uint32_t seqno,
                                uint8_t status)
{
    if (!any_block_seen) {
        return false;
    }
    mavlink_message_t msg {};
    // pack_chan finalises the message: it trims trailing zero bytes
    // off the payload (so a NACK with status=0 ends up with len=6
    // and the trimmed zero overwritten by CRC bytes), then sets the
    // CRC. We must NOT call user_link.send_message() — that does a
    // *second* finalize, which would re-examine the payload buffer,
    // see the CRC byte at offset 6 as "real" payload (non-zero so no
    // trim), bump len back to 7, and emit the CRC byte on the wire
    // where the receiver expects the status field. Instead, serialise
    // the already-finalised bytes via send_buf() and skip the second
    // finalize entirely.
    mavlink_msg_remote_log_block_status_pack_chan(
        PROXY_SYSID, PROXY_COMPID, CHAN_COMM1, &msg,
        target_system, target_component, seqno, status);
    uint8_t buf[MAVLINK_MAX_PACKET_LEN];
    uint16_t len = mavlink_msg_to_send_buffer(buf, &msg);
    if (len == 0) {
        return false;
    }
    return user_link.send_buf(buf, len) == ssize_t(len);
}

void BinlogWriter::tick(MAVLink &user_link)
{
    double now_s = time_seconds();

    if (!any_block_seen) {
        // Vehicle hasn't begun streaming yet. Send the magic
        // REMOTE_LOG_BLOCK_STATUS(status=ACK,
        // seqno=MAV_REMOTE_LOG_DATA_BLOCK_START) at 1 Hz: that's what
        // flips ArduPilot's _sending_to_client = true (so its
        // pre-arm logging_failed() check passes) AND resets the
        // vehicle's seqno counter to 0, which our file-open gate is
        // already waiting for. target_system/target_component are
        // left at 0 (broadcast) because we haven't latched a vehicle
        // sysid yet — ArduPilot's handle_ack() picks up the proxy's
        // src sysid/compid from the message header anyway, not the
        // body's target fields.
        if (now_s - last_start_sent_s >= START_REPEAT_S) {
            mavlink_message_t msg {};
            mavlink_msg_remote_log_block_status_pack_chan(
                PROXY_SYSID, PROXY_COMPID, CHAN_COMM1, &msg,
                /*target_system*/ 0, /*target_component*/ 0,
                /*seqno*/ MAV_REMOTE_LOG_DATA_BLOCK_START,
                /*status*/ MAV_REMOTE_LOG_DATA_BLOCK_ACK);
            uint8_t buf[MAVLINK_MAX_PACKET_LEN];
            uint16_t len = mavlink_msg_to_send_buffer(buf, &msg);
            if (len > 0 && user_link.send_buf(buf, len) == ssize_t(len)) {
                last_start_sent_s = now_s;
            }
        }
        return;
    }

    if (fp == nullptr) {
        return;
    }

    // Drain ALL pending ACKs each tick. They're cheap (one small
    // UDP send each) and the sooner the vehicle gets them the
    // sooner its pending-block queue frees up. The MAX_ACKS_PER_TICK
    // cap was a historical carry-over from MAVProxy's 100 Hz idle
    // loop where 10/loop already gave 1 kHz throughput; our
    // main_loop wakes on each incoming packet, so under a TCP burst
    // (one recv() can return ~45 frames) the cap would let an ACK
    // backlog age 4+ ticks before catching up. The continuous ACK
    // traffic also resets ArduPilot's 10-second _last_response_time
    // client-timeout (see AP_Logger_MAVLink.cpp).
    while (!pending_acks.empty()) {
        uint32_t s = pending_acks.front();
        pending_acks.pop_front();
        send_status(user_link, s, MAV_REMOTE_LOG_DATA_BLOCK_ACK);
    }

    drop_stale_nack_state(now_s);

    // Re-NACK any missing seqno whose 100 ms throttle has elapsed.
    unsigned nack_budget = MAX_NACKS_PER_TICK;
    for (auto &kv : nack_state) {
        if (nack_budget == 0) {
            break;
        }
        double elapsed = now_s - kv.second.last_sent_s;
        // last_sent_s == 0 is the sentinel for "never sent" — always emit.
        if (kv.second.last_sent_s != 0.0 && elapsed < NACK_REPEAT_S) {
            continue;
        }
        if (send_status(user_link, kv.first,
                        MAV_REMOTE_LOG_DATA_BLOCK_NACK)) {
            kv.second.last_sent_s = now_s;
            nack_budget--;
        }
    }
}
