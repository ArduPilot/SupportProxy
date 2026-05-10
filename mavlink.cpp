/*
  mavlink class for UDP

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "mavlink.h"

#include "libraries/mavlink2/generated/mavlink_helpers.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <tdb.h>
#include <sys/time.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include "util.h"
#include "tlog.h"

mavlink_system_t mavlink_system = {0, 0};

bool MAVLink::got_bad_signature[MAVLINK_COMM_NUM_BUFFERS];

// unused comm_send_buffer (as we handle packets as UDP buffers)
void comm_send_buffer(mavlink_channel_t chan, const uint8_t *buf, uint8_t len)
{
}

void tlog_write_message(TlogWriter *tlog, const mavlink_message_t &msg)
{
    if (tlog == nullptr || !tlog->is_open()) {
        return;
    }
    uint8_t buf[MAVLINK_MAX_PACKET_LEN];
    mavlink_message_t msg2 = msg;
    uint16_t len = mavlink_msg_to_send_buffer(buf, &msg2);
    if (len > 0) {
        tlog->write_frame(buf, len);
    }
}

/*
  init connection
 */
void MAVLink::init(int _fd, mavlink_channel_t _chan, bool signing_required, bool _allow_websocket, bool _is_tcp, int _key_id)
{
    fd = _fd;
    chan = _chan;
    key_id = _key_id;
    is_tcp = _is_tcp;

    got_signed_packet = false;
    key_loaded = false;
    last_signing_save_s = 0;
    last_signing_warning_s = 0;
    last_sysid = 0;
    last_compid = 0;
    bad_sig_count = 0;
    allow_websocket = _allow_websocket;
    got_bad_signature[chan] = false;
    use_sendto = false;

    ZERO_STRUCT(signing_streams);
    ZERO_STRUCT(signing);

    if (signing_required) {
	load_signing_key();
        update_signing_timestamp();
    }
}

/*
  send bytes on the link
 */
ssize_t MAVLink::send_data(const void *buf, ssize_t len)
{
    if (ws) {
	return ws->send(buf, len);
    }
    if (use_sendto) {
	return ::sendto(fd, buf, len, 0, (const sockaddr *)&send_addr, send_len);
    }
    return ::send(fd, buf, len, 0);
}

ssize_t MAVLink::send_buf(const void *buf, ssize_t len)
{
    return send_data(buf, len);
}

bool MAVLink::receive_message(uint8_t *&buf, ssize_t &len, mavlink_message_t &msg)
{
    mavlink_status_t status {};
    status.packet_rx_drop_count = 0;
    got_bad_signature[chan] = false;
    while (len--) {
	if (mavlink_parse_char(chan, *buf++, &msg, &status)) {
	    if (key_id != -1) {
		if (!key_loaded) {
                    if (periodic_warning()) {
                        mav_printf(MAV_SEVERITY_CRITICAL, "Need to setup support signing key");
                    }
                    return false;
                } else {
                    if ((msg.incompat_flags & MAVLINK_IFLAG_SIGNED) == 0) {
                        if (periodic_warning()) {
                            mav_printf(MAV_SEVERITY_CRITICAL, "Need to use support signing key");
                        }
                        got_signed_packet = false;
                        return false;
                    }
		    if (got_bad_signature[chan]) {
			if (periodic_warning()) {
                            switch (signing.last_status) {
                            case MAVLINK_SIGNING_STATUS_BAD_SIGNATURE:
                            default:
                                bad_sig_count++;
                                if (bad_sig_count < 3) {
                                    // silently drop it
                                    return false;
                                }
                                mav_printf(MAV_SEVERITY_CRITICAL, "Bad support signing key");
                                break;
                            case MAVLINK_SIGNING_STATUS_REPLAY:
                                bad_sig_count++;
                                if (bad_sig_count < 3) {
                                    // silently drop it
                                    return false;
                                }
                                mav_printf(MAV_SEVERITY_CRITICAL, "Bad signing timestamp - replay");
                                break;
			    case MAVLINK_SIGNING_STATUS_OLD_TIMESTAMP: {
				const uint8_t *psig = msg.signature;
				union tstamp {
				    uint64_t t64;
				    uint8_t t8[8];
				} tstamp;
				tstamp.t64 = 0;
				memcpy(tstamp.t8, psig+1, 6);
				double tserr = (double(tstamp.t64) - double(signing.timestamp))*1.0e-5;
				mav_printf(MAV_SEVERITY_CRITICAL, "Bad signing timestamp - old timestamp (%.2fs)", tserr);
				break;
			    }
                            case MAVLINK_SIGNING_STATUS_NO_STREAMS:
                                mav_printf(MAV_SEVERITY_CRITICAL, "Bad signing timestamp - no streams");
                                break;
                            case MAVLINK_SIGNING_STATUS_TOO_MANY_STREAMS:
                                mav_printf(MAV_SEVERITY_CRITICAL, "Bad signing timestamp - bad streams");
                                break;
                            }
                        }
                        got_signed_packet = false;
                        return false;
                    }
                    bad_sig_count = 0;
                    if (!got_signed_packet) {
                        got_signed_packet = true;
                        ::printf("[%d] Got good signature\n", key_id);
                    }
                    if (msg.msgid == MAVLINK_MSG_ID_SETUP_SIGNING) {
                        // handle SETUP_SIGNING locally
                        handle_setup_signing(msg);
                        return false;
                    }
                }
            }
            return true;
        }
    }
    return false;
}

bool MAVLink::send_message(const mavlink_message_t &msg)
{
    mavlink_message_t msg2 = msg;
    uint8_t buf[300];
    if (is_tcp) {
	if (socket_is_dead(fd)) {
	    return false;
	}
	// if congested then drop this message, so we don't block
	// other links
	if (tcp_writable_bytes(fd) < 400) {
	    return true;
	}
    }
    if (key_id == -1) {
        // strip signing
        msg2.incompat_flags &= ~MAVLINK_IFLAG_SIGNED;
    } else {
        // add signing
        msg2.incompat_flags |= MAVLINK_IFLAG_SIGNED;
        if (!got_signed_packet && msg.msgid != MAVLINK_MSG_ID_HEARTBEAT) {
            // don't send anything but HEARTBEAT until support engineer sends a signed packet
            // we return true so connection stays alive
            return true;
        }
        if (msg.msgid == MAVLINK_MSG_ID_HEARTBEAT) {
            // remember sysid/compid for STATUSTEXT
            last_sysid = msg.sysid;
            last_compid = msg.compid;
	}
        if (key_loaded) {
            update_signing_timestamp();
        }
    }
    const uint8_t crc_extra = mavlink_get_crc_extra(&msg2);
    const uint8_t min_len = mavlink_min_message_length(&msg2);
    const uint8_t max_len = mavlink_max_message_length(&msg2);
    if (min_len == 0 && max_len == 0) {
        ::printf("Unknown MAVLink msg ID %u\n", unsigned(msg.msgid));
        return false;
    }
    mavlink_status_t *status = mavlink_get_channel_status(chan);
    if (status == nullptr) {
        return false;
    }

    // keep the sequence numbers aligned so if there are multiple system IDs we get correct
    // packet loss information
    status->current_tx_seq = msg.seq;

    mavlink_finalize_message_buffer(&msg2, msg2.sysid, msg2.compid, status, min_len, max_len, crc_extra);

    uint16_t len = mavlink_msg_to_send_buffer(buf, &msg2);
    if (len > 0) {
	return send_data(buf, len) == len;
    }
    return false;
}

/*
  callback to accept unsigned (or incorrectly signed) packets
 */
bool MAVLink::accept_unsigned_callback(const mavlink_status_t *status, uint32_t msgId)
{
    // we accept all and use status to check in receive_message()
    if (status->signing) {
	auto _chan = mavlink_channel_t(status->signing->link_id);
	if (_chan < MAVLINK_COMM_NUM_BUFFERS) {
	    got_bad_signature[_chan] = true;
	}
    }
    return true;
}

/*
  load key from keys.tdb
 */
bool MAVLink::load_key(TDB_CONTEXT *tdb)
{
    return db_load_key(tdb, key_id, key);
}

/*
  save key to keys.tdb
 */
bool MAVLink::save_key(TDB_CONTEXT *tdb)
{
    return db_save_key(tdb, key_id, key);
}

/*
  load signing key
 */
void MAVLink::load_signing_key(void)
{
    mavlink_status_t *status = mavlink_get_channel_status(chan);
    if (status == nullptr) {
        ::printf("Failed to load signing key for %d - no status\n", key_id);
        return;        
    }
    auto *db = db_open();
    // we fallback to the default key ID of 0 if no signing key
    if (!load_key(db)) {
        ::printf("Failed to find signing key for ID %d\n", key_id);
        db_close(db);
        return;
    }

    key_loaded = true;

    memcpy(signing.secret_key, key.secret_key, sizeof(key.secret_key));
    signing.link_id = uint8_t(chan);

    // Start signing.timestamp at max(saved + 15s, current wall clock).
    //
    // The +15s buffer over the saved value is the historical guard for the
    // replay window between key saves (saves are throttled to once per 10s,
    // so a crash can lose up to that window of advancement).
    //
    // We take max() with current wall clock so the timestamp doesn't end
    // up parked in the future when the saved value was written long enough
    // ago that real time has caught up. Without this, sequential
    // short-lived connections (e.g. test runs creating a new MAVLink
    // instance per scenario) accumulate +15s of "future" drift per load
    // because update_signing_timestamp() is only invoked from send_message
    // and so doesn't run before the first incoming packet has its tstamp
    // checked against signing.timestamp. The first incoming packet's
    // tstamp is "now", and once signing.timestamp has drifted past
    // now + MAVLINK_SIGNING_TIMESTAMP_LIMIT seconds the helper rejects
    // the packet before any send can pull signing.timestamp back to now.
    {
        uint64_t loaded = key.timestamp + 15ULL * 100ULL * 1000ULL;
        const uint64_t epoch_offset = 1420070400ULL;  // 2015-01-01 UTC
        double now_s = time_seconds();
        uint64_t now_mavlink = 0;
        if (now_s > epoch_offset) {
            now_mavlink = uint64_t(now_s - epoch_offset) * 100ULL * 1000ULL;
        }
        signing.timestamp = (now_mavlink > loaded) ? now_mavlink : loaded;
    }
    signing.flags = MAVLINK_SIGNING_FLAG_SIGN_OUTGOING;
    signing.accept_unsigned_callback = accept_unsigned_callback;

    // if timestamp and key are all zero then we disable signing
    bool all_zero = (key.timestamp == 0);
    for (uint8_t i=0; i<sizeof(key.secret_key); i++) {
        if (signing.secret_key[i] != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) {
        // disable signing
        status->signing = nullptr;
        status->signing_streams = nullptr;
    } else {
        status->signing = &signing;
        status->signing_streams = &signing_streams;
    }
    db_close(db);
}

/*
  update signing timestamp. This is called when we get GPS lock
  timestamp_usec is since 1/1/1970 (the epoch)
 */
void MAVLink::update_signing_timestamp()
{
    double now = time_seconds();
    if (now - last_signing_save_s < 10) {
        return;
    }
    last_signing_save_s = now;
    uint64_t signing_timestamp = now;
    // this is the offset from 1/1/1970 to 1/1/2015
    const uint64_t epoch_offset = 1420070400ULL;
    if (signing_timestamp > epoch_offset) {
        signing_timestamp -= epoch_offset;
    }

    // convert to 10usec units
    signing_timestamp *= 100 * 1000ULL;

    // increase signing timestamp on any links that have signing
    for (uint8_t i=0; i<MAVLINK_COMM_NUM_BUFFERS; i++) {
	mavlink_channel_t _chan = (mavlink_channel_t)(MAVLINK_COMM_0 + i);
	mavlink_status_t *status = mavlink_get_channel_status(_chan);
        if (status && status->signing && status->signing->timestamp < signing_timestamp) {
            status->signing->timestamp = signing_timestamp;
        }
    }

    // save to stable storage as a child process to minimise latency
    // in this process
    signal(SIGCHLD, SIG_IGN);
    if (fork() == 0) {
	save_signing_timestamp();
	exit(0);
    }
}


/*
  save the signing timestamp periodically
 */
void MAVLink::save_signing_timestamp(void)
{
    auto *db = db_open_transaction();
    if (db == nullptr) {
        return;
    }
    if (!load_key(db)) {
        printf("Bad key %d\n", key_id);
        db_close_cancel(db);
        return;
    }
    bool need_save = false;

    // Cap saved value at current real time. The +15s buffer added in
    // load_signing_key() is a per-load replay guard; allowing it to
    // round-trip through this save would let the buffer compound across
    // sequential short-lived sessions until signing.timestamp parks far
    // enough in the future that incoming packets get rejected as
    // MAVLINK_SIGNING_STATUS_OLD_TIMESTAMP. Using the legitimate
    // wall-clock advancement here keeps the stored timestamp in sync
    // with reality.
    double now_s = time_seconds();
    const uint64_t epoch_offset = 1420070400ULL;
    uint64_t now_mavlink = 0;
    if (now_s > epoch_offset) {
        now_mavlink = uint64_t(now_s - epoch_offset) * 100ULL * 1000ULL;
    }

    for (uint8_t i=0; i<MAVLINK_COMM_NUM_BUFFERS; i++) {
	mavlink_channel_t _chan = (mavlink_channel_t)(MAVLINK_COMM_0 + i);
	const mavlink_status_t *status = mavlink_get_channel_status(_chan);
        if (status && status->signing) {
            uint64_t v = status->signing->timestamp;
            if (v > now_mavlink) {
                v = now_mavlink;
            }
            if (v > key.timestamp) {
                key.timestamp = v;
                need_save = true;
            }
        }
    }
    if (need_save) {
        // save updated key
	save_key(db);
	db_close_commit(db);
    } else {
        db_close_cancel(db);
    }
}

/*
  printf via MAVLink STATUSTEXT for communicating from proxy to support engineer
 */
void MAVLink::mav_printf(uint8_t severity, const char *fmt, ...)
{
    va_list arg_list;
    char text[MAVLINK_MSG_STATUSTEXT_FIELD_TEXT_LEN+1] {};
    va_start(arg_list, fmt);
    vsnprintf(text, sizeof(text), fmt, arg_list);
    va_end(arg_list);
    mavlink_message_t msg {};
    // we use CHAN_STATUSTEXT as we don't want these messages signed,
    // as if we sign them and the signature doesn't match then
    // MissionPlanner doesn't display them
    mavlink_msg_statustext_pack_chan(last_sysid, last_compid,
				     CHAN_STATUSTEXT,
                                     &msg,
                                     severity,
                                     text,
                                     0, 0);
    uint8_t buf[300];
    uint16_t len = mavlink_msg_to_send_buffer(buf, &msg);
    if (len > 0) {
        ::printf("[%d]: %s\n", key_id, text);
	send_data(buf, len);
    }

    // also send signed so for old timestamp the client gets a chance
    // to update the timestamp
    mavlink_message_t msg2 {};
    mavlink_msg_statustext_pack_chan(last_sysid, last_compid,
				     chan,
				     &msg2,
                                     severity,
                                     text,
                                     0, 0);
    uint16_t len2 = mavlink_msg_to_send_buffer(buf, &msg2);
    if (len2 > 0) {
	send_data(buf, len2);
    }
}

/*
  control periodic warnings to user
 */
bool MAVLink::periodic_warning(void)
{
    double now = time_seconds();
    if (now - last_signing_warning_s > 2) {
        last_signing_warning_s = now;
        return true;
    }
    return false;
}

/*
  handle a (signed) SETUP_SIGNING request
  this is used to change the support signing key
 */
void MAVLink::handle_setup_signing(const mavlink_message_t &msg)
{
    mavlink_setup_signing_t packet;
    mavlink_msg_setup_signing_decode(&msg, &packet);

    auto *db = db_open_transaction();
    if (db == nullptr) {
        return;
    }

    if (!load_key(db)) {
        printf("Bad key %d\n", key_id);
        db_close_cancel(db);
        return;
    }

    key.timestamp = packet.initial_timestamp;
    memcpy(key.secret_key, packet.secret_key, 32);

    ::printf("[%d] Set new signing key\n", key_id);
    save_key(db);

    got_signed_packet = false;
    db_close_commit(db);
    load_signing_key();
}
