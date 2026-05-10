/*
  UDP (and TCP) Proxy for MAVLink, with signing support

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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <signal.h>

#include "mavlink.h"
#include "util.h"
#include "keydb.h"
#include "conntdb.h"
#include "tlog.h"
#include "cleanup.h"
#include "websocket.h"

#include <vector>

/*
  SIGUSR1 from the webadmin asks the per-port-pair child to drop a
  specific connection. The webadmin sets CONN_FLAG_DROP_REQUESTED on
  the matching ConnEntry first; the handler just sets a flag and
  main_loop scans connections.tdb to find the target slot(s).
 */
static volatile sig_atomic_t g_drops_pending = 0;

static void sigusr1_handler(int)
{
    g_drops_pending = 1;
}

#define MAX_EPOLL_EVENTS 64

struct listen_port {
    struct listen_port *next;
    int port1, port2;
    int sock1_udp, sock2_udp;
    int sock1_tcp, sock2_listen;
    pid_t pid;
    uint32_t flags;
    bool seen;     // set true by handle_record() during reload_ports()
                   // for any entry that's still in the DB; entries left
                   // unseen after a reload have been removed.
    bool removed;  // entry no longer in keys.tdb. We keep the struct
                   // around (don't free it under a running child) but
                   // close listening sockets and skip it everywhere.
    WebSocket *ws = nullptr;
};

static struct listen_port *ports;

// PID of the long-lived tlog-cleanup child forked from main(). Tracked
// separately from per-port-pair children so check_children() can
// respawn it if it dies, rather than printing "No child for X found".
static pid_t cleanup_child_pid = 0;
static void fork_cleanup_child(void);

static uint32_t count_ports(void)
{
    uint32_t count = 0;
    for (auto *p = ports; p; p=p->next) {
        count++;
    }
    return count;
}

static void open_sockets(struct listen_port *p);
static void close_sockets(struct listen_port *p);

/*
  Reconcile a single keys.tdb record with our in-memory port list.

    - new port2:                add struct, mark seen, open listeners
    - existing port2, same port1, flags unchanged: just mark seen
    - existing port2 marked removed: un-remove, reopen
    - existing port2, port1 changed: close old listeners, signal the
      running child (if any) to exit so the old port1 is freed, then
      open the new port1
    - existing port2, only flags changed: refresh flags so the next
      child fork picks them up

  Used both at startup and on each reload; reload_ports() handles the
  flip side (entries that were in keys.tdb last time and aren't now).
 */
static void upsert_port(int port1, int port2, uint32_t flags)
{
    for (auto *p = ports; p; p=p->next) {
        if (p->port2 == port2) {
            p->seen = true;
            if (p->removed) {
                // came back: re-add as a fresh listener
                printf("[%d] re-added (port1=%d)\n", port2, port1);
                p->removed = false;
                p->port1 = port1;
                p->flags = flags;
                if (p->pid == 0) {
                    open_sockets(p);
                }
            } else if (p->port1 != port1) {
                printf("[%d] port1 changed %d -> %d\n",
                       port2, p->port1, port1);
                close_sockets(p);
                if (p->pid != 0) {
                    // running child still binds the old port1; signal it
                    // to exit so check_children reopens with the new one
                    kill(p->pid, SIGTERM);
                }
                p->port1 = port1;
                p->flags = flags;
                if (p->pid == 0) {
                    open_sockets(p);
                }
            } else {
                p->flags = flags;
            }
            return;
        }
    }
    struct listen_port *p = new struct listen_port;
    p->next = ports;
    p->port1 = port1;
    p->port2 = port2;
    p->sock1_udp = -1;
    p->sock2_udp = -1;
    p->sock1_tcp = -1;
    p->sock2_listen = -1;
    p->pid = 0;
    p->flags = flags;
    p->seen = true;
    p->removed = false;
    ports = p;
    printf("Added port %d/%d\n", port1, port2);
    open_sockets(p);
}


static int handle_record(struct tdb_context *db, TDB_DATA key, TDB_DATA data, void *ptr)
{
    if (key.dsize != sizeof(int) || data.dsize < KEYENTRY_MIN_SIZE) {
        // skip it
        return 0;
    }
    struct KeyEntry k {};
    int port2 = 0;
    memcpy(&port2, key.dptr, sizeof(int));
    size_t copy = data.dsize < sizeof(KeyEntry) ? data.dsize : sizeof(KeyEntry);
    memcpy(&k, data.dptr, copy);
    upsert_port(k.port1, port2, k.flags);
    return 0;
}

static void close_fd(int &fd)
{
    if (fd != -1) {
	close(fd);
	fd = -1;
    }
}

class Connection2 {
public:
    int sock = -1;
    bool used = false;
    bool tcp_active = false;
    MAVLink mav;
    WebSocket *ws = nullptr;
    struct sockaddr_in from;
    socklen_t fromlen = 0;
    bool is_udp = false;
    double last_pkt = 0;
    // for connections.tdb visibility
    time_t connected_at = 0;
    uint32_t rx_msgs = 0;
    uint32_t tx_msgs = 0;

    void close(void) {
	close_fd(sock);
	tcp_active = false;
	used = false;
	delete ws;
	ws = nullptr;
	connected_at = 0;
	rx_msgs = 0;
	tx_msgs = 0;
    }
};

static void main_loop(struct listen_port *p)
{
    unsigned char buf[10240] {};
    bool have_conn1=false;
    double last_pkt1=0;
    uint32_t count1=0, count2=0;
    int fdmax = -1;
    // bidi-sign: enforce signing on the user side too. mav1 then loads the
    // same key keys.tdb stores for the engineer side, so unsigned and
    // wrong-key user packets are rejected before being forwarded.
    const bool bidi = (p->flags & KEY_FLAG_BIDI_SIGN) != 0;
    const int conn1_key_id = bidi ? p->port2 : -1;
    /*
      we allow more than one connection on the support engineer side
     */
    uint8_t max_conn2_count = 0;
    uint8_t conn2_count = 0;
    MAVLink mav_blank;
    MAVLink mav1;
    Connection2 conn2[MAX_COMM2_LINKS];

    // Webadmin sends SIGUSR1 to ask us to drop a specific connection.
    // The signal handler just sets a flag; we scan connections.tdb at
    // the top of each main_loop iteration to find the target slot(s).
    {
        struct sigaction sa = {};
        sa.sa_handler = sigusr1_handler;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGUSR1, &sa, nullptr);
    }

    // tlog: opened lazily on first received frame so an idle child that
    // never sees traffic doesn't leave behind an empty session file.
    TlogWriter tlog;
    const bool tlog_enabled = (p->flags & KEY_FLAG_TLOG) != 0;
    auto ensure_tlog_open = [&]() {
        if (tlog_enabled && !tlog.is_open()) {
            tlog.open(uint32_t(p->port2));
        }
    };
    auto tlog_ptr = [&]() -> TlogWriter * {
        return tlog_enabled ? &tlog : nullptr;
    };

    // Live state mirrored into connections.tdb so the web UI can show
    // who is connected right now. Captured here, snapshotted into TDB
    // on a 10s heartbeat below (mirroring save_signing_timestamp's
    // fork-and-write pattern in mavlink.cpp).
    struct sockaddr_in mav1_peer {};
    time_t mav1_connected_at = 0;
    uint32_t mav1_rx_msgs = 0, mav1_tx_msgs = 0;
    bool mav1_is_tcp = false;
    double last_conn_save_s = 0;
    const pid_t my_pid = getpid();

    fdmax = MAX(fdmax, p->sock1_udp);
    fdmax = MAX(fdmax, p->sock2_udp);
    fdmax = MAX(fdmax, p->sock1_tcp);
    fdmax = MAX(fdmax, p->sock2_listen);

    // Pull DROP_REQUESTED entries for our port2 out of connections.tdb,
    // close the matching slots, and delete the records. Returns true if
    // the user side was dropped (caller should exit main_loop).
    auto process_drops = [&]() -> bool {
        std::vector<int> indices;
        struct collect_ctx {
            int port2;
            std::vector<int> *out;
        } ctx { p->port2, &indices };

        auto cb = [](struct tdb_context *, TDB_DATA key, TDB_DATA data,
                     void *vptr) -> int {
            auto *c = static_cast<collect_ctx *>(vptr);
            if (key.dsize != sizeof(struct ConnKey)
                || data.dsize < CONNENTRY_MIN_SIZE) {
                return 0;
            }
            struct ConnKey k {};
            memcpy(&k, key.dptr, sizeof(k));
            if (k.port2 != c->port2) {
                return 0;
            }
            struct ConnEntry e {};
            size_t copy = data.dsize < sizeof(e) ? data.dsize : sizeof(e);
            memcpy(&e, data.dptr, copy);
            if (e.magic == CONN_MAGIC
                && (e.flags & CONN_FLAG_DROP_REQUESTED) != 0) {
                c->out->push_back(k.conn_index);
            }
            return 0;
        };

        auto *db = conn_db_open_transaction();
        if (db == nullptr) {
            return false;
        }
        tdb_traverse(db, cb, &ctx);
        for (int idx : indices) {
            conn_delete(db, p->port2, idx);
        }
        conn_db_close_commit(db);

        bool exit_loop = false;
        for (int idx : indices) {
            if (idx == 0) {
                printf("[%d] %s drop user requested -> ending session\n",
                       p->port2, time_string());
                exit_loop = true;
            } else if (idx >= 1 && idx <= MAX_COMM2_LINKS) {
                auto &c2 = conn2[idx - 1];
                if (c2.used) {
                    printf("[%d] %s drop conn2[%d] requested\n",
                           p->port2, time_string(), idx - 1);
                    c2.close();
                    if (conn2_count > 0) {
                        conn2_count--;
                    }
                    if (max_conn2_count > 0 && idx == max_conn2_count) {
                        max_conn2_count--;
                    }
                }
            }
        }
        return exit_loop;
    };

    while (1) {
        if (g_drops_pending) {
            g_drops_pending = 0;
            if (process_drops()) {
                break;
            }
        }
        fd_set fds;
        int ret;
        struct timeval tval;
        double now = time_seconds();

        if (have_conn1 && now - last_pkt1 > 10) {
            break;
        }

	FD_ZERO(&fds);
	if (p->sock1_udp != -1) {
	    FD_SET(p->sock1_udp, &fds);
	}
	if (p->sock2_udp != -1) {
	    FD_SET(p->sock2_udp, &fds);
	}
	if (p->sock1_tcp != -1) {
	    FD_SET(p->sock1_tcp, &fds);
	}
	if (p->sock2_listen != -1) {
	    FD_SET(p->sock2_listen, &fds);
	}
	for (uint8_t i=0; i<max_conn2_count; i++) {
	    const auto &c2 = conn2[i];
	    if (c2.sock != -1) {
		FD_SET(c2.sock, &fds);
	    }
	}

        tval.tv_sec = 10;
        tval.tv_usec = 0;

	ret = select(fdmax+1, &fds, NULL, NULL, &tval);
        if (ret == -1 && errno == EINTR) continue;
        if (ret <= 0) break;

	now = time_seconds();

	if (max_conn2_count > MAX_COMM2_LINKS) {
	    printf("BUG: max_conn2_count=%d\n", int(max_conn2_count));
	    exit(1);
	}

	/*
	  check for dead UDP conn2
	 */
	for (uint8_t i=0; i<max_conn2_count; i++) {
	    auto &c2 = conn2[i];
	    if (c2.used && c2.is_udp && now - c2.last_pkt > 10) {
		printf("[%d] %s dead UDP conn2[%u]\n",
		       unsigned(p->port2), time_string(),
		       unsigned(i));
		c2.close();
	    }
	}

	/*
	  check for UDP user data
	 */
	if (p->sock1_udp != -1 &&
	    FD_ISSET(p->sock1_udp, &fds)) {
	    close_fd(p->sock1_tcp);
	    struct sockaddr_in from;
            socklen_t fromlen = sizeof(from);
	    ssize_t n = recvfrom(p->sock1_udp, buf, sizeof(buf), 0,
                             (struct sockaddr *)&from, &fromlen);
	    if (n < 0) break;
            last_pkt1 = now;
            count1++;
            if (!have_conn1) {
                if (connect(p->sock1_udp, (struct sockaddr *)&from, fromlen) != 0) {
                    break;
                }
		mav1.init(p->sock1_udp, CHAN_COMM1, bidi, false, false, conn1_key_id);
                have_conn1 = true;
		mav1_peer = from;
		mav1_connected_at = time(nullptr);
		mav1_is_tcp = false;
		// trigger an immediate connections.tdb snapshot on the next
		// loop iteration so the web UI sees the new conn quickly
		last_conn_save_s = 0;
		printf("[%d] %s have UDP conn1 for from %s\n", unsigned(p->port2), time_string(), addr_to_str(from));
            }
            mavlink_message_t msg {};
	    if (conn2_count > 0) {
		uint8_t *buf0 = buf;
		while (n > 0 && mav1.receive_message(buf0, n, msg)) {
		    mav1_rx_msgs++;
		    ensure_tlog_open();
		    tlog_write_message(tlog_ptr(), msg);
		    for (uint8_t i=0; i<max_conn2_count; i++) {
			auto &c2 = conn2[i];
			if (!c2.used) {
			    continue;
			}
			if (!c2.is_udp && c2.sock != -1) {
			    if (!c2.mav.send_message(msg)) {
				c2.close();
				if (conn2_count == max_conn2_count) {
				    max_conn2_count--;
				}
				conn2_count--;
			    } else {
				c2.tx_msgs++;
			    }
			}
			if (c2.is_udp) {
			    c2.mav.send_message(msg);
			    c2.tx_msgs++;
			}
		    }
		}
	    }
        }

	/*
	  check for UDP support engineer data
	 */
	if (p->sock2_udp != -1 &&
	    FD_ISSET(p->sock2_udp, &fds)) {
	    struct sockaddr_in from;
            socklen_t fromlen = sizeof(from);
	    ssize_t n = recvfrom(p->sock2_udp, buf, sizeof(buf), 0,
                             (struct sockaddr *)&from, &fromlen);
	    if (n < 0) break;
	    count2++;

	    // find existing slot
	    int idx = -1;
	    for (uint8_t i=0; i<max_conn2_count; i++) {
		auto &c2 = conn2[i];
		if (c2.used && c2.is_udp &&
		    from.sin_addr.s_addr == c2.from.sin_addr.s_addr &&
		    from.sin_port == c2.from.sin_port &&
		    fromlen == c2.fromlen) {
		    // found it
		    idx = &c2 - &conn2[0];
		    c2.last_pkt = now;
		    break;
		}
	    }

	    if (idx == -1) {
		// find a free slot
		for (auto &c2 : conn2) {
		    if (!c2.used) {
			idx = int(&c2 - &conn2[0]),
			c2.from = from;
			c2.fromlen = fromlen;
			c2.tcp_active = true;
			c2.sock = -1;
			c2.is_udp = true;
			conn2_count++;
			max_conn2_count = MAX(max_conn2_count, conn2_count);
			c2.mav.init(p->sock2_udp, CHAN_COMM2(idx), true, false, false, p->port2);
			c2.mav.set_sendto(from, fromlen);
			c2.used = true;
			c2.last_pkt = now;
			c2.connected_at = time(nullptr);
			c2.rx_msgs = 0;
			c2.tx_msgs = 0;
			last_conn_save_s = 0;  // immediate snapshot
			printf("[%u] %s have UDP conn2[%u] from %s\n",
			       unsigned(p->port2), time_string(),
			       unsigned(idx+1),
			       addr_to_str(from));
			break;
		    }
		}
	    }

	    if (idx != -1) {
		mavlink_message_t msg {};
		if (have_conn1) {
		    uint8_t *buf0 = buf;
		    bool failed = false;
		    auto &c2 = conn2[idx];
		    while (n > 0 && c2.mav.receive_message(buf0, n, msg)) {
			c2.rx_msgs++;
			ensure_tlog_open();
			tlog_write_message(tlog_ptr(), msg);
			if (!mav1.send_message(msg)) {
			    failed = true;
			    break;
			}
			mav1_tx_msgs++;
		    }
		    if (failed) {
			break;
		    }
		}
	    }
	}

	/*
	  check for TCP user new connections
	 */
	if (!have_conn1 &&
	    p->sock1_tcp != -1 &&
	    FD_ISSET(p->sock1_tcp, &fds)) {
	    close_fd(p->sock1_udp);
	    struct sockaddr_in from;
	    socklen_t fromlen = sizeof(from);
	    int fd2 = accept(p->sock1_tcp, (struct sockaddr *)&from, &fromlen);
	    if (fd2 < 0) {
		break;
	    }
	    set_tcp_options(fd2);
	    set_nonblocking(fd2);
	    close(p->sock1_tcp);
	    p->sock1_tcp = fd2;
	    fdmax = MAX(fdmax, p->sock1_tcp);
	    have_conn1 = true;
	    mav1_peer = from;
	    mav1_connected_at = time(nullptr);
	    mav1_is_tcp = true;
	    last_conn_save_s = 0;  // immediate snapshot
	    printf("[%d] %s have TCP conn1 for from %s\n", unsigned(p->port2), time_string(), addr_to_str(from));
	    mav1.init(p->sock1_tcp, CHAN_COMM1, bidi, false, true, conn1_key_id);
	    last_pkt1 = now;
	    continue;
	}

	/*
	  check for TCP user data
	 */
	if (p->sock1_tcp != -1 &&
	    FD_ISSET(p->sock1_tcp, &fds)) {
	    close_fd(p->sock1_udp);

	    if (count1 == 0 && WebSocket::detect(p->sock1_tcp)) {
		p->ws = new WebSocket(p->sock1_tcp);
		if (p->ws == nullptr) {
		    break;
		}
		mav1.set_ws(p->ws);
		printf("[%d] %s WebSocket%s conn1\n", unsigned(p->port2), time_string(),
		       p->ws->is_SSL()?" SSL":"");
	    }
	    ssize_t n;
	    if (p->ws) {
		n = p->ws->recv(buf, sizeof(buf)-1);
	    } else {
		n = recv(p->sock1_tcp, buf, sizeof(buf)-1, 0);
	    }
	    if (p->ws) {
		    if (n < 0) { printf("[%d] %s EOF TCP conn1\n", unsigned(p->port2), time_string()); break; }
		    if (n == 0) { /* no complete frame yet */ ; }
		} else {
		    if (n <= 0) { printf("[%d] %s EOF TCP conn1\n", unsigned(p->port2), time_string()); break; }
		}
	    last_pkt1 = now;
            count1++;
	    mavlink_message_t msg {};
	    if (conn2_count > 0) {
		uint8_t *buf0 = buf;
		while (n > 0 && mav1.receive_message(buf0, n, msg)) {
		    mav1_rx_msgs++;
		    ensure_tlog_open();
		    tlog_write_message(tlog_ptr(), msg);
		    for (uint8_t i=0; i<max_conn2_count; i++) {
			auto &c2 = conn2[i];
			if (!c2.used) {
			    continue;
			}
			if (!c2.mav.send_message(msg)) {
			    c2.close();
			    if (conn2_count == max_conn2_count) {
				max_conn2_count--;
			    }
			    conn2_count--;
			} else {
			    c2.tx_msgs++;
			}
		    }
		}
	    }
	}

	/*
	  check for new TCP support engineer connection
	 */
	if (p->sock2_listen != -1 &&
	    FD_ISSET(p->sock2_listen, &fds)) {
	    struct sockaddr_in from;
	    socklen_t fromlen = sizeof(from);
	    int fd2 = accept(p->sock2_listen, (struct sockaddr *)&from, &fromlen);
	    if (fd2 < 0) {
		continue;
	    }
	    if (conn2_count >= MAX_COMM2_LINKS) {
		close(fd2);
		continue;
	    }

	    set_tcp_options(fd2);
	    set_nonblocking(fd2);

	    uint8_t i;
	    for (i=0; i<MAX_COMM2_LINKS; i++) {
		if (!conn2[i].used) {
		    break;
		}
	    }
	    if (i == MAX_COMM2_LINKS) {
		printf("[%d] %s too many TCP connections BUG: max %u\n", unsigned(p->port2), time_string(), unsigned(MAX_COMM2_LINKS));
		close(fd2);
		continue;
	    }
	    auto &c2 = conn2[i];
	    c2.sock = fd2;
	    c2.tcp_active = false;
	    c2.used = true;
	    c2.is_udp = false;
	    c2.from = from;
	    c2.fromlen = fromlen;
	    c2.connected_at = time(nullptr);
	    c2.rx_msgs = 0;
	    c2.tx_msgs = 0;
	    last_conn_save_s = 0;  // immediate snapshot
	    fdmax = MAX(fdmax, c2.sock);
	    printf("[%d] %s have TCP conn2[%u] for from %s\n", unsigned(p->port2), time_string(), unsigned(i+1), addr_to_str(from));
	    c2.mav.init(c2.sock, CHAN_COMM2(i), true, true, true, p->port2);
	    conn2_count++;
	    max_conn2_count = MAX(max_conn2_count, conn2_count);
	    continue;
	}

	/*
	  check for new TCP support engineer data
	 */
	for (uint8_t i=0; i<max_conn2_count; i++) {
	    auto &c2 = conn2[i];
	    if (c2.is_udp || !c2.used || c2.sock == -1) {
		continue;
	    }
	    if (FD_ISSET(c2.sock, &fds)) {
		if (!c2.tcp_active && WebSocket::detect(c2.sock)) {
		    c2.ws = new WebSocket(c2.sock);
		    if (c2.ws == nullptr) {
			break;
		    }
		    c2.mav.set_ws(c2.ws);
		    printf("[%d] %s WebSocket%s conn2\n", unsigned(p->port2), time_string(), c2.ws->is_SSL()?" SSL":"");
		}
		ssize_t n;
		if (c2.ws) {
		    n = c2.ws->recv(buf, sizeof(buf)-1);
		} else {
		    n = recv(c2.sock, buf, sizeof(buf)-1, 0);
		}
		if (c2.ws) {
		            if (n < 0) {
		                printf("[%d] %s EOF TCP conn2[%u]\n", unsigned(p->port2), time_string(), unsigned(i+1));
		                c2.close();
		                if (conn2_count == max_conn2_count) { max_conn2_count--; }
		                conn2_count--;
		                continue;
		            }
		            if (n == 0) {
		                // no complete frame yet
		                continue;
		            }
		        } else {
		            if (n <= 0) {
		                printf("[%d] %s EOF TCP conn2[%u]\n", unsigned(p->port2), time_string(), unsigned(i+1));
		                c2.close();
		                if (conn2_count == max_conn2_count) { max_conn2_count--; }
		                conn2_count--;
		                continue;
		            }
		        }
		buf[n] = 0;
		count2++;
		c2.tcp_active = true;
		mavlink_message_t msg {};
		if (have_conn1) {
		    uint8_t *buf0 = buf;
		    bool failed = false;
		    while (n > 0 && c2.mav.receive_message(buf0, n, msg)) {
			c2.rx_msgs++;
			ensure_tlog_open();
			tlog_write_message(tlog_ptr(), msg);
			if (!mav1.send_message(msg)) {
			    failed = true;
			    break;
			}
			mav1_tx_msgs++;
		    }
		    if (failed) {
			break;
		    }
		}
	    }
	}

	/*
	  Heartbeat snapshot of live connections to connections.tdb.
	  Throttled to 10s and forked into a grandchild so we don't
	  block main_loop on disk I/O. Same pattern as
	  save_signing_timestamp() in mavlink.cpp.
	 */
	{
	    double snap_now = time_seconds();
	    if (snap_now - last_conn_save_s > 10) {
		last_conn_save_s = snap_now;
		signal(SIGCHLD, SIG_IGN);
		if (fork() == 0) {
		    auto *db = conn_db_open_transaction();
		    if (db != nullptr) {
			conn_delete_for_port2(db, p->port2);
			time_t now_t = time(nullptr);
			if (have_conn1) {
			    struct ConnEntry e {};
			    e.magic = CONN_MAGIC;
			    e.connected_at = mav1_connected_at;
			    e.last_update = now_t;
			    e.port2 = p->port2;
			    e.conn_index = 0;
			    e.pid = my_pid;
			    e.rx_msgs = mav1_rx_msgs;
			    e.tx_msgs = mav1_tx_msgs;
			    e.peer_ip_be = mav1_peer.sin_addr.s_addr;
			    e.peer_port_be = mav1_peer.sin_port;
			    if (p->ws) {
				e.transport = p->ws->is_SSL() ? CONN_TRANSPORT_WSS : CONN_TRANSPORT_WS;
			    } else {
				e.transport = mav1_is_tcp ? CONN_TRANSPORT_TCP : CONN_TRANSPORT_UDP;
			    }
			    e.is_user = 1;
			    conn_write(db, e);
			}
			for (uint8_t i = 0; i < max_conn2_count; i++) {
			    const auto &c2 = conn2[i];
			    if (!c2.used) {
				continue;
			    }
			    struct ConnEntry e {};
			    e.magic = CONN_MAGIC;
			    e.connected_at = c2.connected_at;
			    e.last_update = now_t;
			    e.port2 = p->port2;
			    e.conn_index = i + 1;
			    e.pid = my_pid;
			    e.rx_msgs = c2.rx_msgs;
			    e.tx_msgs = c2.tx_msgs;
			    e.peer_ip_be = c2.from.sin_addr.s_addr;
			    e.peer_port_be = c2.from.sin_port;
			    if (c2.is_udp) {
				e.transport = CONN_TRANSPORT_UDP;
			    } else if (c2.ws) {
				e.transport = c2.ws->is_SSL() ? CONN_TRANSPORT_WSS : CONN_TRANSPORT_WS;
			    } else {
				e.transport = CONN_TRANSPORT_TCP;
			    }
			    e.is_user = 0;
			    conn_write(db, e);
			}
			conn_db_close_commit(db);
		    }
		    exit(0);
		}
	    }
	}
    }

    if (count1 != 0 || count2 != 0) {
        printf("[%d] %s Closed connection count1=%u count2=%u\n",
               p->port2,
               time_string(),
               unsigned(count1),
	       unsigned(count2));
        // update database
        auto *db = db_open_transaction();
        if (db != nullptr) {
            struct KeyEntry ke;
            if (db_load_key(db, p->port2, ke)) {
                ke.count1 += count1;
		ke.count2 += count2;
                ke.connections++;
                db_save_key(db, p->port2, ke);
                db_close_commit(db);
            } else {
                db_close_cancel(db);
            }
        }
    }
}

static void close_socket(int *s)
{
    if (*s != -1) {
	close(*s);
	*s = -1;
    }
}

/*
  close all sockets
 */
static void close_sockets(struct listen_port *p)
{
    close_socket(&p->sock1_udp);
    close_socket(&p->sock2_udp);
    close_socket(&p->sock1_tcp);
    close_socket(&p->sock2_listen);
}

/*
  open one socket pair
 */
static void open_sockets(struct listen_port *p)
{
    if (p->sock1_udp == -1) {
	p->sock1_udp = open_socket_in_udp(p->port1);
	if (p->sock1_udp == -1) {
	    printf("[%d] Failed to open UDP port %d - %s\n", p->port2, p->port1, strerror(errno));
	}
    }
    if (p->sock2_udp == -1) {
	p->sock2_udp = open_socket_in_udp(p->port2);
	if (p->sock2_udp == -1) {
	    printf("[%d] Failed to open UDP port %d - %s\n", p->port2, p->port2, strerror(errno));
	}
    }
    if (p->sock1_tcp == -1) {
	p->sock1_tcp = open_socket_in_tcp(p->port1);
	if (p->sock1_tcp == -1) {
	    printf("[%d] Failed to open TCP port %d - %s\n", p->port2, p->port1, strerror(errno));
	}
    }
    if (p->sock2_listen == -1) {
	p->sock2_listen = open_socket_in_tcp(p->port2);
	if (p->sock2_listen == -1) {
	    printf("[%d] Failed to open TCP port %d - %s\n", p->port2, p->port2, strerror(errno));
	}
    }
}

/*
  check for child exit
 */
static void check_children(void)
{
    int wstatus = 0;
    while (true) {
        pid_t pid = waitpid(-1, &wstatus, WNOHANG);
        if (pid <= 0) {
            break;
        }
        if (pid == cleanup_child_pid) {
            printf("tlog cleanup child %d exited; respawning\n", int(pid));
            cleanup_child_pid = 0;
            fork_cleanup_child();
            continue;
        }
        bool found_child = false;
        for (auto *p = ports; p; p=p->next) {
            if (p->pid == pid) {
                printf("[%d] Child %d exited\n", p->port2, int(pid));
                p->pid = 0;
		// drop any live-connection records the child wrote
		conn_remove_port2(p->port2);
		found_child = true;
		// Don't reopen listening sockets for an entry that was
		// removed from keys.tdb between fork and exit; that would
		// rebind the port for a record that no longer exists.
		if (!p->removed) {
			open_sockets(p);
		}
                break;
            }
        }
        if (!found_child) {
            printf("No child for %d found\n", int(pid));
        }
    }
}

/*
  fork the long-lived cleanup child once. The child closes all listening
  sockets it inherited from the parent (so it doesn't keep the ports
  bound), then runs tlog_cleanup_loop forever.
 */
static void fork_cleanup_child(void)
{
    pid_t pid = fork();
    if (pid == 0) {
        for (auto *p = ports; p; p = p->next) {
            close_sockets(p);
        }
        tlog_cleanup_loop();
        _exit(0);
    }
    if (pid < 0) {
        perror("fork(cleanup)");
        return;
    }
    cleanup_child_pid = pid;
    printf("tlog cleanup child %d started\n", int(pid));
}

/*
  handle a new connection
 */
static void handle_connection(struct listen_port *p)
{
    pid_t pid = fork();
    if (pid == 0) {
	for (auto *p2 = ports; p2; p2=p2->next) {
	    if (p2 != p) {
		close_sockets(p2);
	    }
	}
	main_loop(p);
	exit(0);
    }
    p->pid = pid;
    printf("[%d] New child %d\n", p->port2, int(p->pid));

    close_sockets(p);
}

static void reload_ports(void)
{
    // mark every port pair we know about as "unseen". upsert_port()
    // will set seen=true for any port2 it finds in the DB; entries
    // still unseen after the traverse are gone from keys.tdb and
    // need to be torn down.
    for (auto *p = ports; p; p = p->next) {
        p->seen = false;
    }

    // wrap the traversal in a transaction so we see a consistent snapshot
    // even if keydb.py / the web admin UI is mutating in parallel
    auto *db = db_open_transaction();
    if (db == nullptr) {
        printf("Database not found\n");
        exit(1);
    }
    tdb_traverse(db, handle_record, nullptr);
    db_close_cancel(db);

    // any port pair not seen during the traverse has been removed from
    // keys.tdb. Close listening sockets, signal the running child to
    // exit so any active conn1/conn2 dies, and mark the struct removed
    // so we don't reopen sockets when the child exits.
    for (auto *p = ports; p; p = p->next) {
        if (!p->seen && !p->removed) {
            printf("[%d] removed from keys.tdb\n", p->port2);
            p->removed = true;
            close_sockets(p);
            if (p->pid != 0) {
                kill(p->pid, SIGTERM);
            }
            conn_remove_port2(p->port2);
        }
    }

    // see if any sockets need opening
    for (auto *p = ports; p; p=p->next) {
	if (p->pid == 0 && !p->removed) {
	    open_sockets(p);
	}
    }
}

/*
  wait for incoming connections
 */
static void wait_connection(void)
{
    int epfd = epoll_create1(0);
    if (epfd == -1) {
        perror("epoll_create1");
        exit(1);
    }

    /*
      rebuild epoll structure for current list of connections
     */
    auto rebuild_epoll_set = [&]() {
        epoll_ctl(epfd, EPOLL_CTL_DEL, -1, nullptr); // dummy cleanup if needed
        for (auto *p = ports; p; p = p->next) {
            if (p->pid != 0 || p->removed) continue;

            struct epoll_event ev = {};
            ev.events = EPOLLIN;
            ev.data.ptr = p;

            if (p->sock1_udp != -1) {
                ev.data.fd = p->sock1_udp;
                epoll_ctl(epfd, EPOLL_CTL_ADD, p->sock1_udp, &ev);
            }
            if (p->sock2_udp != -1) {
                ev.data.fd = p->sock2_udp;
                epoll_ctl(epfd, EPOLL_CTL_ADD, p->sock2_udp, &ev);
            }
            if (p->sock1_tcp != -1) {
                ev.data.fd = p->sock1_tcp;
                epoll_ctl(epfd, EPOLL_CTL_ADD, p->sock1_tcp, &ev);
            }
            if (p->sock2_listen != -1) {
                ev.data.fd = p->sock2_listen;
                epoll_ctl(epfd, EPOLL_CTL_ADD, p->sock2_listen, &ev);
            }
        }
    };

    rebuild_epoll_set();

    double last_reload = time_seconds();
    struct epoll_event events[MAX_EPOLL_EVENTS];

    while (true) {
	int ret = epoll_wait(epfd, events, MAX_EPOLL_EVENTS, 1000); // 1 second timeout

        if (ret == -1) {
            if (errno == EINTR) continue;
            perror("epoll_wait");
            break;
        }

        if (ret == 0) {
            check_children();
            double now = time_seconds();
            if (now - last_reload > 5) {
                last_reload = now;
                reload_ports();
                close(epfd);
                epfd = epoll_create1(0);
                rebuild_epoll_set();
            }
            continue;
        }

        for (int i = 0; i < ret; i++) {
            int fd = events[i].data.fd;

            for (auto *p = ports; p; p = p->next) {
                if (p->pid != 0 || p->removed) continue;
                if ((p->sock1_udp == fd || p->sock2_udp == fd ||
                     p->sock1_tcp == fd || p->sock2_listen == fd)) {
                    handle_connection(p);
                    break;
                }
            }
        }
    }
    close(epfd);
}

int main(int argc, char *argv[])
{
    setvbuf(stdout, nullptr, _IOLBF, 4096);
    printf("Opening sockets\n");
    // Wipe any connections.tdb records left behind by a previous run.
    // Per-port-pair children write into this file; on a fresh start no
    // record can be live yet. Doing this in the parent before any fork
    // means we never race with a live writer.
    conn_recreate_empty();
    auto *db = db_open_transaction();
    if (db == nullptr) {
        printf("Database not found\n");
        exit(1);
    }
    tdb_traverse(db, handle_record, nullptr);
    printf("Added %u ports\n", unsigned(count_ports()));
    db_close_cancel(db);

    fork_cleanup_child();

    wait_connection();

    return 0;
}
