#include <stdio.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <stddef.h>
#include <poll.h>
#include <sys/fcntl.h>

#ifdef __linux__
#include <linux/sockios.h>   // SIOCOUTQ
#endif

double time_seconds(void)
{
    struct timeval tval;
    gettimeofday(&tval,NULL);
    return tval.tv_sec + (tval.tv_usec*1.0e-6);
}

/*
  open a UDP socket on the given port
*/
int open_socket_in_udp(int port)
{
    struct sockaddr_in sock;
    int res;
    int one=1;

    memset(&sock,0,sizeof(sock));

#ifdef HAVE_SOCK_SIN_LEN
    sock.sin_len = sizeof(sock);
#endif
    sock.sin_port = htons(port);
    sock.sin_family = AF_INET;

    res = socket(AF_INET, SOCK_DGRAM, 0);
    if (res == -1) { 
        fprintf(stderr, "socket failed\n"); return -1; 
        return -1;
    }

    setsockopt(res,SOL_SOCKET,SO_REUSEADDR,(char *)&one,sizeof(one));

    if (bind(res, (struct sockaddr *)&sock, sizeof(sock)) < 0) { 
        return(-1); 
    }

    return res;
}

/*
  setup TCP options for a socket
*/
void set_tcp_options(int fd)
{
    int one=1;
    setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,(char *)&one,sizeof(one));
    setsockopt(fd, SOL_TCP, TCP_NODELAY, &one, sizeof(one));
}

/*
  open a TCP socket on the given port
*/
int open_socket_in_tcp(int port)
{
    struct sockaddr_in sock;
    int res;

    memset(&sock,0,sizeof(sock));

#ifdef HAVE_SOCK_SIN_LEN
    sock.sin_len = sizeof(sock);
#endif
    sock.sin_port = htons(port);
    sock.sin_family = AF_INET;

    res = socket(AF_INET, SOCK_STREAM, 0);
    if (res == -1) { 
        fprintf(stderr, "socket failed\n"); return -1; 
        return -1;
    }

    set_tcp_options(res);

    if (bind(res, (struct sockaddr *)&sock, sizeof(sock)) < 0) {
        return(-1); 
    }

    if (listen(res, 100) != 0) {
	return(-1);
    }

    set_tcp_options(res);

    return res;
}

/*
  convert address to string, uses a static return buffer
 */
const char *addr_to_str(struct sockaddr_in &addr)
{
    static char str[INET_ADDRSTRLEN+1];
    inet_ntop(AF_INET, &addr.sin_addr, str, INET_ADDRSTRLEN);
    return str;
}

/*
  return time as a string, using a static buffer
 */
const char *time_string(void)
{
    time_t t = time(nullptr);
    struct tm *tm = localtime(&t);
    static char str[100] {};
    strftime(str, sizeof(str)-1, "%F %T", tm);
    return str;
}

/*
  Returns the number of bytes that can be written to fd without blocking.
  On error returns -1 and sets errno.
*/
ssize_t tcp_writable_bytes(int fd)
{
    int outq = 0;             // bytes currently queued in the send buffer
#if defined(SIOCOUTQ)
    if (ioctl(fd, SIOCOUTQ, &outq) == -1) {
        return -1;
    }
#else
# error "SIOCOUTQ not available on this platform"
#endif

    int sndbuf = 0;           // total size of the send buffer
    socklen_t optlen = sizeof(sndbuf);
    if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, &optlen) == -1) {
        return -1;
    }

    // Linux returns the kernel's accounting size for SO_SNDBUF (often doubled).
    // The available space is the remainder; clamp at 0.
    ssize_t avail = (ssize_t)sndbuf - (ssize_t)outq;
    if (avail < 0) avail = 0;
    return avail;
}

/*
  return true if a TCP socket is dead
*/
bool socket_is_dead(int fd)
{
    // Verify it's a stream socket (TCP).
    int type = 0;
    socklen_t tlen = sizeof(type);
    if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &tlen) == -1) {
	return true;
    }
    if (type != SOCK_STREAM) {
	return true;
    }

    // Quick, non-blocking health probe.
    struct pollfd pfd {};
    pfd.fd = fd;
    pfd.events = POLLOUT | POLLERR | POLLHUP | POLLNVAL;
    int pr = poll(&pfd, 1, 0);
    if (pr < 0) {
	return true;
    }
    if (pr == 1 && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
	return true;
    }

    // Check for a queued asynchronous error even if poll() looked fine.
    // (This also catches connect() failures on nonblocking sockets.)
    int soerr = 0; socklen_t slen = sizeof(soerr);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) == 0 && soerr != 0) {
	return true;
    }

#ifdef TCP_INFO
    // Inspect TCP state. Consider only states that are writable as "alive".
    struct tcp_info ti;
    socklen_t tilen = sizeof(ti);
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &tilen) == 0) {
        // Writable in practice: ESTABLISHED, and often CLOSE_WAIT (peer sent FIN, but we can still write).
        if (ti.tcpi_state != TCP_ESTABLISHED && ti.tcpi_state != TCP_CLOSE_WAIT) {
	    return true;
        }
    }
#endif

    // looks healthy for writing
    return false;
}

void set_nonblocking(int fd)
{
    unsigned v = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, v | O_NONBLOCK);
}
