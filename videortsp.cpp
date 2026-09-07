/*
  RTSP ingest by splicing to a loopback ffmpeg. See videortsp.h.
 */
#include "videortsp.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

RtspBackend::~RtspBackend(void)
{
    stop();
}

int RtspBackend::pick_loopback_port(int socktype)
{
    const int s = socket(AF_INET, socktype, 0);
    if (s < 0) {
        return -1;
    }
    struct sockaddr_in a {};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(s, (struct sockaddr *)&a, sizeof(a)) != 0) {
        ::close(s);
        return -1;
    }
    socklen_t alen = sizeof(a);
    if (getsockname(s, (struct sockaddr *)&a, &alen) != 0) {
        ::close(s);
        return -1;
    }
    const int port = ntohs(a.sin_port);
    ::close(s);
    return port;
}

// Is 127.0.0.1:port bound by a UDP socket? Linux-only, like the rest.
bool RtspBackend::loopback_udp_bound(int port)
{
    FILE *f = fopen("/proc/net/udp", "r");
    if (f == nullptr) {
        return false;
    }
    char want[32];
    snprintf(want, sizeof(want), " 0100007F:%04X ", port);
    char line[512];
    bool found = false;
    while (!found && fgets(line, sizeof(line), f) != nullptr) {
        found = strstr(line, want) != nullptr;
    }
    fclose(f);
    return found;
}

const char *splice_proto_name(splice_proto_t p)
{
    switch (p) {
    case SPLICE_RTMP: return "RTMP";
    case SPLICE_RTP:  return "RTP";
    default:          return "RTSP";
    }
}

bool RtspBackend::start(int port2, int slot, bool want_audio,
                        splice_proto_t proto, const char *vbsf,
                        const char *rtp_codec, int rtp_pt)
{
    port2_ = port2;
    slot_ = slot;
    proto_ = proto;

    // RTSP splices into a loopback listener; RTMP is fed FLV on stdin;
    // RTP is forwarded to a loopback UDP port named in an SDP on stdin.
    int lport = 0;
    if (proto == SPLICE_RTSP || proto == SPLICE_RTP) {
        lport = pick_loopback_port(proto == SPLICE_RTP ? SOCK_DGRAM
                                                       : SOCK_STREAM);
        if (lport <= 0) {
            printf("[%d] video slot %d: no loopback port for the %s "
                   "backend\n", port2_, slot_, splice_proto_name(proto));
            return false;
        }
    }
    char sdp[256] = "";
    if (proto == SPLICE_RTP) {
        if (rtp_codec == nullptr) {
            return false;
        }
        snprintf(sdp, sizeof(sdp),
                 "v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=SupportProxy\r\n"
                 "c=IN IP4 127.0.0.1\r\nt=0 0\r\n"
                 "m=video %d RTP/AVP %d\r\na=rtpmap:%d %s/90000\r\n",
                 lport, rtp_pt, rtp_pt, rtp_codec);
    }

    int media[2] = { -1, -1 };
    if (pipe(media) != 0) {
        printf("[%d] video slot %d: pipe failed - %s\n",
               port2_, slot_, strerror(errno));
        return false;
    }
    /*
      A socketpair rather than a pipe: the caller pushes FLV through the
      same queue it uses for the RTSP splice, and that writes with
      send(MSG_NOSIGNAL), which fails ENOTSOCK on a pipe. The child sees
      it as fd 0 either way.
     */
    int feed[2] = { -1, -1 };
    if (proto == SPLICE_RTMP
        && socketpair(AF_UNIX, SOCK_STREAM, 0, feed) != 0) {
        ::close(media[0]);
        ::close(media[1]);
        printf("[%d] video slot %d: socketpair failed - %s\n",
               port2_, slot_, strerror(errno));
        return false;
    }
    // The SDP is a few lines: a pipe holds it whole, and closing our
    // end after writing is the EOF the sdp demuxer reads up to.
    if (proto == SPLICE_RTP && pipe(feed) != 0) {
        ::close(media[0]);
        ::close(media[1]);
        printf("[%d] video slot %d: pipe failed - %s\n",
               port2_, slot_, strerror(errno));
        return false;
    }

    char url[128];
    if (proto == SPLICE_RTMP || proto == SPLICE_RTP) {
        snprintf(url, sizeof(url), "pipe:0");
    } else {
        snprintf(url, sizeof(url), "rtsp://127.0.0.1:%d/", lport);
    }

    const pid_t pid = fork();
    if (pid < 0) {
        ::close(media[0]);
        ::close(media[1]);
        if (feed[0] >= 0) {
            ::close(feed[0]);
            ::close(feed[1]);
        }
        printf("[%d] video slot %d: fork failed - %s\n",
               port2_, slot_, strerror(errno));
        return false;
    }
    if (pid == 0) {
        // die with us rather than lingering on a crash
        prctl(PR_SET_PDEATHSIG, SIGTERM);
        if (getppid() == 1) {
            _exit(0);
        }
        /*
          The backend parses SDP, RTP and codec bitstreams from a peer
          we have only address-authorised. Fixed argv stops shell
          injection; these stop a parser bug from becoming worse.
         */
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        struct rlimit rl {};
        rl.rlim_cur = rl.rlim_max = RTSP_BACKEND_MEM_BYTES;
        setrlimit(RLIMIT_AS, &rl);
        rl.rlim_cur = rl.rlim_max = RTSP_BACKEND_CPU_SECONDS;
        setrlimit(RLIMIT_CPU, &rl);
        /*
          Deliberately no RLIMIT_NPROC. It bounds processes and threads
          per *UID*, not per process, so a small value is instantly
          exceeded by whatever else the account is already running --
          ffmpeg then fails at pthread_create and produces no output at
          all. It is the wrong tool for sandboxing one child.
         */

        /*
          Unchecked, a failed dup2 would leave the child running with
          our stdout -- writing MPEG-TS into the proxy's log. Die
          instead; the parent sees the exit and reports it.
         */
        ::close(media[0]);
        if (dup2(media[1], STDOUT_FILENO) == -1) {
            _exit(126);
        }
        ::close(media[1]);
        if (proto == SPLICE_RTMP || proto == SPLICE_RTP) {
            ::close(feed[1]);
            if (dup2(feed[0], STDIN_FILENO) == -1) {
                _exit(126);
            }
            ::close(feed[0]);
        } else {
            const int devnull = open("/dev/null", O_RDONLY);
            if (devnull >= 0) {
                if (dup2(devnull, STDIN_FILENO) == -1) {
                    _exit(126);
                }
                ::close(devnull);
            }
        }

        /*
          Drop every other inherited descriptor.

          Without this the backend keeps the accepted publisher socket
          open -- visible in ss as ffmpeg and supportproxy both holding
          the same public connection. The damage is not the leak itself
          but that the socket never fully closes, so ffmpeg never sees
          the end of its input, never exits, and running() stays true --
          which refuses every later publisher on that slot as slot-busy
          until the child is killed by hand.
         */
#ifdef SYS_close_range
        if (syscall(SYS_close_range, 3, ~0U, 0) != 0)
#endif
        {
            /*
              Close up to the real limit, not 4096. The old bound only
              applied when RLIMIT_NOFILE was under 65536, so on a host
              with a high limit every descriptor above 4095 survived --
              which is the case this loop exists to cover.
             */
            struct rlimit nof {};
            long maxfd = 4096;
            if (getrlimit(RLIMIT_NOFILE, &nof) == 0
                && nof.rlim_cur != RLIM_INFINITY) {
                maxfd = long(nof.rlim_cur);
            } else {
                const long n = sysconf(_SC_OPEN_MAX);
                maxfd = (n > 0) ? n : 65536;
            }
            for (int f = 3; f < maxfd; f++) {
                ::close(f);
            }
        }

        /*
          -an by default: audio is rarely useful from an aircraft, and
          dropping it keeps the muxed stream video-only. With audio on,
          it must be re-encoded -- pcm_s16be cannot be carried in
          MPEG-TS at all (ffmpeg emits it as private data that probes
          back as bin_data), so "copy" would silently destroy it.
         */
        const char *audio1 = want_audio ? "-c:a" : "-an";
        const char *audio2 = want_audio ? "aac" : nullptr;

        const char *argv[40];
        int n = 0;
        argv[n++] = "ffmpeg";
        argv[n++] = "-hide_banner";
        argv[n++] = "-nostdin";
        argv[n++] = "-loglevel";
        argv[n++] = "warning";
        if (proto == SPLICE_RTMP) {
            // live_flv rather than flv: the stream never ends, and the
            // plain flv demuxer waits for a file it will never see.
            // No -timeout: that is a socket option, and this is a pipe.
            argv[n++] = "-protocol_whitelist";
            argv[n++] = "file,pipe";
            argv[n++] = "-f";
            argv[n++] = "live_flv";
        } else if (proto == SPLICE_RTP) {
            /*
              max_delay bounds how long the RTP demuxer holds later
              packets waiting for a lost one before giving up on it;
              the default is 0.5 s of stall per loss. We forward in
              arrival order, so there is nothing to wait for.
             */
            argv[n++] = "-protocol_whitelist";
            argv[n++] = "file,pipe,rtp,udp";
            argv[n++] = "-max_delay";
            argv[n++] = "100000";
            // Without this the sdp demuxer binds 0.0.0.0, and the
            // ephemeral port is then reachable from the internet with
            // no admission check at all.
            argv[n++] = "-localaddr";
            argv[n++] = "127.0.0.1";
            argv[n++] = "-f";
            argv[n++] = "sdp";
        } else {
            argv[n++] = "-protocol_whitelist";
            argv[n++] = "file,rtp,udp,tcp";
            argv[n++] = "-rtsp_flags";
            argv[n++] = "listen";
            argv[n++] = "-rtsp_transport";
            argv[n++] = "tcp";
            argv[n++] = "-timeout";
            argv[n++] = "10000000";
        }
        argv[n++] = "-i";
        argv[n++] = url;
        /*
          Map the streams we can actually carry, not everything.

          "-map 0" took whatever the publisher offered, and a stream
          MPEG-TS has no encoder for kills the whole output: ffmpeg
          fails with "Error selecting an encoder" before writing a byte,
          so the slot sits at 0 KiB with the backend apparently running.

          gstreamer walks straight into this. flvmux re-sends
          onMetaData throughout the stream rather than once at the head,
          and ffmpeg's FLV demuxer surfaces that as a second, data
          stream -- so the stock gst-launch RTMP pipeline never
          produced a frame here, while ffmpeg publishing the same video
          worked, because its own FLV carries no such stream.

          "0:a?" is optional: no audio track is not an error.
         */
        argv[n++] = "-map";
        argv[n++] = "0:v:0";
        if (want_audio) {
            argv[n++] = "-map";
            argv[n++] = "0:a?";
        }
        argv[n++] = "-c:v";
        argv[n++] = "copy";
        if (vbsf != nullptr && vbsf[0] != '\0') {
            argv[n++] = "-bsf:v";
            argv[n++] = vbsf;
        }
        argv[n++] = audio1;
        if (audio2 != nullptr) {
            argv[n++] = audio2;
        }
        /*
          Live output, so do not let the muxer sit on data. The default
          32 KiB AVIO buffer is most of a second at this camera's ~0.4
          Mbit/s, and muxdelay/muxpreload add their own offset on top.
          Measured as part of the join-to-live delay.
         */
        argv[n++] = "-muxdelay";
        argv[n++] = "0";
        argv[n++] = "-muxpreload";
        argv[n++] = "0";
        argv[n++] = "-flush_packets";
        argv[n++] = "1";
        argv[n++] = "-f";
        argv[n++] = "mpegts";
        argv[n++] = "pipe:1";
        argv[n] = nullptr;

        execvp("ffmpeg", const_cast<char *const *>(argv));
        // Only reached if ffmpeg is missing.
        _exit(127);
    }

    ::close(media[1]);
    pid_ = pid;
    media_fd_ = media[0];
    fcntl(media_fd_, F_SETFL, fcntl(media_fd_, F_GETFL, 0) | O_NONBLOCK);

    if (proto == SPLICE_RTMP) {
        ::close(feed[0]);
        backend_fd_ = feed[1];
        fcntl(backend_fd_, F_SETFL,
              fcntl(backend_fd_, F_GETFL, 0) | O_NONBLOCK);
        printf("[%d] video slot %d RTMP backend pid %d (FLV on stdin, "
               "bsf %s)\n", port2_, slot_, int(pid_),
               (vbsf != nullptr && vbsf[0] != '\0') ? vbsf : "none");
        return true;
    }
    if (proto == SPLICE_RTP) {
        ::close(feed[0]);
        const size_t len = strlen(sdp);
        const ssize_t w = ::write(feed[1], sdp, len);
        ::close(feed[1]);
        rtp_fd_ = socket(AF_INET, SOCK_DGRAM, 0);
        if (w != ssize_t(len) || rtp_fd_ < 0) {
            printf("[%d] video slot %d: RTP backend setup failed - %s\n",
                   port2_, slot_, strerror(errno));
            stop();
            return false;
        }
        fcntl(rtp_fd_, F_SETFL, fcntl(rtp_fd_, F_GETFL, 0) | O_NONBLOCK);
        rtp_dst_ = {};
        rtp_dst_.sin_family = AF_INET;
        rtp_dst_.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        rtp_dst_.sin_port = htons(uint16_t(lport));
        /*
          Wait for the bind, as the RTSP path waits for its listener:
          datagrams sent before it are lost, and a sender that puts its
          parameter sets only at the start would never decode. The
          public socket queues what arrives meanwhile.
         */
        const int step_ms = 20;
        int waited = 0;
        for (; waited < RTSP_BACKEND_READY_MS; waited += step_ms) {
            if (loopback_udp_bound(lport)) {
                break;
            }
            struct timespec ts { 0, step_ms * 1000000L };
            nanosleep(&ts, nullptr);
        }
        printf("[%d] video slot %d RTP/%s backend pid %d on "
               "127.0.0.1:%d (pt %d)%s\n", port2_, slot_, rtp_codec,
               int(pid_), lport, rtp_pt,
               waited >= RTSP_BACKEND_READY_MS ? " -- not bound yet" : "");
        return true;
    }

    // Retry-connect until the backend's listener is up. It bound the
    // port after we picked it, so a short race is expected.
    const int step_ms = 20;
    for (int waited = 0; waited < RTSP_BACKEND_READY_MS; waited += step_ms) {
        const int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) {
            break;
        }
        struct sockaddr_in a {};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = htons(uint16_t(lport));
        if (connect(s, (struct sockaddr *)&a, sizeof(a)) == 0) {
            int one = 1;
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK);
            backend_fd_ = s;
            printf("[%d] video slot %d RTSP backend pid %d on 127.0.0.1:%d\n",
                   port2_, slot_, int(pid_), lport);
            return true;
        }
        ::close(s);
        if (reap()) {
            printf("[%d] video slot %d: RTSP backend exited before it "
                   "listened (is ffmpeg installed?)\n", port2_, slot_);
            stop();
            return false;
        }
        struct timespec ts { 0, step_ms * 1000000L };
        nanosleep(&ts, nullptr);
    }
    printf("[%d] video slot %d: RTSP backend never became connectable\n",
           port2_, slot_);
    stop();
    return false;
}

bool RtspBackend::reap(void)
{
    if (pid_ <= 0) {
        return true;
    }
    int status = 0;
    const pid_t r = waitpid(pid_, &status, WNOHANG);
    if (r == pid_) {
        if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
            printf("[%d] video slot %d: ffmpeg not found; RTSP ingest needs "
                   "it installed\n", port2_, slot_);
        }
        pid_ = -1;
        return true;
    }
    if (r < 0 && errno == ECHILD) {
        pid_ = -1;
        return true;
    }
    return false;
}

bool RtspBackend::send_rtp(const uint8_t *buf, size_t n)
{
    if (rtp_fd_ < 0) {
        return false;
    }
    // Datagrams before ffmpeg has bound its port are simply lost, as
    // they would be on any UDP path; the sender's next IDR recovers.
    const ssize_t w = ::sendto(rtp_fd_, buf, n, MSG_DONTWAIT,
                               (const struct sockaddr *)&rtp_dst_,
                               sizeof(rtp_dst_));
    return w == ssize_t(n);
}

void RtspBackend::stop(void)
{
    if (backend_fd_ >= 0) {
        ::close(backend_fd_);
        backend_fd_ = -1;
    }
    if (rtp_fd_ >= 0) {
        ::close(rtp_fd_);
        rtp_fd_ = -1;
    }
    if (media_fd_ >= 0) {
        ::close(media_fd_);
        media_fd_ = -1;
    }
    if (pid_ > 0) {
        kill(pid_, SIGTERM);
        // Give it a moment to go on its own, then insist.
        for (int i = 0; i < 50; i++) {
            if (reap()) {
                return;
            }
            struct timespec ts { 0, 10 * 1000000L };
            nanosleep(&ts, nullptr);
        }
        kill(pid_, SIGKILL);
        int status = 0;
        waitpid(pid_, &status, 0);
        pid_ = -1;
    }
}
