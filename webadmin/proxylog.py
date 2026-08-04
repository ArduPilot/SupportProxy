"""The daemon's own activity log, and control over the daemon itself.

Distinct from logs.py, which serves per-entry session recordings. This
is proxy.log -- what the running daemon prints -- plus the restart
control, both admin-only.

Restart works by signalling rather than by systemctl. supportproxy.service
sets Restart=always and runs as the same user as this process, so a
SIGTERM to the parent is enough: systemd respawns it. That needs no sudo
and no privileged helper, and it degrades honestly without systemd --
the daemon stops and the caller is told which pid was signalled.
"""
import hashlib
import os
import re
import signal
import subprocess

SUPPORTPROXY_COMM = 'supportproxy'

# How much of the tail to show on first load. Rotation bounds the file,
# but it can still be large between rotations, so never read it whole.
INITIAL_TAIL_BYTES = 64 * 1024

# Ceiling on one incremental fetch, so a burst cannot make a single
# response enormous.
MAX_CHUNK_BYTES = 256 * 1024

# Belt and braces. The daemon redacts credentials before it writes them
# (http_redact_target), which is what keeps them off disk; this catches
# anything already in an older log, and any path that forgets to.
#
# Matches the value of a credential query parameter up to the next
# delimiter rather than a token's exact shape: the previous pattern
# wanted lowercase hex after a literal dot, so an uppercase HMAC or a
# %2E-encoded dot slipped straight through, and it knew nothing about
# ?pw= at all.
_SECRET_RE = re.compile(r'([?&](?:pw|password|t|key)=)[^&\s"\']+',
                        re.IGNORECASE)


def redact(text):
    return _SECRET_RE.sub(r'\1<redacted>', text)


def log_path(app):
    """Absolute path of the daemon log.

    Defaults beside keys.tdb: the daemon's working directory is where it
    writes both, and the web admin is started from the same place.
    """
    configured = app.config.get('PROXY_LOG_PATH')
    if configured:
        return configured
    return os.path.join(os.path.dirname(
        os.path.abspath(app.config['KEYDB_PATH'])), 'proxy.log')


def _head_tag(path, n=256):
    """A short digest of the file's first bytes.

    Cheap, and it changes whenever the log is truncated or replaced --
    the two things an offset cannot survive.
    """
    try:
        with open(path, 'rb') as f:
            head = f.read(n)
    except OSError:
        return ''
    return hashlib.sha256(head).hexdigest()[:16]


def read_since(path, offset, ident=None):
    """Return (text, next_offset, restarted, ident).

    `restarted` says the caller's offset no longer refers to the same
    content -- rotated, truncated or replaced under it -- so the view
    should replace what it has rather than append to it.

    `ident` is an opaque tag the caller passes back, covering both the
    inode and a fingerprint of the file's first bytes.

    Size alone is not enough: with copytruncate the log can be truncated
    and grow past the old offset between two polls, and a size check
    then seeks straight into the new generation, skipping its start and
    reporting nothing unusual. Nor is the inode enough on its own --
    copytruncate keeps it by design, and a rename-and-create rotation
    can be handed the freed inode straight back. What does change either
    way is the start of the file, so that is what is fingerprinted.
    """
    try:
        st = os.stat(path)
    except OSError:
        return ('', 0, False, None)
    size = st.st_size
    now_ident = '%d:%d:%s' % (st.st_dev, st.st_ino, _head_tag(path))

    restarted = False
    if ident is not None and ident != now_ident:
        # Replaced outright (rename-and-create rotation).
        offset = None
    if offset is None or offset < 0 or offset > size:
        # First load, or the file shrank: show the tail.
        offset = max(0, size - INITIAL_TAIL_BYTES)
        restarted = True

    if size - offset > MAX_CHUNK_BYTES:
        # Fell too far behind to catch up in one response; skip ahead
        # rather than serve a huge body, and say the view is not
        # contiguous with what it had.
        offset = size - MAX_CHUNK_BYTES
        restarted = True

    try:
        with open(path, 'rb') as f:
            f.seek(offset)
            data = f.read(MAX_CHUNK_BYTES)
    except OSError:
        return ('', offset, restarted, now_ident)

    next_offset = offset + len(data)
    text = data.decode('utf-8', 'replace')
    if restarted and offset > 0:
        # A tail taken mid-file almost never starts on a line boundary.
        # Only mid-file: from the start there is no partial line, and
        # stripping there threw away the log's first line.
        nl = text.find('\n')
        if nl >= 0:
            text = text[nl + 1:]
    return (redact(text), next_offset, restarted, now_ident)


def _comm(pid):
    try:
        with open('/proc/%d/comm' % pid) as f:
            return f.read().strip()
    except OSError:
        return None


def _ppid(pid):
    try:
        with open('/proc/%d/status' % pid) as f:
            for line in f:
                if line.startswith('PPid:'):
                    return int(line.split()[1])
    except (OSError, ValueError):
        pass
    return None


def _cwd(pid):
    try:
        return os.readlink('/proc/%d/cwd' % pid)
    except OSError:
        return None


def _systemd_main_pid(unit='supportproxy'):
    """The unit's MainPID, or None if systemd cannot tell us.

    Authoritative when it answers: it names the process systemd will
    restart, which is exactly the one worth signalling.
    """
    try:
        out = subprocess.run(
            ['systemctl', 'show', '-p', 'MainPID', '--value', unit],
            capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.SubprocessError):
        return None
    try:
        pid = int(out.stdout.strip())
    except ValueError:
        return None
    return pid if pid > 0 else None


def find_daemon(workdir=None):
    """The pid of the daemon this web admin belongs to, or None.

    Identity matters here: min(pid) over every process named
    supportproxy will happily pick a staging instance, or a session
    child that was reparented when its own parent died, and the restart
    then hits the wrong thing. So:

      1. Ask systemd, which knows which process it supervises.
      2. Otherwise require the same working directory as this web admin
         -- the daemon writes keys.tdb there, and that is the one thing
         tying a process to this configuration -- and that its parent is
         not itself supportproxy, which excludes the session children.
    """
    pid = _systemd_main_pid()
    if pid is not None and _comm(pid) == SUPPORTPROXY_COMM:
        return pid

    if workdir is None:
        workdir = os.getcwd()
    try:
        workdir = os.path.realpath(workdir)
    except OSError:
        pass

    best = None
    for name in os.listdir('/proc'):
        if not name.isdigit():
            continue
        p = int(name)
        if _comm(p) != SUPPORTPROXY_COMM:
            continue
        if _comm(_ppid(p) or 0) == SUPPORTPROXY_COMM:
            continue            # a session or video child
        if _cwd(p) != workdir:
            continue            # another instance entirely
        if best is None or p < best:
            best = p
    return best


def restart_daemon(workdir=None):
    """SIGTERM the daemon so its supervisor respawns it.

    Returns (pid, error). A caller that gets a pid should not assume the
    daemon is back: that is up to the supervisor, and RestartSec delays
    it.

    Signalled through a pidfd where the kernel supports one. Between
    finding a pid in /proc and killing it, the process can exit and the
    number be reused by anything else this user runs -- a pidfd refers
    to the process, not the number, so the race cannot land on a
    stranger. The fallback re-checks identity immediately before the
    kill, which narrows the window without closing it.
    """
    pid = find_daemon(workdir)
    if pid is None:
        return (None, 'no running supportproxy process found for this '
                      'installation')
    try:
        opener = getattr(os, 'pidfd_open', None)
        sender = getattr(signal, 'pidfd_send_signal', None)
        if opener is not None and sender is not None:
            fd = opener(pid, 0)
            try:
                sender(fd, signal.SIGTERM)
            finally:
                os.close(fd)
        else:
            if _comm(pid) != SUPPORTPROXY_COMM:
                return (None, 'the daemon exited while we were looking at it')
            os.kill(pid, signal.SIGTERM)
    except OSError as e:
        return (None, 'could not signal pid %d: %s' % (pid, e))
    return (pid, None)
