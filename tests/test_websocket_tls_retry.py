"""Exercise real TLS writes while the WebSocket output queue grows under backpressure."""
import base64
from pathlib import Path
import select
import socket
import ssl
import subprocess

import pytest


HARNESS = r'''
#include "websocket.h"
#include <arpa/inet.h>
#include <cassert>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <poll.h>
#include <vector>

int main()
{
    setbuf(stdout, nullptr);
    alarm(20);
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener >= 0);
    sockaddr_in address {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(listener, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0);
    socklen_t length = sizeof(address);
    assert(getsockname(listener, reinterpret_cast<sockaddr *>(&address), &length) == 0);
    assert(listen(listener, 1) == 0);
    printf("PORT %u\n", ntohs(address.sin_port));
    int fd = accept(listener, nullptr, nullptr);
    assert(fd >= 0);
    close(listener);
    int size = 4096;
    assert(setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == 0);
    assert(fcntl(fd, F_SETFL, O_NONBLOCK) == 0);
    pollfd event {fd, POLLIN, 0};
    assert(poll(&event, 1, 5000) == 1);
    WebSocket ws(fd);
    assert(ws.is_SSL());
    char input[32];
    ssize_t count;
    do {
        count = ws.recv(input, sizeof(input));
        assert(count >= 0);
        usleep(1000);
    } while (count == 0);
    assert(count == 5 && memcmp(input, "start", 5) == 0);
    std::vector<uint8_t> first(65536, 0x41);
    std::vector<uint8_t> second(196608, 0x42);
    assert(ws.send(first.data(), first.size()) == ssize_t(first.size()));
    assert(ws.has_pending_output());  // force a nonblocking TLS write retry
    // Appending a larger message changes tx's length and forces a reallocation
    // while SSL_write is pending. The pre-fix implementation disconnects here.
    assert(ws.send(second.data(), second.size()) == ssize_t(second.size()));
    printf("QUEUED\n");
    for (;;) {
        assert(ws.flush());
        count = ws.recv(input, sizeof(input));
        assert(count >= 0);
        if (count == 4 && memcmp(input, "done", 4) == 0) break;
        usleep(1000);
    }
    assert(!ws.has_pending_output());
    close(fd);
    printf("PASS\n");
}
'''


@pytest.fixture(scope='module')
def tls_writer(tmp_path_factory):
    directory = tmp_path_factory.mktemp('tls-write-retry')
    source = directory / 'writer.cpp'
    source.write_text(HARNESS)
    repo = Path(__file__).resolve().parents[1]
    binary = directory / 'writer'
    subprocess.run(['g++', '-std=c++11', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-I' + str(repo), str(source), str(repo / 'websocket.cpp'),
                    '-lssl', '-lcrypto', '-o', str(binary)], check=True)
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                    '-keyout', str(directory / 'privkey.pem'),
                    '-out', str(directory / 'fullchain.pem'),
                    '-days', '1', '-subj', '/CN=localhost'],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return binary


def wait_line(process, marker):
    while True:
        assert select.select([process.stdout], [], [], 10)[0], marker
        line = process.stdout.readline()
        assert line, f'writer exited before {marker}'
        if line.startswith(marker):
            return line


def read_exact(connection, length):
    result = b''
    while len(result) < length:
        data = connection.recv(length - len(result))
        assert data, 'TLS writer disconnected'
        result += data
    return result


def frame(connection):
    header = read_exact(connection, 2)
    assert header[0] == 0x82 and header[1] & 0x80 == 0
    length = header[1] & 127
    if length == 126:
        length = int.from_bytes(read_exact(connection, 2), 'big')
    elif length == 127:
        length = int.from_bytes(read_exact(connection, 8), 'big')
    return read_exact(connection, length)


def send_frame(connection, payload):
    connection.sendall(bytes([0x82, 0x80 | len(payload)]) + b'\0' * 4 + payload)


@pytest.mark.parametrize('version', [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3])
def test_tls_retry_preserves_queued_video(tls_writer, version):
    process = subprocess.Popen([str(tls_writer)], cwd=tls_writer.parent,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               bufsize=0)
    try:
        port = int(wait_line(process, b'PORT ').split()[1])
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = context.maximum_version = version
        with socket.socket() as raw:
            # A small receive window makes the first SSL_write wait while the
            # next WebSocket message is queued, even on a fast loopback link.
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            raw.settimeout(10)
            raw.connect(('127.0.0.1', port))
            with context.wrap_socket(raw, server_hostname='localhost') as connection:
                key = base64.b64encode(b'x' * 16).decode()
                connection.sendall(('GET /v1 HTTP/1.1\r\nHost: localhost\r\n'
                                    'Upgrade: websocket\r\nConnection: Upgrade\r\n'
                                    f'Sec-WebSocket-Key: {key}\r\n'
                                    'Sec-WebSocket-Version: 13\r\n\r\n').encode())
                response = b''
                while not response.endswith(b'\r\n\r\n'):
                    response += read_exact(connection, 1)
                assert b'101 Switching Protocols' in response
                send_frame(connection, b'start')
                wait_line(process, b'QUEUED')
                assert frame(connection) == b'A' * 65536
                assert frame(connection) == b'B' * 196608
                send_frame(connection, b'done')
                wait_line(process, b'PASS')
        assert process.wait(timeout=5) == 0
    finally:
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
