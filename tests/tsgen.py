"""Synthetic MPEG-TS generator for the video tests.

Nothing in SupportProxy decodes video -- the scanner only reads PSI and
adaptation fields -- so a generator with filler payload is enough for
every scanner and fan-out assertion, and it gives byte-exact control
over where the join anchors are. That is worth more than a recorded
sample here: with a real file you cannot say "put a keyframe exactly
here" and then assert a viewer started exactly there.

Real-codec checks (does the recording actually decode?) use a real
fixture instead; see the phase 3 tests.
"""
import struct

PACKET_SIZE = 188
SYNC = 0x47

PAT_PID = 0x0000
DEFAULT_PMT_PID = 0x1000
DEFAULT_VIDEO_PID = 0x0100

STREAM_H264 = 0x1B
STREAM_HEVC = 0x24

# A datagram of 7 packets is what every MPEG-TS/UDP sender produces.
PACKETS_PER_DATAGRAM = 7
DATAGRAM_SIZE = PACKET_SIZE * PACKETS_PER_DATAGRAM


def crc32_mpeg(data):
    """MPEG-2 section CRC: poly 0x04C11DB7, MSB-first, init 0xFFFFFFFF."""
    crc = 0xFFFFFFFF
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if crc & 0x80000000 \
                else (crc << 1) & 0xFFFFFFFF
    return crc


class TSGen:
    def __init__(self, pmt_pid=DEFAULT_PMT_PID, video_pid=DEFAULT_VIDEO_PID,
                 stream_type=STREAM_H264):
        self.pmt_pid = pmt_pid
        self.video_pid = video_pid
        self.stream_type = stream_type
        self._cc = {}

    def _next_cc(self, pid):
        c = self._cc.get(pid, 0)
        self._cc[pid] = (c + 1) & 0x0F
        return c

    def _packet(self, pid, payload, pusi=False, rai=False):
        """One 188-byte packet. Payload is padded with an adaptation
        field so it always lands at the end of the packet."""
        assert len(payload) <= PACKET_SIZE - 4
        hdr = bytearray(4)
        hdr[0] = SYNC
        hdr[1] = ((0x40 if pusi else 0) | ((pid >> 8) & 0x1F))
        hdr[2] = pid & 0xFF
        cc = self._next_cc(pid)

        stuff = PACKET_SIZE - 4 - len(payload)
        if rai or stuff > 0:
            # adaptation field present, plus payload
            hdr[3] = 0x30 | cc
            af_len = stuff - 1
            if af_len < 0:
                raise ValueError('payload too long for an adaptation field')
            af = bytearray([af_len])
            if af_len > 0:
                af.append(0x40 if rai else 0x00)     # flags
                af.extend(b'\xff' * (af_len - 1))
            return bytes(hdr) + bytes(af) + bytes(payload)
        hdr[3] = 0x10 | cc
        return bytes(hdr) + bytes(payload)

    def _section_packet(self, pid, section):
        """Wrap a complete PSI section in a single packet.

        PSI packets are padded with trailing 0xFF after the section, not
        with an adaptation field -- that is what real muxers emit, and a
        fixture that used an adaptation field here would be testing a
        packet layout nothing actually sends.
        """
        payload = b'\x00' + section            # pointer_field
        payload += b'\xff' * (PACKET_SIZE - 4 - len(payload))
        hdr = bytearray(4)
        hdr[0] = SYNC
        hdr[1] = 0x40 | ((pid >> 8) & 0x1F)    # PUSI
        hdr[2] = pid & 0xFF
        hdr[3] = 0x10 | self._next_cc(pid)     # payload only, no AF
        return bytes(hdr) + payload

    def pat(self, version=0):
        body = bytearray()
        body += b'\x00'                                    # table_id
        body += b'\x00\x00'                                # length, patched
        body += b'\x00\x01'                                # ts id
        body += bytes([0xC1 | (version << 1)])
        body += b'\x00\x00'                                # section numbers
        body += b'\x00\x01'                                # program 1
        body += bytes([0xE0 | ((self.pmt_pid >> 8) & 0x1F),
                       self.pmt_pid & 0xFF])
        return self._section_packet(PAT_PID, self._finish(body))

    def pmt(self, version=0, extra_streams=()):
        body = bytearray()
        body += b'\x02'
        body += b'\x00\x00'
        body += b'\x00\x01'
        body += bytes([0xC1 | (version << 1)])
        body += b'\x00\x00'
        body += bytes([0xE0 | ((self.video_pid >> 8) & 0x1F),
                       self.video_pid & 0xFF])              # PCR PID
        body += b'\xF0\x00'                                 # program_info_len
        body += bytes([self.stream_type,
                       0xE0 | ((self.video_pid >> 8) & 0x1F),
                       self.video_pid & 0xFF,
                       0xF0, 0x00])
        for stype, pid in extra_streams:
            body += bytes([stype, 0xE0 | ((pid >> 8) & 0x1F), pid & 0xFF,
                           0xF0, 0x00])
        return self._section_packet(self.pmt_pid, self._finish(body))

    @staticmethod
    def _finish(body):
        """Patch section_length and append the CRC."""
        section_length = len(body) - 3 + 4
        body[1] = 0xB0 | ((section_length >> 8) & 0x0F)
        body[2] = section_length & 0xFF
        return bytes(body) + struct.pack('>I', crc32_mpeg(bytes(body)))

    def video(self, key=False, size=160):
        """One video packet. `key` sets both a keyframe payload and the
        adaptation field's random_access_indicator."""
        pes = bytearray()
        pes += b'\x00\x00\x01\xe0'          # PES start, video stream id
        pes += b'\x00\x00'                  # unbounded length
        pes += b'\x80\x00\x00'              # flags, no PTS
        if self.stream_type == STREAM_HEVC:
            # HEVC NAL header is 2 bytes, type is bits 6..1
            pes += b'\x00\x00\x01' + bytes([(35 if key else 1) << 1, 0x01])
        else:
            pes += b'\x00\x00\x01' + bytes([0x09 if key else 0x41])
        pes += b'\x10'
        pes += b'\xAA' * max(0, size - len(pes))
        return self._packet(self.video_pid, bytes(pes[:size]),
                            pusi=True, rai=key)

    def stream(self, packets, gop=10, psi_every=20):
        """A run of `packets` video packets with PSI interleaved.

        Returns the whole stream as bytes. Every `gop`-th video packet
        is a keyframe, and PAT+PMT are emitted every `psi_every`
        packets, mirroring what real muxers do.
        """
        out = bytearray()
        for i in range(packets):
            if i % psi_every == 0:
                out += self.pat()
                out += self.pmt()
            out += self.video(key=(i % gop == 0))
        return bytes(out)

    def datagrams(self, data):
        """Split a stream into 1316-byte datagrams, as udpsink would.

        Any trailing partial datagram is dropped rather than sent short:
        a real sender emits whole 7-packet groups, and the ingest path
        rejects anything that is not a multiple of 188 anyway.
        """
        n = len(data) // DATAGRAM_SIZE
        return [data[i * DATAGRAM_SIZE:(i + 1) * DATAGRAM_SIZE]
                for i in range(n)]
