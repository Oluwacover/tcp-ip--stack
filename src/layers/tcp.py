import enum
import socket
import struct
import time
from typing import Optional, Tuple, List
from src.layers.ipv4 import calculate_checksum, verify_checksum

# TCP Flags
TCP_FLAG_FIN = 0x01
TCP_FLAG_SYN = 0x02
TCP_FLAG_RST = 0x04
TCP_FLAG_PSH = 0x08
TCP_FLAG_ACK = 0x10
TCP_FLAG_URG = 0x20
TCP_FLAG_ECE = 0x40
TCP_FLAG_CWR = 0x80


class TCPState(enum.Enum):
    CLOSED       = "CLOSED"
    LISTEN       = "LISTEN"
    SYN_SENT     = "SYN_SENT"
    SYN_RECEIVED = "SYN_RECEIVED"
    ESTABLISHED  = "ESTABLISHED"
    FIN_WAIT_1   = "FIN_WAIT_1"
    FIN_WAIT_2   = "FIN_WAIT_2"
    CLOSE_WAIT   = "CLOSE_WAIT"
    CLOSING      = "CLOSING"
    LAST_ACK     = "LAST_ACK"
    TIME_WAIT    = "TIME_WAIT"


def flags_to_str(flags: int) -> str:
    """Format TCP flags as human-readable string (e.g. [SYN, ACK])."""
    names = []
    if flags & TCP_FLAG_SYN: names.append("SYN")
    if flags & TCP_FLAG_ACK: names.append("ACK")
    if flags & TCP_FLAG_FIN: names.append("FIN")
    if flags & TCP_FLAG_RST: names.append("RST")
    if flags & TCP_FLAG_PSH: names.append("PSH")
    if flags & TCP_FLAG_URG: names.append("URG")
    if flags & TCP_FLAG_ECE: names.append("ECE")
    if flags & TCP_FLAG_CWR: names.append("CWR")
    return "[" + "|".join(names) + "]" if names else "[]"


def compute_tcp_checksum(
    src_ip: str,
    dst_ip: str,
    tcp_segment_no_cksum: bytes,
) -> int:
    """
    Compute TCP checksum including the IPv4 Pseudo-Header per RFC 793:
    Pseudo-Header:
      - Source IP (4 bytes)
      - Destination IP (4 bytes)
      - Zero (1 byte)
      - Protocol 6 (1 byte)
      - TCP Segment Length (2 bytes)
    """
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    tcp_len = len(tcp_segment_no_cksum)

    pseudo_hdr = struct.pack(
        "!4s4sBBH",
        src_bytes,
        dst_bytes,
        0,
        6,  # IPPROTO_TCP
        tcp_len,
    )

    data = pseudo_hdr + tcp_segment_no_cksum
    return calculate_checksum(data)


def verify_tcp_checksum(src_ip: str, dst_ip: str, tcp_segment: bytes) -> bool:
    """Verify TCP checksum using the IPv4 pseudo-header."""
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    tcp_len = len(tcp_segment)

    pseudo_hdr = struct.pack("!4s4sBBH", src_bytes, dst_bytes, 0, 6, tcp_len)
    data = pseudo_hdr + tcp_segment
    return verify_checksum(data)


class TCPSegment:
    """
    Transmission Control Protocol (TCP) segment per RFC 793.
    Base header: 20 bytes (Data Offset = 5).
    """
    MIN_HEADER_LEN = 20

    def __init__(
        self,
        src_port: int,
        dst_port: int,
        seq_num: int,
        ack_num: int = 0,
        flags: int = 0,
        window_size: int = 65535,
        urgent_pointer: int = 0,
        options: bytes = b"",
        payload: bytes = b"",
    ):
        self.src_port = src_port
        self.dst_port = dst_port
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.flags = flags
        self.window_size = window_size
        self.urgent_pointer = urgent_pointer
        self.options = options
        self.payload = payload

        # Data offset in 32-bit (4-byte) words
        self.data_offset = (self.MIN_HEADER_LEN + len(options)) // 4

    def pack(self, src_ip: str, dst_ip: str) -> bytes:
        """
        Serialize TCP segment into binary wire format,
        computing checksum with IPv4 pseudo-header.
        """
        offset_res = (self.data_offset << 4) & 0xF0

        # Header with checksum = 0
        header_no_cksum = struct.pack(
            "!HHIIBBHHH",
            self.src_port,
            self.dst_port,
            self.seq_num,
            self.ack_num,
            offset_res,
            self.flags,
            self.window_size,
            0,
            self.urgent_pointer,
        ) + self.options

        segment_no_cksum = header_no_cksum + self.payload
        cksum = compute_tcp_checksum(src_ip, dst_ip, segment_no_cksum)

        # Header with computed checksum
        header_with_cksum = struct.pack(
            "!HHIIBBHHH",
            self.src_port,
            self.dst_port,
            self.seq_num,
            self.ack_num,
            offset_res,
            self.flags,
            self.window_size,
            cksum,
            self.urgent_pointer,
        ) + self.options

        return header_with_cksum + self.payload

    @classmethod
    def unpack(cls, raw: bytes, src_ip: str, dst_ip: str, validate_cksum: bool = True) -> Tuple["TCPSegment", bytes]:
        """Deserialize and validate TCP segment from wire format."""
        if len(raw) < cls.MIN_HEADER_LEN:
            raise ValueError(f"Packet too short for TCP header ({len(raw)} bytes < 20)")

        if validate_cksum and not verify_tcp_checksum(src_ip, dst_ip, raw):
            raise ValueError("Invalid TCP checksum (pseudo-header validation failed)!")

        (
            src_port,
            dst_port,
            seq_num,
            ack_num,
            offset_res,
            flags,
            window_size,
            _,
            urgent_pointer,
        ) = struct.unpack("!HHIIBBHHH", raw[:cls.MIN_HEADER_LEN])

        data_offset = (offset_res >> 4) * 4
        if data_offset < cls.MIN_HEADER_LEN or len(raw) < data_offset:
            raise ValueError(f"Invalid TCP data offset ({data_offset})")

        options = raw[cls.MIN_HEADER_LEN:data_offset]
        payload = raw[data_offset:]

        segment = cls(
            src_port=src_port,
            dst_port=dst_port,
            seq_num=seq_num,
            ack_num=ack_num,
            flags=flags,
            window_size=window_size,
            urgent_pointer=urgent_pointer,
            options=options,
            payload=payload,
        )
        return segment, payload

    def __repr__(self) -> str:
        return (
            f"<TCP {self.src_port}->{self.dst_port} {flags_to_str(self.flags)} "
            f"seq={self.seq_num} ack={self.ack_num} win={self.window_size} len={len(self.payload)}>"
        )


class TCPConnection:
    """
    Transmission Control Block (TCB) managing TCP connection state (RFC 793).
    Tracks sequence numbers, window sizes, state transitions, and byte streams.
    """
    def __init__(
        self,
        local_ip: str,
        local_port: int,
        remote_ip: str,
        remote_port: int,
        initial_state: TCPState = TCPState.CLOSED,
        isn: int = 1000,
    ):
        self.local_ip = local_ip
        self.local_port = local_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port

        self.state = initial_state

        # Sequence number variables per RFC 793
        self.snd_una = isn       # send unacknowledged
        self.snd_nxt = isn       # send next
        self.snd_wnd = 65535     # send window
        self.rcv_nxt = 0         # receive next
        self.rcv_wnd = 65535     # receive window
        self.irs = 0             # initial receive sequence

        # Data buffers
        self.recv_buf = bytearray()
        self.send_buf = bytearray()

        # Connection metadata
        self.created_at = time.time()
        self.state_history: List[Tuple[float, TCPState]] = [(self.created_at, self.state)]

    def transition_to(self, new_state: TCPState) -> None:
        """Record state transition."""
        self.state = new_state
        self.state_history.append((time.time(), new_state))

    def make_segment(
        self,
        flags: int,
        payload: bytes = b"",
        seq_num: Optional[int] = None,
        ack_num: Optional[int] = None,
    ) -> TCPSegment:
        """Create a segment adhering to current TCB state."""
        seq = self.snd_nxt if seq_num is None else seq_num
        ack = self.rcv_nxt if ack_num is None else ack_num

        seg = TCPSegment(
            src_port=self.local_port,
            dst_port=self.remote_port,
            seq_num=seq,
            ack_num=ack,
            flags=flags,
            window_size=self.rcv_wnd,
            payload=payload,
        )

        # Advance snd_nxt if SYN or FIN or data present
        advance = len(payload)
        if flags & TCP_FLAG_SYN:
            advance += 1
        if flags & TCP_FLAG_FIN:
            advance += 1

        if seq_num is None:
            self.snd_nxt += advance

        return seg
