import struct
from typing import Tuple
from src.layers.ipv4 import calculate_checksum, verify_checksum

ICMP_TYPE_ECHO_REPLY       = 0
ICMP_TYPE_DEST_UNREACHABLE = 3
ICMP_TYPE_ECHO_REQUEST     = 8

ICMP_CODE_PORT_UNREACHABLE = 3


class ICMPPacket:
    """
    Internet Control Message Protocol (ICMP) packet per RFC 792.
    Header: 8 bytes (Type [1], Code [1], Checksum [2], Rest of Header [4]).
    """
    HEADER_LEN = 8

    def __init__(
        self,
        icmp_type: int,
        code: int = 0,
        ident: int = 0,
        seq: int = 0,
        payload: bytes = b"",
    ):
        self.icmp_type = icmp_type
        self.code = code
        self.ident = ident
        self.seq = seq
        self.payload = payload

    def pack(self) -> bytes:
        """Serialize ICMP packet into wire format, computing the ICMP checksum."""
        # Header with checksum = 0
        header_no_cksum = struct.pack("!BBHHH", self.icmp_type, self.code, 0, self.ident, self.seq)
        data = header_no_cksum + self.payload
        cksum = calculate_checksum(data)

        # Header with computed checksum
        header_with_cksum = struct.pack("!BBHHH", self.icmp_type, self.code, cksum, self.ident, self.seq)
        return header_with_cksum + self.payload

    @classmethod
    def unpack(cls, raw: bytes) -> Tuple["ICMPPacket", bytes]:
        """
        Deserialize and validate ICMP packet from wire format.
        Validates the ICMP checksum over header and payload.
        """
        if len(raw) < cls.HEADER_LEN:
            raise ValueError(f"Packet too short for ICMP header ({len(raw)} bytes < 8)")

        if not verify_checksum(raw):
            raise ValueError("Invalid ICMP checksum!")

        icmp_type, code, _, ident, seq = struct.unpack("!BBHHH", raw[:cls.HEADER_LEN])
        payload = raw[cls.HEADER_LEN:]

        packet = cls(icmp_type=icmp_type, code=code, ident=ident, seq=seq, payload=payload)
        return packet, payload

    @classmethod
    def create_echo_request(cls, ident: int = 1, seq: int = 1, payload: bytes = b"abcdefghijklmnopqrstuvwabcdefghi") -> "ICMPPacket":
        """Generate a ping (Echo Request) packet."""
        return cls(icmp_type=ICMP_TYPE_ECHO_REQUEST, code=0, ident=ident, seq=seq, payload=payload)

    @classmethod
    def create_echo_reply(cls, ident: int, seq: int, payload: bytes) -> "ICMPPacket":
        """Generate an Echo Reply packet in response to an Echo Request."""
        return cls(icmp_type=ICMP_TYPE_ECHO_REPLY, code=0, ident=ident, seq=seq, payload=payload)

    def __repr__(self) -> str:
        type_names = {
            ICMP_TYPE_ECHO_REQUEST: "Echo Request (Ping)",
            ICMP_TYPE_ECHO_REPLY: "Echo Reply (Pong)",
            ICMP_TYPE_DEST_UNREACHABLE: "Destination Unreachable",
        }
        name = type_names.get(self.icmp_type, f"Type {self.icmp_type}")
        return f"<ICMP {name} code={self.code} id={self.ident} seq={self.seq} len={len(self.payload)}>"
