import struct
import socket
from typing import Optional, Tuple, List

IP_PROTO_ICMP = 1
IP_PROTO_TCP  = 6
IP_PROTO_UDP  = 17

IP_FLAG_DF = 0x02  # Don't Fragment
IP_FLAG_MF = 0x01  # More Fragments


def calculate_checksum(data: bytes) -> int:
    """
    Calculate RFC 791 / RFC 1071 standard Internet Checksum:
    16-bit one's complement of the one's complement sum of 16-bit words.
    """
    if len(data) % 2 == 1:
        data += b"\x00"

    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
        # Fold carries immediately or at end
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    # Fold any remaining carry
    while checksum >> 16:
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    # One's complement
    return (~checksum) & 0xFFFF


def verify_checksum(header_bytes: bytes) -> bool:
    """
    Verify Internet Checksum. A valid header computed with its checksum
    results in 0x0000 (one's complement of 0xFFFF).
    """
    return calculate_checksum(header_bytes) == 0


class IPv4Packet:
    """
    IPv4 Datagram per RFC 791.
    Default header size: 20 bytes (IHL = 5).
    """
    MIN_HEADER_LEN = 20

    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: int,
        payload: bytes = b"",
        identification: int = 1,
        flags: int = 0,
        fragment_offset: int = 0,
        ttl: int = 64,
        tos: int = 0,
        options: bytes = b"",
    ):
        self.version = 4
        self.tos = tos
        self.identification = identification
        self.flags = flags
        self.fragment_offset = fragment_offset
        self.ttl = ttl
        self.protocol = protocol
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.options = options
        self.payload = payload

        # IHL in 32-bit words
        self.ihl = (self.MIN_HEADER_LEN + len(options)) // 4

    def pack(self) -> bytes:
        """Serialize IPv4 packet into wire format, computing the IP header checksum."""
        total_len = (self.ihl * 4) + len(self.payload)
        flags_and_offset = ((self.flags & 0x07) << 13) | (self.fragment_offset & 0x1FFF)
        version_ihl = (self.version << 4) | (self.ihl & 0x0F)

        src_bytes = socket.inet_aton(self.src_ip)
        dst_bytes = socket.inet_aton(self.dst_ip)

        # Header with checksum = 0 for calculation
        header_no_cksum = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            self.tos,
            total_len,
            self.identification,
            flags_and_offset,
            self.ttl,
            self.protocol,
            0,
            src_bytes,
            dst_bytes,
        ) + self.options

        checksum = calculate_checksum(header_no_cksum)

        # Re-pack with valid checksum
        header_with_cksum = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl,
            self.tos,
            total_len,
            self.identification,
            flags_and_offset,
            self.ttl,
            self.protocol,
            checksum,
            src_bytes,
            dst_bytes,
        ) + self.options

        return header_with_cksum + self.payload

    @classmethod
    def unpack(cls, raw: bytes) -> Tuple["IPv4Packet", bytes]:
        """
        Deserialize and validate IPv4 packet from wire binary format.
        Validates Version, IHL, Total Length, and Checksum.
        """
        if len(raw) < cls.MIN_HEADER_LEN:
            raise ValueError(f"Packet too short for IPv4 header ({len(raw)} bytes < 20)")

        version_ihl, tos, total_len, ident, flags_offset, ttl, proto, cksum, src_bytes, dst_bytes = (
            struct.unpack("!BBHHHBBH4s4s", raw[:cls.MIN_HEADER_LEN])
        )

        version = version_ihl >> 4
        ihl = version_ihl & 0x0F
        header_len = ihl * 4

        if version != 4:
            raise ValueError(f"Invalid IP version: {version} (expected 4)")
        if header_len < cls.MIN_HEADER_LEN:
            raise ValueError(f"Invalid IHL: {ihl} ({header_len} bytes < 20)")
        if len(raw) < header_len:
            raise ValueError(f"Truncated IP header: got {len(raw)} bytes, needed {header_len}")
        if len(raw) < total_len:
            raise ValueError(f"Truncated IP payload: got {len(raw)} bytes, header indicates {total_len}")

        # Checksum validation over the header
        header_bytes = raw[:header_len]
        if not verify_checksum(header_bytes):
            calc_val = calculate_checksum(header_bytes)
            raise ValueError(f"Invalid IPv4 header checksum! (computed residue 0x{calc_val:04x} != 0)")

        flags = (flags_offset >> 13) & 0x07
        offset = flags_offset & 0x1FFF
        options = raw[cls.MIN_HEADER_LEN:header_len]
        payload = raw[header_len:total_len]

        packet = cls(
            src_ip=socket.inet_ntoa(src_bytes),
            dst_ip=socket.inet_ntoa(dst_bytes),
            protocol=proto,
            payload=payload,
            identification=ident,
            flags=flags,
            fragment_offset=offset,
            ttl=ttl,
            tos=tos,
            options=options,
        )
        return packet, payload

    def __repr__(self) -> str:
        proto_map = {IP_PROTO_ICMP: "ICMP", IP_PROTO_TCP: "TCP", IP_PROTO_UDP: "UDP"}
        proto_str = proto_map.get(self.protocol, str(self.protocol))
        return (
            f"<IPv4 src={self.src_ip} dst={self.dst_ip} proto={proto_str} "
            f"ttl={self.ttl} len={len(self.payload)}>"
        )


class RouteEntry:
    def __init__(self, dest_net: str, netmask: str, gateway: Optional[str] = None, interface_name: str = "eth0"):
        self.dest_net = dest_net
        self.netmask = netmask
        self.gateway = gateway
        self.interface_name = interface_name
        self.dest_int = struct.unpack("!I", socket.inet_aton(dest_net))[0]
        self.mask_int = struct.unpack("!I", socket.inet_aton(netmask))[0]

    def matches(self, ip_str: str) -> bool:
        ip_int = struct.unpack("!I", socket.inet_aton(ip_str))[0]
        return (ip_int & self.mask_int) == (self.dest_int & self.mask_int)

    def prefix_length(self) -> int:
        return bin(self.mask_int).count("1")


class RoutingTable:
    """
    IPv4 Routing Table implementing Longest Prefix Match (LPM).
    """
    def __init__(self):
        self.routes: List[RouteEntry] = []

    def add_route(self, dest_net: str, netmask: str, gateway: Optional[str] = None, interface_name: str = "eth0") -> None:
        route = RouteEntry(dest_net, netmask, gateway, interface_name)
        self.routes.append(route)
        # Keep sorted by longest prefix match (most specific first)
        self.routes.sort(key=lambda r: r.prefix_length(), reverse=True)

    def lookup(self, dst_ip: str) -> Optional[RouteEntry]:
        for route in self.routes:
            if route.matches(dst_ip):
                return route
        return None
