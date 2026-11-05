import struct
import socket
import time
from typing import Dict, Optional, Tuple

ARP_HTYPE_ETHERNET = 1
ARP_PTYPE_IPV4     = 0x0800
ARP_HLEN_ETHERNET  = 6
ARP_PLEN_IPV4      = 4

ARP_OP_REQUEST     = 1
ARP_OP_REPLY       = 2


def ip_to_str(ip_bytes: bytes) -> str:
    """Convert 4-byte binary IPv4 address to string (e.g. 192.168.1.1)."""
    return socket.inet_ntoa(ip_bytes)


def str_to_ip(ip_str: str) -> bytes:
    """Convert IPv4 string to 4-byte binary."""
    return socket.inet_aton(ip_str)


class ARPPacket:
    """
    Address Resolution Protocol (ARP) packet per RFC 826.
    Size: 28 bytes for Ethernet + IPv4.
    """
    HEADER_LEN = 28

    def __init__(
        self,
        opcode: int,
        sender_mac: bytes,
        sender_ip: bytes,
        target_mac: bytes,
        target_ip: bytes,
        htype: int = ARP_HTYPE_ETHERNET,
        ptype: int = ARP_PTYPE_IPV4,
        hlen: int = ARP_HLEN_ETHERNET,
        plen: int = ARP_PLEN_IPV4,
    ):
        self.htype = htype
        self.ptype = ptype
        self.hlen = hlen
        self.plen = plen
        self.opcode = opcode
        self.sender_mac = sender_mac
        self.sender_ip = sender_ip
        self.target_mac = target_mac
        self.target_ip = target_ip

    def pack(self) -> bytes:
        """Serialize ARP packet into wire binary format."""
        return struct.pack(
            "!HHBBH6s4s6s4s",
            self.htype,
            self.ptype,
            self.hlen,
            self.plen,
            self.opcode,
            self.sender_mac,
            self.sender_ip,
            self.target_mac,
            self.target_ip,
        )

    @classmethod
    def unpack(cls, raw: bytes) -> Tuple["ARPPacket", bytes]:
        """Deserialize ARP packet from wire binary format."""
        if len(raw) < cls.HEADER_LEN:
            raise ValueError(f"Packet too short for ARP ({len(raw)} bytes < 28)")
        (
            htype,
            ptype,
            hlen,
            plen,
            opcode,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        ) = struct.unpack("!HHBBH6s4s6s4s", raw[:cls.HEADER_LEN])

        packet = cls(
            opcode=opcode,
            sender_mac=sender_mac,
            sender_ip=sender_ip,
            target_mac=target_mac,
            target_ip=target_ip,
            htype=htype,
            ptype=ptype,
            hlen=hlen,
            plen=plen,
        )
        return packet, raw[cls.HEADER_LEN:]

    @classmethod
    def create_request(cls, sender_mac: bytes, sender_ip: str, target_ip: str) -> "ARPPacket":
        """Build an ARP Request packet (who-has target_ip tell sender_ip)."""
        return cls(
            opcode=ARP_OP_REQUEST,
            sender_mac=sender_mac,
            sender_ip=str_to_ip(sender_ip),
            target_mac=b"\x00\x00\x00\x00\x00\x00",
            target_ip=str_to_ip(target_ip),
        )

    @classmethod
    def create_reply(
        cls, sender_mac: bytes, sender_ip: str, target_mac: bytes, target_ip: str
    ) -> "ARPPacket":
        """Build an ARP Reply packet (target_ip is at sender_mac)."""
        return cls(
            opcode=ARP_OP_REPLY,
            sender_mac=sender_mac,
            sender_ip=str_to_ip(sender_ip),
            target_mac=target_mac,
            target_ip=str_to_ip(target_ip),
        )

    def __repr__(self) -> str:
        op_str = "REQUEST" if self.opcode == ARP_OP_REQUEST else "REPLY"
        from src.layers.ethernet import mac_to_str
        return (
            f"<ARP {op_str} sender={ip_to_str(self.sender_ip)} ({mac_to_str(self.sender_mac)}) "
            f"target={ip_to_str(self.target_ip)} ({mac_to_str(self.target_mac)})>"
        )


class ARPEntry:
    def __init__(self, mac: bytes, ttl: float = 300.0):
        self.mac = mac
        self.expires_at = time.time() + ttl

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


class ARPTable:
    """
    ARP Cache Table for translating IPv4 addresses to MAC addresses.
    Supports dynamic learning and table lookups.
    """
    def __init__(self, default_ttl: float = 300.0):
        self._entries: Dict[str, ARPEntry] = {}
        self.default_ttl = default_ttl

    def update(self, ip_str: str, mac: bytes, ttl: Optional[float] = None) -> None:
        """Add or update an IP -> MAC mapping in the ARP cache."""
        actual_ttl = ttl if ttl is not None else self.default_ttl
        self._entries[ip_str] = ARPEntry(mac=mac, ttl=actual_ttl)

    def lookup(self, ip_str: str) -> Optional[bytes]:
        """Look up MAC address for given IP string. Returns None if absent or expired."""
        entry = self._entries.get(ip_str)
        if entry is None:
            return None
        if entry.is_expired():
            del self._entries[ip_str]
            return None
        return entry.mac

    def get_all(self) -> Dict[str, bytes]:
        """Return valid active mappings."""
        now = time.time()
        valid = {}
        to_del = []
        for ip, entry in self._entries.items():
            if entry.expires_at > now:
                valid[ip] = entry.mac
            else:
                to_del.append(ip)
        for ip in to_del:
            del self._entries[ip]
        return valid

    def clear(self) -> None:
        self._entries.clear()
