import struct
from typing import Tuple

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP  = 0x0806

BROADCAST_MAC = b"\xff\xff\xff\xff\xff\xff"


def mac_to_str(mac_bytes: bytes) -> str:
    """Convert 6-byte binary MAC address to human-readable string (e.g. 52:54:00:12:34:56)."""
    return ":".join(f"{b:02x}" for b in mac_bytes)


def str_to_mac(mac_str: str) -> bytes:
    """Convert human-readable MAC string (e.g. 52:54:00:12:34:56) to 6-byte binary."""
    parts = mac_str.strip().split(":")
    if len(parts) != 6:
        raise ValueError(f"Invalid MAC address format: {mac_str}")
    return bytes(int(p, 16) for p in parts)


class EthernetFrame:
    """
    IEEE 802.3 Ethernet II Frame representation.
    Header: 14 bytes (Dest MAC [6], Src MAC [6], EtherType [2])
    """
    HEADER_LEN = 14

    def __init__(self, dst_mac: bytes, src_mac: bytes, ethertype: int, payload: bytes = b""):
        self.dst_mac = dst_mac
        self.src_mac = src_mac
        self.ethertype = ethertype
        self.payload = payload

    def pack(self) -> bytes:
        """Serialize Ethernet frame to binary wire format."""
        header = struct.pack("!6s6sH", self.dst_mac, self.src_mac, self.ethertype)
        return header + self.payload

    @classmethod
    def unpack(cls, raw: bytes) -> Tuple["EthernetFrame", bytes]:
        """Deserialize Ethernet frame from binary wire format."""
        if len(raw) < cls.HEADER_LEN:
            raise ValueError(f"Packet too short for Ethernet header ({len(raw)} bytes < 14)")
        dst_mac, src_mac, ethertype = struct.unpack("!6s6sH", raw[:cls.HEADER_LEN])
        payload = raw[cls.HEADER_LEN:]
        return cls(dst_mac=dst_mac, src_mac=src_mac, ethertype=ethertype, payload=payload), payload

    def __repr__(self) -> str:
        ethertype_name = {
            ETHERTYPE_IPV4: "IPv4",
            ETHERTYPE_ARP: "ARP"
        }.get(self.ethertype, f"0x{self.ethertype:04x}")
        return (f"<EthernetFrame src={mac_to_str(self.src_mac)} "
                f"dst={mac_to_str(self.dst_mac)} type={ethertype_name} "
                f"len={len(self.payload)}>")
