import os
import struct
import sys

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from typing import Iterator, Tuple
from src.layers.ethernet import EthernetFrame, ETHERTYPE_ARP, ETHERTYPE_IPV4, mac_to_str
from src.layers.arp import ARPPacket, ip_to_str, ARP_OP_REQUEST
from src.layers.ipv4 import IPv4Packet, IP_PROTO_ICMP, IP_PROTO_TCP, IP_PROTO_UDP
from src.layers.icmp import ICMPPacket, ICMP_TYPE_ECHO_REQUEST, ICMP_TYPE_ECHO_REPLY
from src.layers.tcp import TCPSegment, flags_to_str


def parse_pcap(filepath: str) -> Iterator[Tuple[float, bytes]]:
    """Parse a .pcap file and yield (timestamp, frame_bytes)."""
    with open(filepath, "rb") as f:
        global_header = f.read(24)
        if len(global_header) < 24:
            return

        magic, = struct.unpack("=I", global_header[:4])
        if magic != 0xA1B2C3D4:
            raise ValueError(f"Invalid PCAP magic number: 0x{magic:08x}")

        while True:
            pkt_hdr = f.read(16)
            if len(pkt_hdr) < 16:
                break
            sec, usec, incl_len, orig_len = struct.unpack("=IIII", pkt_hdr)
            ts = sec + (usec / 1_000_000.0)
            data = f.read(incl_len)
            yield ts, data


def dissect_frame(frame_bytes: bytes) -> str:
    """Dissect an Ethernet frame into human-readable Wireshark / tcpdump format."""
    if len(frame_bytes) < 14:
        return f"Corrupt Frame ({len(frame_bytes)} bytes)"

    eth, payload = EthernetFrame.unpack(frame_bytes)
    src_mac = mac_to_str(eth.src_mac)
    dst_mac = mac_to_str(eth.dst_mac)

    if eth.ethertype == ETHERTYPE_ARP:
        arp, _ = ARPPacket.unpack(payload)
        sender_ip = ip_to_str(arp.sender_ip)
        target_ip = ip_to_str(arp.target_ip)
        if arp.opcode == ARP_OP_REQUEST:
            return f"ARP  | Who has {target_ip}? Tell {sender_ip} (hw: {src_mac})"
        else:
            return f"ARP  | {sender_ip} is at {mac_to_str(arp.sender_mac)}"

    elif eth.ethertype == ETHERTYPE_IPV4:
        try:
            ip, ip_payload = IPv4Packet.unpack(payload)
        except Exception as e:
            return f"IPv4 | Invalid packet: {e}"

        if ip.protocol == IP_PROTO_ICMP:
            try:
                icmp, _ = ICMPPacket.unpack(ip_payload)
                if icmp.icmp_type == ICMP_TYPE_ECHO_REQUEST:
                    return f"ICMP | {ip.src_ip} -> {ip.dst_ip} Echo (ping) request  id={icmp.ident} seq={icmp.seq} len={len(icmp.payload)}"
                elif icmp.icmp_type == ICMP_TYPE_ECHO_REPLY:
                    return f"ICMP | {ip.src_ip} -> {ip.dst_ip} Echo (ping) reply    id={icmp.ident} seq={icmp.seq} len={len(icmp.payload)}"
                else:
                    return f"ICMP | {ip.src_ip} -> {ip.dst_ip} Type={icmp.icmp_type} Code={icmp.code}"
            except Exception:
                return f"ICMP | {ip.src_ip} -> {ip.dst_ip} Corrupt ICMP"

        elif ip.protocol == IP_PROTO_TCP:
            try:
                tcp, tcp_payload = TCPSegment.unpack(ip_payload, ip.src_ip, ip.dst_ip, validate_cksum=False)
                return (
                    f"TCP  | {ip.src_ip}:{tcp.src_port} -> {ip.dst_ip}:{tcp.dst_port} "
                    f"{flags_to_str(tcp.flags):<14} Seq={tcp.seq_num:<10} Ack={tcp.ack_num:<10} "
                    f"Win={tcp.window_size:<5} Len={len(tcp_payload)}"
                )
            except Exception as e:
                return f"TCP  | {ip.src_ip} -> {ip.dst_ip} Corrupt TCP: {e}"

        return f"IPv4 | {ip.src_ip} -> {ip.dst_ip} Proto={ip.protocol} Len={len(ip_payload)}"

    return f"ETH  | {src_mac} -> {dst_mac} Type=0x{eth.ethertype:04x} Len={len(payload)}"


def print_pcap_summary(filepath: str) -> None:
    """Print dissected packets from a .pcap capture file."""
    print(f"\nDissecting PCAP capture file: {filepath}")
    print("=" * 95)
    print(f"{'#':<4} | {'Timestamp':<12} | {'Protocol':<4} | Details")
    print("-" * 95)

    idx = 0
    start_ts = None
    for ts, data in parse_pcap(filepath):
        idx += 1
        if start_ts is None:
            start_ts = ts
        rel_ts = ts - start_ts
        dissected = dissect_frame(data)
        if "|" in dissected:
            proto, details = dissected.split("|", 1)
            proto = proto.strip()
            details = details.strip()
        else:
            proto = "RAW"
            details = dissected
        print(f"{idx:<4} | {rel_ts:>9.4f}s  | {proto:<4} | {details}")

    print("=" * 95)
    print(f"Total packets captured: {idx}\n")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        print_pcap_summary(sys.argv[1])
    else:
        print("Usage: python wireshark_dumper.py <file.pcap>")
