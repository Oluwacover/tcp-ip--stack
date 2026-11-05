import os
import random
import sys
import time
from typing import List, Dict, Optional, Tuple

# Ensure workspace root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from src.layers.ethernet import EthernetFrame, ETHERTYPE_IPV4, ETHERTYPE_ARP, BROADCAST_MAC, mac_to_str
from src.layers.arp import ARPPacket, str_to_ip, ip_to_str
from src.layers.ipv4 import IPv4Packet, IP_PROTO_ICMP, IP_PROTO_TCP
from src.layers.icmp import ICMPPacket, ICMP_TYPE_ECHO_REQUEST, ICMP_TYPE_ECHO_REPLY
from src.layers.tcp import (
    TCPSegment,
    TCP_FLAG_SYN,
    TCP_FLAG_ACK,
    TCP_FLAG_RST,
    flags_to_str,
)
from src.net.interface import VirtualInterface


COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    3306: "mysql",
    5432: "postgresql",
    8080: "http-proxy",
    8443: "https-alt",
}


class PyNmapScanner:
    """
    Nmap-style network diagnostic tool crafted on top of our virtual link.
    Supports ARP discovery, ICMP Ping, and TCP SYN Stealth Port Scanning (-sS).
    """
    def __init__(self, interface: VirtualInterface):
        self.interface = interface

    def arp_ping(self, target_ip: str, timeout: float = 1.0) -> Optional[str]:
        """ARP discovery scan (-PR). Returns target MAC or None."""
        req = ARPPacket.create_request(
            sender_mac=self.interface.mac,
            sender_ip=self.interface.ip,
            target_ip=target_ip,
        )
        frame = EthernetFrame(
            dst_mac=BROADCAST_MAC,
            src_mac=self.interface.mac,
            ethertype=ETHERTYPE_ARP,
            payload=req.pack(),
        )
        self.interface.send_raw(frame.pack())

        start = time.time()
        while time.time() - start < timeout:
            raw = self.interface.recv_raw(timeout=0.05)
            if not raw:
                continue
            eth, payload = EthernetFrame.unpack(raw)
            if eth.ethertype == ETHERTYPE_ARP:
                arp, _ = ARPPacket.unpack(payload)
                if ip_to_str(arp.sender_ip) == target_ip:
                    return mac_to_str(arp.sender_mac)
        return None

    def icmp_ping(self, target_ip: str, target_mac: bytes, timeout: float = 1.0) -> Optional[float]:
        """ICMP echo ping scan (-PE). Returns latency in milliseconds or None."""
        icmp = ICMPPacket.create_echo_request(ident=random.randint(1, 65535), seq=1)
        ip = IPv4Packet(
            src_ip=self.interface.ip,
            dst_ip=target_ip,
            protocol=IP_PROTO_ICMP,
            payload=icmp.pack(),
        )
        frame = EthernetFrame(
            dst_mac=target_mac,
            src_mac=self.interface.mac,
            ethertype=ETHERTYPE_IPV4,
            payload=ip.pack(),
        )

        t0 = time.perf_counter()
        self.interface.send_raw(frame.pack())

        start = time.time()
        while time.time() - start < timeout:
            raw = self.interface.recv_raw(timeout=0.05)
            if not raw:
                continue
            eth, payload = EthernetFrame.unpack(raw)
            if eth.ethertype == ETHERTYPE_IPV4:
                ip_resp, ip_payload = IPv4Packet.unpack(payload)
                if ip_resp.protocol == IP_PROTO_ICMP and ip_resp.src_ip == target_ip:
                    icmp_resp, _ = ICMPPacket.unpack(ip_payload)
                    if icmp_resp.icmp_type == ICMP_TYPE_ECHO_REPLY and icmp_resp.ident == icmp.ident:
                        latency_ms = (time.perf_counter() - t0) * 1000.0
                        return latency_ms
        return None

    def tcp_syn_scan(
        self, target_ip: str, target_mac: bytes, ports: List[int], timeout: float = 0.8
    ) -> Dict[int, str]:
        """
        Nmap TCP SYN Stealth Scan (-sS).
        Sends SYN packet;
        - SYN+ACK response => OPEN (we reply with RST to tear down)
        - RST response     => CLOSED
        - No response      => FILTERED
        """
        results = {}

        for port in ports:
            src_port = random.randint(40000, 60000)
            syn_seg = TCPSegment(
                src_port=src_port,
                dst_port=port,
                seq_num=random.randint(1000, 99999),
                ack_num=0,
                flags=TCP_FLAG_SYN,
                window_size=65535,
            )
            raw_tcp = syn_seg.pack(src_ip=self.interface.ip, dst_ip=target_ip)
            ip_pkt = IPv4Packet(
                src_ip=self.interface.ip,
                dst_ip=target_ip,
                protocol=IP_PROTO_TCP,
                payload=raw_tcp,
            )
            frame = EthernetFrame(
                dst_mac=target_mac,
                src_mac=self.interface.mac,
                ethertype=ETHERTYPE_IPV4,
                payload=ip_pkt.pack(),
            )

            self.interface.send_raw(frame.pack())

            status = "filtered"
            start = time.time()
            while time.time() - start < timeout:
                raw = self.interface.recv_raw(timeout=0.05)
                if not raw:
                    continue
                eth, payload = EthernetFrame.unpack(raw)
                if eth.ethertype == ETHERTYPE_IPV4:
                    ip_resp, ip_payload = IPv4Packet.unpack(payload)
                    if ip_resp.src_ip == target_ip and ip_resp.protocol == IP_PROTO_TCP:
                        tcp_resp, _ = TCPSegment.unpack(
                            ip_payload, ip_resp.src_ip, ip_resp.dst_ip, validate_cksum=False
                        )
                        if tcp_resp.dst_port == src_port and tcp_resp.src_port == port:
                            if (tcp_resp.flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK):
                                status = "open"
                                # Send RST to reset the half-open connection cleanly
                                rst_seg = TCPSegment(
                                    src_port=src_port,
                                    dst_port=port,
                                    seq_num=tcp_resp.ack_num,
                                    ack_num=0,
                                    flags=TCP_FLAG_RST,
                                )
                                rst_raw = rst_seg.pack(src_ip=self.interface.ip, dst_ip=target_ip)
                                rst_ip = IPv4Packet(
                                    src_ip=self.interface.ip,
                                    dst_ip=target_ip,
                                    protocol=IP_PROTO_TCP,
                                    payload=rst_raw,
                                )
                                rst_frame = EthernetFrame(
                                    dst_mac=target_mac,
                                    src_mac=self.interface.mac,
                                    ethertype=ETHERTYPE_IPV4,
                                    payload=rst_ip.pack(),
                                )
                                self.interface.send_raw(rst_frame.pack())
                                break
                            elif tcp_resp.flags & TCP_FLAG_RST:
                                status = "closed"
                                break

            results[port] = status

        return results

    def run_full_scan(self, target_ip: str, ports: List[int]) -> None:
        """Execute full Nmap-like diagnostic sweep and print formatted report."""
        print(f"\nStarting PyNmap 1.0 ( Protocol Analysis & Port Scanner )")
        print(f"Scanning target: {target_ip} on ports: {ports}")
        print("-" * 65)

        # 1. ARP Resolution
        mac_str = self.arp_ping(target_ip)
        if not mac_str:
            print(f"[-] Host {target_ip} seems down (ARP discovery failed).")
            return

        from src.layers.ethernet import str_to_mac
        target_mac = str_to_mac(mac_str)
        print(f"[+] Host is up! Resolved MAC: {mac_str}")

        # 2. ICMP Echo Ping
        latency = self.icmp_ping(target_ip, target_mac)
        if latency is not None:
            print(f"[+] ICMP Ping Echo Reply: latency = {latency:.3f} ms")
        else:
            print(f"[*] ICMP Ping: No reply (ICMP filtered or dropped)")

        # 3. TCP SYN Port Scan
        print(f"\nInitiating SYN Stealth Scan (-sS)...")
        results = self.tcp_syn_scan(target_ip, target_mac, ports)

        print("\nPORT       STATE    SERVICE")
        print("---------------------------")
        for port, state in results.items():
            service = COMMON_SERVICES.get(port, "unknown")
            print(f"{port:<10}/tcp {state:<8} {service}")
        print("-" * 65)
        print("Nmap scan complete.\n")
