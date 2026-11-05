import os
import tempfile
import time
import unittest

from src.layers.ethernet import (
    EthernetFrame,
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    str_to_mac,
    mac_to_str,
    BROADCAST_MAC,
)
from src.layers.arp import (
    ARPPacket,
    ARPTable,
    ARP_OP_REQUEST,
    ARP_OP_REPLY,
    str_to_ip,
    ip_to_str,
)
from src.layers.ipv4 import (
    IPv4Packet,
    calculate_checksum,
    verify_checksum,
    RoutingTable,
    IP_PROTO_ICMP,
    IP_PROTO_TCP,
)
from src.layers.icmp import (
    ICMPPacket,
    ICMP_TYPE_ECHO_REQUEST,
    ICMP_TYPE_ECHO_REPLY,
)
from src.layers.tcp import (
    TCPSegment,
    TCPState,
    TCP_FLAG_SYN,
    TCP_FLAG_ACK,
    TCP_FLAG_FIN,
    TCP_FLAG_RST,
    compute_tcp_checksum,
    verify_tcp_checksum,
)
from src.net.interface import VirtualInterface
from src.net.wire import VirtualWire
from src.net.pcap import PCAPWriter
from src.stack.tcp_ip_stack import TCPIPStack
from src.stack.socket_api import POSIXSocket, RAIISocket
from src.tools.nmap_scanner import PyNmapScanner
from src.tools.wireshark_dumper import parse_pcap


class TestTCPIPStack(unittest.TestCase):

    def test_01_ethernet_serialization(self):
        src_mac = str_to_mac("00:11:22:33:44:55")
        dst_mac = str_to_mac("66:77:88:99:aa:bb")
        payload = b"Hello Ethernet"

        frame = EthernetFrame(dst_mac=dst_mac, src_mac=src_mac, ethertype=ETHERTYPE_IPV4, payload=payload)
        wire_bytes = frame.pack()
        self.assertEqual(len(wire_bytes), 14 + len(payload))

        unpacked_frame, unpacked_payload = EthernetFrame.unpack(wire_bytes)
        self.assertEqual(unpacked_frame.src_mac, src_mac)
        self.assertEqual(unpacked_frame.dst_mac, dst_mac)
        self.assertEqual(unpacked_frame.ethertype, ETHERTYPE_IPV4)
        self.assertEqual(unpacked_payload, payload)
        self.assertEqual(mac_to_str(unpacked_frame.src_mac), "00:11:22:33:44:55")

    def test_02_arp_packet_and_cache(self):
        sender_mac = str_to_mac("52:54:00:12:34:56")
        sender_ip = "192.168.1.10"
        target_ip = "192.168.1.20"

        req = ARPPacket.create_request(sender_mac=sender_mac, sender_ip=sender_ip, target_ip=target_ip)
        raw_arp = req.pack()
        self.assertEqual(len(raw_arp), 28)

        unpacked_arp, _ = ARPPacket.unpack(raw_arp)
        self.assertEqual(unpacked_arp.opcode, ARP_OP_REQUEST)
        self.assertEqual(ip_to_str(unpacked_arp.sender_ip), sender_ip)
        self.assertEqual(ip_to_str(unpacked_arp.target_ip), target_ip)

        # Test ARP Cache Table
        cache = ARPTable(default_ttl=5.0)
        cache.update("192.168.1.20", str_to_mac("52:54:00:aa:bb:cc"))
        self.assertEqual(cache.lookup("192.168.1.20"), str_to_mac("52:54:00:aa:bb:cc"))
        self.assertIsNone(cache.lookup("192.168.1.99"))

    def test_03_ipv4_checksum_validation(self):
        payload = b"Sample IPv4 Payload"
        pkt = IPv4Packet(
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            protocol=IP_PROTO_TCP,
            payload=payload,
        )
        raw_ip = pkt.pack()
        self.assertTrue(len(raw_ip) >= 20 + len(payload))

        # Should unpack and validate checksum cleanly
        unpacked_pkt, unpacked_payload = IPv4Packet.unpack(raw_ip)
        self.assertEqual(unpacked_pkt.src_ip, "192.168.1.10")
        self.assertEqual(unpacked_pkt.dst_ip, "192.168.1.20")
        self.assertEqual(unpacked_payload, payload)

        # Corrupt one byte in header and verify checksum fails
        corrupted = bytearray(raw_ip)
        corrupted[10] ^= 0xFF  # corrupt checksum field
        with self.assertRaises(ValueError):
            IPv4Packet.unpack(bytes(corrupted))

    def test_04_icmp_echo_request_reply(self):
        req = ICMPPacket.create_echo_request(ident=42, seq=7, payload=b"ping-payload")
        raw_icmp = req.pack()

        unpacked_req, unpacked_payload = ICMPPacket.unpack(raw_icmp)
        self.assertEqual(unpacked_req.icmp_type, ICMP_TYPE_ECHO_REQUEST)
        self.assertEqual(unpacked_req.ident, 42)
        self.assertEqual(unpacked_req.seq, 7)
        self.assertEqual(unpacked_payload, b"ping-payload")

        reply = ICMPPacket.create_echo_reply(ident=unpacked_req.ident, seq=unpacked_req.seq, payload=unpacked_payload)
        raw_reply = reply.pack()
        unpacked_reply, _ = ICMPPacket.unpack(raw_reply)
        self.assertEqual(unpacked_reply.icmp_type, ICMP_TYPE_ECHO_REPLY)
        self.assertEqual(unpacked_reply.ident, 42)
        self.assertEqual(unpacked_reply.seq, 7)

    def test_05_tcp_pseudo_header_checksum(self):
        src_ip = "192.168.1.10"
        dst_ip = "192.168.1.20"
        payload = b"GET / HTTP/1.1\r\n\r\n"

        seg = TCPSegment(
            src_port=12345,
            dst_port=80,
            seq_num=1000,
            ack_num=0,
            flags=TCP_FLAG_SYN,
            payload=payload,
        )
        raw_tcp = seg.pack(src_ip=src_ip, dst_ip=dst_ip)

        unpacked_seg, unpacked_payload = TCPSegment.unpack(raw_tcp, src_ip, dst_ip, validate_cksum=True)
        self.assertEqual(unpacked_seg.src_port, 12345)
        self.assertEqual(unpacked_seg.dst_port, 80)
        self.assertEqual(unpacked_seg.seq_num, 1000)
        self.assertEqual(unpacked_payload, payload)

        # Checksum with wrong IP must fail
        with self.assertRaises(ValueError):
            TCPSegment.unpack(raw_tcp, "10.0.0.1", dst_ip, validate_cksum=True)

    def test_06_stack_arp_and_icmp_ping(self):
        wire = VirtualWire()

        iface_a = VirtualInterface(name="ethA", mac="52:54:00:00:00:01", ip="192.168.1.1")
        iface_b = VirtualInterface(name="ethB", mac="52:54:00:00:00:02", ip="192.168.1.2")

        iface_a.attach_wire(wire)
        iface_b.attach_wire(wire)

        stack_a = TCPIPStack(iface_a, name="StackA")
        stack_b = TCPIPStack(iface_b, name="StackB")

        stack_a.start()
        stack_b.start()

        try:
            # 1. ARP Resolution: Stack A resolves Stack B's MAC
            resolved_mac = stack_a.resolve_mac("192.168.1.2", timeout=1.0)
            self.assertEqual(resolved_mac, iface_b.mac)

            # 2. ICMP Ping from Stack A to Stack B
            latency = stack_a.ping("192.168.1.2", timeout=1.0)
            self.assertIsNotNone(latency)
            self.assertGreater(latency, 0.0)
        finally:
            stack_a.stop()
            stack_b.stop()

    def test_07_tcp_full_handshake_data_and_teardown(self):
        wire = VirtualWire()

        server_iface = VirtualInterface(name="srv", mac="52:54:00:11:11:11", ip="192.168.1.10")
        client_iface = VirtualInterface(name="cli", mac="52:54:00:22:22:22", ip="192.168.1.20")

        server_iface.attach_wire(wire)
        client_iface.attach_wire(wire)

        server_stack = TCPIPStack(server_iface, name="ServerStack")
        client_stack = TCPIPStack(client_iface, name="ClientStack")

        server_stack.start()
        client_stack.start()

        try:
            # Server listens on port 8080
            server_sock = POSIXSocket(server_stack)
            server_sock.bind(("192.168.1.10", 8080))
            server_sock.listen()

            # Client connects to 192.168.1.10:8080
            client_sock = POSIXSocket(client_stack)
            client_sock.connect(("192.168.1.10", 8080), timeout=2.0)

            # Accept on server
            conn_sock, client_addr = server_sock.accept(timeout=2.0)
            self.assertEqual(client_addr[0], "192.168.1.20")
            self.assertEqual(client_sock.conn.state, TCPState.ESTABLISHED)
            self.assertEqual(conn_sock.conn.state, TCPState.ESTABLISHED)

            # Client sends data to server
            msg_to_server = b"GET /index.html HTTP/1.1\r\nHost: stack\r\n\r\n"
            client_sock.send(msg_to_server)

            # Server receives data
            received_by_server = conn_sock.recv(timeout=2.0)
            self.assertEqual(received_by_server, msg_to_server)

            # Server replies to client
            reply_to_client = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHELLO"
            conn_sock.send(reply_to_client)

            # Client receives reply
            received_by_client = client_sock.recv(timeout=2.0)
            self.assertEqual(received_by_client, reply_to_client)

            # Client teardown
            client_sock.close()
            time.sleep(0.05)
            conn_sock.close()
            server_sock.close()

        finally:
            server_stack.stop()
            client_stack.stop()

    def test_08_raii_socket_context_manager(self):
        wire = VirtualWire()
        iface = VirtualInterface(name="eth0", ip="192.168.1.50")
        iface.attach_wire(wire)
        stack = TCPIPStack(iface)
        stack.start()

        try:
            with RAIISocket(stack) as sock:
                sock.bind(("192.168.1.50", 9000))
                sock.listen()
                self.assertIn(("192.168.1.50", 9000), stack.listeners)

            # Exiting with block must automatically unbind and close
            self.assertNotIn(("192.168.1.50", 9000), stack.listeners)
        finally:
            stack.stop()

    def test_09_pcap_generation_and_nmap_scan(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            pcap_path = tf.name

        try:
            pcap = PCAPWriter(pcap_path)
            wire = VirtualWire(pcap_writer=pcap)

            target_iface = VirtualInterface(name="target", mac="52:54:00:33:33:33", ip="192.168.1.100")
            scanner_iface = VirtualInterface(name="scan", mac="52:54:00:44:44:44", ip="192.168.1.200")

            target_iface.attach_wire(wire)
            scanner_iface.attach_wire(wire)

            target_stack = TCPIPStack(target_iface, name="TargetStack")
            target_stack.start()

            # Open port 8080 on target
            srv = POSIXSocket(target_stack)
            srv.bind(("192.168.1.100", 8080))
            srv.listen()

            # Run Nmap SYN scan from scanner interface
            scanner = PyNmapScanner(scanner_iface)
            results = scanner.tcp_syn_scan(
                target_ip="192.168.1.100",
                target_mac=target_iface.mac,
                ports=[22, 8080, 443],
                timeout=0.5,
            )

            self.assertEqual(results[8080], "open")
            self.assertEqual(results[22], "closed")
            self.assertEqual(results[443], "closed")

            srv.close()
            target_stack.stop()
            pcap.close()

            # Verify PCAP file contains packets
            packets = list(parse_pcap(pcap_path))
            self.assertGreater(len(packets), 0)

        finally:
            if os.path.exists(pcap_path):
                os.remove(pcap_path)


if __name__ == "__main__":
    unittest.main()
