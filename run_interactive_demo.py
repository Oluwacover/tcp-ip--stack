#!/usr/bin/env python3
"""
Interactive Demonstration of the User-Space TCP/IP Protocol Stack in Python.
Demonstrates:
  1. Ethernet Frame framing and MAC addressing
  2. ARP Address Resolution and dynamic ARP Cache
  3. IPv4 Datagram routing and RFC 791 Checksum calculation/validation
  4. ICMP Echo Request & Echo Reply (Ping)
  5. Modern RAII Sockets vs POSIX Sockets
  6. TCP 3-Way Handshake, Full-Duplex Data Transmission, and Teardown
  7. Nmap-style TCP SYN Stealth Port Scan (-sS)
  8. Libpcap packet capture and terminal Wireshark/tcpdump packet dissection
"""

import os
import sys
import time

from src.layers.ethernet import mac_to_str
from src.layers.tcp import TCPState
from src.net.interface import VirtualInterface
from src.net.wire import VirtualWire
from src.net.pcap import PCAPWriter
from src.stack.tcp_ip_stack import TCPIPStack
from src.stack.socket_api import POSIXSocket, RAIISocket
from src.tools.nmap_scanner import PyNmapScanner
from src.tools.wireshark_dumper import print_pcap_summary


def banner(title: str):
    print("\n" + "=" * 80)
    print(f" >>> {title}")
    print("=" * 80)


def main():
    pcap_file = "demo_capture.pcap"
    if os.path.exists(pcap_file):
        os.remove(pcap_file)

    pcap_writer = PCAPWriter(pcap_file)
    wire = VirtualWire(pcap_writer=pcap_writer)

    banner("STEP 1: INITIALIZING VIRTUAL NETWORK INTERFACES & STACKS")

    # Host A: Web Server Stack (192.168.1.10)
    iface_server = VirtualInterface(
        name="eth0",
        mac="52:54:00:12:34:56",
        ip="192.168.1.10",
        netmask="255.255.255.0",
    )
    iface_server.attach_wire(wire)
    server_stack = TCPIPStack(iface_server, name="WebServer")
    server_stack.start()
    print(f"[*] Booted WebServer Stack on {iface_server.name}: IP={iface_server.ip}, MAC={mac_to_str(iface_server.mac)}")

    # Host B: Client Stack (192.168.1.20)
    iface_client = VirtualInterface(
        name="eth1",
        mac="52:54:00:ab:cd:ef",
        ip="192.168.1.20",
        netmask="255.255.255.0",
    )
    iface_client.attach_wire(wire)
    client_stack = TCPIPStack(iface_client, name="ClientHost")
    client_stack.start()
    print(f"[*] Booted ClientHost Stack on {iface_client.name}: IP={iface_client.ip}, MAC={mac_to_str(iface_client.mac)}")

    time.sleep(0.1)

    banner("STEP 2: ARP ADDRESS RESOLUTION PROTOCOL (RFC 826)")
    print("[*] Client wants to communicate with 192.168.1.10, but its MAC is unknown.")
    print("[*] Client broadcasts ARP Request: 'Who has 192.168.1.10? Tell 192.168.1.20'...")
    resolved_mac = client_stack.resolve_mac("192.168.1.10", timeout=1.0)
    print(f"[+] Server responded with ARP Reply!")
    print(f"[+] Client ARP Cache updated: 192.168.1.10 -> {mac_to_str(resolved_mac)}")

    banner("STEP 3: ICMP ECHO REQUEST & REPLY (PING - RFC 792)")
    print("[*] Client sending ICMP Echo Request to 192.168.1.10...")
    for seq in range(1, 4):
        latency = client_stack.ping("192.168.1.10", timeout=1.0)
        print(f"    64 bytes from 192.168.1.10: icmp_seq={seq} rtt={latency:.3f} ms")
        time.sleep(0.05)

    banner("STEP 4: MODERN RAII TCP SERVER & CLIENT (RFC 793)")
    print("[*] Starting TCP HTTP Server on 192.168.1.10:8080 using Modern RAII Sockets...")

    # Server listening socket
    server_sock = POSIXSocket(server_stack)
    server_sock.bind(("192.168.1.10", 8080))
    server_sock.listen()
    print("[+] Server socket bound to 192.168.1.10:8080 (Listening for connections)")

    # Client connects using RAII context manager
    print("[*] Client initiating TCP 3-Way Handshake (SYN -> SYN-ACK -> ACK)...")
    with RAIISocket(client_stack) as client:
        client.connect(("192.168.1.10", 8080))
        print(f"[+] Handshake complete! Client connection state: {client.conn.state.value}")

        # Server accepts
        server_conn_sock, client_addr = server_sock.accept(timeout=1.0)
        print(f"[+] Server accepted incoming connection from {client_addr[0]}:{client_addr[1]}")

        # Client sends HTTP GET request
        http_request = b"GET /api/status HTTP/1.1\r\nHost: 192.168.1.10\r\nUser-Agent: PyTCPStack/1.0\r\n\r\n"
        print(f"\n[Client -> Server] Transmitting {len(http_request)} bytes HTTP Request:")
        print("    " + http_request.decode().replace("\r\n", "\n    ").strip())
        client.send(http_request)

        # Server receives and parses
        received_data = server_conn_sock.recv(4096, timeout=1.0)
        print(f"\n[Server <- Client] Received {len(received_data)} bytes:")
        print("    " + received_data.decode().replace("\r\n", "\n    ").strip())

        # Server sends HTTP 200 OK Response
        http_response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Connection: close\r\n"
            b"\r\n"
            b'{"status": "ok", "stack": "Custom Python TCP/IP", "protocols": ["ETH", "ARP", "IP", "ICMP", "TCP"]}\n'
        )
        print(f"\n[Server -> Client] Sending {len(http_response)} bytes HTTP Response:")
        print("    " + http_response.decode().replace("\r\n", "\n    ").strip())
        server_conn_sock.send(http_response)

        # Client receives response
        response_data = client.recv(4096, timeout=1.0)
        print(f"\n[Client <- Server] Received {len(response_data)} bytes payload:")
        print("    " + response_data.decode().replace("\r\n", "\n    ").strip())

        print("\n[*] Exiting RAII scope -> automatically triggers graceful TCP FIN-ACK connection teardown...")

    server_conn_sock.close()
    server_sock.close()
    time.sleep(0.1)

    banner("STEP 5: NMAP-STYLE TCP SYN STEALTH SCAN (-sS)")
    # Host C: Scanner
    iface_scanner = VirtualInterface(
        name="eth2",
        mac="52:54:00:99:88:77",
        ip="192.168.1.99",
        netmask="255.255.255.0",
    )
    iface_scanner.attach_wire(wire)

    # Re-open port 8080 on the server so Nmap can probe it
    srv_probe = POSIXSocket(server_stack)
    srv_probe.bind(("192.168.1.10", 8080))
    srv_probe.listen()

    scanner = PyNmapScanner(iface_scanner)
    target_ports = [21, 22, 80, 443, 3306, 8080]
    scanner.run_full_scan("192.168.1.10", target_ports)

    srv_probe.close()
    server_stack.stop()
    client_stack.stop()
    pcap_writer.close()

    banner("STEP 6: WIRESHARK & TCPDUMP PACKET DISSECTION")
    print(f"[*] Analyzing captured packets saved to '{pcap_file}'...")
    print_pcap_summary(pcap_file)

    banner("ALL DEMONSTRATION STEPS COMPLETED SUCCESSFULLY!")
    print(f"[+] PCAP file saved: {os.path.abspath(pcap_file)}")
    print("[+] You can open this file anytime in Wireshark or with tcpdump -r demo_capture.pcap")


if __name__ == "__main__":
    main()
