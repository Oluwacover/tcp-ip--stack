#!/usr/bin/env python3
"""
Standalone TCP/IP Stack HTTP Server.
Can be run in Terminal 1.
Communicates with other terminal processes via the UDP virtual Ethernet bridge.
"""

import sys
import time
from src.layers.ethernet import mac_to_str
from src.net.interface import VirtualInterface
from src.net.wire import UDPBridgeWire
from src.net.pcap import PCAPWriter
from src.stack.tcp_ip_stack import TCPIPStack
from src.stack.socket_api import POSIXSocket, RAIISocket


def main():
    print("=" * 70)
    print("       USER-SPACE TCP/IP STACK: HTTP SERVER (TERMINAL 1)       ")
    print("=" * 70)

    pcap_writer = PCAPWriter("server_traffic.pcap")
    # Listen on UDP 15000, forward to peer on UDP 15001
    wire = UDPBridgeWire(listen_port=15000, peer_port=15001, pcap_writer=pcap_writer)

    iface = VirtualInterface(
        name="eth0",
        mac="52:54:00:12:34:56",
        ip="192.168.1.10",
        netmask="255.255.255.0",
    )
    iface.attach_wire(wire)

    stack = TCPIPStack(iface, name="ServerStack")
    stack.start()

    print(f"[*] Virtual NIC: {iface.name} | MAC: {mac_to_str(iface.mac)} | IP: {iface.ip}")
    print(f"[*] Virtual Wire: Bridged via UDP port 15000 <-> 15001")
    print(f"[*] Traffic Logging: server_traffic.pcap (Wireshark ready)")

    # Start TCP Server on 192.168.1.10:8080
    with RAIISocket(stack) as server_sock:
        server_sock.bind(("192.168.1.10", 8080))
        server_sock.listen()
        print(f"\n[+] HTTP Server is LISTENING on http://192.168.1.10:8080")
        print("[*] Ready to accept ping, Nmap scans, and TCP HTTP connections.")
        print("[*] Press Ctrl+C to stop.\n")

        try:
            while True:
                try:
                    conn_sock, client_addr = server_sock.accept(timeout=1.0)
                except TimeoutError:
                    continue

                print(f"[+] [TCP 3-Way Handshake OK] Accepted connection from {client_addr[0]}:{client_addr[1]}")

                with conn_sock:
                    req_bytes = conn_sock.recv(4096, timeout=2.0)
                    if req_bytes:
                        first_line = req_bytes.decode(errors="replace").split("\r\n")[0]
                        print(f"    <- Received Request: {first_line}")

                        response = (
                            b"HTTP/1.1 200 OK\r\n"
                            b"Server: PyTCPIPStack/1.0\r\n"
                            b"Content-Type: text/plain\r\n"
                            b"Connection: close\r\n"
                            b"\r\n"
                            b"Hello from Custom Python TCP/IP Stack!\n"
                        )
                        conn_sock.send(response)
                        print(f"    -> Sent HTTP 200 OK ({len(response)} bytes)")

                print(f"[-] Connection with {client_addr[0]}:{client_addr[1]} closed.\n")

        except KeyboardInterrupt:
            print("\n[*] Shutting down server...")

    stack.stop()
    wire.close()
    pcap_writer.close()
    print("[+] Server stopped. PCAP traffic saved to 'server_traffic.pcap'.")


if __name__ == "__main__":
    main()
