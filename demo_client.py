#!/usr/bin/env python3
"""
Standalone TCP/IP Stack Client.
Can be run in Terminal 2 while demo_server.py is running in Terminal 1.
"""

import time
from src.layers.ethernet import mac_to_str
from src.net.interface import VirtualInterface
from src.net.wire import UDPBridgeWire
from src.stack.tcp_ip_stack import TCPIPStack
from src.stack.socket_api import RAIISocket


def main():
    print("=" * 70)
    print("       USER-SPACE TCP/IP STACK: CLIENT (TERMINAL 2)            ")
    print("=" * 70)

    # Listen on UDP 15001, peer is 15000
    wire = UDPBridgeWire(listen_port=15001, peer_port=15000)

    iface = VirtualInterface(
        name="eth1",
        mac="52:54:00:ab:cd:ef",
        ip="192.168.1.20",
        netmask="255.255.255.0",
    )
    iface.attach_wire(wire)

    stack = TCPIPStack(iface, name="ClientStack")
    stack.start()

    print(f"[*] Virtual NIC: {iface.name} | MAC: {mac_to_str(iface.mac)} | IP: {iface.ip}")
    print(f"[*] Bridged via UDP port 15001 <-> 15000\n")

    # Step 1: ARP Resolution
    print("[1] Resolving 192.168.1.10 via ARP...")
    mac = stack.resolve_mac("192.168.1.10", timeout=2.0)
    if not mac:
        print("[-] Server 192.168.1.10 not found. Is demo_server.py running in Terminal 1?")
        stack.stop()
        wire.close()
        return

    print(f"[+] ARP Resolution Success! 192.168.1.10 is at {mac_to_str(mac)}")

    # Step 2: Ping
    print("\n[2] Sending ICMP Pings to 192.168.1.10...")
    for seq in range(1, 4):
        latency = stack.ping("192.168.1.10", timeout=1.0)
        if latency is not None:
            print(f"    64 bytes from 192.168.1.10: icmp_seq={seq} time={latency:.3f} ms")
        else:
            print(f"    Request timeout for icmp_seq={seq}")
        time.sleep(0.1)

    # Step 3: Modern RAII Socket TCP Request
    print("\n[3] Connecting to http://192.168.1.10:8080 via Modern RAII Socket...")
    with RAIISocket(stack) as sock:
        sock.connect(("192.168.1.10", 8080))
        print(f"[+] Connected! TCP State: {sock.conn.state.value}")

        http_req = b"GET / HTTP/1.1\r\nHost: 192.168.1.10\r\nUser-Agent: PyTCPStackClient/1.0\r\n\r\n"
        print(f"[*] Sending HTTP request ({len(http_req)} bytes)...")
        sock.send(http_req)

        print("[*] Waiting for response...")
        response = sock.recv(4096, timeout=2.0)
        print("\n--- [SERVER RESPONSE] ---")
        print(response.decode(errors="replace").strip())
        print("-------------------------\n")

        print("[*] Leaving 'with' block -> Automatic RAII socket closure and FIN-ACK handshake.")

    stack.stop()
    wire.close()
    print("[+] Done!")


if __name__ == "__main__":
    main()
