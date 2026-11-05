#!/usr/bin/env python3
"""
Standalone Nmap-style Protocol Scanner against demo_server.py.
Can be run in Terminal 2 or 3 while demo_server.py is running.
"""

from src.net.interface import VirtualInterface
from src.net.wire import UDPBridgeWire
from src.tools.nmap_scanner import PyNmapScanner


def main():
    print("=" * 70)
    print("       USER-SPACE TCP/IP STACK: NMAP SCANNER                   ")
    print("=" * 70)

    # Listen on UDP 15001 (or probe port), peer is 15000 (demo_server)
    wire = UDPBridgeWire(listen_port=15001, peer_port=15000)

    iface = VirtualInterface(
        name="eth_scan",
        mac="52:54:00:ee:ff:00",
        ip="192.168.1.99",
        netmask="255.255.255.0",
    )
    iface.attach_wire(wire)

    scanner = PyNmapScanner(iface)
    target_ip = "192.168.1.10"
    target_ports = [21, 22, 53, 80, 443, 3306, 8080, 8443]

    scanner.run_full_scan(target_ip, target_ports)
    wire.close()


if __name__ == "__main__":
    main()
