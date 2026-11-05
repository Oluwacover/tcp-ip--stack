# User-Space TCP/IP Protocol Stack in Python

A complete, byte-level user-space implementation of the **TCP/IP Protocol Suite** written in Python, adhering to RFC standards. Designed with clean modular layer separation, binary packet serialization/deserialization, one's complement Internet checksum algorithms, pseudo-header verification, full TCP state machine management, standard libpcap export, diagnostic tools (Nmap scanner), and Modern RAII socket abstractions.

---

## Architecture Overview

```
+--------------------------------------------------------------------+
|                    Application Layer (HTTP / API)                  |
+---------------------------------+----------------------------------+
                                  |
              +-------------------+--------------------+
              |                                        |
              v                                        v
     [ POSIX Sockets ]                        [ Modern RAII Sockets ]
     - bind / listen / accept                 - Context Manager (__enter__/__exit__)
     - connect / send / recv / close          - Deterministic cleanup & teardown
              |                                        |
              +-------------------+--------------------+
                                  |
+---------------------------------v----------------------------------+
|                    Transport Layer (L4: TCP)                       |
|  - RFC 793 Transmission Control Block (TCB) & Connection States    |
|  - 3-Way Handshake (SYN, SYN-ACK, ACK), Data Streaming & Teardown  |
|  - IPv4 Pseudo-Header Checksum Verification & Calculation          |
+---------------------------------+----------------------------------+
                                  |
+---------------------------------v----------------------------------+
|                 Network Layer (L3: IPv4 & ICMP)                    |
|  - RFC 791 IPv4 Framing, Routing Table (LPM), 16-bit Checksum     |
|  - RFC 792 ICMP Echo Request & Echo Reply (Ping Engine)            |
+---------------------------------+----------------------------------+
                                  |
+---------------------------------v----------------------------------+
|               Data Link Layer (L2: Ethernet & ARP)                 |
|  - IEEE 802.3 Ethernet II Framing (MAC Addressing & EtherTypes)    |
|  - RFC 826 ARP Protocol, Dynamic ARP Cache Table & MAC Resolution  |
+---------------------------------+----------------------------------+
                                  |
+---------------------------------v----------------------------------+
|               Virtual Link Layer & Diagnostics                     |
|  - VirtualWire & UDPBridgeWire (Multi-terminal virtual Ethernet)   |
|  - Libpcap (.pcap) Live Logger for Wireshark / tcpdump analysis   |
|  - PyNmap: ARP Scan (-PR), ICMP Ping (-PE), TCP SYN Stealth (-sS)  |
+--------------------------------------------------------------------+
```

---

## Implemented Protocols & Core Features

### 1. Data Link Layer (Ethernet & ARP)
- **Ethernet II Frames (`src/layers/ethernet.py`)**: 14-byte header packing/unpacking (Dest MAC, Src MAC, EtherType `0x0806` ARP / `0x0800` IPv4), MAC string formatting (`aa:bb:cc:dd:ee:ff`), and broadcast frame routing.
- **ARP Protocol (`src/layers/arp.py`)**: RFC 826 Address Resolution Protocol implementation. Generates ARP Requests (`who-has`) and ARP Replies (`is-at`). Includes a thread-safe `ARPTable` cache supporting dynamic learning and TTL expiration.

### 2. Network Layer (IPv4 & ICMP)
- **IPv4 Datagrams (`src/layers/ipv4.py`)**: RFC 791 20-byte base header parsing, IHL validation, TTL handling, and Longest Prefix Match (LPM) routing table.
- **RFC 791/1071 Internet Checksum**: Pure bitwise 16-bit one's complement sum calculation and residue validation (`verify_checksum()`).
- **ICMP Protocol (`src/layers/icmp.py`)**: RFC 792 Echo Request (Type 8) and Echo Reply (Type 0) generation with ICMP checksum verification and native `stack.ping()` engine.

### 3. Transport Layer (TCP)
- **TCP Segment (`src/layers/tcp.py`)**: RFC 793 header parsing and flag manipulation (`SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`).
- **IPv4 Pseudo-Header Checksum**: RFC 793 TCP checksum algorithm calculating one's complement sum over the pseudo-header (Source IP, Dest IP, Zero, Protocol 6, TCP Length) + TCP header and payload.
- **RFC 793 State Machine**: Manages states (`CLOSED`, `LISTEN`, `SYN_SENT`, `SYN_RECEIVED`, `ESTABLISHED`, `FIN_WAIT_1`, `FIN_WAIT_2`, `CLOSE_WAIT`, `LAST_ACK`, `TIME_WAIT`). Tracks `snd_nxt`, `rcv_nxt`, `snd_una`, window sizes, sequence numbers, and buffering.

### 4. Socket API: POSIX vs Modern RAII
- **`POSIXSocket` (`src/stack/socket_api.py`)**: Classic C-style socket API (`bind()`, `listen()`, `accept()`, `connect()`, `send()`, `recv()`, `close()`).
- **`RAIISocket` (`src/stack/socket_api.py`)**: Modern C++ RAII-inspired design pattern using Python context managers (`with RAIISocket(stack) as sock:`). Guarantees deterministic resource deallocation, socket unbinding, and TCP connection teardown upon scope exit.

### 5. Wireshark, tcpdump & Nmap Tooling
- **PCAP Writer (`src/net/pcap.py`)**: Captures raw frames to standard binary `.pcap` files readable by Wireshark and `tcpdump`.
- **Wireshark Dumper (`src/tools/wireshark_dumper.py`)**: Terminal packet dissector and inspector displaying protocol breakdowns, flags, sequence numbers, and timing.
- **PyNmap Scanner (`src/tools/nmap_scanner.py`)**: Network diagnostic tool executing ARP ping sweeps (`-PR`), ICMP echo latency probes (`-PE`), and raw TCP SYN stealth half-open port scans (`-sS`).

---

## Step-by-Step Instructions

### Step 1: Run the Automated Test Suite

Verify all protocol layers, checksums, state machines, and socket abstractions:

```powershell
python -m unittest tests/test_stack.py -v
```

All 9 test suites will run and pass:
- `test_01_ethernet_serialization`: Ethernet frame serialization & MAC conversions.
- `test_02_arp_packet_and_cache`: ARP Request/Reply round-trip and dynamic cache.
- `test_03_ipv4_checksum_validation`: RFC 791 16-bit Internet checksum calculation & corruption detection.
- `test_04_icmp_echo_request_reply`: ICMP echo payload and checksum verification.
- `test_05_tcp_pseudo_header_checksum`: TCP pseudo-header checksum verification.
- `test_06_stack_arp_and_icmp_ping`: Full round-trip ARP resolution and ICMP ping.
- `test_07_tcp_full_handshake_data_and_teardown`: TCP 3-way handshake, HTTP data stream, and teardown.
- `test_08_raii_socket_context_manager`: Automatic RAII cleanup upon scope exit.
- `test_09_pcap_generation_and_nmap_scan`: PCAP file generation and Nmap SYN stealth scan verification.

---

### Step 2: Run the All-in-One Interactive Terminal Demo

Run the end-to-end demonstration showcasing every bullet point:

```powershell
python run_interactive_demo.py
```

This single command demonstrates:
1. Booting virtual network interfaces for Web Server (`192.168.1.10`) and Client (`192.168.1.20`).
2. Live ARP broadcast discovery and ARP table population.
3. Multi-packet ICMP Ping with millisecond RTT latency tracking.
4. TCP 3-Way Handshake (`SYN` -> `SYN-ACK` -> `ACK`), HTTP request/response exchange, and RAII teardown.
5. Nmap SYN stealth scan probing ports 21, 22, 80, 443, 3306, 8080 (identifying open vs closed ports).
6. Packet dissection table of all captured frames matching Wireshark / `tcpdump`.
7. Saving the session into `demo_capture.pcap`.

---

### Step 3: Run Multi-Process Cross-Terminal Networking

The stack supports cross-process communication over a local virtual Ethernet bridge (`UDPBridgeWire`). You can test this using two or three separate terminal windows:

#### Terminal 1: Start the HTTP Server Stack
```powershell
python demo_server.py
```
*Listens on `192.168.1.10:8080` and begins logging traffic to `server_traffic.pcap`.*

#### Terminal 2: Run the Client
```powershell
python demo_client.py
```
*Resolves MAC via ARP, performs ICMP ping, connects over TCP, and downloads the HTTP response.*

#### Terminal 3: Run the Nmap Port Scanner
```powershell
python demo_scanner.py
```
*Performs an ARP scan, ICMP latency check, and TCP SYN stealth scan against the server.*

#### Terminal 4: Inspect Traffic in Wireshark or via Terminal Dumper
```powershell
python src/tools/wireshark_dumper.py server_traffic.pcap
```
*Or open `server_traffic.pcap` directly in Wireshark GUI or run `tcpdump -r server_traffic.pcap`.*

---

## Project Structure

```
tcp-ip stack/
├── README.md                      # Complete documentation & usage guide
├── requirements.txt               # Dependencies (100% Python standard library)
├── run_interactive_demo.py        # One-command full demonstration
├── demo_server.py                 # Standalone server for multi-terminal demo
├── demo_client.py                 # Standalone client for multi-terminal demo
├── demo_scanner.py                # Standalone Nmap scanner demo
├── src/
│   ├── layers/
│   │   ├── ethernet.py            # L2: Ethernet frame packing/unpacking
│   │   ├── arp.py                 # L2/L3: ARP packet parsing & dynamic cache
│   │   ├── ipv4.py                # L3: IPv4 packet & RFC 791 checksum & LPM routing
│   │   ├── icmp.py                # L3/L4: ICMP Echo Request/Reply & checksum
│   │   └── tcp.py                 # L4: TCP segment, pseudo-header checksum, RFC 793 TCB
│   ├── net/
│   │   ├── interface.py           # VirtualInterface (vNIC with MAC, IP, MTU)
│   │   ├── wire.py                # VirtualWire (switch bus) & UDPBridgeWire (cross-process)
│   │   └── pcap.py                # Libpcap writer for Wireshark compatibility
│   ├── stack/
│   │   ├── tcp_ip_stack.py        # Core protocol demux & orchestrator
│   │   └── socket_api.py          # POSIXSocket & Modern RAIISocket
│   └── tools/
│       ├── nmap_scanner.py        # Nmap-style port scanner (ARP, ICMP, SYN scan)
│       └── wireshark_dumper.py    # Terminal packet dissector and pcap analyzer
└── tests/
    └── test_stack.py              # Automated test suite (9 test suites)
```
