import logging
import queue
import socket
import threading
import time
from typing import Dict, Optional, Tuple, Callable

from src.layers.ethernet import (
    EthernetFrame,
    ETHERTYPE_ARP,
    ETHERTYPE_IPV4,
    BROADCAST_MAC,
    mac_to_str,
    str_to_mac,
)
from src.layers.arp import (
    ARPPacket,
    ARPTable,
    ARP_OP_REQUEST,
    ARP_OP_REPLY,
    ip_to_str,
    str_to_ip,
)
from src.layers.ipv4 import (
    IPv4Packet,
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
    TCPConnection,
    TCPState,
    TCP_FLAG_SYN,
    TCP_FLAG_ACK,
    TCP_FLAG_FIN,
    TCP_FLAG_RST,
    TCP_FLAG_PSH,
    flags_to_str,
)
from src.net.interface import VirtualInterface

logger = logging.getLogger("TCPIPStack")


class TCPIPStack:
    """
    User-space TCP/IP Protocol Stack.
    Implements Ethernet, ARP, IPv4, ICMP, and TCP protocols.
    """
    def __init__(self, interface: VirtualInterface, name: str = "HostStack"):
        self.name = name
        self.interface = interface
        self.arp_table = ARPTable()
        self.routing_table = RoutingTable()

        # Add direct subnet route for local interface
        self.routing_table.add_route(
            dest_net=interface.ip,
            netmask=interface.netmask,
            gateway=None,
            interface_name=interface.name,
        )

        # Active TCP connections: (local_ip, local_port, remote_ip, remote_port) -> TCPConnection
        self.connections: Dict[Tuple[str, int, str, int], TCPConnection] = {}
        # Listening sockets: (local_ip, local_port) -> StackSocket
        self.listeners: Dict[Tuple[str, int], "StackSocket"] = {}

        self.running = False
        self._thread = None
        self._lock = threading.Lock()

        # Stats counters
        self.stats = {
            "rx_frames": 0,
            "tx_frames": 0,
            "rx_arp": 0,
            "tx_arp": 0,
            "rx_ip": 0,
            "tx_ip": 0,
            "rx_icmp": 0,
            "tx_icmp": 0,
            "rx_tcp": 0,
            "tx_tcp": 0,
        }
        self._pending_pings: Dict[int, Tuple[float, threading.Event, list]] = {}

    def start(self) -> None:
        """Start the protocol processing event loop in a background thread."""
        self.running = True
        self._thread = threading.Thread(target=self._run_loop, name=f"{self.name}-Worker", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop stack execution."""
        self.running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)

    def _run_loop(self) -> None:
        """Continuously poll interface for incoming frames."""
        while self.running:
            raw_frame = self.interface.recv_raw(timeout=0.05)
            if raw_frame:
                try:
                    self._process_ethernet(raw_frame)
                except Exception as e:
                    logger.debug(f"[{self.name}] Error processing frame: {e}")

    # =========================================================================
    # Layer 2: Ethernet Processing
    # =========================================================================
    def _process_ethernet(self, raw_frame: bytes) -> None:
        self.stats["rx_frames"] += 1
        eth_frame, payload = EthernetFrame.unpack(raw_frame)

        if eth_frame.ethertype == ETHERTYPE_ARP:
            self._process_arp(eth_frame, payload)
        elif eth_frame.ethertype == ETHERTYPE_IPV4:
            self._process_ipv4(eth_frame, payload)

    def send_ethernet(self, dst_mac: bytes, ethertype: int, payload: bytes) -> None:
        """Send an Ethernet frame out onto the virtual interface."""
        frame = EthernetFrame(
            dst_mac=dst_mac,
            src_mac=self.interface.mac,
            ethertype=ethertype,
            payload=payload,
        )
        self.stats["tx_frames"] += 1
        self.interface.send_raw(frame.pack())

    # =========================================================================
    # ARP Processing (RFC 826)
    # =========================================================================
    def _process_arp(self, eth_frame: EthernetFrame, payload: bytes) -> None:
        self.stats["rx_arp"] += 1
        arp_pkt, _ = ARPPacket.unpack(payload)
        sender_ip = ip_to_str(arp_pkt.sender_ip)
        target_ip = ip_to_str(arp_pkt.target_ip)

        # Learn sender MAC in ARP cache
        self.arp_table.update(sender_ip, arp_pkt.sender_mac)

        if arp_pkt.opcode == ARP_OP_REQUEST:
            # If the request is for our interface IP, send an ARP Reply
            if target_ip == self.interface.ip:
                reply_pkt = ARPPacket.create_reply(
                    sender_mac=self.interface.mac,
                    sender_ip=self.interface.ip,
                    target_mac=arp_pkt.sender_mac,
                    target_ip=sender_ip,
                )
                self.stats["tx_arp"] += 1
                self.send_ethernet(
                    dst_mac=arp_pkt.sender_mac,
                    ethertype=ETHERTYPE_ARP,
                    payload=reply_pkt.pack(),
                )

    def resolve_mac(self, ip_str: str, timeout: float = 0.5) -> Optional[bytes]:
        """Resolve IP address to MAC address using ARP table or sending an ARP Request."""
        mac = self.arp_table.lookup(ip_str)
        if mac:
            return mac

        # Broadcast ARP Request
        req_pkt = ARPPacket.create_request(
            sender_mac=self.interface.mac,
            sender_ip=self.interface.ip,
            target_ip=ip_str,
        )
        self.stats["tx_arp"] += 1
        self.send_ethernet(
            dst_mac=BROADCAST_MAC,
            ethertype=ETHERTYPE_ARP,
            payload=req_pkt.pack(),
        )

        start = time.time()
        while time.time() - start < timeout:
            mac = self.arp_table.lookup(ip_str)
            if mac:
                return mac
            time.sleep(0.01)
        return None

    # =========================================================================
    # Layer 3: IPv4 Processing (RFC 791)
    # =========================================================================
    def _process_ipv4(self, eth_frame: EthernetFrame, payload: bytes) -> None:
        self.stats["rx_ip"] += 1
        try:
            ip_pkt, ip_payload = IPv4Packet.unpack(payload)
        except Exception:
            return

        # Learn sender MAC from Ethernet header
        self.arp_table.update(ip_pkt.src_ip, eth_frame.src_mac)

        # Drop packet if not addressed to our IP and not broadcast
        if ip_pkt.dst_ip != self.interface.ip and ip_pkt.dst_ip != "255.255.255.255":
            return

        if ip_pkt.protocol == IP_PROTO_ICMP:
            self._process_icmp(ip_pkt, ip_payload)
        elif ip_pkt.protocol == IP_PROTO_TCP:
            self._process_tcp(ip_pkt, ip_payload)

    def send_ipv4(self, dst_ip: str, protocol: int, payload: bytes) -> None:
        """Encapsulate payload into IPv4 and send via resolved MAC."""
        dst_mac = self.resolve_mac(dst_ip)
        if not dst_mac:
            logger.warning(f"[{self.name}] Failed to resolve MAC for {dst_ip}")
            return

        ip_pkt = IPv4Packet(
            src_ip=self.interface.ip,
            dst_ip=dst_ip,
            protocol=protocol,
            payload=payload,
        )
        self.stats["tx_ip"] += 1
        self.send_ethernet(dst_mac=dst_mac, ethertype=ETHERTYPE_IPV4, payload=ip_pkt.pack())

    # =========================================================================
    # ICMP Processing (RFC 792)
    # =========================================================================
    def _process_icmp(self, ip_pkt: IPv4Packet, payload: bytes) -> None:
        self.stats["rx_icmp"] += 1
        try:
            icmp_pkt, _ = ICMPPacket.unpack(payload)
        except Exception:
            return

        if icmp_pkt.icmp_type == ICMP_TYPE_ECHO_REQUEST:
            # Echo Reply (Ping response)
            reply = ICMPPacket.create_echo_reply(
                ident=icmp_pkt.ident,
                seq=icmp_pkt.seq,
                payload=icmp_pkt.payload,
            )
            self.stats["tx_icmp"] += 1
            self.send_ipv4(dst_ip=ip_pkt.src_ip, protocol=IP_PROTO_ICMP, payload=reply.pack())
        elif icmp_pkt.icmp_type == ICMP_TYPE_ECHO_REPLY:
            waiter = self._pending_pings.get(icmp_pkt.ident)
            if waiter:
                t0, event, result_holder = waiter
                rtt_ms = (time.perf_counter() - t0) * 1000.0
                result_holder.append(rtt_ms)
                event.set()

    def ping(self, dst_ip: str, timeout: float = 1.0) -> Optional[float]:
        """Send an ICMP Echo Request and wait for Echo Reply. Returns round-trip time in milliseconds."""
        import random
        ident = random.randint(1, 65535)
        event = threading.Event()
        result_holder = []
        t0 = time.perf_counter()
        self._pending_pings[ident] = (t0, event, result_holder)

        req = ICMPPacket.create_echo_request(ident=ident, seq=1)
        self.stats["tx_icmp"] += 1
        self.send_ipv4(dst_ip=dst_ip, protocol=IP_PROTO_ICMP, payload=req.pack())

        if event.wait(timeout=timeout):
            self._pending_pings.pop(ident, None)
            return result_holder[0] if result_holder else 0.0

        self._pending_pings.pop(ident, None)
        return None

    # =========================================================================
    # Layer 4: TCP Processing (RFC 793)
    # =========================================================================
    def _process_tcp(self, ip_pkt: IPv4Packet, payload: bytes) -> None:
        self.stats["rx_tcp"] += 1
        try:
            tcp_seg, seg_payload = TCPSegment.unpack(
                raw=payload,
                src_ip=ip_pkt.src_ip,
                dst_ip=ip_pkt.dst_ip,
                validate_cksum=True,
            )
        except Exception:
            return

        src_ip = ip_pkt.src_ip
        src_port = tcp_seg.src_port
        dst_ip = ip_pkt.dst_ip
        dst_port = tcp_seg.dst_port

        conn_key = (dst_ip, dst_port, src_ip, src_port)
        conn = self.connections.get(conn_key)

        if conn is not None:
            self._handle_conn_packet(conn, tcp_seg, seg_payload)
            return

        # Check for listening socket
        listener = self.listeners.get((dst_ip, dst_port)) or self.listeners.get(("0.0.0.0", dst_port))
        if listener is not None:
            if tcp_seg.flags & TCP_FLAG_SYN and not (tcp_seg.flags & TCP_FLAG_ACK):
                # New incoming connection handshake
                server_isn = 50000 + (int(time.time() * 1000) % 10000)
                new_conn = TCPConnection(
                    local_ip=dst_ip,
                    local_port=dst_port,
                    remote_ip=src_ip,
                    remote_port=src_port,
                    initial_state=TCPState.SYN_RECEIVED,
                    isn=server_isn,
                )
                new_conn.irs = tcp_seg.seq_num
                new_conn.rcv_nxt = tcp_seg.seq_num + 1

                self.connections[conn_key] = new_conn

                # Send SYN-ACK
                syn_ack = new_conn.make_segment(
                    flags=TCP_FLAG_SYN | TCP_FLAG_ACK,
                    seq_num=new_conn.snd_una,
                    ack_num=new_conn.rcv_nxt,
                )
                self.send_tcp_segment(new_conn, syn_ack)
                listener._pending_connections[conn_key] = new_conn
                return

        # If not listening and not an existing connection, respond with RST if not already RST
        if not (tcp_seg.flags & TCP_FLAG_RST):
            self._send_rst(ip_pkt, tcp_seg)

    def _handle_conn_packet(self, conn: TCPConnection, seg: TCPSegment, payload: bytes) -> None:
        """Handle incoming TCP segment for an established or transitioning connection."""
        if seg.flags & TCP_FLAG_RST:
            conn.transition_to(TCPState.CLOSED)
            return

        if conn.state == TCPState.SYN_RECEIVED:
            if seg.flags & TCP_FLAG_ACK:
                conn.snd_una = seg.ack_num
                conn.transition_to(TCPState.ESTABLISHED)
                listener = self.listeners.get((conn.local_ip, conn.local_port)) or self.listeners.get(("0.0.0.0", conn.local_port))
                if listener:
                    listener._accept_queue.put(conn)

        elif conn.state == TCPState.SYN_SENT:
            if (seg.flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK):
                conn.irs = seg.seq_num
                conn.rcv_nxt = seg.seq_num + 1
                conn.snd_una = seg.ack_num
                conn.transition_to(TCPState.ESTABLISHED)
                # Send ACK
                ack_seg = conn.make_segment(flags=TCP_FLAG_ACK, seq_num=conn.snd_nxt, ack_num=conn.rcv_nxt)
                self.send_tcp_segment(conn, ack_seg)

        elif conn.state == TCPState.ESTABLISHED:
            # Handle incoming data
            if payload:
                conn.recv_buf.extend(payload)
                conn.rcv_nxt += len(payload)
                # Acknowledge data
                ack_seg = conn.make_segment(flags=TCP_FLAG_ACK, seq_num=conn.snd_nxt, ack_num=conn.rcv_nxt)
                self.send_tcp_segment(conn, ack_seg)

            # Handle peer FIN (passive close)
            if seg.flags & TCP_FLAG_FIN:
                conn.rcv_nxt += 1
                conn.transition_to(TCPState.CLOSE_WAIT)
                ack_seg = conn.make_segment(flags=TCP_FLAG_ACK, seq_num=conn.snd_nxt, ack_num=conn.rcv_nxt)
                self.send_tcp_segment(conn, ack_seg)

        elif conn.state == TCPState.FIN_WAIT_1:
            if seg.flags & TCP_FLAG_ACK:
                conn.transition_to(TCPState.FIN_WAIT_2)
            if seg.flags & TCP_FLAG_FIN:
                conn.rcv_nxt += 1
                ack_seg = conn.make_segment(flags=TCP_FLAG_ACK, seq_num=conn.snd_nxt, ack_num=conn.rcv_nxt)
                self.send_tcp_segment(conn, ack_seg)
                conn.transition_to(TCPState.TIME_WAIT)
                conn.transition_to(TCPState.CLOSED)

        elif conn.state == TCPState.FIN_WAIT_2:
            if seg.flags & TCP_FLAG_FIN:
                conn.rcv_nxt += 1
                ack_seg = conn.make_segment(flags=TCP_FLAG_ACK, seq_num=conn.snd_nxt, ack_num=conn.rcv_nxt)
                self.send_tcp_segment(conn, ack_seg)
                conn.transition_to(TCPState.TIME_WAIT)
                conn.transition_to(TCPState.CLOSED)

        elif conn.state == TCPState.LAST_ACK:
            if seg.flags & TCP_FLAG_ACK:
                conn.transition_to(TCPState.CLOSED)

    def _send_rst(self, ip_pkt: IPv4Packet, tcp_seg: TCPSegment) -> None:
        """Send TCP RST in response to unexpected segment or closed port."""
        if tcp_seg.flags & TCP_FLAG_ACK:
            seq = tcp_seg.ack_num
            ack = 0
            flags = TCP_FLAG_RST
        else:
            seq = 0
            ack = tcp_seg.seq_num + (1 if tcp_seg.flags & TCP_FLAG_SYN else len(tcp_seg.payload))
            flags = TCP_FLAG_RST | TCP_FLAG_ACK

        rst_seg = TCPSegment(
            src_port=tcp_seg.dst_port,
            dst_port=tcp_seg.src_port,
            seq_num=seq,
            ack_num=ack,
            flags=flags,
            window_size=0,
        )
        self.stats["tx_tcp"] += 1
        raw_tcp = rst_seg.pack(src_ip=ip_pkt.dst_ip, dst_ip=ip_pkt.src_ip)
        self.send_ipv4(dst_ip=ip_pkt.src_ip, protocol=IP_PROTO_TCP, payload=raw_tcp)

    def send_tcp_segment(self, conn: TCPConnection, seg: TCPSegment) -> None:
        """Serialize and send TCP segment via IPv4."""
        self.stats["tx_tcp"] += 1
        raw_tcp = seg.pack(src_ip=conn.local_ip, dst_ip=conn.remote_ip)
        self.send_ipv4(dst_ip=conn.remote_ip, protocol=IP_PROTO_TCP, payload=raw_tcp)
