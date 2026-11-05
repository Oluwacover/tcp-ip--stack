import threading
import socket
from typing import List, Optional
from src.layers.ethernet import BROADCAST_MAC
from src.net.pcap import PCAPWriter


class VirtualWire:
    """
    Virtual Ethernet Switch / Bus.
    Connects multiple VirtualInterfaces together within a single broadcast domain.
    Optionally records all frame traffic to a PCAP file for Wireshark analysis.
    """
    def __init__(self, pcap_writer: Optional[PCAPWriter] = None):
        self.interfaces: List["VirtualInterface"] = []
        self.pcap_writer = pcap_writer
        self._lock = threading.Lock()

    def connect(self, iface: "VirtualInterface") -> None:
        with self._lock:
            if iface not in self.interfaces:
                self.interfaces.append(iface)

    def disconnect(self, iface: "VirtualInterface") -> None:
        with self._lock:
            if iface in self.interfaces:
                self.interfaces.remove(iface)

    def broadcast(self, sender: "VirtualInterface", frame_bytes: bytes) -> None:
        """Deliver frame to all other interfaces on this segment."""
        # Log to PCAP if enabled
        if self.pcap_writer:
            self.pcap_writer.write_frame(frame_bytes)

        if len(frame_bytes) < 14:
            return

        dst_mac = frame_bytes[0:6]

        with self._lock:
            for iface in self.interfaces:
                if iface is sender:
                    continue
                # Accept if broadcast, multicast, or addressed to this interface's MAC
                if dst_mac == BROADCAST_MAC or dst_mac == iface.mac or dst_mac[0] & 0x01:
                    iface.inbox.put(frame_bytes)


class UDPBridgeWire(VirtualWire):
    """
    Virtual Ethernet Wire bridged over a local UDP port.
    Enables multi-process networking across multiple terminal tabs.
    """
    def __init__(self, listen_port: int, peer_port: int, pcap_writer: Optional[PCAPWriter] = None):
        super().__init__(pcap_writer=pcap_writer)
        self.listen_port = listen_port
        self.peer_port = peer_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", self.listen_port))
        self.running = True

        self._rx_thread = threading.Thread(target=self._rx_loop, daemon=True)
        self._rx_thread.start()

    def broadcast(self, sender: "VirtualInterface", frame_bytes: bytes) -> None:
        # Deliver locally first
        super().broadcast(sender, frame_bytes)
        # Send over UDP to remote peer process
        try:
            self.sock.sendto(frame_bytes, ("127.0.0.1", self.peer_port))
        except Exception:
            pass

    def _rx_loop(self) -> None:
        while self.running:
            try:
                frame_bytes, _ = self.sock.recvfrom(65535)
                if not frame_bytes:
                    break
                if self.pcap_writer:
                    self.pcap_writer.write_frame(frame_bytes)

                dst_mac = frame_bytes[0:6] if len(frame_bytes) >= 6 else b""
                with self._lock:
                    for iface in self.interfaces:
                        if dst_mac == BROADCAST_MAC or dst_mac == iface.mac or (dst_mac and dst_mac[0] & 0x01):
                            iface.inbox.put(frame_bytes)
            except Exception:
                break

    def close(self) -> None:
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass
