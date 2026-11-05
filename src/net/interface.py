import queue
from typing import Optional, Tuple
from src.layers.ethernet import str_to_mac, mac_to_str


class VirtualInterface:
    """
    Represents a Virtual Network Interface Card (vNIC).
    Maintains MAC address, assigned IPv4 address, MTU, and frame queues.
    """
    def __init__(
        self,
        name: str = "eth0",
        mac: str = "52:54:00:12:34:56",
        ip: str = "192.168.1.10",
        netmask: str = "255.255.255.0",
        mtu: int = 1500,
    ):
        self.name = name
        self.mac_str = mac
        self.mac = str_to_mac(mac)
        self.ip = ip
        self.netmask = netmask
        self.mtu = mtu

        self.wire = None
        self.inbox: queue.Queue = queue.Queue()

    def attach_wire(self, wire: "VirtualWire") -> None:
        self.wire = wire
        wire.connect(self)

    def send_raw(self, frame_bytes: bytes) -> None:
        """Transmit raw Ethernet frame out onto the attached virtual wire."""
        if self.wire is None:
            raise RuntimeError(f"Interface {self.name} is not attached to a virtual wire!")
        self.wire.broadcast(self, frame_bytes)

    def recv_raw(self, timeout: Optional[float] = 0.1) -> Optional[bytes]:
        """Receive next available raw Ethernet frame from the interface inbox."""
        try:
            return self.inbox.get(timeout=timeout)
        except queue.Empty:
            return None

    def __repr__(self) -> str:
        return f"<VirtualInterface {self.name} ip={self.ip}/{self.netmask} mac={self.mac_str}>"
