import os
import struct
import time
from typing import Optional

# PCAP constants
PCAP_MAGIC_NUMBER = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_SNAPLEN = 65535
LINKTYPE_ETHERNET = 1  # IEEE 802.3 Ethernet


class PCAPWriter:
    """
    Writes raw network frames to standard libpcap (.pcap) format.
    The resulting file can be opened directly with Wireshark, tcpdump, or tshark.
    """
    def __init__(self, filename: str):
        self.filename = filename
        self._file = None
        self._init_file()

    def _init_file(self) -> None:
        parent = os.path.dirname(self.filename)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._file = open(self.filename, "wb")
        # Global header: 24 bytes
        # magic (4), ver_major (2), ver_minor (2), thiszone (4), sigfigs (4), snaplen (4), linktype (4)
        global_header = struct.pack(
            "=IHHiIII",
            PCAP_MAGIC_NUMBER,
            PCAP_VERSION_MAJOR,
            PCAP_VERSION_MINOR,
            0,
            0,
            PCAP_SNAPLEN,
            LINKTYPE_ETHERNET,
        )
        self._file.write(global_header)
        self._file.flush()

    def write_frame(self, frame_bytes: bytes, timestamp: Optional[float] = None) -> None:
        """Write an Ethernet frame to the pcap file."""
        if not self._file or self._file.closed:
            return

        ts = timestamp if timestamp is not None else time.time()
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000)
        length = len(frame_bytes)

        # Packet header: 16 bytes
        # ts_sec (4), ts_usec (4), incl_len (4), orig_len (4)
        pkt_header = struct.pack("=IIII", sec, usec, length, length)
        self._file.write(pkt_header)
        self._file.write(frame_bytes)
        self._file.flush()

    def close(self) -> None:
        if self._file and not self._file.closed:
            self._file.flush()
            self._file.close()

    def __enter__(self) -> "PCAPWriter":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
