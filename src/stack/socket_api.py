import queue
import time
from typing import Optional, Tuple
from src.layers.tcp import (
    TCPConnection,
    TCPState,
    TCP_FLAG_SYN,
    TCP_FLAG_ACK,
    TCP_FLAG_FIN,
    TCP_FLAG_PSH,
)


class POSIXSocket:
    """
    Standard POSIX-style low-level socket interface on top of our TCP/IP stack.
    Mirrors standard C socket system calls: socket(), bind(), listen(), accept(), connect(), send(), recv(), close().
    """
    def __init__(self, stack: "TCPIPStack"):
        self.stack = stack
        self.local_ip: Optional[str] = None
        self.local_port: Optional[int] = None
        self.remote_ip: Optional[str] = None
        self.remote_port: Optional[int] = None

        self.conn: Optional[TCPConnection] = None
        self.is_listening = False
        self._accept_queue: queue.Queue = queue.Queue()
        self._pending_connections = {}
        self.closed = False

    def bind(self, address: Tuple[str, int]) -> None:
        """Bind socket to local IP and Port."""
        self.local_ip, self.local_port = address
        if self.local_ip == "0.0.0.0" or not self.local_ip:
            self.local_ip = self.stack.interface.ip

    def listen(self, backlog: int = 5) -> None:
        """Mark socket as passive listener for incoming connections."""
        if not self.local_port:
            raise RuntimeError("Cannot listen on unbound socket!")
        self.is_listening = True
        self.stack.listeners[(self.local_ip, self.local_port)] = self

    def accept(self, timeout: Optional[float] = 5.0) -> Tuple["POSIXSocket", Tuple[str, int]]:
        """Accept an incoming established connection."""
        if not self.is_listening:
            raise RuntimeError("Socket is not in listening state!")
        try:
            conn: TCPConnection = self._accept_queue.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError("accept() timed out waiting for connection")

        client_sock = POSIXSocket(self.stack)
        client_sock.local_ip = conn.local_ip
        client_sock.local_port = conn.local_port
        client_sock.remote_ip = conn.remote_ip
        client_sock.remote_port = conn.remote_port
        client_sock.conn = conn

        return client_sock, (conn.remote_ip, conn.remote_port)

    def connect(self, address: Tuple[str, int], timeout: float = 3.0) -> None:
        """Initiate 3-way handshake to connect to remote host."""
        self.remote_ip, self.remote_port = address
        if not self.local_ip:
            self.local_ip = self.stack.interface.ip
        if not self.local_port:
            import random
            self.local_port = random.randint(49152, 65530)

        # Create TCB in SYN_SENT
        client_isn = 10000 + int(time.time() * 1000) % 10000
        self.conn = TCPConnection(
            local_ip=self.local_ip,
            local_port=self.local_port,
            remote_ip=self.remote_ip,
            remote_port=self.remote_port,
            initial_state=TCPState.SYN_SENT,
            isn=client_isn,
        )

        conn_key = (self.local_ip, self.local_port, self.remote_ip, self.remote_port)
        self.stack.connections[conn_key] = self.conn

        # Send SYN
        syn_seg = self.conn.make_segment(flags=TCP_FLAG_SYN)
        self.stack.send_tcp_segment(self.conn, syn_seg)

        # Wait for handshake completion
        start = time.time()
        while time.time() - start < timeout:
            if self.conn.state == TCPState.ESTABLISHED:
                return
            if self.conn.state == TCPState.CLOSED:
                raise ConnectionRefusedError(f"Connection refused by {self.remote_ip}:{self.remote_port}")
            time.sleep(0.01)

        raise TimeoutError(f"Connect timed out to {self.remote_ip}:{self.remote_port}")

    def send(self, data: bytes) -> int:
        """Transmit data through the established TCP connection."""
        if not self.conn or self.conn.state != TCPState.ESTABLISHED:
            raise ConnectionError("Socket is not connected!")

        seg = self.conn.make_segment(flags=TCP_FLAG_ACK | TCP_FLAG_PSH, payload=data)
        self.stack.send_tcp_segment(self.conn, seg)
        return len(data)

    def recv(self, bufsize: int = 4096, timeout: Optional[float] = 2.0) -> bytes:
        """Read received bytes from the connection receive buffer."""
        if not self.conn:
            raise ConnectionError("Socket is not connected!")

        start = time.time()
        while len(self.conn.recv_buf) == 0:
            if self.conn.state in (TCPState.CLOSE_WAIT, TCPState.CLOSED):
                return b""  # EOF
            if timeout and (time.time() - start > timeout):
                break
            time.sleep(0.01)

        chunk = bytes(self.conn.recv_buf[:bufsize])
        del self.conn.recv_buf[:bufsize]
        return chunk

    def close(self) -> None:
        """Close socket and perform TCP teardown."""
        if self.closed:
            return
        self.closed = True

        if self.is_listening:
            self.is_listening = False
            self.stack.listeners.pop((self.local_ip, self.local_port), None)
            return

        if self.conn and self.conn.state == TCPState.ESTABLISHED:
            # Active close: send FIN
            self.conn.transition_to(TCPState.FIN_WAIT_1)
            fin_seg = self.conn.make_segment(flags=TCP_FLAG_FIN | TCP_FLAG_ACK)
            self.stack.send_tcp_segment(self.conn, fin_seg)
        elif self.conn and self.conn.state == TCPState.CLOSE_WAIT:
            # Passive close continuation: send FIN
            self.conn.transition_to(TCPState.LAST_ACK)
            fin_seg = self.conn.make_segment(flags=TCP_FLAG_FIN | TCP_FLAG_ACK)
            self.stack.send_tcp_segment(self.conn, fin_seg)


class RAIISocket:
    """
    Modern C++ RAII-inspired Socket wrapper.
    Ensures deterministic resource cleanup, unbinding, and TCP connection teardown
    via context manager semantics (`with RAIISocket(stack) as sock:`).
    """
    def __init__(self, stack_or_posix: "TCPIPStack | POSIXSocket"):
        if isinstance(stack_or_posix, POSIXSocket):
            self._sock = stack_or_posix
        else:
            self._sock = POSIXSocket(stack_or_posix)

    def __enter__(self) -> "RAIISocket":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def bind(self, address: Tuple[str, int]) -> "RAIISocket":
        self._sock.bind(address)
        return self

    def listen(self, backlog: int = 5) -> "RAIISocket":
        self._sock.listen(backlog)
        return self

    def accept(self, timeout: Optional[float] = 5.0) -> Tuple["RAIISocket", Tuple[str, int]]:
        client_sock, addr = self._sock.accept(timeout=timeout)
        return RAIISocket(client_sock), addr

    def connect(self, address: Tuple[str, int], timeout: float = 3.0) -> "RAIISocket":
        self._sock.connect(address, timeout=timeout)
        return self

    def send(self, data: bytes) -> int:
        return self._sock.send(data)

    def recv(self, bufsize: int = 4096, timeout: Optional[float] = 2.0) -> bytes:
        return self._sock.recv(bufsize, timeout=timeout)

    def close(self) -> None:
        self._sock.close()

    @property
    def conn(self) -> Optional[TCPConnection]:
        return self._sock.conn
