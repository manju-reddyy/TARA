"""Minimal server-side WebSocket for the board (the board is the only client).

Used by board_push for the board's always-open link (/tara/events) and by call_bridge
for call audio (/tara/call). Runs on top of http.server's request handler.
"""
import base64
import hashlib
import struct
import threading

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class WebSocketConn:
    def __init__(self, handler):
        self.rfile, self.sock = handler.rfile, handler.connection
        self.lock = threading.Lock()

    @staticmethod
    def accept(handler):
        key = handler.headers.get("Sec-WebSocket-Key", "")
        if handler.headers.get("Upgrade", "").lower() != "websocket" or not key:
            return None
        accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        handler.send_response(101, "Switching Protocols")
        handler.send_header("Upgrade", "websocket")
        handler.send_header("Connection", "Upgrade")
        handler.send_header("Sec-WebSocket-Accept", accept)
        handler.end_headers()
        handler.wfile.flush()
        handler.close_connection = True
        return WebSocketConn(handler)

    def send(self, data, binary=True):
        if isinstance(data, str):
            data, binary = data.encode(), False
        n = len(data)
        head = bytes([0x82 if binary else 0x81])
        if n < 126:
            head += bytes([n])
        elif n < 65536:
            head += bytes([126]) + struct.pack(">H", n)
        else:
            head += bytes([127]) + struct.pack(">Q", n)
        with self.lock:
            self.sock.sendall(head + data)

    def recv(self):
        """Returns (opcode, payload); raises EOFError when the connection is gone."""
        while True:
            h = self.rfile.read(2)
            if len(h) < 2:
                raise EOFError
            opcode, n = h[0] & 0x0F, h[1] & 0x7F
            if n == 126:
                n = struct.unpack(">H", self.rfile.read(2))[0]
            elif n == 127:
                n = struct.unpack(">Q", self.rfile.read(8))[0]
            if n > 65536:
                raise EOFError
            mask = self.rfile.read(4) if h[1] & 0x80 else b"\0\0\0\0"
            data = bytearray(self.rfile.read(n))
            if len(data) < n:
                raise EOFError
            for i in range(n):
                data[i] ^= mask[i & 3]
            if opcode == 0x8:
                raise EOFError
            if opcode == 0x9:
                with self.lock:
                    self.sock.sendall(bytes([0x8A, len(data)]) + bytes(data))
                continue
            if opcode in (0x1, 0x2):
                return opcode, bytes(data)

    def close(self):
        try:
            with self.lock:
                self.sock.sendall(b"\x88\x00")
        except OSError:
            pass
