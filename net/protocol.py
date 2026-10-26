import json
import secrets
import socket
import struct

HEADER_SIZE = 4
MAX_MSG_SIZE = 1 << 20

ID_ALICE = "ALICE"
ID_BOB = "BOB"


def send_msg(sock: socket.socket, obj: dict) -> None:
    raise NotImplementedError


def recv_msg(sock: socket.socket) -> dict:
    raise NotImplementedError


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"Koneksi terputus setelah {len(buf)} byte diterima, diharapkan {n} byte")
        buf.extend(chunk)
    return bytes(buf)


def generate_nonce() -> int:
    raise NotImplementedError


def log(tag: str, direction: str, detail: str) -> None:
    raise NotImplementedError