import json
import secrets
import socket
import struct

HEADER_SIZE = 4
MAX_MSG_SIZE = 1 << 20

ID_ALICE = "ALICE"
ID_BOB = "BOB"


def send_msg(sock: socket.socket, obj: dict) -> None:
    data = json.dumps(obj).encode("utf-8")
    if len(data) > MAX_MSG_SIZE:
        raise ValueError(f"Pesan terlalu besar: {len(data)} byte, maksimum {MAX_MSG_SIZE} byte")
    header = struct.pack(">I", len(data))
    sock.sendall(header + data)


def recv_msg(sock: socket.socket) -> dict:
    header = _recv_exact(sock, HEADER_SIZE)
    (msg_len,) = struct.unpack(">I", header)
    if msg_len > MAX_MSG_SIZE:
        raise ValueError(f"Pesan terlalu besar: {msg_len} byte, maksimum {MAX_MSG_SIZE} byte")
    data = _recv_exact(sock, msg_len)
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f"Pesan tidak valid: {e}")
    if not isinstance(obj, dict):
        raise ValueError(f"Pesan tidak valid: diharapkan berupa objek JSON")
    return obj


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(f"Koneksi terputus setelah {len(buf)} byte diterima, diharapkan {n} byte")
        buf.extend(chunk)
    return bytes(buf)


def generate_nonce() -> int:
    return secrets.randbits(64)


def log(tag: str, direction: str, detail: str) -> None:
    print(f"{f'[{tag}]':<8} {direction:<7}: {detail}", flush=True)