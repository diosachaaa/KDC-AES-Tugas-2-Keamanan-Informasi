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
    raise NotImplementedError


def generate_nonce() -> int:
    raise NotImplementedError


def log(tag: str, direction: str, detail: str) -> None:
    raise NotImplementedError