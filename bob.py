import argparse
import getpass
import json
import socket

from crypto.api import decrypt, encrypt, validate_key
from net.chat import ChatSession
from net.protocol import ID_BOB, generate_nonce, log, recv_msg, send_msg

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 6000


class Bob:
    identity = ID_BOB

    def __init__(self) -> None:
        self.master_key: str | None = None
        self.session_key: str | None = None
        self.chat: ChatSession | None = None

    def set_master_key(self, key: str) -> None:
        raise NotImplementedError

    def handle_ticket(self, msg: dict) -> tuple[str, str]:
        raise NotImplementedError

    def send_challenge(self, conn: socket.socket, ks: str) -> int:
        raise NotImplementedError

    def verify_response(self, msg: dict, ks: str, n2: int) -> bool:
        raise NotImplementedError

    def handle_connection(self, conn: socket.socket, addr) -> None:
        raise NotImplementedError

    def serve(self, host: str, port: int) -> None:
        raise NotImplementedError

    def handle_command(self, line: str) -> bool:
        raise NotImplementedError


def parse_args() -> argparse.Namespace:
    raise NotImplementedError


def main() -> None:
    raise NotImplementedError


if __name__ == "__main__":
    main()