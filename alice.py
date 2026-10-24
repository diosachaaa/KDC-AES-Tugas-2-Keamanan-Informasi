import argparse
import getpass
import json
import socket

from crypto.api import decrypt, encrypt, validate_key
from net.chat import ChatSession
from net.protocol import ID_ALICE, ID_BOB, generate_nonce, log, recv_msg, send_msg


class Alice:
    identity = ID_ALICE

    def __init__(self, kdc_addr: tuple[str, int], bob_addr: tuple[str, int]) -> None:
        self.kdc_addr = kdc_addr
        self.bob_addr = bob_addr
        self.master_key: str | None = None
        self.session_key: str | None = None
        self.chat: ChatSession | None = None

    def set_master_key(self, key: str) -> None:
        raise NotImplementedError

    def request_session_key(self) -> tuple[str, str]:
        raise NotImplementedError

    def authenticate_with_bob(self, ks: str, ticket_b: str) -> socket.socket:
        raise NotImplementedError

    def handshake(self) -> None:
        raise NotImplementedError

    def handle_command(self, line: str) -> bool:
        raise NotImplementedError


def parse_addr(text: str) -> tuple[str, int]:
    raise NotImplementedError


def parse_args() -> argparse.Namespace:
    raise NotImplementedError


def main() -> None:
    raise NotImplementedError


if __name__ == "__main__":
    main()