import argparse
import getpass
import secrets
import socket
import string
import threading

from crypto.api import encrypt, validate_key
from net.protocol import ID_ALICE, ID_BOB, log, recv_msg, send_msg

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5000
KS_ALPHABET = string.ascii_letters + string.digits
KS_LENGTH = 16


class KDC:
    def __init__(self) -> None:
        self.master_keys: dict[str, str] = {}
        self.lock = threading.Lock()

    def set_master_key(self, identity: str, key: str) -> None:
        raise NotImplementedError

    def generate_session_key(self) -> str:
        raise NotImplementedError

    def build_step2(self, id_a: str, id_b: str, n1: str) -> dict:
        raise NotImplementedError

    def handle_client(self, conn: socket.socket, addr) -> None:
        raise NotImplementedError

    def serve(self, host: str, port: int) -> None:
        raise NotImplementedError


def command_loop(kdc: KDC) -> None:
    raise NotImplementedError


def parse_args() -> argparse.Namespace:
    raise NotImplementedError


def main() -> None:
    raise NotImplementedError


if __name__ == "__main__":
    main()