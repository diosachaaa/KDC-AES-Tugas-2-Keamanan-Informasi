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
KNOWN_IDENTITIES = (ID_ALICE, ID_BOB)

class KDC:
    def __init__(self) -> None:
        self.master_keys: dict[str, str] = {}
        self.lock = threading.Lock()

    def set_master_key(self, identity: str, key: str) -> None:
        identity = identity.upper()
        if identity not in KNOWN_IDENTITIES:
            raise ValueError(f"Identitas tidak dikenal: {identity}")
        validate_key(key)
        with self.lock:
            self.master_keys[identity] = key

    def get_master_key(self, identity: str) -> str:
        with self.lock:
            key = self.master_keys.get(identity)
        if key is None:
            raise ValueError(f"Master key untuk {identity} belum diatur")
        return key

    def generate_session_key(self) -> str:
        return "".join(secrets.choice(KS_ALPHABET) for _ in range(KS_LENGTH))

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