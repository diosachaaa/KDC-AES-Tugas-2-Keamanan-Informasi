import argparse
import getpass
import json
import socket

from crypto.api import decrypt, encrypt, validate_key
from net.chat import ChatSession
from net.protocol import ID_ALICE, ID_BOB, generate_nonce, log, recv_msg, send_msg

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 6000


class Bob:
    identity = ID_BOB

    def __init__(self) -> None:
        self.master_key: str | None = None
        self.session_key: str | None = None
        self.chat: ChatSession | None = None

    def set_master_key(self, key: str) -> None:
        validate_key(key)
        self.master_key = key

    def handle_ticket(self, msg: dict) -> tuple[str, str]:
        if msg.get("step") != 3:
            raise ValueError("Pesan pertama harus step 3")
        ticket = msg.get("ticket_b")
        if not isinstance(ticket, str):
            raise ValueError("ticket_b wajib berupa string")
        if self.master_key is None:
            raise ValueError("Master key Bob belum diatur")

        try:
            data = json.loads(decrypt(ticket, self.master_key))
        except ValueError as e:
            raise ValueError("Ticket tidak bisa didekripsi (Kb salah atau ticket rusak)") from e
        if not isinstance(data, dict):
            raise ValueError("Isi ticket tidak valid")

        ks, id_a = data.get("ks"), data.get("id_a")
        if not isinstance(ks, str) or not isinstance(id_a, str):
            raise ValueError("Isi ticket tidak lengkap")
        try:
            validate_key(ks)
        except ValueError as e:
            raise ValueError("Session key di dalam ticket tidak valid") from e
        if id_a != ID_ALICE:
            raise ValueError(f"Ticket berasal dari identitas tidak dikenal: {id_a}")
        return ks, id_a
    
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