import argparse
import getpass
import json
import socket

from crypto.api import decrypt, encrypt, validate_key
from net.chat import ChatSession
from net.protocol import ID_ALICE, ID_BOB, generate_nonce, log, recv_msg, send_msg

NETWORK_TIMEOUT = 10

class Alice:
    identity = ID_ALICE

    def __init__(self, kdc_addr: tuple[str, int], bob_addr: tuple[str, int]) -> None:
        self.kdc_addr = kdc_addr
        self.bob_addr = bob_addr
        self.master_key: str | None = None
        self.session_key: str | None = None
        self.chat: ChatSession | None = None

    def set_master_key(self, key: str) -> None:
        validate_key(key)
        self.master_key = key

    def request_session_key(self) -> tuple[str, str]:
        if self.master_key is None:
            raise ValueError("Master key Alice belum diatur")

        n1 = str(generate_nonce())
        with socket.create_connection(self.kdc_addr, timeout=NETWORK_TIMEOUT) as s:
            send_msg(s, {"step": 1, "id_a": ID_ALICE, "id_b": ID_BOB, "n1": n1})
            log("STEP 1", "-> KDC", f"id_a={ID_ALICE} id_b={ID_BOB} n1={n1}")
            reply = recv_msg(s)

        if reply.get("type") == "error":
            raise ValueError(f"KDC menolak: {reply.get('message')}")
        if reply.get("step") != 2:
            raise ValueError("Balasan KDC bukan step 2")
        for_a, ticket_b = reply.get("for_a"), reply.get("ticket_b")
        if not isinstance(for_a, str) or not isinstance(ticket_b, str):
            raise ValueError("Balasan KDC tidak lengkap")
        log("STEP 2", "<- KDC", f"for_a={for_a[:16]}... ticket_b={ticket_b[:16]}...")

        try:
            data = json.loads(decrypt(for_a, self.master_key))
        except ValueError as e:
            raise ValueError("for_a tidak bisa didekripsi (Ka salah atau pesan rusak)") from e
        if not isinstance(data, dict):
            raise ValueError("Isi for_a tidak valid")

        if data.get("n1") != n1:
            raise ValueError("N1 tidak cocok, balasan KDC bukan untuk permintaan ini")
        if data.get("id_a") != ID_ALICE or data.get("id_b") != ID_BOB:
            raise ValueError("ID di balasan KDC tidak sesuai dengan permintaan")
        ks = data.get("ks")
        if not isinstance(ks, str):
            raise ValueError("Ks tidak ada di balasan KDC")
        try:
            validate_key(ks)
        except ValueError as e:
            raise ValueError("Ks dari KDC tidak valid") from e

        log("STEP 2", "OK", f"N1 cocok, Ks diterima: {ks}")
        return ks, ticket_b

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