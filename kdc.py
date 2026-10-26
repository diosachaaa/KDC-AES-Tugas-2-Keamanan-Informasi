import argparse
import getpass
import secrets
import socket
import string
import threading
import json

from crypto.api import encrypt, validate_key
from net.protocol import ID_ALICE, ID_BOB, log, recv_msg, send_msg

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5000
KS_ALPHABET = string.ascii_letters + string.digits
KS_LENGTH = 16
KNOWN_IDENTITIES = (ID_ALICE, ID_BOB)
CLIENT_TIMEOUT = 10 # detik

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
        ka = self.get_master_key(id_a)
        kb = self.get_master_key(id_b)
        ks = self.generate_session_key()
        for_a = {"ks": ks, "id_a": id_a, "id_b": id_b, "n1": n1}
        ticket_b = {"ks": ks, "id_a": id_a}

        return {
            "step": 2,
            "for_a": encrypt(json.dumps(for_a), ka),
            "ticket_b": encrypt(json.dumps(ticket_b), kb),
        }

    def handle_client(self, conn: socket.socket, addr) -> None:
        peer = f"{addr[0]}:{addr[1]}"
        with conn:
            conn.settimeout(CLIENT_TIMEOUT)
            try:
                msg = recv_msg(conn)
                id_a, id_b, n1 = self._parse_step1(msg)
                log("STEP 1", "<- Alice", f"dari {peer} id_a={id_a} id_b={id_b} n1={n1}")

                reply = self.build_step2(id_a, id_b, n1)
                send_msg(conn, reply)
                log("STEP 2", "-> Alice", f"for_a={reply['for_a'][:16]}... ticket_b={reply['ticket_b'][:16]}...")
            except ValueError as e:
                log("ERROR", peer, str(e))
                try:
                    send_msg(conn, {"type": "error", "message": str(e)})
                except OSError:
                    pass
            except OSError as e:
                log("ERROR", peer, f"Kesalahan socket: {e}")
    
    @staticmethod
    def _parse_step1(msg: dict) -> tuple[str, str, str]:
        if msg.get("step") != 1:
            raise ValueError("Pesan tidak valid: step harus 1")
        id_a, id_b, n1 = msg.get("id_a"), msg.get("id_b"), msg.get("n1")
        if not all(isinstance(x, str) for x in (id_a, id_b, n1)):
            raise ValueError("Pesan tidak valid: id_a, id_b, dan n1 harus berupa string")
        id_a, id_b = id_a.upper(), id_b.upper()
        for identity in (id_a, id_b):
            if identity not in KNOWN_IDENTITIES:
                raise ValueError(f"Identitas tidak dikenal: {identity}")
        if id_a == id_b:
            raise ValueError("id_a dan id_b tidak boleh sama")
        if not n1.isdigit():
            raise ValueError("n1 harus berupa bilangan desimal")
        return id_a, id_b, n1

    def serve(self, host: str, port: int) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((host, port))
            srv.listen()
            log("KDC", "", f"Menunggu koneksi di {host}:{port}")
            while True:
                conn, addr = srv.accept()
                threading.Thread(
                    target=self.handle_client, args=(conn, addr), daemon=True
                ).start()


def command_loop(kdc: KDC) -> None:
    raise NotImplementedError


def parse_args() -> argparse.Namespace:
    raise NotImplementedError


def main() -> None:
    raise NotImplementedError


if __name__ == "__main__":
    main()