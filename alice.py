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
        self.conn: socket.socket | None = None

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
        s = socket.create_connection(self.bob_addr, timeout=NETWORK_TIMEOUT)
        try:
            send_msg(s, {"step": 3, "ticket_b": ticket_b})
            log("STEP 3", "-> Bob", f"ticket_b={ticket_b[:16]}...")

            msg = recv_msg(s)
            if msg.get("type") == "error":
                raise ValueError(f"Bob menolak: {msg.get('message')}")
            if msg.get("step") != 4:
                raise ValueError("Balasan Bob bukan step 4")
            cipher = msg.get("n2")
            if not isinstance(cipher, str):
                raise ValueError("n2 wajib berupa string")

            try:
                n2 = int(decrypt(cipher, ks))
            except ValueError as e:
                send_msg(s, {"type": "error", "message": "N2 tidak bisa didekripsi dengan Ks"})
                raise ValueError("N2 dari Bob tidak bisa didekripsi dengan Ks") from e
            log("STEP 4", "<- Bob", f"cipher={cipher[:16]}... N2={n2}")

            fn2 = n2 + 1
            cipher = encrypt(str(fn2), ks)
            send_msg(s, {"step": 5, "fn2": cipher})
            log("STEP 5", "-> Bob", f"f(N2)={fn2} cipher={cipher[:16]}...")
        except Exception:
            s.close()
            raise

        s.settimeout(None)
        return s

    def handshake(self) -> None:
        kdc = f"{self.kdc_addr[0]}:{self.kdc_addr[1]}"
        bob = f"{self.bob_addr[0]}:{self.bob_addr[1]}"

        try:
            ks, ticket_b = self.request_session_key()
        except ValueError as e:
            log("ERROR", "KDC", str(e))
            return False
        except OSError as e:
            log("ERROR", "KDC", f"Tidak bisa terhubung ke KDC di {kdc}: {e}")
            return False

        try:
            conn = self.authenticate_with_bob(ks, ticket_b)
        except ValueError as e:
            log("ERROR", "Bob", str(e))
            return False
        except OSError as e:
            log("ERROR", "Bob", f"Tidak bisa terhubung ke Bob di {bob}: {e}")
            return False

        old_conn = self.conn
        self.conn = conn
        self.session_key = ks
        if old_conn is not None:
            old_conn.close()
        log("SESI", "", f"Handshake dengan {ID_BOB} selesai. Ks={ks}")
        return True

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