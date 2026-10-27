import argparse
import json
import os
import secrets
import socket
import string
import threading

from crypto.api import encrypt, validate_key
from net.chat import PROMPT
from net.protocol import ID_ALICE, ID_BOB, log, recv_msg, send_msg

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5000
KS_ALPHABET = string.ascii_letters + string.digits
KS_LENGTH = 16
KNOWN_IDENTITIES = (ID_ALICE, ID_BOB)
CLIENT_TIMEOUT = 10  # detik
ACCEPT_POLL = 1.0  # detik


class KDC:
    def __init__(self) -> None:
        self.master_keys: dict[str, str] = {}
        self.lock = threading.Lock()
        self.address = "-"
        self.issued = 0

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
        with self.lock:
            self.issued += 1
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
        print(PROMPT, end="", flush=True)

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

    def open_server(self, host: str, port: int) -> socket.socket:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if os.name == "posix":
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((host, port))
            srv.listen()
            srv.settimeout(ACCEPT_POLL)
        except OSError:
            srv.close()
            raise
        self.address = f"{host}:{port}"
        log("KDC", "", f"Menunggu koneksi di {self.address}")
        return srv

    def accept_loop(self, srv: socket.socket) -> None:
        while True:
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(
                target=self.handle_client, args=(conn, addr), daemon=True
            ).start()

    def handle_command(self, line: str) -> bool:
        parts = line.split(maxsplit=2)
        command = parts[0].lower()

        if command == "/setkey":
            if len(parts) < 3:
                print("[!] Format: /setkey alice|bob <key>")
                return True
            identity, key = parts[1].upper(), parts[2]
            try:
                self.set_master_key(identity, key)
            except ValueError as e:
                print(f"[!] Ditolak: {e}")
                return True
            print(f"[KEY] Master key {identity} di KDC diganti menjadi: {key}")
            return True

        if command == "/status":
            with self.lock:
                keys = dict(self.master_keys)
            print(f"Alamat    : {self.address}")
            for identity in KNOWN_IDENTITIES:
                print(f"Key {identity:<6}: {keys.get(identity, '(belum diatur)')}")
            print(f"Ks dibuat : {self.issued}")
            return True

        if command == "/help":
            print("/setkey alice|bob <key>  ganti master key yang disimpan KDC")
            print("/status                  tampilkan alamat, master key, dan jumlah Ks")
            print("/help                    tampilkan daftar perintah")
            print("/quit                    hentikan KDC")
            return True

        return False


def command_loop(kdc: KDC) -> None:
    while True:
        try:
            line = input(PROMPT)
        except (EOFError, KeyboardInterrupt):
            print()
            return

        line = line.strip()
        if not line:
            continue
        if not line.startswith("/"):
            print("[!] KDC hanya menerima perintah. Ketik /help")
            continue
        if line.split()[0].lower() == "/quit":
            return
        if not kdc.handle_command(line):
            print(f"[!] Perintah tidak dikenal: {line.split()[0]}. Ketik /help")


def prompt_master_key(kdc: KDC, identity: str) -> None:
    while True:
        key = input(f"Master key {identity} (16 karakter ASCII): ")
        try:
            kdc.set_master_key(identity, key)
            return
        except ValueError as e:
            print(f"Ditolak: {e}. Coba lagi.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Key Distribution Center (KDC)")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Alamat host untuk KDC (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port untuk KDC (default: {DEFAULT_PORT})")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    kdc = KDC()

    print("=== Key Distribution Center (KDC) ===")
    for identity in KNOWN_IDENTITIES:
        prompt_master_key(kdc, identity)

    try:
        srv = kdc.open_server(args.host, args.port)
    except OSError as e:
        print(f"Kesalahan socket: KDC tidak dapat dijalankan di {args.host}:{args.port}: {e}")
        return

    threading.Thread(target=kdc.accept_loop, args=(srv,), daemon=True).start()
    print("KDC berjalan. Ketik /help untuk daftar perintah.")
    try:
        command_loop(kdc)
    finally:
        srv.close()
        print("KDC dihentikan.")


if __name__ == "__main__":
    main()
