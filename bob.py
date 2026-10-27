import argparse
import json
import os
import socket
import threading

from crypto.api import decrypt, encrypt, validate_key
from net.chat import ChatSession
from net.protocol import ID_ALICE, ID_BOB, generate_nonce, log, recv_msg, send_msg

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 6000
HANDSHAKE_TIMEOUT = 10  # detik
ACCEPT_POLL = 1.0  # detik

class Bob:
    identity = ID_BOB

    def __init__(self) -> None:
        self.master_key: str | None = None
        self.session_key: str | None = None
        self.chat: ChatSession | None = None
        self.conn: socket.socket | None = None
        self.lock = threading.Lock()

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
        n2 = generate_nonce()
        cipher = encrypt(str(n2), ks)
        send_msg(conn, {"step": 4, "n2": cipher})
        log("STEP 4", "-> Alice", f"N2={n2} cipher={cipher[:16]}...")
        return n2

    def verify_response(self, msg: dict, ks: str, n2: int) -> None:
        if msg.get("type") == "error":
            raise ValueError(f"Alice mengirim error: {msg.get('message')}")
        if msg.get("step") != 5:
            raise ValueError("Pesan berikutnya harus step 5")
        cipher = msg.get("fn2")
        if not isinstance(cipher, str):
            raise ValueError("fn2 wajib berupa string")

        try:
            fn2 = int(decrypt(cipher, ks))
        except ValueError as e:
            raise ValueError("Respons step 5 tidak bisa didekripsi dengan Ks") from e
        if fn2 != n2 + 1:
            raise ValueError("f(N2) tidak cocok, Alice tidak terbukti memegang Ks")
        log("STEP 5", "<- Alice", f"f(N2)={fn2} cocok")

    def handle_connection(self, conn: socket.socket, addr) -> None:
        peer = f"{addr[0]}:{addr[1]}"
        conn.settimeout(HANDSHAKE_TIMEOUT)
        try:
            ks, id_a = self.handle_ticket(recv_msg(conn))
            log("STEP 3", "<- Alice", f"dari {peer} ticket valid, id_a={id_a}")
            n2 = self.send_challenge(conn, ks)
            self.verify_response(recv_msg(conn), ks, n2)
        except ValueError as e:
            log("ERROR", peer, str(e))
            try:
                send_msg(conn, {"type": "error", "message": str(e)})
            except OSError:
                pass
            conn.close()
            return
        except OSError as e:
            log("ERROR", peer, f"Kesalahan socket: {e}")
            conn.close()
            return

        conn.settimeout(None)
        with self.lock:
            old_conn = self.conn
            self.conn = conn
            self.session_key = ks
        if old_conn is not None:
            old_conn.close()
        log("SESI", "", f"Handshake dengan {id_a} selesai. Ks={ks}")

    def serve(self, host: str, port: int) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            if os.name == "posix":
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((host, port))
            srv.listen()
            srv.settimeout(ACCEPT_POLL)
            log("BOB", "", f"Menunggu Alice di {host}:{port}")
            while True:
                try:
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                threading.Thread(
                    target=self.handle_connection, args=(conn, addr), daemon=True
                ).start()

    def handle_command(self, line: str) -> bool:
        raise NotImplementedError


def prompt_master_key(bob: Bob) -> None:
    while True:
        key = input(f"Master key {bob.identity} (16 karakter ASCII): ")
        try:
            bob.set_master_key(key)
            return
        except ValueError as e:
            print(f"Ditolak: {e}. Coba lagi.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bob (responder)")
    parser.add_argument("--host", default=DEFAULT_HOST, help=f"Alamat host untuk Bob (default: {DEFAULT_HOST})")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"Port untuk Bob (default: {DEFAULT_PORT})")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    bob = Bob()

    print("=== Bob ===")
    prompt_master_key(bob)

    try:
        bob.serve(args.host, args.port)
    except KeyboardInterrupt:
        print("\nBob dihentikan.")
    except OSError as e:
        print(f"Kesalahan socket: Bob tidak dapat dijalankan di {args.host}:{args.port}: {e}")


if __name__ == "__main__":
    main()
