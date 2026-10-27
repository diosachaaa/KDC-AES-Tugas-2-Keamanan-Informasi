import socket
import threading

from crypto.api import decrypt, encrypt
from net.protocol import recv_msg, send_msg

PROMPT = "> "


class ChatSession:
    def __init__(self, sock: socket.socket, session_key: str, peer_name: str, verbose: bool = False) -> None:
        self.sock = sock
        self.session_key = session_key
        self.peer_name = peer_name
        self.verbose = verbose
        self.active = False
        self._closing = False
        self._receiver: threading.Thread | None = None
        self._send_lock = threading.Lock()

    def start(self) -> None:
        self.active = True
        self._receiver = threading.Thread(target=self._receive_loop, daemon=True)
        self._receiver.start()

    def _receive_loop(self) -> None:
        while self.active:
            try:
                msg = recv_msg(self.sock)
            except ValueError as e:
                if not self._closing:
                    self._display(f"[SESI] Pesan dari {self.peer_name} rusak ({e}), sesi ditutup")
                break
            except OSError:
                if not self._closing:
                    self._display(f"[SESI] {self.peer_name} terputus")
                break

            kind = msg.get("type")
            if kind == "chat":
                self._handle_chat(msg)
            elif kind == "error":
                self._display(f"[!] {self.peer_name} mengirim error: {msg.get('message')}")
            elif kind == "bye":
                self._display(f"[SESI] {self.peer_name} menutup sesi")
                break

        self.close(notify=False)

    def _handle_chat(self, msg: dict) -> None:
        ct = msg.get("ct")
        if not isinstance(ct, str):
            return
        try:
            text = decrypt(ct, self.session_key)
        except ValueError:
            self._display(f"[!] Pesan dari {self.peer_name} tidak bisa didekripsi")
            return

        line = f"[{self.peer_name}] {text}"
        if self.verbose:
            line += f"\n    ct={ct}"
        self._display(line)

    @staticmethod
    def _display(text: str) -> None:
        print(f"\n{text}\n{PROMPT}", end="", flush=True)

    def send_text(self, text: str) -> str:
        if not self.active:
            raise ConnectionError(f"Sesi dengan {self.peer_name} tidak aktif")
        ct = encrypt(text, self.session_key)
        with self._send_lock:
            send_msg(self.sock, {"type": "chat", "ct": ct})
        if self.verbose:
            print(f"    ct={ct}", flush=True)
        return ct

    def close(self, notify: bool = True) -> None:
        if self._closing:
            return
        self._closing = True

        if notify and self.active:
            try:
                with self._send_lock:
                    send_msg(self.sock, {"type": "bye"})
            except OSError:
                pass
        self.active = False

        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


def run_input_loop(owner) -> None:
    while True:
        try:
            line = input(PROMPT)
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if not line.strip():
            continue

        if line.startswith("/"):
            command = line.split()[0].lower()
            if command == "/quit":
                return
            if command == "/verbose":
                _set_verbose(owner, line)
                continue
            if not owner.handle_command(line):
                print(f"[!] Perintah tidak dikenal: {command}")
            continue

        chat = owner.chat
        if chat is None or not chat.active:
            print("[!] Belum ada sesi aktif, pesan tidak dikirim")
            continue
        try:
            chat.send_text(line)
        except (OSError, ValueError) as e:
            print(f"[!] Gagal mengirim: {e}")


def _set_verbose(owner, line: str) -> None:
    parts = line.split()
    if len(parts) == 1:
        value = not owner.verbose
    elif parts[1].lower() in ("on", "off"):
        value = parts[1].lower() == "on"
    else:
        print("[!] Format: /verbose on|off")
        return

    owner.verbose = value
    if owner.chat is not None:
        owner.chat.verbose = value
    print(f"[VERBOSE] {'on: ciphertext ditampilkan' if value else 'off'}")
