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
        self._receiver: threading.Thread | None = None

    def start(self) -> None:
        self.active = True
        self._receiver = threading.Thread(target=self._receive_loop, daemon=True)
        self._receiver.start()

    def _receive_loop(self) -> None:
        while self.active:
            try:
                msg = recv_msg(self.sock)
            except (OSError, ValueError):
                break

            if msg.get("type") != "chat":
                continue
            ct = msg.get("ct")
            if not isinstance(ct, str):
                continue
            try:
                text = decrypt(ct, self.session_key)
            except ValueError:
                self._display(f"[!] Pesan dari {self.peer_name} tidak bisa didekripsi")
                continue

            line = f"[{self.peer_name}] {text}"
            if self.verbose:
                line += f"\n    ct={ct}"
            self._display(line)
        self.active = False

    @staticmethod
    def _display(text: str) -> None:
        print(f"\n{text}\n{PROMPT}", end="", flush=True)

    def send_text(self, text: str) -> None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError