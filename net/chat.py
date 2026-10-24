import socket
import threading
from typing import Callable, Optional

from crypto.api import decrypt, encrypt
from net.protocol import recv_msg, send_msg

CommandHandler = Callable[[str], bool]


class ChatSession:
    def __init__(
        self,
        sock: socket.socket,
        session_key: str,
        peer_name: str,
        command_handler: Optional[CommandHandler] = None,
        verbose: bool = False,
    ) -> None:
        self.sock = sock
        self.session_key = session_key
        self.peer_name = peer_name
        self.command_handler = command_handler
        self.verbose = verbose
        self.running = threading.Event()
        self._receiver: Optional[threading.Thread] = None

    def start(self) -> None:
        raise NotImplementedError

    def _receive_loop(self) -> None:
        raise NotImplementedError

    def _input_loop(self) -> None:
        raise NotImplementedError

    def send_text(self, text: str) -> None:
        raise NotImplementedError

    def handle_builtin_command(self, line: str) -> bool:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError