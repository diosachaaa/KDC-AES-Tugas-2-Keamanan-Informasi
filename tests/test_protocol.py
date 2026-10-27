import socket
import struct
import threading
import unittest

from net.protocol import (
    MAX_MSG_SIZE,
    _recv_exact,
    generate_nonce,
    recv_msg,
    send_msg,
)


class TestFraming(unittest.TestCase):
    def setUp(self):
        self.a, self.b = socket.socketpair()
        self.b.settimeout(5)

    def tearDown(self):
        self.a.close()
        self.b.close()

    def test_roundtrip_simple(self):
        msg = {"step": 1, "id_a": "ALICE", "id_b": "BOB", "n1": "12345"}
        send_msg(self.a, msg)
        self.assertEqual(recv_msg(self.b), msg)

    def test_roundtrip_unicode(self):
        msg = {"msg": "halo ñ 😀"}
        send_msg(self.a, msg)
        self.assertEqual(recv_msg(self.b), msg)

    def test_roundtrip_large_message(self):
        msg = {"ct": "ab" * 50_000}  # ~100 KB
        # Dikirim dari thread lain: buffer socket bisa lebih kecil dari pesan,
        # sehingga sendall akan menunggu sampai penerima mulai membaca.
        sender = threading.Thread(target=send_msg, args=(self.a, msg))
        sender.start()
        self.assertEqual(recv_msg(self.b), msg)
        sender.join()

    def test_multiple_messages_in_a_row(self):
        msgs = [{"i": i} for i in range(5)]
        for m in msgs:
            send_msg(self.a, m)
        self.assertEqual([recv_msg(self.b) for _ in msgs], msgs)

    def test_recv_exact_joins_partial_chunks(self):
        for part in (b"Hal", b"o B", b"ob!"):
            self.a.sendall(part)
        self.assertEqual(_recv_exact(self.b, 9), b"Halo Bob!")

    def test_connection_closed(self):
        self.a.sendall(struct.pack(">I", 10) + b"{}")  # header bilang 10, isi cuma 2
        self.a.close()
        with self.assertRaises(ConnectionError):
            recv_msg(self.b)

    def test_rejects_oversized_length(self):
        self.a.sendall(b"GET / HTTP/1.1\r\n")  # "GET " terbaca sebagai ~1,1 GB
        with self.assertRaises(ValueError):
            recv_msg(self.b)

    def test_rejects_invalid_json(self):
        self.a.sendall(struct.pack(">I", 5) + b"bukan")
        with self.assertRaises(ValueError):
            recv_msg(self.b)

    def test_rejects_non_object_json(self):
        self.a.sendall(struct.pack(">I", 3) + b"[1]")
        with self.assertRaises(ValueError):
            recv_msg(self.b)

    def test_send_rejects_too_large(self):
        with self.assertRaises(ValueError):
            send_msg(self.a, {"ct": "x" * (MAX_MSG_SIZE + 1)})


class TestNonce(unittest.TestCase):
    def test_nonce_is_64_bit(self):
        for _ in range(100):
            n = generate_nonce()
            self.assertIsInstance(n, int)
            self.assertTrue(0 <= n < 2**64)

    def test_nonce_not_repeated(self):
        nonces = {generate_nonce() for _ in range(1000)}
        self.assertEqual(len(nonces), 1000)


if __name__ == "__main__":
    unittest.main()
