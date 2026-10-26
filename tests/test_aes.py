import unittest

from crypto.aes import AES
from crypto.api import decrypt, encrypt
from crypto.modes import cbc_decrypt, cbc_encrypt, pkcs7_pad, pkcs7_unpad

h = bytes.fromhex


class TestAESBlock(unittest.TestCase):
    def test_fips197_appendix_c1(self):
        a = AES(h("000102030405060708090a0b0c0d0e0f"))
        pt = h("00112233445566778899aabbccddeeff")
        ct = h("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(a.encrypt_block(pt), ct)
        self.assertEqual(a.decrypt_block(ct), pt)

    def test_fips197_appendix_b(self):
        a = AES(h("2b7e151628aed2a6abf7158809cf4f3c"))
        pt = h("3243f6a8885a308d313198a2e0370734")
        ct = h("3925841d02dc09fbdc118597196a0b32")
        self.assertEqual(a.encrypt_block(pt), ct)
        self.assertEqual(a.decrypt_block(ct), pt)

    def test_aes192_and_256(self):
        pt = h("00112233445566778899aabbccddeeff")
        a192 = AES(h("000102030405060708090a0b0c0d0e0f1011121314151617"))
        self.assertEqual(a192.encrypt_block(pt), h("dda97ca4864cdfe06eaf70a0ec0d7191"))
        a256 = AES(h("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
        self.assertEqual(a256.encrypt_block(pt), h("8ea2b7ca516745bfeafc49904b496089"))


class TestModes(unittest.TestCase):
    def test_cbc_nist_sp800_38a(self):
        key = h("2b7e151628aed2a6abf7158809cf4f3c")
        iv = h("000102030405060708090a0b0c0d0e0f")
        pt = h("6bc1bee22e409f96e93d7e117393172a")
        out = cbc_encrypt(pt, key, iv)
        self.assertEqual(out[16:32], h("7649abac8119b246cee98e9b12e9197d"))
        self.assertEqual(cbc_decrypt(out, key), pt)

    def test_padding(self):
        for n in range(0, 40):
            d = b"x" * n
            self.assertEqual(pkcs7_unpad(pkcs7_pad(d)), d)
            self.assertEqual(len(pkcs7_pad(d)) % 16, 0)


class TestAPI(unittest.TestCase):
    KEY = "kunci-rahasia-16"

    def test_roundtrip(self):
        for msg in ["", "a", "Halo Bob!", "A" * 16, "B" * 100, "ID_A||ID_B||12345"]:
            self.assertEqual(decrypt(encrypt(msg, self.KEY), self.KEY), msg)

    def test_output_is_hex_and_iv_random(self):
        c1, c2 = encrypt("sama", self.KEY), encrypt("sama", self.KEY)
        int(c1, 16)
        self.assertNotEqual(c1, c2)

    def test_wrong_key(self):
        c = encrypt("rahasia banget", self.KEY)
        with self.assertRaises(ValueError):
            decrypt(c, "kunci-salah-1234")

    def test_bad_input(self):
        with self.assertRaises(ValueError):
            encrypt("x", "pendek")
        with self.assertRaises(ValueError):
            decrypt("zzzz", self.KEY)


if __name__ == "__main__":
    unittest.main()
