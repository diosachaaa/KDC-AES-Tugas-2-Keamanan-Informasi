"""
!!! STUB SEMENTARA - BUKAN AES !!!
Isi file ini hanya XOR sederhana supaya modul jaringan bisa dikembangkan secara paralel sebelum AES selesai. 
Saat integrasi, seluruh isi fungsi diganti dengan pemanggilan crypto.modes (CBC + PKCS#7) di atas crypto.aes.
"""

VALID_KEY_LENGTHS = (16,)

def validate_key(key: str) -> None:
    if not key.isascii():
        raise ValueError("Key harus berisi karakter ASCII")
    if len(key) not in VALID_KEY_LENGTHS:
        raise ValueError(
            f"Panjang key harus {VALID_KEY_LENGTHS} karakter, sekarang {len(key)}"
        )

def encrypt(plaintext: str, key: str) -> str:
    validate_key(key)
    p, k = plaintext.encode("utf-8"), key.encode("ascii")
    return bytes(b ^ k[i % len(k)] for i, b in enumerate(p)).hex()


def decrypt(cipher_hex: str, key: str) -> str:
    validate_key(key)
    try:
        c = bytes.fromhex(cipher_hex)
    except ValueError as exc:
        raise ValueError("Ciphertext bukan hex yang valid") from exc
    k = key.encode("ascii")
    try:
        return bytes(b ^ k[i % len(k)] for i, b in enumerate(c)).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Gagal dekripsi (kemungkinan key salah)") from exc