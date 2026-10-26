from crypto.modes import cbc_decrypt, cbc_encrypt

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
    return cbc_encrypt(plaintext.encode("utf-8"), key.encode("ascii")).hex()


def decrypt(cipher_hex: str, key: str) -> str:
    validate_key(key)
    try:
        c = bytes.fromhex(cipher_hex)
    except ValueError as exc:
        raise ValueError("Ciphertext bukan hex yang valid") from exc
    try:
        return cbc_decrypt(c, key.encode("ascii")).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ValueError("Gagal dekripsi (kemungkinan key salah)") from exc
