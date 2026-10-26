import secrets

from crypto.aes import AES

BLOCK = 16


def pkcs7_pad(data: bytes) -> bytes:
    n = BLOCK - (len(data) % BLOCK)
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK != 0:
        raise ValueError("Panjang data tidak valid")
    n = data[-1]
    if n < 1 or n > BLOCK or data[-n:] != bytes([n]) * n:
        raise ValueError("Padding tidak valid (kemungkinan key salah)")
    return data[:-n]


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes = None) -> bytes:
    if iv is None:
        iv = secrets.token_bytes(BLOCK)
    if len(iv) != BLOCK:
        raise ValueError("IV harus 16 byte")
    cipher = AES(key)
    data = pkcs7_pad(plaintext)
    prev, out = iv, []
    for i in range(0, len(data), BLOCK):
        block = cipher.encrypt_block(_xor(data[i:i + BLOCK], prev))
        out.append(block)
        prev = block
    return iv + b"".join(out)


def cbc_decrypt(iv_and_cipher: bytes, key: bytes) -> bytes:
    if len(iv_and_cipher) < 2 * BLOCK or len(iv_and_cipher) % BLOCK != 0:
        raise ValueError("Ciphertext terlalu pendek / panjang bukan kelipatan 16")
    iv, data = iv_and_cipher[:BLOCK], iv_and_cipher[BLOCK:]
    cipher = AES(key)
    prev, out = iv, []
    for i in range(0, len(data), BLOCK):
        block = data[i:i + BLOCK]
        out.append(_xor(cipher.decrypt_block(block), prev))
        prev = block
    return pkcs7_unpad(b"".join(out))
