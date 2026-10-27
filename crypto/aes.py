def xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def gf_mul(a: int, b: int) -> int:
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result


def _rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_sbox() -> list:
    sbox = [0] * 256
    for x in range(256):
        inv = 0
        if x:
            inv = 1
            for _ in range(254):
                inv = gf_mul(inv, x)
        sbox[x] = (inv ^ _rotl8(inv, 1) ^ _rotl8(inv, 2)
                   ^ _rotl8(inv, 3) ^ _rotl8(inv, 4) ^ 0x63)
    return sbox


SBOX = _build_sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

assert SBOX[0x00] == 0x63 and SBOX[0x01] == 0x7C and SBOX[0x53] == 0xED


def sub_bytes(s: list) -> list:
    return [SBOX[b] for b in s]


def inv_sub_bytes(s: list) -> list:
    return [INV_SBOX[b] for b in s]


def shift_rows(s: list) -> list:
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
    return out


def inv_shift_rows(s: list) -> list:
    out = [0] * 16
    for r in range(4):
        for c in range(4):
            out[r + 4 * ((c + r) % 4)] = s[r + 4 * c]
    return out


def mix_columns(s: list) -> list:
    out = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c: 4 * c + 4]
        out[4 * c + 0] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3
        out[4 * c + 1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3
        out[4 * c + 2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3)
        out[4 * c + 3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3)
    return out


def inv_mix_columns(s: list) -> list:
    out = [0] * 16
    for c in range(4):
        a0, a1, a2, a3 = s[4 * c: 4 * c + 4]
        out[4 * c + 0] = gf_mul(a0, 14) ^ gf_mul(a1, 11) ^ gf_mul(a2, 13) ^ gf_mul(a3, 9)
        out[4 * c + 1] = gf_mul(a0, 9) ^ gf_mul(a1, 14) ^ gf_mul(a2, 11) ^ gf_mul(a3, 13)
        out[4 * c + 2] = gf_mul(a0, 13) ^ gf_mul(a1, 9) ^ gf_mul(a2, 14) ^ gf_mul(a3, 11)
        out[4 * c + 3] = gf_mul(a0, 11) ^ gf_mul(a1, 13) ^ gf_mul(a2, 9) ^ gf_mul(a3, 14)
    return out


def add_round_key(s: list, round_key: list) -> list:
    return [a ^ b for a, b in zip(s, round_key)]


def expand_key(key: bytes) -> list:
    if len(key) not in (16, 24, 32):
        raise ValueError("Panjang key AES harus 16, 24, atau 32 byte")
    nk = len(key) // 4
    nr = nk + 6
    w = [list(key[4 * i: 4 * i + 4]) for i in range(nk)]

    rcon = 1
    for i in range(nk, 4 * (nr + 1)):
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= rcon
            rcon = xtime(rcon)
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]
        w.append([a ^ b for a, b in zip(w[i - nk], temp)])

    return [sum((w[4 * r + j] for j in range(4)), []) for r in range(nr + 1)]


class AES:
    BLOCK_SIZE = 16

    def __init__(self, key: bytes) -> None:
        self.round_keys = expand_key(key)
        self.nr = len(self.round_keys) - 1

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Blok harus 16 byte")
        s = add_round_key(list(block), self.round_keys[0])
        for r in range(1, self.nr):
            s = sub_bytes(s)
            s = shift_rows(s)
            s = mix_columns(s)
            s = add_round_key(s, self.round_keys[r])
        s = sub_bytes(s)
        s = shift_rows(s)
        s = add_round_key(s, self.round_keys[self.nr])
        return bytes(s)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("Blok harus 16 byte")
        s = add_round_key(list(block), self.round_keys[self.nr])
        for r in range(self.nr - 1, 0, -1):
            s = inv_shift_rows(s)
            s = inv_sub_bytes(s)
            s = add_round_key(s, self.round_keys[r])
            s = inv_mix_columns(s)
        s = inv_shift_rows(s)
        s = inv_sub_bytes(s)
        s = add_round_key(s, self.round_keys[0])
        return bytes(s)
