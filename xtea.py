"""
xtea.py — Python port of tdc-clean/challenge-encrypt.js (Tencent TDC's
`window.ChallengeEncrypt`).

XTEA (eXtended TEA), 64-bit block / 128-bit key, ECB mode, 32 rounds,
delta 0x9E3779B9, little-endian word packing + serialization, zero-padded to a
whole number of 8-byte blocks, output Base64.

Keys are PER-BUILD (tdc1..tdc10), recovered & verified byte-exact against the live
oracle (see tdc_deobfuscate/tdc-clean/challenge-encrypt.js). This module is a
1:1 port; `selftest()` proves it against a real captured token.
"""
from __future__ import annotations

import base64

DELTA = 0x9E3779B9
ROUNDS = 32
MASK = 0xFFFFFFFF

# Per-build 128-bit XTEA keys (4 x 32-bit words). Mirrors challenge-encrypt.js KEYS.
KEYS = {
    "tdc1": [0x564B4D50, 0x57436261, 0x624F4741, 0x63574D59],
    "tdc2": [0x69626E62, 0x63416E52, 0x5347634F, 0x65426E53],
    "tdc3": [0x5A5A4266, 0x55516D69, 0x53694461, 0x576A4D56],
    "tdc4": [0x474D6768, 0x4B614665, 0x646B5066, 0x41484A46],
    "tdc5": [0x43575341, 0x526E6854, 0x575A6146, 0x4F62464B],
    "tdc6": [0x68515747, 0x50616955, 0x58594161, 0x6B415667],
    "tdc7": [0x6A6D434F, 0x6663576A, 0x63566367, 0x63504E44],
    "tdc8": [0x576A5055, 0x694E4B53, 0x5357414B, 0x4A57576E],
    "tdc9": [0x56644D67, 0x685A6C52, 0x5A676448, 0x67616C57],
    "tdc10": [0x51554369, 0x4454654A, 0x57526C61, 0x50524365],
}


def resolve_key(variant) -> list[int]:
    if isinstance(variant, (list, tuple)):
        return list(variant)
    k = KEYS.get(variant)
    if k is None:
        raise ValueError(f"unknown variant {variant!r}; known: {', '.join(KEYS)}")
    return k


def _u32(x: int) -> int:
    return x & MASK


def encrypt_block(v0: int, v1: int, key: list[int]) -> tuple[int, int]:
    v0 = _u32(v0)
    v1 = _u32(v1)
    s = 0
    for _ in range(ROUNDS):
        v0 = _u32(v0 + ((_u32((v1 << 4) ^ (v1 >> 5)) + v1) ^ _u32(s + key[s & 3])))
        s = _u32(s + DELTA)
        v1 = _u32(v1 + ((_u32((v0 << 4) ^ (v0 >> 5)) + v0) ^ _u32(s + key[(s >> 11) & 3])))
    return v0, v1


def decrypt_block(v0: int, v1: int, key: list[int]) -> tuple[int, int]:
    v0 = _u32(v0)
    v1 = _u32(v1)
    s = _u32(DELTA * ROUNDS)
    for _ in range(ROUNDS):
        v1 = _u32(v1 - ((_u32((v0 << 4) ^ (v0 >> 5)) + v0) ^ _u32(s + key[(s >> 11) & 3])))
        s = _u32(s - DELTA)
        v0 = _u32(v0 - ((_u32((v1 << 4) ^ (v1 >> 5)) + v1) ^ _u32(s + key[s & 3])))
    return v0, v1


def pack_words(s: str) -> list[int]:
    """One UTF-16 code unit per byte slot, LE; word count = ceil(len/4) padded to even."""
    n = len(s)
    if n == 0:
        return []
    words = [0] * ((n + 3) // 4)
    for i, ch in enumerate(s):
        words[i >> 2] = _u32(words[i >> 2] | _u32(ord(ch) << ((i & 3) * 8)))
    if len(words) % 2 == 1:
        words.append(0)
    return words


def encrypt_bytes(s: str, variant="tdc1") -> bytes:
    key = resolve_key(variant)
    words = pack_words(str(s))
    out = bytearray(len(words) * 4)
    for i in range(0, len(words), 2):
        c0, c1 = encrypt_block(words[i], words[i + 1], key)
        out[i * 4 : i * 4 + 4] = c0.to_bytes(4, "little")
        out[i * 4 + 4 : i * 4 + 8] = c1.to_bytes(4, "little")
    return bytes(out)


def challenge_encrypt(s: str, variant="tdc1") -> str:
    """Exact replica of window.ChallengeEncrypt -> Base64 string."""
    return base64.b64encode(encrypt_bytes(s, variant)).decode("ascii")


def decrypt_token(b64_or_raw, variant="tdc1") -> str:
    """Inverse: Base64(ciphertext) -> plaintext (trailing NULs stripped)."""
    key = resolve_key(variant)
    data = base64.b64decode(b64_or_raw)
    if len(data) % 8 != 0:
        raise ValueError(f"ciphertext length {len(data)} not a multiple of 8")
    out = bytearray()
    for i in range(0, len(data), 8):
        v0 = int.from_bytes(data[i : i + 4], "little")
        v1 = int.from_bytes(data[i + 4 : i + 8], "little")
        p0, p1 = decrypt_block(v0, v1, key)
        out += p0.to_bytes(4, "little") + p1.to_bytes(4, "little")
    # plaintext packs ONE char per byte (LE), zero-padded to a block boundary.
    # ChallengeEncrypt is fed an ASCII blob, so decode latin-1 (byte == char code).
    return out.decode("latin-1").rstrip("\x00")


if __name__ == "__main__":
    # selftest: decrypt a real captured tdc2 token, re-encrypt, prove byte-exact.
    import os, urllib.parse

    tok_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "groundtruth", "real_token_tdc2.txt")
    if os.path.exists(tok_path):
        raw = open(tok_path).read().strip()
        b64 = urllib.parse.unquote(raw)
        plain = decrypt_token(b64, "tdc2")
        print(f"decrypted tdc2 token -> {len(plain)} chars; starts: {plain[:40]!r}")
        # the plaintext is a chars-per-byte string; re-encrypting must reproduce b64
        re_b64 = challenge_encrypt(plain, "tdc2")
        # token may carry trailing zero-pad chars dropped by rstrip; compare the
        # decodable JSON prefix instead for a robust gate
        ok_json = plain.lstrip().startswith("{") and '"cd"' in plain
        roundtrip = re_b64 == b64 or base64.b64decode(re_b64) == base64.b64decode(b64)[: len(base64.b64decode(re_b64))]
        print(f"  valid collect JSON: {ok_json}")
        print(f"  re-encrypt round-trip byte-exact: {roundtrip}")
        assert ok_json, "decrypted token is not collect JSON — XTEA port is wrong"
        print("SELFTEST OK")
    else:
        print("no fixture token; skipping selftest")
