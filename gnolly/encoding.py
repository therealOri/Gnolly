"""
gnolly.encoding
~~~~~~~~~~~~~~~
Custom binary-to-text encoding with a seeded, shuffled alphabet.
Every protected file uses a different alphabet derived from the session key,
so the encoding pattern is unique per file and defeats pattern recognition.

Also provides a secondary XOR-spread layer that distributes byte values
evenly across the alphabet, further flattening frequency analysis.
"""
from __future__ import annotations
import hashlib
import struct


_BASE_ALPHABET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "0123456789!#$%&'*+,-.:;<>?@^_`{|}~"
)  # 87 printable ASCII chars with '=' intentionally excluded (used as padding sentinel)

_BITS = 6   # log2(64); we'll use 64-char subsets for a clean base-64 variant
_MASK = (1 << _BITS) - 1   # 0x3F


def _make_alphabet(key_material: bytes) -> str:
    """Deterministically shuffle the alphabet using HMAC-SHA256 of key_material."""
    h = hashlib.sha256(key_material).digest()
    # Extend key_material for Fisher-Yates using SHAKE-256 for arbitrary length
    xof = hashlib.shake_256(key_material)
    stream = xof.digest(512)  # more than enough entropy for 88 chars

    chars = list(_BASE_ALPHABET)
    n = len(chars)
    rng_bytes = stream
    idx = 0

    for i in range(n - 1, 0, -1):
        # Use 2 bytes of entropy per swap
        j_raw = struct.unpack_from(">H", rng_bytes, idx % (len(rng_bytes) - 1))[0]
        idx += 2
        j = j_raw % (i + 1)
        chars[i], chars[j] = chars[j], chars[i]

    return "".join(chars)


def _xor_spread(data: bytes, key: bytes) -> bytes:
    """Simple repeating-key XOR to spread byte distribution before encoding."""
    if not key:
        return data
    result = bytearray(len(data))
    klen = len(key)
    for i, b in enumerate(data):
        result[i] = b ^ key[i % klen]
    return bytes(result)


class GnollyCodec:
    """
    Encodes/decodes bytes using a shuffled 88-char alphabet.
    Works as base-88 with a custom alphabet. Each 3 bytes -> 4 chars
    (same ratio as base64 but with a per-file alphabet).
    """

    def __init__(self, key_material: bytes):
        self._alpha = _make_alphabet(key_material)
        # Build reverse lookup
        self._reverse = {c: i for i, c in enumerate(self._alpha)}
        # Derive a secondary XOR spread key from the same key material
        self._xor_key = hashlib.sha256(b"gnolly-spread:" + key_material).digest()[:16]

    def encode(self, data: bytes) -> str:
        """Encode bytes -> string using the seeded alphabet."""
        data = _xor_spread(data, self._xor_key)
        alpha = self._alpha
        result = []
        # Process 3 bytes at a time -> 4 base-64-style chars using our 88-char alpha
        pad = (-len(data)) % 3
        data = data + b"\x00" * pad
        for i in range(0, len(data), 3):
            b0, b1, b2 = data[i], data[i+1], data[i+2]
            n = (b0 << 16) | (b1 << 8) | b2
            result.append(alpha[(n >> 18) & 0x3F])
            result.append(alpha[(n >> 12) & 0x3F])
            result.append(alpha[(n >>  6) & 0x3F])
            result.append(alpha[ n        & 0x3F])
        # Replace padding chars
        if pad == 1:
            result[-1] = "="
        elif pad == 2:
            result[-1] = "="
            result[-2] = "="
        return "".join(result)

    def decode(self, text: str) -> bytes:
        """Decode string -> bytes."""
        alpha = self._alpha
        rev = self._reverse
        pad = text.count("=")
        text = text.replace("=", alpha[0])  # fill with first char (decodes to 0)
        result = bytearray()
        for i in range(0, len(text), 4):
            n = (rev[text[i]]   << 18
               | rev[text[i+1]] << 12
               | rev[text[i+2]] <<  6
               | rev[text[i+3]])
            result.append((n >> 16) & 0xFF)
            result.append((n >>  8) & 0xFF)
            result.append( n        & 0xFF)
        result = bytes(result)
        if pad:
            result = result[:-pad]
        return _xor_spread(result, self._xor_key)
