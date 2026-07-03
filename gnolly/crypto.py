"""
gnolly.crypto
~~~~~~~~~~~~~
AES-256-GCM encryption with Argon2-style PBKDF2 key derivation.
All crypto is self-contained; no exec(), no string eval.
"""
from __future__ import annotations
import os
import hashlib
import hmac
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# ── constants ─────────────────────────────────────────────────────────────────
_MAGIC    = b"GNLY"          # 4-byte file magic
_VERSION  = b"\x02\x00"     # format version 2.0
_SALT_LEN = 32
_IV_LEN   = 12
_TAG_LEN  = 16
_KEY_LEN  = 32               # AES-256
_PBKDF2_ITERS = 600_000      # OWASP and NIST recommendation for SHA-256


def derive_key(password: bytes, salt: bytes) -> bytes:
    """PBKDF2-HMAC-SHA256 key derivation."""
    return hashlib.pbkdf2_hmac("sha256", password, salt, _PBKDF2_ITERS, dklen=_KEY_LEN)


def encrypt(plaintext: bytes, password: bytes) -> bytes:
    """
    Encrypt *plaintext* and return a self-contained blob:
        MAGIC | VERSION | SALT(32) | IV(12) | TAG(16) | CIPHERTEXT
    """
    salt = get_random_bytes(_SALT_LEN)
    iv   = get_random_bytes(_IV_LEN)
    key  = derive_key(password, salt)

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=_TAG_LEN)
    # Bind magic+version as additional authenticated data so the header
    # can't be tampered with without breaking authentication.
    cipher.update(_MAGIC + _VERSION)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return _MAGIC + _VERSION + salt + iv + tag + ciphertext


def decrypt(blob: bytes, password: bytes) -> bytes:
    """Decrypt a blob produced by encrypt(). Raises ValueError on bad key/tamper."""
    if not blob.startswith(_MAGIC + _VERSION):
        raise ValueError("Not a valid Gnolly blob or version mismatch.")

    offset = len(_MAGIC) + len(_VERSION)
    salt       = blob[offset : offset + _SALT_LEN];   offset += _SALT_LEN
    iv         = blob[offset : offset + _IV_LEN];     offset += _IV_LEN
    tag        = blob[offset : offset + _TAG_LEN];    offset += _TAG_LEN
    ciphertext = blob[offset:]

    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=_TAG_LEN)
    cipher.update(_MAGIC + _VERSION)
    try:
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        raise ValueError("Decryption failed: wrong key or data was tampered with.")


def generate_key() -> bytes:
    """Generate a random 32-byte key (for keyfile mode)."""
    return get_random_bytes(_KEY_LEN)


def fingerprint(data: bytes) -> str:
    """SHA-256 hex digest — used for integrity checks in the loader stub."""
    return hashlib.sha256(data).hexdigest()
