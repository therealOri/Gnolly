"""
gnolly.crypto
~~~~~~~~~~~~~
AES-256-GCM encryption with Argon2id key derivation.
All crypto is self-contained; no exec(), no string eval.
"""
from __future__ import annotations
import os
import hashlib
import hmac
import struct
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from argon2.low_level import hash_secret_raw, Type as _Argon2Type

# ── constants ─────────────────────────────────────────────────────────────────
_MAGIC    = b"GNLY"          # 4-byte file magic
_VERSION  = b"\x01\x00"      # format version 1.0
_SALT_LEN = 32
_IV_LEN   = 12
_TAG_LEN  = 16
_KEY_LEN  = 32               # AES-256

# Argon2id parameters -> RFC 9106's second ("memory-constrained") recommendation:
# 64 MiB, 3 passes, 4 lanes. Chosen over the 2 GiB "first" recommendation
# because this KDF runs on arbitrary end-user machines at every single
# startup of a protected program, not once at a server-side login endpoint.
_ARGON2_TIME_COST    = 3
_ARGON2_MEMORY_COST  = 65536   # KiB (64 MiB)
_ARGON2_PARALLELISM  = 4


def derive_key(password: bytes, salt: bytes) -> bytes:
    """Argon2id key derivation (time_cost=3, memory_cost=64MiB, parallelism=4)."""
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=_ARGON2_TIME_COST,
        memory_cost=_ARGON2_MEMORY_COST,
        parallelism=_ARGON2_PARALLELISM,
        hash_len=_KEY_LEN,
        type=_Argon2Type.ID,
    )


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
