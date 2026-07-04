"""
gnolly.keymanager
~~~~~~~~~~~~~~~~~
Key generation, storage, and loading.

Keys are stored as a simple JSON file:
    {
        "version": 1,
        "key_hex": "...",          # the raw 32-byte key, hex-encoded
        "protected_file": "...",   # which file this key belongs to (informational)
        "created": "ISO-8601",
        "hint": "..."              # optional user-supplied hint
    }

The key itself is just bytes, how you transmit it to users is up to you.
Common approaches: send via secure channel, embed in env var, use a key server.
"""
from __future__ import annotations
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from Crypto.Random import get_random_bytes


def generate_key(length: int = 32) -> bytes:
    """Generate a cryptographically random key."""
    return get_random_bytes(length)


def save_keyfile(
    key: bytes,
    path: str | Path,
    protected_file: str = "",
    hint: str = "",
) -> None:
    """
    Save *key* to a JSON keyfile at *path*.
    The keyfile is hex-encoded, transmit it out-of-band to your users.
    """
    path = Path(path)
    data = {
        "version": 1,
        "key_hex": key.hex(),
        "protected_file": protected_file,
        "created": datetime.now(timezone.utc).isoformat(),
        "hint": hint,
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_keyfile(path: str | Path) -> bytes:
    """Load a key from a JSON keyfile."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Keyfile not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if "key_hex" not in data:
        raise ValueError("Invalid keyfile: missing 'key_hex' field.")
    return bytes.fromhex(data["key_hex"])


def key_from_env(var: str = "GNOLLY_KEY") -> bytes | None:
    """
    Load a key from an environment variable.
    The env var should contain the hex-encoded key (same format as keyfile).
    Returns None if the variable is not set.

    Usage (bash):
        export GNOLLY_KEY=<hex from keyfile>
        python protected_script.gnolly.py

    In the stub, GNOLLY_KEY is checked before prompting the user.
    """
    val = os.environ.get(var)
    if val is None:
        return None
    val = val.strip()
    try:
        return bytes.fromhex(val)
    except ValueError:
        return None


def key_to_hex(key: bytes) -> str:
    """Return the hex representation of a key for display / .env files."""
    return key.hex()


def key_from_hex(hex_str: str) -> bytes:
    """Parse a hex key string back to bytes."""
    return bytes.fromhex(hex_str.strip())
