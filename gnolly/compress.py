"""
gnolly.compress
~~~~~~~~~~~~~~~
Multi-algorithm compression with automatic best-pick.
Tries zlib, lzma, and bz2 and selects the smallest output.
A 1-byte algorithm tag is prepended so the decompressor knows what to use.
"""
from __future__ import annotations
import zlib
import lzma
import bz2

_ALGO_ZLIB = b"\x01"
_ALGO_LZMA = b"\x02"
_ALGO_BZ2  = b"\x03"
_ALGO_NONE = b"\x00"   # fallback: data already small / incompressible


def compress(data: bytes) -> bytes:
    """Compress *data* and return tagged blob. Picks the smallest result."""
    candidates: list[tuple[bytes, bytes]] = []

    try:
        c = zlib.compress(data, level=9)
        candidates.append((_ALGO_ZLIB, c))
    except Exception:
        pass

    try:
        c = lzma.compress(data, preset=9)
        candidates.append((_ALGO_LZMA, c))
    except Exception:
        pass

    try:
        c = bz2.compress(data, compresslevel=9)
        candidates.append((_ALGO_BZ2, c))
    except Exception:
        pass

    if not candidates:
        return _ALGO_NONE + data

    tag, best = min(candidates, key=lambda x: len(x[1]))

    # Only use compression if it actually shrinks the data
    if len(best) >= len(data):
        return _ALGO_NONE + data

    return tag + best


def decompress(blob: bytes) -> bytes:
    """Decompress a blob produced by compress()."""
    if len(blob) < 1:
        raise ValueError("Empty compression blob.")
    tag  = blob[:1]
    data = blob[1:]

    if tag == _ALGO_NONE:
        return data
    elif tag == _ALGO_ZLIB:
        return zlib.decompress(data)
    elif tag == _ALGO_LZMA:
        return lzma.decompress(data)
    elif tag == _ALGO_BZ2:
        return bz2.decompress(data)
    else:
        raise ValueError(f"Unknown compression tag: {tag!r}")
