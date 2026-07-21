"""
gnolly.pack
~~~~~~~~~~~
Final packing pass, run after flatten+minify. Takes the fully-generated
stub source and replaces it with a tiny bootstrap loader plus one
opaque compressed blob that the bootstrap inflates and runs.

Two independent choices are made per build, both picked empirically
(by actually trying every combination and measuring, not by assuming
one is always best) rather than hardcoded:

Mode
  "source"   - compress the source text itself (UTF-8 bytes), and
               have the bootstrap decompress + exec() the resulting
               string directly (exec() compiles a string argument
               itself).
  "bytecode" - compile the source to a code object first
               (compile(..., 'exec')), marshal.dumps() that, and
               compress the marshaled bytes. The bootstrap decompresses
               + marshal.loads() + exec()s the resulting code object.


Algorithm
  Whichever of zlib/bz2/lzma actually produces the smallest output for
  this specific blob -> also measured per build, not assumed.

Both the module names and attribute names involved (zlib/bz2/lzma,
marshal, base64, decompress/loads/b85decode, "utf-8"/"decode") are
hidden via strcodec._hidden_import_attr/_hidden_str_expr, the same
mechanism used everywhere else in the pipeline, nothing about which
algorithm or mode was chosen is visible as plain text in the output
either. The compressed blob itself is embedded as base85 text (not a
raw bytes literal via repr()) -> see pack_source()'s docstring for why
that specifically matters here.
"""
from __future__ import annotations
import base64
import bz2
import lzma
import marshal
import random
import secrets
import zlib

from .strcodec import _hidden_import_attr, _hidden_str_expr, random_confusable_name

_ALGOS = {
    "zlib": (lambda b: zlib.compress(b, 9), "decompress"),
    "bz2":  (lambda b: bz2.compress(b, 9), "decompress"),
    "lzma": (lambda b: lzma.compress(b, preset=9), "decompress"),
}


def _best_candidate(source: str):
    """Try every (mode, algorithm) combination and return the smallest
    one as (mode, algo_name, compressed_bytes), or None if every single
    combination failed."""
    candidates = []

    src_bytes = source.encode("utf-8")
    for algo_name, (compress_fn, _) in _ALGOS.items():
        try:
            c = compress_fn(src_bytes)
            candidates.append((len(c), "source", algo_name, c))
        except Exception:
            continue

    try:
        code = compile(source, "<string>", "exec")
        blob = marshal.dumps(code)
        for algo_name, (compress_fn, _) in _ALGOS.items():
            try:
                c = compress_fn(blob)
                candidates.append((len(c), "bytecode", algo_name, c))
            except Exception:
                continue
    except Exception:
        pass  # compile() failing here would be a pre-existing bug elsewhere; degrade gracefully regardless

    if not candidates:
        return None
    candidates.sort(key=lambda t: t[0])
    _, mode, algo_name, compressed = candidates[0]
    return mode, algo_name, compressed


def pack_source(source: str) -> str:
    """
    Return a tiny bootstrap + compressed-blob replacement for "source",
    or leave "source" unchanged if anything goes wrong. This is the very
    last transformation before the file is shipped, so it has the
    strictest possible "never break a build" bar of anything in the
    pipeline.
    """
    best = _best_candidate(source)
    if best is None:
        return source
    mode, algo_name, compressed = best

    rng = random.Random(secrets.randbits(64))
    used: set = set()
    blob_var = random_confusable_name(rng, used, length=rng.randint(9, 14))

    b85_text = base64.b85encode(compressed).decode("ascii")
    b85_decode_call = _hidden_import_attr("base64", "b85decode", rng)

    decompress_call = _hidden_import_attr(algo_name, "decompress", rng)
    inflated = f"{decompress_call}({b85_decode_call}({blob_var}))"

    if mode == "bytecode":
        loads_call = _hidden_import_attr("marshal", "loads", rng)
        payload = f"{loads_call}({inflated})"
    else:
        decode_attr = _hidden_str_expr("decode", rng)
        utf8_attr = _hidden_str_expr("utf-8", rng)
        payload = f"getattr({inflated}, {decode_attr})({utf8_attr})"

    lines = [
        f"{blob_var} = {b85_text!r}",
        f"exec({payload}, globals())",
    ]
    result = "\n".join(lines)

    if len(result) >= len(source):
        return source

    try:
        restored_compressed = base64.b85decode(b85_text)
        if restored_compressed != compressed:
            return source
        decompress_fn = {"zlib": zlib.decompress, "bz2": bz2.decompress, "lzma": lzma.decompress}[algo_name]
        restored = decompress_fn(restored_compressed)
        if mode == "bytecode":
            marshal.loads(restored)  # just confirm it unmarshals; exact byte match isn't meaningful for code objects
        else:
            if restored.decode("utf-8") != source:
                return source
        compile(result, "<pack_check>", "exec")
    except Exception:
        return source

    return result
