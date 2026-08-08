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

Decompression pathway
  For zlib and bz2 specifically, decompression goes through
  codecs.decode(data, "zlib") / codecs.decode(data, "bz2") instead of
  zlib.decompress()/bz2.decompress() directly. Both are registered
  as standard library codecs. (a route most people reach for exclusively for text
  encodings and don't think to associate with binary compression.)
  This means both algorithms share a single hidden lookup (codecs.decode)
  rather than each needing its own separate hidden module import.
  Lzma has no codecs registration so it still goes through the traditional
  lzma.decompress() route when chosen.

One hidden __import__ reference, not several
  Every lookup needed at runtime (the decompressor, base64.b85decode,
  and marshal.loads in bytecode mode) shares a single hidden
  __import__ indirection computed once and stored in a local variable,
  rather than each one independently reconstructing that whole chain
  from scratch the way naive repeated strcodec._hidden_import_attr()
  calls would. Real, measurable bootstrap-size savings, and it's what
  makes routing zlib/bz2 through one shared codecs.decode lookup
  actually pay off rather than just moving the cost around.

The bootstrap this module generates is minified before being returned,
the same as everything else in the pipeline.
"""
from __future__ import annotations
import base64
import bz2
import lzma
import marshal
import random
import secrets
import zlib

from .strcodec import _hidden_import_call, _hidden_str_expr, random_confusable_name, _hidden_exec_ref
from .minify import minify_source

_ALGOS = {
    "zlib": lambda b: zlib.compress(b, 9),
    "bz2":  lambda b: bz2.compress(b, 9),
    "lzma": lambda b: lzma.compress(b, preset=9),
}

_CODEC_REGISTERED = {"zlib", "bz2"}


def _best_candidate(source: str):
    """Try every (mode, algorithm) combination and return the smallest
    one as (mode, algo_name, compressed_bytes), or None if every single
    combination failed."""
    candidates = []

    src_bytes = source.encode("utf-8")
    for algo_name, compress_fn in _ALGOS.items():
        try:
            c = compress_fn(src_bytes)
            candidates.append((len(c), "source", algo_name, c))
        except Exception:
            continue

    try:
        code = compile(source, "<string>", "exec")
        blob = marshal.dumps(code)
        for algo_name, compress_fn in _ALGOS.items():
            try:
                c = compress_fn(blob)
                candidates.append((len(c), "bytecode", algo_name, c))
            except Exception:
                continue
    except Exception:
        pass

    if not candidates:
        return None
    candidates.sort(key=lambda t: t[0])
    _, mode, algo_name, compressed = candidates[0]
    return mode, algo_name, compressed


def _decompress_reference(algo_name: str, rng: random.Random, imp_var: str) -> str:
    """Expression for the callable that decompresses this build's
    chosen algorithm, built against the shared "imp_var" import
    reference rather than deriving its own."""
    if algo_name in _CODEC_REGISTERED:
        codecs_str = _hidden_str_expr("codecs", rng)
        decode_str = _hidden_str_expr("decode", rng)
        algo_str = _hidden_str_expr(algo_name, rng)
        decode_fn = f"getattr({imp_var}({codecs_str}), {decode_str})"
        return f"(lambda _i: {decode_fn}(_i, {algo_str}))"
    else:
        mod_str = _hidden_str_expr(algo_name, rng)
        attr_str = _hidden_str_expr("decompress", rng)
        return f"getattr({imp_var}({mod_str}), {attr_str})"


def pack_source(source: str) -> str:
    """
    Return a tiny bootstrap + compressed-blob replacement for "source",
    or "source" unchanged if anything goes wrong.
    """
    best = _best_candidate(source)
    if best is None:
        return source
    mode, algo_name, compressed = best

    rng = random.Random(secrets.randbits(64))
    used: set = set()
    blob_var = random_confusable_name(rng, used, length=rng.randint(9, 14))
    imp_var = random_confusable_name(rng, used, length=rng.randint(9, 14))

    b85_text = base64.b85encode(compressed).decode("ascii")

    b85mod_str = _hidden_str_expr("base64", rng)
    b85attr_str = _hidden_str_expr("b85decode", rng)
    b85_decode_call = f"getattr({imp_var}({b85mod_str}), {b85attr_str})"

    decompress_ref = _decompress_reference(algo_name, rng, imp_var)
    inflated = f"{decompress_ref}({b85_decode_call}({blob_var}))"

    if mode == "bytecode":
        marshal_str = _hidden_str_expr("marshal", rng)
        loads_str = _hidden_str_expr("loads", rng)
        loads_call = f"getattr({imp_var}({marshal_str}), {loads_str})"
        payload = f"{loads_call}({inflated})"
    else:
        decode_attr = _hidden_str_expr("decode", rng)
        utf8_attr = _hidden_str_expr("utf-8", rng)
        payload = f"getattr({inflated}, {decode_attr})({utf8_attr})"

    lines = [
        f"{blob_var} = {b85_text!r}",
        f"{imp_var} = {_hidden_import_call(rng)}",
        f"({_hidden_exec_ref(rng)})({payload}, globals())",
    ]
    result = "\n".join(lines)

    # Minify our own generated bootstrap.
    try:
        result = minify_source(result)
    except Exception:
        pass

    if len(result) >= len(source):
        return source

    try:
        restored_compressed = base64.b85decode(b85_text)
        if restored_compressed != compressed:
            return source
        if algo_name in _CODEC_REGISTERED:
            import codecs
            restored = codecs.decode(restored_compressed, algo_name)
        else:
            decompress_fn = {"lzma": lzma.decompress}[algo_name]
            restored = decompress_fn(restored_compressed)
        if mode == "bytecode":
            marshal.loads(restored)  # confirm it unmarshals;
        else:
            if restored.decode("utf-8") != source:
                return source
        compile(result, "<pack_check>", "exec")
    except Exception:
        return source

    return result
