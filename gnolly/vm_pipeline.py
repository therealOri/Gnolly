"""
gnolly.vm_pipeline
~~~~~~~~~~~~~~~~~~

Integrates the GIR VM into the Gnolly protect pipeline.

High-level flow
---------------

protect-time (developer machine):
  1. Parse + AST-obfuscate source (existing pipeline).
  2. compile() -> CPython code object.
  3. vm_translate.translate_module()  ->  GIRCode tree.
  4. vm_serialize.serialize_module()  ->  raw bytes.
  5. Derive per-file VM opcode shuffle table from the session key.
  6. Apply the forward table to every instruction byte in the blob.
  7. Encrypt the shuffled blob (AES-GCM, same key ladder as before).
  8. Store encrypted blob + reverse table in the .gno output bundle
     alongside the module stub.

load-time (end user machine):
  The stub calls vm_exec.vm_exec_module(blob, table_blob, globs)
  which runs inside _gnolly_vm (Cython, compiled extension -> no fallback).
  The interpreter un-shuffles opcodes on the fly during deserialisation.
"""
from __future__ import annotations
import os

from .vm_isa import build_vm_shuffle_table, serialise_vm_table
from .vm_translate import translate_module, VMUnsupportedError
from .vm_serialize import serialize_module


def protect_with_vm(
    source: str,
    filename: str,
    key: bytes,
    *,
    fallback_fn=None,
    inject_junk: bool = True,
) -> tuple[bytes, bytes] | None:
    """
    Attempt to translate source through the GIR VM pipeline.

    Returns (shuffled_gir_blob, reverse_table_blob) on success.
    Returns None if the module uses unsupported constructs.

    key:
        per-file encryption key (used to derive the VM shuffle table).
    inject_junk:
        emit real GIR-level junk instructions alongside the translated
        code (see vm_translate.py) -> distinct from and in addition to
        the AST-level dead code obfuscate.py already injects before
        compilation.
    """
    try:
        code_obj = compile(source, filename, "exec", optimize=1)
        gir = translate_module(code_obj, inject_junk=inject_junk)
    except VMUnsupportedError as exc:
        if fallback_fn is not None:
            fallback_fn(exc)
        return None
    except SyntaxError:
        raise  # propagate compile errors normally

    raw_blob = serialize_module(gir)
    forward, reverse = build_vm_shuffle_table(key)
    shuffled = _apply_forward_table(raw_blob, gir, forward)
    table_blob = serialise_vm_table(reverse)
    return shuffled, table_blob


def _apply_forward_table(raw_blob: bytes, gir, forward: dict[int, int]) -> bytes:
    """
    Walk the serialised blob and replace every instruction opcode byte
    with its shuffled equivalent.

    This re-serialises only the opcode bytes; all other bytes (varints,
    string lengths, constant tags, etc.) are copied verbatim.  The safest
    implementation re-serialises from the GIRCode tree with forward-mapped
    opcodes rather than patching bytes in place (the varint-length
    instruction stream makes positional patching error-prone).
    """
    from .vm_serialize import GIRCode, serialize_module as _ser
    import copy

    def _map_code(c):
        nc = copy.copy(c)
        nc.instructions = [(forward.get(op, op), arg) for op, arg in c.instructions]
        nc.consts = [_map_code(cv) if isinstance(cv, GIRCode) else cv for cv in c.consts]
        return nc

    mapped = _map_code(gir)
    return _ser(mapped)


def vm_stub_template(module_name: str, blob_var: str, table_var: str) -> str:
    """
    Return Python source for the load-time stub that calls vm_exec_module.

    blob_var / table_var are the names of the bytes literals embedded
    in the stub (or loaded from .gno sidecar files).
    """
    return (
        f"import gnolly._gnolly_vm as _gvm\n"
        f"_gvm.vm_exec_module({blob_var}, {table_var}, globals())\n"
        f"del _gvm\n"
    )
