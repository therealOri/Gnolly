"""
gnolly.pipeline
~~~~~~~~~~~~~~~
Orchestrates the full Gnolly protection pipeline:

  Source (.py)
    │
    ├─ [1] AST obfuscation      name mangling, dead code, string/int encoding
    ├─ [2] VM translate         source -> GIR bytecode (true VM, no marshal)
    ├─ [3] VM opcode shuffle    per-file GIR opcode permutation
    ├─ [4] Compress             zlib/lzma/bz2, best wins
    ├─ [5] Encrypt              AES-256-GCM + PBKDF2-HMAC-SHA256 (600k iters)
    ├─ [6] Custom encode        per-file seeded alphabet, unique every run
    └─ [7] Stub generation      obfuscated I/l/O/0 loader
              │
              └─ protected_output.gnly.py

NOTE: The legacy marshal+exec path has been removed.  All protected files
      now require both _gnolly_core.so (crypto/decryption) and
      _gnolly_vm.so (GIR interpreter) to be present at runtime.

Code layout (after AES-GCM decrypt + decompress):
    b'\x01'                     VM-mode flag (1 byte)
    u32_BE(gir_len)             GIR blob length
    <gir_blob>                  shuffled GIR bytecode
    u32_BE(table_len)           reverse table length (always 128)
    <table_blob>                128-byte reverse opcode table
"""
from __future__ import annotations
import hashlib
import secrets
import struct
import sys
from pathlib import Path

from .obfuscate   import obfuscate_source
from .compress    import compress
from .crypto      import encrypt, _MAGIC, _VERSION, _SALT_LEN, _IV_LEN, _TAG_LEN
from .encoding    import GnollyCodec
from .stub        import generate_stub
from .build_core  import ensure_core
from .binding     import bind_salt, collect_fingerprint, fingerprint_from_hex
from .vm_pipeline import protect_with_vm
from .vm_translate import VMUnsupportedError

# Auto-build the Cython extension on first import.
ensure_core(verbose=False)

_MAGIC_VER_LEN = len(_MAGIC) + len(_VERSION)   # 6
_HEADER_LEN    = _MAGIC_VER_LEN + _SALT_LEN + _IV_LEN + _TAG_LEN  # 66

# VM mode flag byte prepended to the payload
_VM_MODE_BYTE = b'\x01'


def protect(
    source: str,
    password: bytes,
    *,
    filename: str = "<gnly>",
    mangle_names: bool = True,
    obf_strings: bool = True,
    inject_dead: bool = True,
    obf_numbers: bool = True,
    machine_fingerprint: bytes | None = None,
    seed: int | None = None,
    verbose: bool = False,
    silent: bool = True,
) -> str:
    """
    Run the full Gnolly pipeline on *source* and return the loader stub source.

    Parameters
    ----------
    source          : original Python source code
    password        : bytes key for AES-256-GCM encryption
    filename        : reported filename in compile() tracebacks
    mangle_names    : toggle AST name mangling
    obf_strings     : toggle string literal hex-encoding
    inject_dead     : toggle dead-code injection
    obf_numbers     : toggle integer XOR obfuscation
    seed            : fixed RNG seed for reproducible output (None = random)
    verbose         : print stage progress to stderr
    machine_fingerprint : 32-byte fingerprint from binding.collect_fingerprint().
                      When set, the file will only decrypt on the bound machine.
    silent          : suppress ALL error output from the protected stub (default: True).
    """
    if seed is None:
        seed = secrets.randbits(32)

    def _log(msg: str) -> None:
        if verbose:
            print(f"  [gnolly] {msg}", file=sys.stderr)

    # Stage 1: AST obfuscation
    _log("Stage 1/5  AST obfuscation …")
    obf_source = obfuscate_source(source, seed=seed) \
        if (mangle_names or obf_strings or inject_dead or obf_numbers) \
        else source

    # Stage 2+3: VM translate + GIR opcode shuffle
    # The VM key is derived from password so the shuffle is file-unique.
    _log("Stage 2/5  VM translate + GIR opcode shuffle …")
    vm_key = hashlib.sha256(b"gnolly-vm-key:" + password).digest()

    def _vm_fallback(exc: VMUnsupportedError) -> None:
        # No fallback allowed -> report and abort.
        print(
            f"\n[gnolly] ERROR: Source uses unsupported construct for VM pipeline:\n"
            f"  {exc}\n"
            f"  Gnolly requires full VM protection; no legacy fallback is available.\n",
            file=sys.stderr,
        )
        sys.exit(1)

    result = protect_with_vm(
        obf_source,
        filename=filename,
        key=vm_key,
        fallback_fn=_vm_fallback,
    )
    if result is None:
        # protect_with_vm already called _vm_fallback which exits, but
        # guard here in case caller overrides fallback_fn.
        sys.exit(1)

    gir_blob, table_blob = result

    # Stage 4: Pack VM payload + compress
    _log("Stage 4/5  Compression …")
    # Layout: VM_MODE_FLAG | u32_BE(gir_len) | gir_blob | u32_BE(table_len) | table_blob
    gir_len   = len(gir_blob)
    table_len = len(table_blob)
    packed = (
        _VM_MODE_BYTE
        + struct.pack(">I", gir_len)
        + gir_blob
        + struct.pack(">I", table_len)
        + table_blob
    )
    compressed = compress(packed)

    # Stage 5: Encrypt
    _log("Stage 5/5  Encryption (AES-256-GCM / PBKDF2-600k) …")
    _effective_password = password
    if machine_fingerprint is not None:
        import hmac as _hmac
        _effective_password = _hmac.new(
            machine_fingerprint, password, __import__('hashlib').sha256
        ).digest()
    encrypted_blob = encrypt(compressed, _effective_password)

    salt = encrypted_blob[_MAGIC_VER_LEN            : _MAGIC_VER_LEN + _SALT_LEN]
    iv   = encrypted_blob[_MAGIC_VER_LEN + _SALT_LEN: _MAGIC_VER_LEN + _SALT_LEN + _IV_LEN]
    tag  = encrypted_blob[_HEADER_LEN - _TAG_LEN    : _HEADER_LEN]

    # Stage 6: Custom encode + stub generation
    _log("Stub generation …")
    codec = GnollyCodec(seed=password + seed.to_bytes(4, "big"))
    encoded_payload = codec.encode(encrypted_blob)

    stub_source = generate_stub(
        blob_encoded    = encoded_payload,
        blob_raw_bytes  = encrypted_blob,
        alpha           = codec._alpha,
        xor_key         = codec._xor_key,
        salt            = salt,
        iv              = iv,
        tag             = tag,
        blob_header_skip= _HEADER_LEN,
        use_vm          = True,
        bound           = (machine_fingerprint is not None),
        seed            = seed,
        silent          = silent,
    )
    return stub_source


def protect_file(
    input_path: str | Path,
    output_path: str | Path,
    password: bytes,
    **kwargs,
) -> None:
    """Convenience: read input_path, protect it, write to output_path."""
    input_path  = Path(input_path)
    output_path = Path(output_path)
    source = input_path.read_text(encoding="utf-8")
    stub   = protect(source, password, filename=input_path.name, **kwargs)
    output_path.write_text(stub, encoding="utf-8")
