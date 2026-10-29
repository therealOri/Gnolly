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
    ├─ [5] Encrypt              AES-256-GCM + Argon2id (t=3, m=64MiB, p=4)
    ├─ [6] Custom encode        per-file alphabet keyed from password + random salt, unique every run
    └─ [7] Stub generation      obfuscated I/l/O/0 loader
              │
              └─ protected_output.gnly.py


Code layout (after AES-GCM decrypt + decompress):
    b'\x01'                     VM-mode flag (1 byte)
    u32_BE(gir_len)             GIR blob length
    <gir_blob>                  shuffled GIR bytecode
    u32_BE(table_len)           reverse table length (always 256)
    <table_blob>                256-byte reverse opcode table
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
from .minify      import minify_source
from .pack        import pack_source
from .build_core  import ensure_core
from .binding     import collect_fingerprint, fingerprint_from_hex
from .integrity   import collect_runtime_hashes, fold_integrity
from .poison      import fold_poison
from .ptrace_guard import DEFAULT_HEARTBEAT_MIN_DELAY, DEFAULT_HEARTBEAT_MAX_DELAY
from .heartbeat import (
    DEFAULT_MIN_DELAY as HEARTBEAT_DEFAULT_MIN_DELAY,
    DEFAULT_MAX_DELAY as HEARTBEAT_DEFAULT_MAX_DELAY,
)
from .vm_pipeline import protect_with_vm
from .vm_translate import VMUnsupportedError

# Auto-build the Cython extension on first import.
ensure_core(verbose=False)

_MAGIC_VER_LEN = len(_MAGIC) + len(_VERSION)
_HEADER_LEN    = _MAGIC_VER_LEN + _SALT_LEN + _IV_LEN + _TAG_LEN

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
    inject_junk: bool = True,
    machine_fingerprint: bytes | None = None,
    verbose: bool = False,
    silent: bool = True,
    flatten: bool = True,
    minify: bool = True,
    pack: bool = True,
    self_hash: bool = True,
    module_mode: bool = False,
    bogus_hierarchy: bool = True,
    alias_exprs: bool = True,
    decorrelate_checks: bool = True,
    poison_watchdog: bool = True,
    ptrace_guard: bool = True,
    ptrace_guard_heartbeat: bool = True,
    ptrace_guard_heartbeat_min_delay: float = DEFAULT_HEARTBEAT_MIN_DELAY,
    ptrace_guard_heartbeat_max_delay: float = DEFAULT_HEARTBEAT_MAX_DELAY,
    python_heartbeat: bool = True,
    python_heartbeat_min_delay: float = HEARTBEAT_DEFAULT_MIN_DELAY,
    python_heartbeat_max_delay: float = HEARTBEAT_DEFAULT_MAX_DELAY,
) -> str:
    """
    Parameters
    ----------
    source          : original Python source code
    password        : bytes key for AES-256-GCM encryption
    filename        : reported filename in compile() tracebacks
    mangle_names    : toggle AST name mangling
    obf_strings     : toggle string/bytes/float keyed encoding (gnolly.strcodec scheme)
    inject_dead     : toggle AST-level dead-code injection (before compilation)
    obf_numbers     : toggle integer XOR obfuscation
    inject_junk     : toggle GIR-level junk instruction injection (after compilation,
                      alongside the translated bytecode -> see vm_translate.py)
    verbose         : print stage progress to stderr
    machine_fingerprint : 32-byte fingerprint from binding.collect_fingerprint().
                      When set, the file will only decrypt on the bound machine.
    silent          : suppress ALL error output from the protected stub (default: True).
    flatten         : toggle control-flow flattening of the generated stub
                      (opaque dispatch-loop state machine -> see gnolly.flatten).
    minify          : toggle post-generation minification of the stub
                      (see gnolly.minify). On by default; disable via
                      --no-minify on the CLI if you want to inspect the
                      unminified output.
    pack            : toggle final compression pass (see gnolly.pack)
                      This replaces the generated stub with a tiny bootstrap
                      plus one opaque compressed blob.
                      On by default; disable via --no-pack on the CLI
                      if you want the readable (flattened/minified)
                      stub as the shipped output instead.
    self_hash       : toggle self-hash verification of the stub's own
                      source text (see gnolly.selfhash). Several
                      independent checks, run at startup, detect any
                      reformatting/patching of the shipped file. On by
                      default. Collapses the stub's visible line count
                      down to essentially one line (an assignment plus
                      exec()), since the checked text has to be
                      self-referenced as a string rather than left as
                      literal top-level statements -> disable if you
                      specifically need to inspect the readable
                      (flattened/minified) stub source, e.g. with
                      pack=False.
    module_mode     : toggle "importable module" execution feature
                      instead of "standalone script" feature -> the
                      protected code executes into the stub's own
                      globals() instead of a __main__ namespace.
                      This is used by gnolly.package / gnolly.wheel for package and wheel
                      protection. Off by default (single-file "protect"
                      behavior is unchanged).
    bogus_hierarchy : toggle AST-level fake inherited class hierarchy
                      and also diversify the opaque-True tokens used in AST
                      obfuscation passes. On by default.
    alias_exprs     : toggle AST-level expression aliasing -> call results are randomly
                      routed through one or more layer(s) of indirection.
    decorrelate_checks : toggle decorrelated/delayed failure reaction for
                      the stub's anti-debug, timing, and cosmetic
                      checks (see gnolly.poison). On by default: a
                      failed check no longer exit()s at the point it's
                      detected -> it corrupts an accumulator that gets
                      folded into the decryption key hundreds of lines
                      later instead. Disable to get the old
                      immediate-exit-at-detection-site behavior back.
    poison_watchdog : default True. An independent backup reaction
                      (hard process kill if the poison accumulator is
                      nonzero), on top of the key fold above -> catches
                      a tamper attempt that would defeat the key fold
                      itself. Only has an effect when decorrelate_checks
                      is True. When python_heartbeat is ALSO on (the
                      default), this is folded into that thread's
                      repeating loop as one more indistinguishable
                      branch, rather than a second single-purpose
                      thread.
    ptrace_guard    : Linux-only. When True, the protected stub
                      self-attaches via ptrace(PTRACE_TRACEME,...)
                      immediately after it loads and SHA-256-verifies
                      gnolly/_gnolly_core.so, which blocks any debugger
                      (gdb, strace, etc.) from attaching to the process
                      at all, since the OS only permits one tracer per
                      process. A self-attach failure always reacts like
                      every other antidebug check (poison-mark if
                      decorrelate_checks, else immediate exit).
                      A deployment target that can't guarantee CAP_SYS_PTRACE should
                      set this to False rather than expect a lenient mode.
    ptrace_guard_heartbeat : when True (default), a detached pthread in
                      the core .so periodically
                      re-reads /proc/<pid>/status's TracerPid and
                      hard-kills the process (_exit() in C) the moment
                      it reads back 0. No effect when ptrace_guard
                      is False.
    ptrace_guard_heartbeat_min_delay, ptrace_guard_heartbeat_max_delay :
                      randomized re-check interval in seconds (default
                      gnolly.ptrace_guard.DEFAULT_HEARTBEAT_MIN_DELAY/
                      MAX_DELAY, 0.0005-0.002, i.e. 0.5-2ms -> edit
                      those two constants directly to change the
                      project-wide default). This bounds how long an
                      attacker can act against the *running* process
                      after detaching it, not how long they can inspect
                      memory while it's stopped. No effect when
                      ptrace_guard_heartbeat is False.
    python_heartbeat : when True (default), a daemon thread
                      (gnolly.heartbeat) re-verifies the stub's own
                      self-hash, both compiled .so's on-disk hashes, and
                      antidebug signals on a randomized interval for the
                      life of the process -> the Python-layer companion
                      to the GIR VM's own continuous check
                      (gnolly/_gnolly_vm.pyx), which only covers code
                      running through the VM. A detected mismatch calls
                      os._exit(1) directly.
    python_heartbeat_min_delay, python_heartbeat_max_delay :
                      randomized re-check interval in seconds (default
                      gnolly.heartbeat.DEFAULT_MIN_DELAY/MAX_DELAY,
                      0.4-1.0s -> coarser than ptrace_guard_heartbeat's
                      0.5-2ms since this does real disk I/O re-reading
                      both .so's each pass). No effect when
                      python_heartbeat is False.
    """
    def _log(msg: str) -> None:
        if verbose:
            print(f"  [gnolly] {msg}", file=sys.stderr)

    # Stage 1: AST obfuscation
    _log("Stage 1/5  AST obfuscation …")
    obf_source = obfuscate_source(source, preserve_toplevel=module_mode,
                                   bogus_hierarchy=bogus_hierarchy,
                                   alias_exprs=alias_exprs) \
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
        inject_junk=inject_junk,
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
    _log("Stage 5/5  Encryption (AES-256-GCM / Argon2id) …")
    _effective_password = password
    if machine_fingerprint is not None:
        import hmac as _hmac
        _effective_password = _hmac.new(
            machine_fingerprint, password, __import__('hashlib').sha256
        ).digest()
    runtime_hashes = collect_runtime_hashes()
    _effective_password = fold_integrity(_effective_password, runtime_hashes)
    if decorrelate_checks:
        # Mirror of the runtime poison fold (see gnolly.poison and
        # stub.py) with the accumulator fixed at 0 -> nothing has
        # failed yet at build time by definition.
        _effective_password = fold_poison(_effective_password, poison_value=0)
    encrypted_blob = encrypt(compressed, _effective_password)

    salt = encrypted_blob[_MAGIC_VER_LEN            : _MAGIC_VER_LEN + _SALT_LEN]
    iv   = encrypted_blob[_MAGIC_VER_LEN + _SALT_LEN: _MAGIC_VER_LEN + _SALT_LEN + _IV_LEN]
    tag  = encrypted_blob[_HEADER_LEN - _TAG_LEN    : _HEADER_LEN]

    # Stage 6: Custom encode + stub generation
    _log("Stub generation …")
    codec = GnollyCodec(key_material=password + secrets.token_bytes(16))
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
        silent          = silent,
        flatten         = flatten,
        self_hash       = self_hash,
        will_be_packed  = pack,
        module_mode     = module_mode,
        decorrelate_checks = decorrelate_checks,
        poison_watchdog = poison_watchdog,
        ptrace_guard = ptrace_guard,
        ptrace_guard_heartbeat = ptrace_guard_heartbeat,
        ptrace_guard_heartbeat_min_delay = ptrace_guard_heartbeat_min_delay,
        ptrace_guard_heartbeat_max_delay = ptrace_guard_heartbeat_max_delay,
        python_heartbeat = python_heartbeat,
        python_heartbeat_min_delay = python_heartbeat_min_delay,
        python_heartbeat_max_delay = python_heartbeat_max_delay,
    )
    if minify:
        _log("Minifying stub …")
        stub_source = minify_source(stub_source)
    if pack:
        _log("Packing stub …")
        stub_source = pack_source(stub_source)
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
