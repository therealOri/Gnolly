# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
# cython: embedsignature=False
# cython: emit_code_comments=False
"""
gnolly/_gnolly_core.pyx  ->  Compiled C runtime core
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Decrypt -> decompress -> dispatch to GIR VM.
All security-critical crypto logic lives here as native machine code.

Execution model
----------------
After AES-256-GCM decrypt + decompress, the resulting payload/code is a GIR
(Gnolly Intermediate Representation) blob -> a custom bytecode format produced by gnolly.vm_translate at protect-time.
That blob is handed to _gnolly_vm.vm_exec_module(), a separate Cython extension implementing a
full bytecode interpreter (its own stack machine, frame objects, and
dispatch loop). CPython's eval loop (ceval.c) is never invoked on
protected code, and the original CPython opcodes never exist anywhere
at runtime -> they were translated to GIR once, at protect-time, and
the translation is one-way.

Both _gnolly_core.so (this module) and _gnolly_vm.so are required at
runtime. There is no fallback execution path; if _gnolly_vm cannot be
imported, this module exits immediately rather than degrading to a
less-protected mode.

Payload layout (after decrypt + decompress)
--------------------------------------------
  b'\\x01'              VM-mode flag (1 byte)
  u32_BE(gir_len)       GIR blob length
  <gir_blob>            shuffled GIR bytecode (per-file opcode permutation,
                         see vm_translate.py / vm_serialize.py)
  u32_BE(table_len)     reverse opcode table length (always 128)
  <table_blob>          128-byte reverse opcode table for the GIR shuffle
"""

import struct
import sys
import hashlib
import zlib
import lzma
import bz2

from Crypto.Cipher import AES


# ── Constants ─────────────────────────────────────────────────────────────────

cdef bytes _MAGIC_AAD  = b'GNLY\x02\x00'
cdef int   _HEADER_LEN = 6 + 32 + 12 + 16   # magic+ver + salt + iv + tag


# ── Key derivation ────────────────────────────────────────────────────────────

cdef bytes _pbkdf2_key(bytes password, bytes salt):
    """PBKDF2-HMAC-SHA256, 600 000 iterations → 32-byte key."""
    return hashlib.pbkdf2_hmac('sha256', password, salt, 600_000, dklen=32)


# ── Decompression ─────────────────────────────────────────────────────────────

cdef bytes _decompress(bytes data):
    cdef bytes tag_b = data[:1]
    cdef bytes body  = data[1:]
    if tag_b == b'\x00':
        return body
    elif tag_b == b'\x01':
        return zlib.decompress(body)
    elif tag_b == b'\x02':
        return lzma.decompress(body)
    elif tag_b == b'\x03':
        return bz2.decompress(body)
    else:
        raise ValueError("Unknown compression tag")


# ── Anti-debug ────────────────────────────────────────────────────────────────

cdef void _anti_debug_c():
    """
    C-level anti-debug sweep -> runs after the stub's Python checks so it
    catches any hooks installed between stub execution and here.
    """
    if getattr(sys, 'gettrace', lambda: None)() is not None:
        sys.exit(1)
    if getattr(sys, 'getprofile', lambda: None)() is not None:
        sys.exit(1)

    cdef object _mods = sys.modules
    for _dbg in ('pydevd', 'debugpy', 'pydevd_tracing', '_pydevd_bundle',
                 'rpdb', 'wingdbstub', 'pywin32trace', 'birdseye',
                 '_pydev_bundle', 'pydev_ipython'):
        if _dbg in _mods:
            sys.exit(1)

    cdef object _mon = getattr(sys, 'monitoring', None)
    if _mon is not None:
        try:
            for _tid in (1, 2, 3):
                if getattr(_mon, 'get_tool', lambda _: None)(_tid) is not None:
                    sys.exit(1)
        except Exception:
            pass


# ── sys.monitoring blackout ───────────────────────────────────────────────────

cdef object _monitoring_blackout_enter():
    cdef object _mon = getattr(sys, 'monitoring', None)
    if _mon is None:
        return None
    cdef int _TOOL = 5
    try:
        getattr(_mon, 'use_tool_id')(_TOOL, 'gnolly_runtime')
        getattr(_mon, 'set_events')(_TOOL, 0)
        return _TOOL
    except Exception:
        return None


cdef void _monitoring_blackout_exit(object state):
    if state is None:
        return
    cdef object _mon = getattr(sys, 'monitoring', None)
    if _mon is None:
        return
    try:
        getattr(_mon, 'free_tool_id')(state)
    except Exception:
        pass

# ── Load _gnolly_vm -> required, no fallback ───────────────────────────────────
# Both .so files must be present. If _gnolly_vm is missing, we exit immediately
# rather than falling back to marshal+exec (which would be a security regression).
cdef object _gvm_exec_module = None
cdef bint _VM_LOADED = False

def _gnolly_load_vm_module(object vm_module):
    """
    Called by the stub immediately after loading _gnolly_vm.so, before any
    call to gnolly_run(). Registers the VM's exec function for use below.
    This is the ONLY way gnolly_run can access the VM.
    """
    global _gvm_exec_module, _VM_LOADED
    try:
        _gvm_exec_module = vm_module.vm_exec_module
        _VM_LOADED = True
    except AttributeError:
        _VM_LOADED = False
        sys.exit(1)


# ── Public: gnolly_run ────────────────────────────────────────────────────────

def gnolly_run(
    bytes blob_raw,
    object key_input,
    bytes salt,
    bytes iv,
    bytes tag,
    int header_skip,
    bytes alpha_bytes,
    bytes xor_key,
    object caller_globals=None,
):
    """
    Full Gnolly runtime pipeline -> compiled to C.

    decrypt -> decompress -> GIR VM execute

    Payload/code format (after AES-GCM decrypt + decompress):
        b'\\x01'              VM-mode flag
        u32_BE(gir_len)      GIR blob length
        <gir_blob>           shuffled GIR bytecode
        u32_BE(table_len)    reverse table length (128)
        <table_blob>         128-byte reverse opcode table

    caller_globals : when provided (module_mode stubs, e.g. protected
        package/wheel submodules), the decoded output executes directly into
        a dict instead of throwaway namespace.
    """
    _anti_debug_c()
    if not _VM_LOADED:
        # _gnolly_vm.so was never registered via _gnolly_load_vm_module().
        # No fallback execution path exists -> refuse to run.
        sys.exit(1)
    cdef object _blackout_state = _monitoring_blackout_enter()

    # ── 1. Normalise key ──────────────────────────────────────────────────────
    cdef bytes key
    if isinstance(key_input, (bytes, bytearray)):
        key = bytes(key_input)
    else:
        key = key_input.encode('utf-8')

    # ── 2. KDF ────────────────────────────────────────────────────────────────
    cdef bytes derived = _pbkdf2_key(key, salt)
    key = b''

    # ── 3. AES-256-GCM decrypt ────────────────────────────────────────────────
    cdef bytes ciphertext = blob_raw[header_skip:]
    cdef bytes plaintext
    try:
        cipher = AES.new(derived, AES.MODE_GCM, nonce=iv, mac_len=16)
        cipher.update(_MAGIC_AAD)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError:
        sys.exit(1)
    finally:
        derived = b''

    # ── 4. Decompress ─────────────────────────────────────────────────────────
    cdef bytes decompressed = _decompress(plaintext)
    plaintext = b''

    # ── 5. Unpack VM-mode payload ─────────────────────────────────────────────
    # Layout: VM_FLAG(1) | u32(gir_len) | gir_blob | u32(table_len) | table_blob
    if len(decompressed) < 1 or decompressed[0:1] != b'\x01':
        # Not a VM-mode payload/code -> refuse to execute
        sys.exit(1)

    cdef unsigned int gir_len, table_len
    gir_len,   = struct.unpack_from('>I', decompressed, 1)
    cdef bytes gir_blob    = decompressed[5 : 5 + gir_len]
    table_len, = struct.unpack_from('>I', decompressed, 5 + gir_len)
    cdef bytes table_blob  = decompressed[9 + gir_len : 9 + gir_len + table_len]
    decompressed = b''

    # ── 6. Dispatch to GIR VM interpreter ─────────────────────────────────────
    # CPython's eval loop never runs on this code.
    # _gnolly_vm.vm_exec_module deserialises the GIR blob and runs it
    # through its own Cython stack machine.
    cdef dict globs
    if caller_globals is not None:
        globs = caller_globals
        if '__builtins__' not in globs:
            globs['__builtins__'] = __builtins__
    else:
        globs = {
            '__name__':     '__main__',
            '__builtins__': __builtins__,
            '__doc__':      None,
            '__package__':  None,
            '__spec__':     None,
        }
    _gvm_exec_module(gir_blob, table_blob, globs)
    gir_blob   = b''
    table_blob = b''
    _monitoring_blackout_exit(_blackout_state)
