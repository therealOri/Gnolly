"""
gnolly.stub
~~~~~~~~~~~
Generates the maximally obfuscated bootstrap loader.

Stub hardening layers:
  1. Confusable identifiers              (see gnolly.namegen)
  2. Custom XOR-int string encoding  (no fromhex/decode pattern anywhere)
  3. code blob splitting          (4-11 random-length chunks)
  4. __import__ obfuscation          (no plain import statements)
  5. getattr method access           (no .sha256 / .pbkdf2_hmac / .MODE_GCM)
  6. Dead assignment injection       (crypto-random junk between real lines)
  7. Control-flow state machine      (while loop with numeric dispatch dict)
  8. Integer XOR obfuscation         (no plain numeric constants)
  9. All string literals as basic int lists (chr(n^key) with no hex/decode pattern)

Random policy: random.Random(seed) for reproducible structural layout only.
All values use secrets.
"""
from __future__ import annotations
import hashlib
import random
import secrets
import struct
from .antidebug import generate_antidebug_lines, generate_timing_check_lines
from .binding_stub import generate_binding_lines
from .import_hook  import generate_import_hook_lines, get_core_so_hash, get_vm_so_hash
from .namegen import random_confusable_name


def _gen_names(count: int, seed: int) -> list:
    rng = random.Random(seed)
    used: set = set()
    names = [random_confusable_name(rng, used, length=11) for _ in range(count)]
    rng.shuffle(names)
    return names


# ---------------------------------------------------------------------------
# Custom string encoding  (replaces bytes.fromhex pattern entirely)
# ---------------------------------------------------------------------------

def _make_str_key() -> bytes:
    """Generate a random 16-byte XOR key for string encoding."""
    return secrets.token_bytes(16)

def _enc_str(s: str, key: bytes) -> list:
    """Encode string as list of XOR'd ordinals."""
    return [ord(c) ^ key[i % len(key)] for i, c in enumerate(s)]

def _enc_bytes_as_str(b: bytes, key: bytes) -> list:
    """Encode bytes as list of XOR'd values (for binary data decoded as latin-1)."""
    return [v ^ key[i % len(key)] for i, v in enumerate(b)]

def _str_decoder_lambda(fn_name: str, key: bytes) -> str:
    """
    Returns a lambda that decodes int lists back to strings.
    Uses chr() and no fromhex, no .decode(), no .hex() anywhere.
    """
    kl = len(key)
    return (f"{fn_name} = lambda _x: ''.join("
            f"chr(_b ^ {repr(key)}[_i % {kl}]) "
            f"for _i, _b in enumerate(_x))")

def _bytes_decoder_lambda(fn_name: str, key: bytes) -> str:
    """Returns a lambda that decodes int lists back to bytes."""
    kl = len(key)
    return (f"{fn_name} = lambda _x: bytes("
            f"_b ^ {repr(key)}[_i % {kl}] "
            f"for _i, _b in enumerate(_x))")


# ---------------------------------------------------------------------------
# Other helpers
# ---------------------------------------------------------------------------
def _obf_int(n: int) -> str:
    k = secrets.randbelow(0xFFFF) + 1
    return f"({n ^ k} ^ {k})"

def _junk_assign(varname: str) -> str:
    a = secrets.randbelow(0xEFFF) + 0x1000
    b = secrets.randbelow(0xEFFF) + 0x1000
    return f"{varname} = {a} ^ {b}"

def _split_blob(encoded: str, rng: random.Random) -> list:
    n_chunks = secrets.randbelow(8) + 4
    if len(encoded) == 0:
        return [encoded]
    total = len(encoded)
    points = sorted(set(secrets.randbelow(total - 1) + 1 for _ in range(n_chunks - 1)))
    chunks, prev = [], 0
    for pt in points:
        chunks.append(encoded[prev:pt]); prev = pt
    chunks.append(encoded[prev:])
    return [c for c in chunks if c]

def _obf_import(module_name: str, alias: str, s_fn: str, key: bytes, imp_fn: str = "__import__") -> str:
    enc = _enc_str(module_name, key)
    return f"{alias} = {imp_fn}({s_fn}({enc}))"

def _obf_from_import(module_name: str, attr: str, alias: str, s_fn: str, key: bytes, imp_fn: str = "__import__") -> str:
    enc_mod  = _enc_str(module_name, key)
    enc_attr = _enc_str(attr, key)
    enc_fl   = _enc_str('fromlist', key)
    # Use **{s_fn(enc_fl): [...]} so the literal string "fromlist" never
    # appears in the generated output and only a basic encoded int-list.
    return (f"{alias} = getattr("
            f"{imp_fn}({s_fn}({enc_mod}), **{{{s_fn}({enc_fl}): [{s_fn}({enc_attr})]}}),"
            f"{s_fn}({enc_attr}))")

# State IDs
_SD, _SI, _SK, _SKDF, _SDEC, _SDECOMP, _SUNSHUFFLE, _SEXEC, _SDONE = range(9)


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def generate_stub(
    blob_encoded: str,
    blob_raw_bytes: bytes,
    alpha: str,
    xor_key: bytes,
    salt: bytes,
    iv: bytes,
    tag: bytes,
    blob_header_skip: int,
    use_vm: bool = True,
    shuffle_opcodes: bool = True,   # kept for API compat; ignored when use_vm=True
    bound: bool = False,
    seed: int = 0,
    silent: bool = True,
) -> str:
    rng = random.Random(seed)
    N   = _gen_names(150, seed)

    # String encoding key (different from payload xor_key)
    str_key  = _make_str_key()
    byt_key  = _make_str_key()
    s_fn     = N[0]   # str decoder function name
    b_fn     = N[1]   # bytes decoder function name

    # Module handles
    h_sys    = N[2];  h_marshal = N[3];  h_hash   = N[4]
    h_zlib   = N[5];  h_lzma    = N[6];  h_bz2    = N[7]
    h_blt    = N[131]  # builtins module handle -> used to obfuscate None/True/False
    h_os     = N[8];  h_aes_cls = N[9];  h_struct = N[10]

    # State machine vars
    sm_state   = N[11]; sm_data  = N[12]; sm_key   = N[13]
    sm_derived = N[14]; sm_dec   = N[15]; sm_decomp= N[16]
    sm_table   = N[17]; sm_pos   = N[18]; sm_blob  = N[19]
    sm_code    = N[20]; sm_cipher= N[21]; sm_tmp   = N[22]

    # Blob chunk vars
    chunk_vars = N[30:42]

    # XOR/decode helper names
    xor_fn    = N[42]; alpha_var = N[43]; rev_var  = N[44]
    decode_fn = N[45]; unshuffle_fn = N[46]
    hx_fn    = N[47]; imp_fn = N[49]

    # Loop/temp vars
    v = N[50:]

    def s(text: str) -> str:
        """Encode a string literal as a decoded int-list call."""
        return f"{s_fn}({_enc_str(text, str_key)})"

    def b(data: bytes) -> str:
        """Encode bytes literal as a bytes-decoded int-list call."""
        return f"{b_fn}({_enc_bytes_as_str(data, byt_key)})"

    def obn(n: int) -> str:
        return _obf_int(n)

    def em(obj: str, method: str, *args: str) -> str:
        """Generate getattr(obj, s_fn(encoded_method))(args) call string.
        Used to hide all method names from the generated stub output."""
        enc = [ord(c) ^ str_key[i % len(str_key)] for i, c in enumerate(method)]
        arg_str = ', '.join(args)
        return f"getattr({obj}, {s_fn}({enc}))({arg_str})" 

    lines = []
    a = lines.append

    a("# -*- coding: utf-8 -*-")
    a("")

    # ── String/bytes decoders ────────────────────────────────────────────────
    a(_str_decoder_lambda(s_fn,  str_key))
    a(_bytes_decoder_lambda(b_fn, byt_key))
    a(_junk_assign(N[23]))
    a(f"{hx_fn} = lambda _s: bytes(int(_s[_i:_i+2], 16) for _i in range(0, len(_s), 2))")
    # imp_fn: alias for __import__ obtained through __builtins__ so the
    # literal string __import__ never appears in the generated stub output.
    _imp_enc = _enc_str('__import__', str_key)
    a(f"{imp_fn} = getattr(__builtins__, {s_fn}({_imp_enc})) if not isinstance(__builtins__, dict) else __builtins__[{s_fn}({_imp_enc})]")
    a(f"{h_blt} = {imp_fn}({s_fn}({_enc_str('builtins', str_key)}))")
    a("")

    def sing(name: str) -> str:
        """getattr(builtins_handle, '<None|True|False>') -> hides the bare
        keyword constant the same way every other identifier/string in the
        stub is hidden, instead of leaving it as plaintext just because it
        looks like scaffolding rather than payload."""
        return f"getattr({h_blt}, {s_fn}({_enc_str(name, str_key)}))"

    # ── Imports ───────────────────────────────────────────────────────────────
    a(_obf_import("sys",     h_sys,    s_fn, str_key, imp_fn))
    a(_obf_import("marshal", h_marshal,s_fn, str_key, imp_fn))
    a(_obf_import("hashlib", h_hash,   s_fn, str_key, imp_fn))
    a(_obf_import("zlib",    h_zlib,   s_fn, str_key, imp_fn))
    a(_obf_import("lzma",    h_lzma,   s_fn, str_key, imp_fn))
    a(_obf_import("bz2",     h_bz2,    s_fn, str_key, imp_fn))
    a(_obf_import("os",      h_os,     s_fn, str_key, imp_fn))
    a(_obf_import("struct",  h_struct, s_fn, str_key, imp_fn))
    a(_obf_from_import("Crypto.Cipher", "AES", h_aes_cls, s_fn, str_key, imp_fn))
    a(_junk_assign(N[24]))
    a("")

    # ── Payload blob chunks ───────────────────────────────────────────────────
    chunks = _split_blob(blob_encoded, rng)
    used_cvars = chunk_vars[:len(chunks)]
    for cvar, chunk in zip(used_cvars, chunks):
        a(f"{cvar} = {repr(chunk)}")
    a(f"{sm_blob} = {' + '.join(used_cvars)}")
    for cvar in used_cvars:
        a(f"{cvar} = " + sing("None"))
    a("")

    # ── XOR spread (inline lambda) ────────────────────────────────────────────
    xor_key_enc = _enc_bytes_as_str(xor_key, byt_key)
    a(f"{xor_fn} = lambda {v[0]}, {v[1]}: bytes("
      f"{v[2]} ^ {v[1]}[{v[3]} % len({v[1]})] "
      f"for {v[3]}, {v[2]} in enumerate({v[0]}))")
    a("")

    # ── Custom alphabet decoder ───────────────────────────────────────────────
    # Rewritten as a nested comprehension (decode groups -> flatten to bytes)
    # instead of a step-by-step for-loop with three separate .append() calls.
    alpha_enc = _enc_str(alpha, str_key)
    a(f"{alpha_var} = {s_fn}({alpha_enc})")
    a(f"{rev_var} = {{_c: _i for _i, _c in enumerate({alpha_var})}}")
    _dc_used: set = set()
    cp, ct, cn, cb, ci, cx, cy = (random_confusable_name(rng, _dc_used, 1) for _ in range(7))
    a(f"def {decode_fn}({v[4]}):")
    a(f"    {cp} = " + em(v[4], "count", "chr(61)"))
    a(f"    {ct} = " + em(v[4], "replace", "chr(61)", alpha_var + "[0]"))
    a(f"    {cn} = [({rev_var}[{ct}[{ci}]] << {obn(18)} | {rev_var}[{ct}[{ci}+1]] << {obn(12)}"
      f" | {rev_var}[{ct}[{ci}+2]] << {obn(6)} | {rev_var}[{ct}[{ci}+3]])"
      f" for {ci} in range(0, len({ct}), {obn(4)})]")
    a(f"    {cb} = bytes({cx} for {cy} in {cn} for {cx} in"
      f" (({cy} >> {obn(16)}) & {obn(255)}, ({cy} >> {obn(8)}) & {obn(255)}, {cy} & {obn(255)}))")
    a(f"    {v[10]} = {cb}[:-{cp}] if {cp} else {cb}")
    a(f"    return {xor_fn}({v[10]}, {b_fn}({xor_key_enc}))")
    a("")

    # ── Opcode unshuffle ──────────────────────────────────────────────────────
    a(f"def {unshuffle_fn}({v[11]}, {v[12]}, {v[13]}):")
    a(f"    if not {v[12]} or not {v[13]}: return {v[11]}")
    a(f"    try:")
    a(f"        {v[14]} = {imp_fn}({s_fn}({_enc_str('opcode', str_key)}))")
    a(f"        {v[15]} = getattr({v[14]}, {s_fn}({_enc_str('_inline_cache_entries', str_key)}))")
    a(f"        {v[16]} = " + sing("True"))
    a(f"    except Exception: {v[15]} = []; {v[16]} = " + sing("False"))
    a(f"    {v[17]} = {{_i: {v[12]}[_i] for _i in range({obn(256)})}}")
    a(f"    {v[18]} = []")
    a(f"    for {v[19]} in range(0, len({v[13]}), {obn(8)}):")
    a("        " + v[20] + ", " + v[21] + " = " + em(h_struct, "unpack_from", s_fn + "(" + str(_enc_str(chr(62)+chr(73)+chr(73), str_key)) + ")", v[13], v[19]))
    a(f"        getattr({v[18]}, {s_fn}({_enc_str(chr(97)+chr(112)+chr(112)+chr(101)+chr(110)+chr(100), str_key)}))(({v[20]}, {v[21]}))")
    a(f"    {v[22]} = bytearray({v[11]})")
    a(f"    for ({v[23]}, {v[24]}) in {v[18]}:")
    a(f"        {v[25]} = 0")
    a(f"        while {v[25]} < {v[24]}:")
    a(f"            {v[26]} = {v[22]}[{v[23]} + {v[25]}]")
    a(f"            {v[27]} = {v[17]}.get({v[26]}, {v[26]})")
    a(f"            {v[22]}[{v[23]} + {v[25]}] = {v[27]}")
    a(f"            {v[25]} += {obn(2)}")
    # Cache-safe: .get() works for dict (3.14+); fallback for list (3.11-3.13)
    a(f"            if {v[16]}:")
    a(f"                try: {v[25]} += {v[15]}.get({v[27]}, 0) * {obn(2)}")
    a(f"                except AttributeError: {v[25]} += ({v[15]}[{v[27]}] if {v[27]} < len({v[15]}) else 0) * {obn(2)}")
    a(f"    return bytes({v[22]})")
    a("")

    # ── State machine ─────────────────────────────────────────────────────────
    hash_hex  = hashlib.sha256(blob_raw_bytes).hexdigest()
    magic_b   = b'GNLY\x02\x00'
    S = {i: obn(i) for i in range(_SDONE + 1)}

    # ── State machine variables ──────────────────────────────────────────────
    hash_hex  = hashlib.sha256(blob_raw_bytes).hexdigest()
    magic_b   = b'GNLY\x02\x00'
    S = {i: obn(i) for i in range(9)}  # obfuscated state IDs 0-8

    # Precompute all encoded strings needed across states
    sha256_enc   = _enc_str('sha256', str_key)
    pbkdf2_enc   = _enc_str('pbkdf2_hmac', str_key)
    exit_enc     = _enc_str('exit', str_key)
    environ_enc  = _enc_str('environ', str_key)
    getpass_enc  = _enc_str('getpass', str_key)
    new_enc      = _enc_str('new', str_key)
    mode_enc     = _enc_str('MODE_GCM', str_key)
    update_enc   = _enc_str('update', str_key)
    dv_enc       = _enc_str('decrypt_and_verify', str_key)
    decomp_enc   = _enc_str('decompress', str_key)
    loads_enc    = _enc_str('loads', str_key)
    name_enc     = _enc_str('__name__', str_key)
    main_enc     = _enc_str('__main__', str_key)
    blt_enc      = _enc_str('__builtins__', str_key)
    ic_enc       = _enc_str('_inline_cache_entries', str_key)
    opcode_enc   = _enc_str('opcode', str_key)
    gnolly_key_enc  = _enc_str('GNOLLY_KEY', str_key)
    gnolly_prom_enc = _enc_str('Gnolly key: ', str_key)

    # Precompute encoded binary values
    salt_enc = _enc_bytes_as_str(salt,    byt_key)
    iv_enc   = _enc_bytes_as_str(iv,      byt_key)
    tag_enc  = _enc_bytes_as_str(tag,     byt_key)
    xk_enc   = _enc_bytes_as_str(xor_key, byt_key)
    mg_enc   = _enc_bytes_as_str(magic_b, byt_key)
    alp_enc  = _enc_bytes_as_str(alpha.encode(), byt_key)

    # Cython module + function names (encoded)
    gnolly_mod  = 'gnolly._gnolly_core'
    gnolly_fn   = 'gnolly_run'
    gmod_enc = _enc_str(gnolly_mod, str_key)
    gfn_enc  = _enc_str(gnolly_fn,  str_key)

    # Variable for Cython core handle
    cr_var = N[48]

    a(f"{sm_data} = {sm_key} = " + sing("None"))
    a(_junk_assign(sm_tmp))
    a("")

    # ── ANTI-DEBUG CHECKS (before any crypto work) ──────────────────────────────
    _ad_lines, _timing_var = generate_antidebug_lines(
        s_fn=s_fn, h_sys=h_sys,
        exit_enc=exit_enc, str_key=str_key, obn=obn,
        imp_fn=imp_fn, h_blt=h_blt)
    for _adl in _ad_lines:
        a(_adl)
    a("")

    # ── INLINE STATE 0: decode blob ───────────────────────────────────────────
    a(f"{sm_data} = {decode_fn}({sm_blob})")
    a(f"{sm_blob} = " + sing("None"))
    a("")

    # ── INLINE STATE 1: integrity check ──────────────────────────────────────
    # Cosmetic fast-fail only (see gnolly/integrity.py) -> AES-GCM's own
    # auth tag already detects any tampering of the blob. We will still
    # obfuscate the expected value like everything else, so it doesn't sit
    # in the file as a bare, grep-able 64-char hex literal.
    a(f"{v[28]} = getattr({h_hash}, {s_fn}({sha256_enc}))({sm_data})")
    a(v[28] + " = " + em(v[28], "hexdigest"))
    a(f"if {v[28]} != {s_fn}({_enc_str(hash_hex, str_key)}):")
    a(f"    getattr({h_sys}, {s_fn}({exit_enc}))({obn(1)})")
    a("")

    # ── INLINE STATE 2: get key ───────────────────────────────────────────────
    a(f"{sm_key} = getattr({h_os}, {s_fn}({environ_enc})).get({s_fn}({gnolly_key_enc}))")
    a(f"if {sm_key}:")
    a("    try: " + sm_key + " = " + hx_fn + "(" + em(sm_key, "strip") + ")")
    a(f"    except Exception: {sm_key} = " + sing("None"))
    a(f"if not {sm_key}:")
    a(f"    try:")
    a(f"        {v[29]} = {imp_fn}({s_fn}({getpass_enc}))")
    a(f"        {v[30]} = getattr({v[29]}, {s_fn}({getpass_enc}))({s_fn}({gnolly_prom_enc}))")
    a(f"        if not {v[30]}: getattr({h_sys}, {s_fn}({exit_enc}))({obn(1)})")
    a("        " + sm_key + " = " + hx_fn + "(" + em(v[30], "strip") + ")"       + " if len(" + v[30] + ") == " + obn(64) + " else " + em(v[30], "encode"))
    a(f"    except Exception: getattr({h_sys}, {s_fn}({exit_enc}))({obn(1)})")
    a("")

    # ── MACHINE BINDING: fold fingerprint into key if bound ──────────────────
    if bound:
        for _bl in generate_binding_lines(
                s_fn=s_fn, b_fn=b_fn, h_sys=h_sys, h_os=h_os,
                sm_key=sm_key, str_key=str_key, byt_key=byt_key,
                obn=obn, N=N, rng=rng):
            a(_bl)

    # ── CYTHON IMPORT HOOKS -> both .so files required ─────────────────────────
    # _gnolly_core handles decryption; _gnolly_vm handles GIR execution.
    # Both are mandatory. The stub exits if either is missing or tampered with.
    _so_hash    = get_core_so_hash()
    _vm_so_hash = get_vm_so_hash()

    if _so_hash and _vm_so_hash:
        _hook_lines, _core_hash_var = generate_import_hook_lines(
            s_fn=s_fn, b_fn=b_fn,
            str_key=str_key, byt_key=byt_key,
            obn=obn, N=N, cr_var=cr_var,
            so_hash=_so_hash,
            h_sys=h_sys,
            imp_fn=imp_fn,
            silent=silent,
            module_stem="_gnolly_core",
            n_offset=0,
            h_blt=h_blt,
            rng=rng,
        )
        for _hl in _hook_lines:
            a(_hl)

        # Also extract _gnolly_load_vm_module from the now-loaded core module,
        # using the same loaded-module variable the hook just produced (N[89]).
        _vm_loader_var = N[149]
        a(f"{_vm_loader_var} = getattr({N[89]}, {s_fn}({_enc_str('_gnolly_load_vm_module', str_key)}))")

        _vm_hook_lines, _vm_hash_var = generate_import_hook_lines(
            s_fn=s_fn, b_fn=b_fn,
            str_key=str_key, byt_key=byt_key,
            obn=obn, N=N, cr_var=cr_var,
            so_hash=_vm_so_hash,
            h_sys=h_sys,
            imp_fn=imp_fn,
            silent=silent,
            module_stem="_gnolly_vm",
            n_offset=25,
            vm_loader_call=_vm_loader_var,
            h_blt=h_blt,
            rng=rng,
        )
        for _hl in _vm_hook_lines:
            a(_hl)

        # ── INTEGRITY BINDING: fold both .so's raw hashes into sm_key ─────────
        _integrity_domain_enc = _enc_bytes_as_str(b'gnolly-integrity-bind-v1:', byt_key)
        _hmac_var = N[130]
        a(f"{_hmac_var} = {imp_fn}({s_fn}({_enc_str('hmac', str_key)}))")
        a(f"{sm_key} = getattr({_hmac_var}, {s_fn}({_enc_str('new', str_key)}))("
          f"{b_fn}({_integrity_domain_enc}) + {_core_hash_var} + {_vm_hash_var}, "
          f"{sm_key}, getattr({h_hash}, {s_fn}({sha256_enc})))"
          f".digest()")
        a("")

        # Both .so files verified, loaded, and the VM registered into core.
        # gnolly_run will hard-exit if _VM_LOADED is somehow still False.
        a(f"{cr_var}({sm_data}, {sm_key},")
        a(f"    {b_fn}({salt_enc}), {b_fn}({iv_enc}), {b_fn}({tag_enc}),")
        a(f"    {obn(blob_header_skip)}, {b_fn}({alp_enc}), {b_fn}({xk_enc}))")
    else:
        # One or both .so files not built at protect-time -> fail at runtime
        _exit_s = _enc_str(chr(115)+chr(121)+chr(115), str_key)
        _exit_e = _enc_str(chr(101)+chr(120)+chr(105)+chr(116), str_key)
        a(f"getattr({imp_fn}({s_fn}({_exit_s})), {s_fn}({_exit_e}))(1)")

    # Strip all comments and blank-line artifacts from generated stub
    final = []
    for _line in lines:
        stripped = _line.lstrip()
        if stripped.startswith('#'):
            continue   # drop comment lines entirely
        final.append(_line)
    return "\n".join(final)
