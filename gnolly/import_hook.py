"""
gnolly.import_hook
~~~~~~~~~~~~~~~~~~
Generates the obfuscated import hook code embedded in the stub.

The .so is loaded by direct file path using importlib.util, with the
correct module leaf name (_gnolly_core) so PyInit__gnolly_core is found.
The module name string is encoded as a basic int-list so no plaintext appears.

The so_hash is verified before loading to prevent tampered .so injection. (will improve eventually)

Search order for _gnolly_core.so
---------------------------------
1. Alongside the protected .py file     (most common deployment layout)
2. ./gnolly/ relative to cwd            (running from project root)
3. gnolly package path via sys.modules  (gnolly installed in env)
4. sys.path scan for gnolly/            (fallback for non-standard layouts)

If not found: print a human-readable error and exit(1) instead of a
silent failure.
"""
from __future__ import annotations
import hashlib
import secrets
from pathlib import Path


def get_core_so_hash() -> str | None:
    """Return SHA-256 hex of the compiled .so, or None if not built."""
    pkg = Path(__file__).parent
    import sysconfig
    suffix = sysconfig.get_config_var("EXT_SUFFIX") or ".so"
    so = pkg / f"_gnolly_core{suffix}"
    return hashlib.sha256(so.read_bytes()).hexdigest() if so.exists() else None


def get_core_so_path() -> Path | None:
    """Return path to compiled .so or None."""
    pkg = Path(__file__).parent
    import sysconfig
    suffix = sysconfig.get_config_var("EXT_SUFFIX") or ".so"
    so = pkg / f"_gnolly_core{suffix}"
    return so if so.exists() else None


def generate_import_hook_lines(
    s_fn: str,
    b_fn: str,
    str_key: bytes,
    byt_key: bytes,
    obn,
    N: list,
    cr_var: str,
    so_hash: str,
    h_sys: str = "sys",
    imp_fn: str = "__import__",
    silent: bool = True,
    module_stem: str = "_gnolly_core",
    n_offset: int = 0,
    vm_loader_call: str | None = None,
    h_blt: str | None = None,   # builtins module handle -> obfuscates None
) -> tuple[list[str], str]:
    """
    Generate stub lines that:
    1. Find <module_stem>.so via four search locations (see module docstring)
    2. Verify its SHA-256 hash against an obfuscated expected value (cosmetic
       fast-fail only -> see the note above the hash-verification block)
    3. Load it via importlib.util.spec_from_file_location
    4. Extract the requested symbol (gnolly_run for core; the module itself
       for VM, passed to vm_loader_call) from the loaded module
    5. On missing/tampered .so: exit(1)
    6. On any other failure: exit(1)

    Returns
    -------
    (lines, hash_var) -> hash_var is the name of the local variable holding
    the loaded .so's *raw* SHA-256 digest (bytes, not hex). The caller
    (stub.py) folds this into the decryption key alongside the other .so's
    hash -> that fold is the actual integrity enforcement; a tampered .so
    changes hash_var, which changes the derived key, which makes AES-GCM
    reject the ciphertext regardless of whether the cosmetic check above
    was patched out.
    """
    lines = []
    a = lines.append

    def enc(s: str) -> str:
        encoded = [ord(c) ^ str_key[i % len(str_key)] for i, c in enumerate(s)]
        return f"{s_fn}({encoded})"

    def em(obj: str, method: str, *args: str) -> str:
        """Generate getattr(obj, enc(method))(args) -> hides method names."""
        encoded = [ord(c) ^ str_key[i % len(str_key)] for i, c in enumerate(method)]
        arg_str = ', '.join(args)
        return f"getattr({obj}, {s_fn}({encoded}))({arg_str})"

    def sing(name: str) -> str:
        """getattr(builtins_handle, 'None') -> falls back to the bare
        literal if the caller didn't wire up h_blt."""
        if h_blt is None:
            return name
        return f"getattr({h_blt}, {enc(name)})"

    # Variable slots (offset so two calls don't collide)
    o = n_offset
    v_iutil   = N[80 + o]   # importlib.util module
    v_sysconf = N[81 + o]   # sysconfig module
    v_suffix  = N[82 + o]   # .so file suffix string
    v_path    = N[83 + o]   # pathlib.Path class
    v_so      = N[84 + o]   # Path to .so (resolved)
    v_hash_m  = N[85 + o]   # hashlib module
    v_hash_v  = N[86 + o]   # computed hash value (hex)
    v_so_rb   = N[87 + o]   # .so bytes
    v_spec    = N[88 + o]   # module spec
    v_mod     = N[89 + o]   # loaded module object
    v_sysmod  = N[90 + o]   # sys module handle
    v_item    = N[91 + o]   # loop variable
    v_cand    = N[92 + o]   # candidate path being tested
    v_script  = N[93 + o]   # __file__ of the running stub
    v_hash_o  = N[95 + o]   # hash object (so we compute the digest only once)
    v_hash_rw = N[96 + o]   # computed hash value (raw digest bytes, for key folding)

    a(f"try:")

    # ── imports needed by the hook ────────────────────────────────────────────
    a(f"    {v_iutil}   = {imp_fn}({enc('importlib.util')}, **{{{enc('fromlist')}: [{enc('spec_from_file_location')}]}})")
    a(f"    {v_sysconf} = {imp_fn}({enc('sysconfig')})")
    a(f"    {v_suffix}  = {em(v_sysconf, 'get_config_var', enc('EXT_SUFFIX'))} or {enc('.so')}")
    a(f"    {v_path}    = getattr({imp_fn}({enc('pathlib')}), {enc('Path')})")
    a(f"    {v_sysmod}  = {imp_fn}({enc('sys')})")

    # ── build the .so filename stem ───────────────────────────────────────────
    v_soname = N[94 + o]
    a(f"    {v_soname} = {enc(module_stem)} + {v_suffix}")

    # ── search location 1: directory of the protected .py file ───────────────
    # The most common layout: user places the .so right next to their script.
    # __file__ is set to the stub's own path by CPython before execution.
    a(f"    {v_so} = " + sing("None"))
    a(f"    {v_script} = getattr({v_sysmod}, {enc('argv')}, [''])[0]")
    a(f"    if {v_script}:")
    # Path(argv[0]).parent / soname  -> no resolve() needed, parent is a property
    a(f"        {v_cand} = getattr({v_path}({v_script}), {enc('parent')}) / {v_soname}")
    a(f"        if {em(v_cand, 'exists')}: {v_so} = {v_cand}")

    # ── search location 2: ./gnolly/ relative to cwd ─────────────────────────
    a(f"    if {v_so} is " + sing("None") + ":")
    a(f"        {v_cand} = {v_path}({enc('.')}) / {enc('gnolly')} / {v_soname}")
    a(f"        if {em(v_cand, 'exists')}: {v_so} = {v_cand}")

    # ── search location 3: gnolly package dir via sys.modules ────────────────
    a(f"    if {v_so} is " + sing("None") + ":")
    a(f"        if {enc('gnolly')} in getattr({v_sysmod}, {enc('modules')}):")
    a(f"            {v_cand} = {v_path}(getattr(getattr({v_sysmod}, {enc('modules')})[{enc('gnolly')}], {enc('__file__')}, '')) / '..' / {v_soname}")
    a(f"            if {em(v_cand, 'exists')}: {v_so} = {v_cand}")

    # ── search location 4: scan sys.path for gnolly/ subdir ──────────────────
    a(f"    if {v_so} is " + sing("None") + ":")
    a(f"        for {v_item} in getattr({v_sysmod}, {enc('path')}):")
    a(f"            {v_cand} = {v_path}({v_item}) / {enc('gnolly')} / {v_soname}")
    a(f"            if {em(v_cand, 'exists')}:")
    a(f"                {v_so} = {v_cand}")
    a(f"                break")

    # ── not found: silent exit, or helpful message if not in silent mode ────────
    a(f"    if {v_so} is " + sing("None") + ":")
    if not silent:
        _nl = chr(10)
        a(f"        getattr(getattr({v_sysmod}, {enc('stderr')}), {enc('write')})({enc(f'Gnolly runtime ({module_stem}) not found.' + _nl)})")
        a(f"        getattr(getattr({v_sysmod}, {enc('stderr')}), {enc('write')})({enc(f'Place {module_stem}*.so next to this script, or in ./gnolly/, or install gnolly.' + _nl)})")
        a(f"        getattr(getattr({v_sysmod}, {enc('stderr')}), {enc('write')})({enc('  pip install gnolly' + _nl)})")
    a(f"        raise ImportError")

    # ── hash verification -> silent on failure (no hint to attacker) ─────────────
    # This is a cosmetic, obfuscated fast-fail layer only: it gives a clean
    # early exit for an accidental .so/gnolly-version mismatch. It is NOT the
    # real security boundary -> that's the key-derivation fold applied later
    # in stub.py (via v_hash_rw), which an attacker cannot bypass by patching
    # this comparison, because a bypass here still leaves them with the wrong
    # AES key and a GCM authentication failure on decrypt.
    a(f"    {v_hash_m} = {imp_fn}({enc('hashlib')})")
    a(f"    {v_so_rb}  = {em(v_so, 'read_bytes')}")
    a(f"    {v_hash_o} = getattr({v_hash_m}, {enc('sha256')})({v_so_rb})")
    a(f"    {v_hash_v}  = {em(v_hash_o, 'hexdigest')}")
    a(f"    {v_hash_rw} = {em(v_hash_o, 'digest')}")
    a(f"    if {v_hash_v} != {enc(so_hash)}:")
    a(f"        raise ImportError")

    # ── load via importlib.util ───────────────────────────────────────────────
    a(f"    {v_spec} = {em(v_iutil, 'spec_from_file_location', enc(module_stem), 'str(' + v_so + ')')}")
    a(f"    {v_mod}  = {em(v_iutil, 'module_from_spec', v_spec)}")
    _loader_enc = str([ord(c) ^ str_key[i % len(str_key)] for i, c in enumerate("loader")])
    _exec_enc   = str([ord(c) ^ str_key[i % len(str_key)] for i, c in enumerate("exec_module")])
    a(f"    getattr(getattr({v_spec}, {s_fn}({_loader_enc})), {s_fn}({_exec_enc}))({v_mod})")

    if module_stem == "_gnolly_core":
        a(f"    {cr_var} = getattr({v_mod}, {enc('gnolly_run')})")
        # ── verify gnolly_run is callable -> silent on failure ────────────────
        a(f"    if not callable({cr_var}):")
        a(f"        raise ImportError")
    else:
        # VM module: hand the loaded module object to _gnolly_core's
        # registration function (no relative import needed/possible).
        a(f"    {vm_loader_call}({v_mod})")

    # ── catch-all: silent exit -> no hint about failure reason ────────────────────
    exit_enc = [ord(c) ^ str_key[i % len(str_key)] for i, c in enumerate('exit')]
    a(f"except Exception:")
    a(f"    getattr({h_sys}, {s_fn}({exit_enc}))(1)")

    return lines, v_hash_rw


def get_vm_so_hash() -> str | None:
    """Return SHA-256 hex of the compiled _gnolly_vm .so, or None if not built."""
    pkg = Path(__file__).parent
    import sysconfig
    suffix = sysconfig.get_config_var("EXT_SUFFIX") or ".so"
    so = pkg / f"_gnolly_vm{suffix}"
    return hashlib.sha256(so.read_bytes()).hexdigest() if so.exists() else None


def get_vm_so_path() -> Path | None:
    """Return path to compiled _gnolly_vm .so or None."""
    pkg = Path(__file__).parent
    import sysconfig
    suffix = sysconfig.get_config_var("EXT_SUFFIX") or ".so"
    so = pkg / f"_gnolly_vm{suffix}"
    return so if so.exists() else None
