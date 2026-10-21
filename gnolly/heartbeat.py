"""
gnolly.heartbeat
~~~~~~~~~~~~~~~~~
Continuous integrity re-verification for the PYTHON/stub layer.

Companion to the VM-layer check in gnolly/_gnolly_vm.pyx
(_tick_and_maybe_check): that one re-verifies the decoded GIR instruction
stream from inside the VM's own dispatch loop, so it only covers code that
actually runs through the VM. Two things sit outside that loop entirely:

  * The stub's own Python source (decoders, state machine, the self-hash/
    antidebug checks themselves) "fire once, early" and then never run again for the life of the process.

  * Protected modules that fall back to plain-exec, i.e. whatever
    vm_pipeline.protect_with_vm couldn't translate (VMUnsupportedError) ->
    in the current pipeline it's a hard failure, but the fallback_fn hook exists for callers who wire up
    their own non-fatal fallback, and code running that way never enters
    the GIR VM at all.

This module helps close that window the only way available at the Python
level: a daemon thread, started just before the stub hands off to
gnolly_run (cr_var) -> past the point where the main thread is blocked inside
the compiled C/VM code for the rest of the program's run. So anything meant
to keep checking alongside it has to live on its own thread rather than
be intertwined into the main one. The thread loops for the life of the
process, on a randomized interval, and constantly re-running:

  1. Self-hash -> rehashes the stub's own source text (the same "src_var"
     gnolly.selfhash's one-shot checks, and is verified once before any
     of this runs.
  2. .so re-hash -> rereads both compiled extensions from the same on-disk
     paths gnolly.import_hook already resolved and verified once, and
     rehashes them against the same kind of baseline. Independent of (and
     in addition to) gnolly.integrity's one-time key fold, which only
     ever matters once, at decrypt time, and says nothing about the files
     on disk a minute into a long-running process.
  3. Antidebug  -> sys.gettrace()/sys.getprofile()/known debugger modules
     in sys.modules, are the same signals gnolly.antidebug already checks
     once. None of these are "consumed" by checking them, so re-checking
     on a timer is always nice. (The timing-gate checks in antidebug.py are NOT
     repeated here -> those only make sense as one-shot measurements
     bracketing a specific operation, not as a standing probe.)

Reaction: by the time this thread is running, decryption has already
happened -> there is no key left to fold a failure into. So a mismatch here calls
os._exit(1) directly, the same reaction as the VM-layer check: silent, no
stdout/stderr, and nothing in the protected program's own Python code can
intercept a background thread calling os._exit from outside its own call
stack -> no try/except anywhere in the protected program however it's
written, runs on this thread.

Fail-closed, not fail-open: an exception raised from within the probe
itself (e.g. a .so no longer readable) is treated the same as a detected
mismatch, not silently skipped. Worth knowing: an unrelated runtime hiccup touching one of the
watched files (permissions, an antivirus lock, or a rebuild landing mid-run, etc.) on a long-running process will also end it.
"""
from __future__ import annotations
from .strcodec import _enc_str
from .antidebug import _DEBUG_MODULES

DEFAULT_MIN_DELAY = 0.4
DEFAULT_MAX_DELAY = 1.0


def generate_python_heartbeat_lines(
    s_fn: str,        # name of the str-decoder function in the stub
    h_sys: str,        # name of the sys module handle in the stub
    h_os: str,         # name of the os module handle in the stub
    str_key: bytes,    # str encoding key
    obn,               # obf_int callable
    N: list,           # confusable-name pool (stub.py's shared N)
    src_var: str,       # name of the variable holding the stub's full,
                        # reassembled source text at runtime
    so_path_vars: list,    # variable names already holding resolved pathlib.Path objects for each compiled .so

    name_offset: int = 0,   # where in N this call may start claiming names;
                             # caller is responsible for not overlapping offsets across other users of the same N pool
    imp_fn: str = "__import__",
    h_blt: str | None = None,   # builtins module handle
    min_delay: float = DEFAULT_MIN_DELAY,
    max_delay: float = DEFAULT_MAX_DELAY,
    check_self_hash: bool = True,
) -> list[str]:
    """
    Return stub source lines that capture integrity baselines for the
    stub's own source and both compiled extensions, then start a daemon
    thread that re-checks them (plus antidebug signals) on a randomized
    interval for the life of the process.

    Call this AFTER the lines that give src_var its final value and
    define every entry of so_path_vars are in scope, and BEFORE the line
    that calls cr_var(...) (gnolly_run).
    """
    lines = []
    a = lines.append

    def enc(text: str) -> str:
        return _enc_str(text, str_key)

    def s(text: str) -> str:
        return f"{s_fn}({enc(text)})"

    def sing(name: str) -> str:
        """getattr(builtins_handle, 'None'|'True') -> hides the bare
        keyword constant, falling back to the literal if h_blt isn't wired
        up (keeps this function usable standalone/in tests)."""
        if h_blt is None:
            return name
        return f"getattr({h_blt}, {s(name)})"

    def em(obj: str, method: str, *args: str) -> str:
        """getattr(obj, s(method))(args) -> hides method names."""
        arg_str = ", ".join(args)
        return f"getattr({obj}, {s(method)})({arg_str})"

    # Local names, offset into the shared pool so a second call (there's
    # only ever one in practice) can't collide with this one.
    o = name_offset
    v_rand_mod = N[o + 0]
    v_time_mod = N[o + 1]
    v_hash_mod = N[o + 2]
    v_src_base = N[o + 3]
    v_so_bases = N[o + 4]   # list, parallel to so_path_vars
    v_fn       = N[o + 5]
    v_thread   = N[o + 6]
    v_cur      = N[o + 7]   # loop temp: digest currently being compared
    v_mod_iter = N[o + 8]   # loop temp: debugger-module-name comprehension var
    v_mods     = N[o + 9]   # sys.modules handle, re-fetched each pass
    v_delay    = N[o + 10]

    a(f"{v_rand_mod} = {imp_fn}({s('random')})")
    a(f"{v_time_mod} = {imp_fn}({s('time')})")
    a(f"{v_hash_mod} = {imp_fn}({s('hashlib')})")

    # ── Baselines, captured once, right now ──────────────────────────────
    # This is the earliest point a background check COULD run, which is
    # also the latest point every one-shot startup check has already
    # passed (this code is spliced in after all of them) -> "now" is
    # exactly the known-good state to measure future drift against.
    if check_self_hash:
        a(f"{v_src_base} = {em(em(v_hash_mod, 'sha256', em(src_var, 'encode', s('utf-8'))), 'digest')}")
    a(f"{v_so_bases} = []")
    for pvar in so_path_vars:
        a(f"{em(v_so_bases, 'append', em(em(v_hash_mod, 'sha256', em(pvar, 'read_bytes')), 'digest'))}")

    # ── Loop body ─────────────────────────────────────────────────────────
    a(f"def {v_fn}():")
    a(f"    while {sing('True')}:")
    a(f"        try:")
    a(f"            {v_delay} = {em(v_rand_mod, 'uniform', repr(min_delay), repr(max_delay))}")
    a(f"            {em(v_time_mod, 'sleep', v_delay)}")

    # 1. self-hash of the stub's own reassembled source text
    if check_self_hash:
        a(f"            {v_cur} = {em(em(v_hash_mod, 'sha256', em(src_var, 'encode', s('utf-8'))), 'digest')}")
        a(f"            if {v_cur} != {v_src_base}:")
        a(f"                {em(h_os, '_exit', obn(1))}")

    # 2. re-hash both compiled extensions from disk, in the order their baselines were appended.
    for i, pvar in enumerate(so_path_vars):
        a(f"            {v_cur} = {em(em(v_hash_mod, 'sha256', em(pvar, 'read_bytes')), 'digest')}")
        a(f"            if {v_cur} != {v_so_bases}[{obn(i)}]:")
        a(f"                {em(h_os, '_exit', obn(1))}")

    # 3. antidebug signals -> the same ones gnolly.antidebug checks once and re-checked fresh every pass.
    a(f"            if {em(h_sys, 'gettrace')} is not {sing('None')}:")
    a(f"                {em(h_os, '_exit', obn(1))}")
    a(f"            if {em(h_sys, 'getprofile')} is not {sing('None')}:")
    a(f"                {em(h_os, '_exit', obn(1))}")
    a(f"            {v_mods} = getattr({h_sys}, {s('modules')})")
    _mod_list = ", ".join(s(mod) for mod in _DEBUG_MODULES)
    a(f"            if any({v_mod_iter} in {v_mods} for {v_mod_iter} in [{_mod_list}]):")
    a(f"                {em(h_os, '_exit', obn(1))}")

    # Fail-closed: anything going wrong inside the probe itself is treated the same as
    # a detected mismatch rather than being silently skipped.
    a(f"        except Exception:")
    a(f"            {em(h_os, '_exit', obn(1))}")

    a(f"{v_thread} = getattr({imp_fn}({s('threading')}), {s('Thread')})(target={v_fn}, daemon={sing('True')})")
    a(f"{em(v_thread, 'start')}")

    return lines
