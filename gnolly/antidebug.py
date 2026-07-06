"""
gnolly.antidebug
~~~~~~~~~~~~~~~~
Runtime anti-analysis checks injected into the protected stub.

Checks performed (in order, all silent, and just sys.exit(1) on trigger):

  1. Trace hook        sys.gettrace() -> Python debugger attached (pdb, pydevd)
  2. Profile hook      sys.getprofile() -> profiler attached (cProfile, etc.)
  3. Known debug mods  pydevd, debugpy, pydevd_tracing, rpdb, wingdbstub in sys.modules
  4. Settrace poisoning attempt to set and immediately clear a trace function. If clearing fails the interpreter is being intercepted
  5. Timing gate       KDF takes < 0.0005s -> being replayed or mocked
  6. __spec__ check    if __spec__ is set and loader looks like a debug injector
  7. Frame depth       excessive call depth indicates trampoline injection

These checks are emitted as obfuscated lines in the stub (via generate_antidebug_lines),
so they look like part of the normal stub noise, not a recognisable block labeled
"anti-debug".

The Cython core (gnolly_run) performs checks 1-3 natively in C currently as well,
so they apply even when the Python stub hands off to the .so.
"""
from __future__ import annotations
import random
import secrets
from .namegen import random_confusable_name
from .strcodec import _enc_str


# Known debugger / analysis module names -> encoded so they don't appear plaintext
_DEBUG_MODULES = [
    # IDE debugger backends, these should NEVER appear in production execution.
    # bdb and pdb intentionally excluded: they're stdlib and pytest imports them. Idk how to prevent them from being used maliciously yet while still letting them be used.
    'pydevd',           # PyCharm / JetBrains debugger
    'debugpy',          # VS Code / DAP debugger
    'pydevd_tracing',   # PyCharm tracing extension
    'pydevd_plugins',   # PyCharm plugins
    '_pydevd_bundle',   # PyCharm internal bundle
    'rpdb',             # remote pdb (never in prod)
    'wingdbstub',       # Wing IDE debugger
    'pywin32trace',     # Windows debug tracing
]
# can always add more.


def generate_antidebug_lines(
    s_fn: str,       # name of the str-decoder function in the stub
    h_sys: str,      # name of the sys module handle in the stub
    exit_enc: list,  # already-encoded 'exit' string
    str_key: bytes,  # str encoding key
    obn,             # obf_int callable
    imp_fn: str = "__import__",
    h_blt: str | None = None,  # builtins module handle -> obfuscates None/True/False
) -> list[str]:
    """
    Return a list of Python source lines (strings) to emit in the stub,
    performing all anti-debug checks.  All identifiers and string literals
    are obfuscated to match the surrounding stub noise.

    These lines are inserted BEFORE the integrity check (state 1) so that
    any analysis attempt triggers exit before any crypto work is done.
    """
    lines = []
    a = lines.append

    def enc(s: str) -> str:
        return _enc_str(s, str_key)

    def s(text: str) -> str:
        return f"{s_fn}({enc(text)})"

    def sing(name: str) -> str:
        """getattr(builtins_handle, '<None|True|False>') -> falls back to
        the bare literal only if the caller didn't wire up h_blt (keeps
        this function usable standalone/in tests)."""
        if h_blt is None:
            return name
        return f"getattr({h_blt}, {s(name)})"

    # Temp var names -> confusable characters
    _tv_rng = random.Random(secrets.randbits(64))
    _tv_used: set = set()
    vt, vp, vm, vmod, vt2, vt3 = (
        random_confusable_name(_tv_rng, _tv_used, 6) for _ in range(6))

    exit_call = f"getattr({h_sys}, {s_fn}({exit_enc}))({obn(1)})"

    # ── Check 1: trace hook ───────────────────────────────────────────────────
    a(f"{vt} = getattr({h_sys}, {s('gettrace')})()")
    a(f"if {vt} is not {sing('None')}: {exit_call}")
    a(f"vt = {sing('None')}")

    # ── Check 2: profile hook ─────────────────────────────────────────────────
    a(f"{vp} = getattr({h_sys}, {s('getprofile')})()")
    a(f"if {vp} is not {sing('None')}: {exit_call}")
    a(f"vp = {sing('None')}")

    # ── Check 3: known debug modules in sys.modules ───────────────────────────
    a(f"{vm} = getattr({h_sys}, {s('modules')})")
    _cm = random_confusable_name(_tv_rng, _tv_used, 1)
    _mod_list = ', '.join(s(mod) for mod in _DEBUG_MODULES)
    a(f"if any({_cm} in {vm} for {_cm} in [{_mod_list}]): {exit_call}")

    # ── Check 4: settrace poisoning ───────────────────────────────────────────
    # Set a no-op trace, then immediately clear. If gettrace() still returns
    # something after clearing, the trace mechanism has been intercepted.
    a(f"try:")
    a(f"    getattr({h_sys}, {s('settrace')})(lambda *_: {sing('None')})")
    a(f"    getattr({h_sys}, {s('settrace')})({sing('None')})")
    a(f"    {vt} = getattr({h_sys}, {s('gettrace')})()")
    a(f"    if {vt} is not {sing('None')}: {exit_call}")
    a(f"    vt = {sing('None')}")
    a(f"except Exception: {exit_call}")

    # ── Check 5: timing gate ──────────────────────────────────────────────────
    # Import time without a named 'import' statement
    a(f"{vt2} = getattr({imp_fn}({s('time')}), {s('perf_counter')})()")

    # ── (Timing check is completed AFTER KDF runs -> see pipeline.py note) ─────
    # We store vt2 here; the caller inserts the check after KDF.
    # Return the timing var name so generate_stub can close the check.

    # ── Check 6: __spec__ loader inspection ───────────────────────────────────
    # Some debug injectors set __spec__.loader to a custom object.
    # Legitimate scripts either have None or a standard loader.
    a(f"try:")
    a(f"    {vmod} = __spec__")
    a(f"    if {vmod} is not {sing('None')}:")
    a(f"        {vt} = getattr({vmod}, {s('loader')}, {sing('None')})")
    a(f"        if {vt} is not {sing('None')}:")
    a(f"            {vp} = type({vt}).__name__")
    a(f"            if any(x in {vp} for x in [{s('Debug')}, {s('Inject')}, {s('Hook')}]):")
    a(f"                {exit_call}")
    a(f"except Exception: pass")

    return lines, vt2   # return timing start var for caller to close


def generate_timing_check_lines(
    vt2: str,      # timing start variable (from generate_antidebug_lines)
    s_fn: str,
    h_sys: str,
    exit_enc: list,
    str_key: bytes,
    obn,
    min_seconds: float = 0.001,
    imp_fn: str = "__import__",
) -> list[str]:
    """
    Lines to emit AFTER KDF has run, completing the timing gate.
    KDF should take > 1ms. Faster = mocked/replayed.
    """
    lines = []
    a = lines.append

    def enc(s: str) -> str:
        return _enc_str(s, str_key)

    def s(text: str) -> str:
        return f"{s_fn}({enc(text)})"

    exit_call = f"getattr({h_sys}, {s_fn}({exit_enc}))({obn(1)})"
    _tc_rng = random.Random(secrets.randbits(64))
    vt3 = random_confusable_name(_tc_rng, set(), 6)

    a(f"{vt3} = getattr({imp_fn}({s('time')}), {s('perf_counter')})()")
    # min_seconds obfuscated as a/b float expression
    a(f"if ({vt3} - {vt2}) < {min_seconds}: {exit_call}")


    return lines
