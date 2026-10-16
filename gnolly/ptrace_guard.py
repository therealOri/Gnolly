"""
gnolly.ptrace_guard
~~~~~~~~~~~~~~~~~~~
Linux-only ptrace self-attachment ("self-trace") anti-debug.

The actual mechanism lives in compiled C inside gnolly/_gnolly_core.pyx
(see the embedded-C block and _gnolly_ptrace_guard() there), not here.
This module only generates the handful of obfuscated stub lines that
call into it and react to the result -> deliberately as little as
possible, so there's nothing resembling "ptrace" logic left sitting in
the stub's own (even obfuscated) Python source for someone to find and
delete. See the .pyx module for the mechanism itself and its detailed
reasoning; this docstring covers only the parts specific to how the
stub wires it in.

Why the mechanism itself is in the .so and not here
-----------------------------------------------------

  - Tamper resistance. The stub is obfuscated but it is still Python
    source text underneath. Someone willing to deobfuscate it can
    read it and delete the lines that call ptrace. Compiled C in the
    .so doesn't have that problem; removing it means binary-patching
    the extension module, which would fail the .so integrity check.

  - LD_PRELOAD resistance. The compiled version calls the raw
    syscall(2) entry point rather than going through glibc's ptrace()
    *symbol*, so the counter-trick of LD_PRELOAD-ing a fake
    ptrace() that always reports success doesn't intercept it.


Containers/seccomp ambiguity (see strict= below)
--------------------------------------------------
Containers and sandboxes commonly block the ptrace syscall via seccomp
(Docker's default profile does, unless --cap-add=SYS_PTRACE or an
unconfined profile is used). A seccomp denial would show up exactly like
"a debugger is already attached". There is not really a way to tell
them apart from the return value alone. Because of that, a failure
here reacts like every other antidebug.py check by default. Strict=True -> poison-marks
(if decorrelate_checks is on), otherwise exit immediately.

Heartbeat interval (see DEFAULT_HEARTBEAT_MIN_DELAY / MAX_DELAY below)
-----------------------------------------------------------------------
Default 0.5-2ms, randomized -> measured at ~6us of actual CPU work per
check (reading /proc/<pid>/status), with the loop's real-world cost
dominated by thread wake/sleep scheduling rather than the read itself.

"""
from __future__ import annotations
import random
import secrets
from .namegen import random_confusable_name
from .strcodec import _enc_str
from .poison import poison_mark_expr

# Edit these two to change the heartbeat's re-check interval project-wide.
# Both are seconds; the interval is uniformly randomized between them on every cycle and never fixed.
DEFAULT_HEARTBEAT_MIN_DELAY = 0.0005  # 0.5ms
DEFAULT_HEARTBEAT_MAX_DELAY = 0.002   # 2ms


def generate_ptrace_guard_call_lines(
    s_fn: str,       # name of the str-decoder function in the stub
    h_sys: str,       # name of the sys module handle in the stub
    str_key: bytes,   # str encoding key
    obn,              # obf_int callable
    core_var: str,    # stub variable already holding the loaded & hash-verified gnolly._gnolly_core module

    h_blt: str | None = None,  # builtins module handle -> obfuscates None/True/False
    poison_var: str | None = None,  # see gnolly.poison
    heartbeat: bool = True,
    min_delay: float = DEFAULT_HEARTBEAT_MIN_DELAY,
    max_delay: float = DEFAULT_HEARTBEAT_MAX_DELAY,
) -> list[str]:
    """
    Return the stub lines that call _gnolly_core._gnolly_ptrace_guard()
    and react to its result.

    A self-attach failure is always treated like every other
    antidebug.py check (poison-mark if decorrelated, else an immediate
    exit) -> unconditional, not configurable.

    heartbeat : when True (default), and the initial self-attach
        succeeds, the .so starts its own detached pthread that
        periodically re-verifies that the trace is still in place.
    """
    lines = []
    a = lines.append

    def enc(s: str) -> str:
        return _enc_str(s, str_key)

    def s(text: str) -> str:
        return f"{s_fn}({enc(text)})"

    def sing(name: str) -> str:
        if h_blt is None:
            return name
        return f"getattr({h_blt}, {s(name)})"

    react = (
        poison_mark_expr(poison_var, obn) if poison_var is not None
        else f"getattr({h_sys}, {s('exit')})({obn(1)})"
    )

    _rng = random.Random(secrets.randbits(64))
    _used: set = set()
    v_rc, v_kw = (
        random_confusable_name(_rng, _used, length=_rng.randint(6, 11)) for _ in range(2)
    )

    guard_fn_enc = s('_gnolly_ptrace_guard')
    hb_kw_enc    = s('start_heartbeat')
    ld_kw_enc    = s('min_delay')
    hd_kw_enc    = s('max_delay')

    # Keyword args passed via dict-unpack (**{...}) so the keyword
    # names themselves never sit in the stub as plaintext identifiers
    # either -> same trick generate_poison_fold_lines/_obf_from_import
    # already use elsewhere in this codebase.
    a(f"{v_kw} = {{{hb_kw_enc}: {sing('True') if heartbeat else sing('False')}, "
      f"{ld_kw_enc}: {min_delay!r}, {hd_kw_enc}: {max_delay!r}}}")
    a(f"{v_rc} = getattr({core_var}, {guard_fn_enc})(**{v_kw})")
    a(f"if {v_rc} == {obn(0)}:")
    a(f"    {react}")

    return lines
