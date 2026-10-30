"""
gnolly.poison
~~~~~~~~~~~~~
Decorrelated / delayed failure reaction.

This module decorrelates detection from reaction in two independent
ways. Every check that opts in (see antidebug.py's poison_var
parameter) uses mechanism 1 unconditionally; mechanism 2 is optional/additional defense-in-depth.

1. Fold into the decryption key (primary mechanism; no exit() anywhere)
   ----------------------------------------------------------------------
   Instead of comparing-and-exiting, a failed check XORs a per-site
   nonce into a small in-memory accumulator ("poison") -> see
   poison_mark_expr. Nothing observable happens at the check site
   itself: no exit(), no distinguishable branch outcome, no stack
   unwind, nothing to breakpoint. Well after every check has already run and
   the stub has moved on to what looks like routine key-derivation bookkeeping,
   generate_poison_fold_lines folds the accumulator into the
   decryption key -> the exact HMAC-fold idiom gnolly.integrity and
   gnolly.binding already use for the same reason (see
   integrity.py's module docstring). The failure
   surfaces deep inside the compiled core, identical to what a plain wrong password produces. That
   handler has no idea any check ever ran, let alone which one.


2. Delayed, out-of-band trigger (optional, defense-in-depth only)
   -------------------------------------------------------------------
   generate_poison_watch_lines adds a second, independent
   reaction that doesn't depend on decryption happening at all: a
   daemon background thread, started immediately after the
   accumulator is initialized, sleeps for a randomized amount of time (re-rolled
   every run, not a fixed offset an attacker can time around) and
   then, only if the accumulator is still nonzero, terminates the
   process from a different thread with a different call stack. This never fires on a
   legitimate run. On a tampered one it will fire off whether or not the
   key fold above was also somehow defeated. It is opt-in (see
   poison_watchdog on protect()/generate_stub()) because killing
   the host process from a background thread is a more
   aggressive default than the key fold alone, which already removes
   every exit() call a static read of the stub could find.

Both mechanisms consume the same accumulator, so neither reveals, on
its own, how many checks exist, which one tripped, or when.
"""
from __future__ import annotations
import hashlib
import hmac
import random
import secrets
from .namegen import random_confusable_name
from .strcodec import _enc_str, _enc_bytes_as_str
from .relay import one_shot_call_lines, _ONE_SHOT_STYLE_COUNT

# Domain separation from binding.py's _BIND_DOMAIN and integrity.py's
# _INTEGRITY_DOMAIN -> all three folds must never be confusable with
# each other even though all three are "HMAC something into the key".
_POISON_DOMAIN = b'gnolly-poison-fold-v1:'
_POISON_MASK = 0xFFFFFFFF


def fold_poison(password: bytes, poison_value: int = 0) -> bytes:
    """
    Fold a 32-bit poison accumulator into password via HMAC-SHA256,
    the same shape as gnolly.integrity.fold_integrity and the
    machine-binding fold in binding.py.
    """
    poison_bytes = (poison_value & _POISON_MASK).to_bytes(4, 'big')
    return hmac.new(_POISON_DOMAIN + poison_bytes, password, hashlib.sha256).digest()


def generate_poison_init_lines(
    s_fn: str, str_key: bytes, obn, rng: random.Random, used: set,
) -> tuple[list[str], str]:
    """
    Emit the accumulator's declaration. Starts at 0 -> the only value
    for which fold_poison() is the correct inverse of the build-time
    fold.
    """
    poison_var = random_confusable_name(rng, used, length=rng.randint(7, 12))
    return [f"{poison_var} = {obn(0)}"], poison_var


def poison_mark_expr(poison_var: str, obn) -> str:
    """
    One statement to run in place of an immediate exit() at a check
    site: OR a per-site random nonzero nonce into the accumulator and
    mask back to 32 bits.

    Re-rolled every call (fresh nonce per check site, per build), so
    two different checks never share a recognizable constant either.
    """
    nonce = secrets.randbelow(_POISON_MASK - 1) + 1  # never 0
    return f"{poison_var} = ({poison_var} | {obn(nonce)}) & {obn(_POISON_MASK)}"


def generate_poison_fold_lines(
    poison_var: str, sm_key: str, h_hash: str, hmac_var: str,
    s_fn: str, b_fn: str, str_key: bytes, byt_key: bytes, obn,
    *,
    wv_fn: str | None,
) -> list[str]:
    """
    Runtime mirror of fold_poison(): sm_key = HMAC(DOMAIN || poison_bytes, sm_key).
    hmac_var must already be bound to the imported hmac module and h_hash to the
    imported hashlib module.

     wv_fn : best-effort secure-zero callable name (see
        gnolly.memwipe_stub). That when given, the fold captures the
        pre-fold sm_key bytes into a throwaway temp var (N[75]),
        reassigns sm_key from that temp, and then wipes the temp right
        after. The password-derived bytes this fold is about to
        replace will get explicitly zeroed out, rather than just falling out of
        scope.
    """
    lines = []
    a = lines.append

    def enc(s: str) -> str:
        return _enc_str(s, str_key)

    def s(text: str) -> str:
        return f"{s_fn}({enc(text)})"

    def encb(data: bytes) -> str:
        return f"{b_fn}({_enc_bytes_as_str(data, byt_key)})"

    rng = random.Random(secrets.randbits(64))
    v_bytes = random_confusable_name(rng, set(), length=rng.randint(7, 12))

    a(f"{v_bytes} = getattr({poison_var}, {s('to_bytes')})({obn(4)}, {s('big')})")
    if wv_fn:
        v_tmp = random_confusable_name(rng, set(), length=rng.randint(7, 12))
        a(f"{v_tmp} = {sm_key}")
        a(f"{sm_key} = getattr({hmac_var}, {s('new')})("
          f"{encb(_POISON_DOMAIN)} + {v_bytes}, {v_tmp}, getattr({h_hash}, {s('sha256')})).digest()")
        a(f"{wv_fn}({v_tmp})")
    else:
        a(f"{sm_key} = getattr({hmac_var}, {s('new')})("
          f"{encb(_POISON_DOMAIN)} + {v_bytes}, {sm_key}, getattr({h_hash}, {s('sha256')})).digest()")
    return lines


def generate_poison_watch_lines(
    poison_var: str, s_fn: str, h_os: str, str_key: bytes, obn,
    imp_fn: str = "__import__",
    min_delay: float = 0.25, max_delay: float = 2.0,
) -> list[str]:
    """
    Background watcher: a daemon thread sleeps a random interval, then kills the process immediately via
    os._exit() if the accumulator is still nonzero.
    """
    lines = []
    a = lines.append

    def enc(s: str) -> str:
        return _enc_str(s, str_key)

    def s(text: str) -> str:
        return f"{s_fn}({enc(text)})"

    rng = random.Random(secrets.randbits(64))
    used: set = set()
    v_thr, v_rnd, v_fn, v_delay = (
        random_confusable_name(rng, used, length=rng.randint(6, 11)) for _ in range(4)
    )

    # The kill itself (os._exit) of this watcher looks like a payload.
    # We will route it through the same relay disguises we use elsewhere. 
    # Setup runs before the timer callback is even defined and the fire statement is the only thing that 
    # actually runs inside the callback body.
    kill_setup, kill_fire = one_shot_call_lines(
        f"getattr({h_os}, {s('_exit')})({obn(1)})",
        rng, rng.randrange(_ONE_SHOT_STYLE_COUNT), used,
    )

    a(f"{v_rnd} = {imp_fn}({s('random')})")
    a(f"{v_delay} = getattr({v_rnd}, {s('uniform')})({min_delay!r}, {max_delay!r})")
    for line in kill_setup:
        a(line)
    a(f"def {v_fn}():")
    a(f"    if {poison_var} & {obn(_POISON_MASK)}:")
    for line in kill_fire:
        a(f"        {line}")
    a(f"{v_thr} = getattr({imp_fn}({s('threading')}), {s('Timer')})({v_delay}, {v_fn})")
    a(f"setattr({v_thr}, {s('daemon')}, True)")
    a(f"getattr({v_thr}, {s('start')})()")

    return lines
