"""
gnolly.modhide
~~~~~~~~~~~~~~
Hides a piece of "internal helper logic" behind a synthetic
sys.meta_path import instead of an inline function definition or an
exec()'d blob.

Why this is a genuinely different hiding mechanism from flatten's
exec-hide: exec-hide still leaves the word "exec(" sitting in the
file, decoding and running a blob inline -> an attacker grepping for
"exec(" finds every one of those instantly. This instead registers a
custom importlib Finder/Loader and lets the stub's own existing
imp_fn("<fake module name>") call synthesize a whole module object on
the fly. From the call site it's indistinguishable from any of the
stub's many other ordinary obfuscated imports (hashlib, os, struct,
...), because it goes through the exact same __import__ mechanism.
Nothing about it looks like code being unpacked and run; it looks
like importing a library.

Namespace isolation
--------------------
A real module gets its own fresh __dict__, not the calling stub's
globals -> the hidden source can't casually reference the stub's own
s_fn/h_hash/etc the way flattened top-level statements can. Rather
than plumbing specific names through into that namespace (which would
mean this module has to know which names the hidden logic happens to
need, coupling it to the caller), the hidden source generated here is
fully self-contained: it does its own hidden imports/constants via
strcodec._hidden_import_attr/_hidden_str_expr (and the local
_hidden_bytes_expr below), the same primitives gnolly.selfhash's
check blocks use for the same reason.

Safe to hand to flatten_source()
----------------------------------
Unlike gnolly.selfhash's check blocks, the statements generated here
have no self-referential placeholder that needs literal find/replace
in the final file text -> the encoded blob and its decode key are
just ordinary constants, computed once. That means (unlike selfhash)
these lines are safe to insert into stub.py's normal pre-flatten line
list and let flatten_source() (including its exec-hide feature)
process them like anything else in the stub.

What's routed through here
----------------------------
Currently: the custom-alphabet blob decoder ("decode_fn" in stub.py)
-> this is on the live decode path for every protected file. Decode is meaningfully more
"interesting" than the small decoy/junk snippets exec-hide already
covers, but well short of the crypto/VM core that intentionally stays
native in the compiled .so. Easy to route more helpers through the
same generate_hidden_module_import()-style call later; kept to one
call site for now, same "conservative surface area" reasoning as
everywhere else new in this codebase.
"""
from __future__ import annotations
import random
import secrets
from .namegen import random_confusable_name
from .strcodec import _enc_str, _hidden_import_attr, _hidden_str_expr, _render_int, _hidden_exec_ref


def _hidden_bytes_expr(data: bytes, rng: random.Random) -> str:
    """bytes analogue of strcodec._hidden_str_expr -> a self-contained,
    decoded-inline expression for a short bytes constant, no dependency
    on anything outside itself."""
    key = rng.randint(1, 250)
    used_local: set = set()
    v = random_confusable_name(rng, used_local, 1)
    ints_exprs = ", ".join(_render_int(b ^ key, rng) for b in data)
    return f"bytes({v}^{key} for {v} in [{ints_exprs}])"


def _encode_bulk_source(text: str, rng: random.Random) -> tuple[str, str]:
    """
    Cheap bulk encoding for the (multi-KB) hidden module source text.

    Returns (encoded_literal, decode_expr_template) where
    decode_expr_template has one "{}" for the literal's variable name.
    """
    import base64
    key = rng.randint(1, 250)
    raw = text.encode("utf-8")
    xored = bytes(b ^ key for b in raw)
    literal = base64.b85encode(xored).decode("ascii")
    b85_ref = _hidden_import_attr("base64", "b85decode", rng)
    used_local: set = set()
    bv = random_confusable_name(rng, used_local, 1)
    utf8_expr = _hidden_str_expr("utf-8", rng)
    decode_tmpl = (
        f"bytes({bv} ^ {key} for {bv} in {b85_ref}({{}})).decode({utf8_expr})"
    )
    return literal, decode_tmpl


def _hidden_decode_source(alpha: str, xor_key: bytes, rng: random.Random) -> tuple[str, str]:
    """
    Self-contained source for the custom-alphabet blob decoder:
    functionally identical to the inline version stub.py used to emit
    directly, but with zero dependency on the outer stub's s_fn/b_fn/
    alpha_var/rev_var/xor_fn/etc, since this text executes inside a
    fresh module namespace rather than the stub's own globals. "alpha" and "xor_key" are baked in directly as
    hidden constants.

    Returns (source_text, exported_function_name).
    """
    used: set = set()
    fn_name = random_confusable_name(rng, used, length=rng.randint(9, 14))
    p_in = random_confusable_name(rng, used, 1)
    alpha_v, rev_v, xor_v = (
        random_confusable_name(rng, used, length=rng.randint(5, 9)) for _ in range(3)
    )
    cp, ct, cn, cb, ci, cx, cy, cv, rc1, rc2 = (
        random_confusable_name(rng, used, 1) for _ in range(10)
    )

    alpha_expr = _hidden_str_expr(alpha, rng)
    key_expr = _hidden_bytes_expr(xor_key, rng)

    lines = []
    a = lines.append
    a(f"{alpha_v} = {alpha_expr}")
    a(f"{xor_v} = {key_expr}")
    a(f"{rev_v} = {{{rc1}: {rc2} for {rc2}, {rc1} in enumerate({alpha_v})}}")
    a(f"def {fn_name}({p_in}):")
    a(f"    {cp} = {p_in}.count(chr(61))")
    a(f"    {ct} = {p_in}.replace(chr(61), {alpha_v}[0])")
    a(f"    {cn} = [({rev_v}[{ct}[{ci}]] << 18 | {rev_v}[{ct}[{ci}+1]] << 12"
      f" | {rev_v}[{ct}[{ci}+2]] << 6 | {rev_v}[{ct}[{ci}+3]])"
      f" for {ci} in range(0, len({ct}), 4)]")
    a(f"    {cb} = bytes({cx} for {cy} in {cn} for {cx} in"
      f" (({cy} >> 16) & 255, ({cy} >> 8) & 255, {cy} & 255))")
    a(f"    {cv} = {cb}[:-{cp}] if {cp} else {cb}")
    a(f"    return bytes({cx} ^ {xor_v}[{ci} % len({xor_v})] for {ci}, {cx} in enumerate({cv}))")
    return "\n".join(lines), fn_name


def generate_hidden_decode_import(
    alpha: str, xor_key: bytes, s_fn: str, imp_fn: str, str_key: bytes,
    obn, rng: random.Random,
) -> tuple[list[str], str]:
    """
    Emits stub statements that:
      1. Define a Finder + Loader implementing importlib's PEP 451
         Finder/Loader protocol, holding the encoded decoder function's source.
      2. Register the finder into sys.meta_path.
      3. Retrieve the function via imp_fn(<fake module name>) -> the
         exact same call shape every other obfuscated import in this
         stub already uses.

    Returns (lines, retrieval_expr) -> retrieval_expr is a Python
    expression yielding the decode function, ready to call exactly
    like the old inline "def decode_fn(...)" was.
    """
    hidden_src, exported_fn = _hidden_decode_source(alpha, xor_key, random.Random(secrets.randbits(64)))
    src_literal, decode_tmpl = _encode_bulk_source(hidden_src, rng)

    used: set = set()
    fake_mod = random_confusable_name(rng, used, length=rng.randint(10, 16))
    finder_cls, loader_cls = (
        random_confusable_name(rng, used, length=rng.randint(9, 14)) for _ in range(2)
    )
    p_self, p_fullname, p_path, p_target, p_spec, p_module = (
        random_confusable_name(rng, used, 1) for _ in range(6)
    )
    v_iutil, v_result, v_lit = (
        random_confusable_name(rng, used, length=rng.randint(6, 11)) for _ in range(3)
    )

    def enc(s: str) -> str:
        return _enc_str(s, str_key)

    def s_(text: str) -> str:
        return f"{s_fn}({enc(text)})"

    lines = []
    a = lines.append

    # ── Loader ────────────────────────────────────────────────────────────
    # The hidden source itself goes through the bulk encoder.
    a(f"{v_lit} = {src_literal!r}")
    a(f"class {loader_cls}:")
    a(f"    def create_module({p_self}, {p_spec}): return None")
    a(f"    def exec_module({p_self}, {p_module}):")
    a(f"        ({_hidden_exec_ref(rng)})({decode_tmpl.format(v_lit)}, {p_module}.__dict__)")
    a("")

    # ── Finder ────────────────────────────────────────────────────────────
    # importlib.util needs the fromlist trick to come back as the actual
    # .util submodule rather than the top-level importlib package -> same
    # pattern gnolly/import_hook.py already relies on for the same reason.
    a(f"class {finder_cls}:")
    a(f"    def find_spec({p_self}, {p_fullname}, {p_path}, {p_target}=None):")
    a(f"        if {p_fullname} != {s_(fake_mod)}: return None")
    a(f"        {v_iutil} = {imp_fn}({s_('importlib.util')}, "
      f"**{{{s_('fromlist')}: [{s_('spec_from_loader')}]}})")
    a(f"        return getattr({v_iutil}, {s_('spec_from_loader')})"
      f"({p_fullname}, {loader_cls}())")
    a("")

    # ── Register + trigger ───────────────────────────────────────────────
    a(f"getattr({imp_fn}({s_('sys')}).meta_path, {s_('insert')})({obn(0)}, {finder_cls}())")
    a(f"{v_result} = {imp_fn}({s_(fake_mod)})")

    exported_ref = f"getattr({v_result}, {s_(exported_fn)})"
    return lines, exported_ref
