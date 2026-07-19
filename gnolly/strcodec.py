"""
gnolly.strcodec
~~~~~~~~~~~~~~~
The one, single, shared implementation of "encode this string/bytes value
for the stub" and "decode it back at runtime". Every file that generates
stub source code (stub.py, antidebug.py, import_hook.py, binding_stub.py)
imports these functions rather than reimplementing the same XOR logic
inline.

Encoding scheme
----------------
_enc_str()/_enc_bytes_as_str() do NOT return a literal list of ints.
They return a Python expression, as source text, that evaluates to the
XOR'd-ordinals list at runtime:

  - The target ints are split into two independently-random component
    lists ("mask" and "other = target XOR mask"), combined back via a
    lambda inside a zip()-based comprehension. Neither component list
    equals the real data on its own.
  - Every individual element of BOTH component lists is itself replaced
    by a small lambda call that computes that one number via a randomly
    varied arithmetic formula (_obf_int_lambda) -> XOR, or add/sub, or
    sub/add, chosen per element.

Callers just embed the returned string directly into an f-string (e.g.
f"{s_fn}({_enc_str(name, key)})") exactly as if it were a literal list
-> the return type changed from list to str specifically so every
existing call site keeps working unchanged; only what appears in the
generated output text is different.
"""
from __future__ import annotations
import math
import random
import secrets
import struct
from .namegen import random_confusable_name


def _bool_int_expr(n: int, rng: random.Random | None = None) -> str:
    """
    Render an int as a sum of shifted True/False terms. Since bool is
    an int subclass in Python (True == 1, False == 0), a term like
    (True<<4) is just 16 and (False<<4) is just 0. Summing one term
    per bit position, up through the highest set bit, reconstructs "n"
    exactly while reading as genuine boolean arithmetic rather than a
    thinly-veiled binary literal.

    A few zero-value "True-True" filler terms are mixed in at random
    positions purely for noise, and the real terms are shuffled, so
    neither term count nor position reveals which bit each term
    represents.
    """
    if rng is None:
        rng = random.Random(secrets.randbits(64))
    if n == 0:
        return "(True and False)"  # == False == 0
    neg = n < 0
    m = -n if neg else n
    bits = m.bit_length()
    terms = []
    for i in range(bits):
        bit = (m >> i) & 1
        word = "True" if bit else "False"
        style = rng.randrange(3)
        if i == 0:
            terms.append(word)  # bit 0 needs no shift at all
        elif style == 0:
            terms.append(f"({word}<<{i})")
        elif style == 1:
            terms.append(f"({word}*{1 << i})")
        else:
            terms.append(f"(int({word})*{1 << i})")
    for _ in range(rng.randint(0, 2)):
        terms.insert(rng.randrange(len(terms) + 1), "(True-True)")
    rng.shuffle(terms)
    expr = "+".join(terms)
    return f"(-({expr}))" if neg else f"({expr})"


# ---------------------------------------------------------------------------
# Dialect registry: several independent & equally-valid ways to write an
# expression that evaluates to a given int, so that adjacent numbers (even
# within the same encoded string) don't all share one recognizable shape.
# A deobfuscation script written against one dialect simply won't match the
# next number over. Each dialect function returns None if it doesn't apply
# to a given "n" (e.g. bitfloat needs a 32-bit-unsigned-representable
# value) -> _render_int() below skips those and falls back automatically.
# ---------------------------------------------------------------------------

def _dialect_xor_lambda(n: int, rng: random.Random) -> str:
    """An immediately-invoked lambda computing "n"
    via one of a few small reversible arithmetic formulas."""
    return _obf_int_lambda(n)


def _dialect_nested_xor(n: int, rng: random.Random) -> str:
    """Same formula family as xor_lambda, but the random constant "k"
    is itself rendered via another xor_lambda call instead of a bare
    literal. A visibly chained/nested shape, still completely
    self-contained and bounded in size, so it's safe for the same high-volume call sites as xor_lambda.
    """
    k = secrets.randbelow(0xFFFF) + 1
    choice = rng.randrange(3)
    k_expr = _dialect_xor_lambda(k, rng)
    if choice == 0:
        body = f"({n ^ k} ^ {k_expr})"
    elif choice == 1:
        body = f"({n + k} - {k_expr})"
    else:
        body = f"({n - k} + {k_expr})"
    return f"(lambda: {body})()"


def _hidden_str_expr(s: str, rng: random.Random | None = None) -> str:
    """
    Renders a short string as a self-contained, decoded-inline
    expression.

    Deliberately built directly from _render_int() in its default
    (cheap-tier-only) mode rather than routing through
    _split_int_list_expr() -> that function's "combine via operator.xor"
    shape itself needs a hidden string, which would call back into this
    function. Cheap-tier dialects never need imports or strings at all,
    so building straight from them here keeps this function trivially
    non-recursive.
    """
    if rng is None:
        rng = random.Random(secrets.randbits(64))
    key = rng.randint(1, 250)
    used_local: set = set()
    v = random_confusable_name(rng, used_local, 1)
    ints_exprs = ", ".join(_render_int(ord(c) ^ key, rng) for c in s)
    return f"''.join(chr({v}^{key}) for {v} in [{ints_exprs}])"


def _hidden_import_call(rng: random.Random | None = None) -> str:
    """
    Expression that evaluates to the __import__ builtin, without the
    literal identifiers "__import__" or "__builtins__" appearing
    anywhere in the source.

    Mirrors the pattern gnolly/stub.py already uses for its own
    internal .so-loading imports (see the "imp_fn" setup there).
    """
    if rng is None:
        rng = random.Random(secrets.randbits(64))
    builtins_key = _hidden_str_expr("__builtins__", rng)
    import_attr = _hidden_str_expr("__import__", rng)
    used_local: set = set()
    b = random_confusable_name(rng, used_local, length=rng.randint(6, 10))
    return (f"(lambda {b}: getattr({b}, {import_attr}) "
            f"if not isinstance({b}, dict) else {b}[{import_attr}])"
            f"(globals()[{builtins_key}])")


def _hidden_import_attr(module: str, attr: str, rng: random.Random | None = None) -> str:
    """Expression equivalent to getattr(__import__(module), attr), with
    the module name, the attribute name, and the __import__ call itself
    all hidden -> see _hidden_import_call."""
    if rng is None:
        rng = random.Random(secrets.randbits(64))
    mod_expr = f"{_hidden_import_call(rng)}({_hidden_str_expr(module, rng)})"
    attr_expr = _hidden_str_expr(attr, rng)
    return f"getattr({mod_expr}, {attr_expr})"


def _dialect_bitfloat(n: int, rng: random.Random) -> str | None:
    """Stores "n"'s bit pattern as an IEEE-754 float32 literal in the
    source (computed once, ahead of time, by us -> not the reader) and
    reinterprets those same bits back to an int at runtime via struct.
    Reading the source you see an unrelated-looking float constant like
    "1.4e-43", not anything that looks like an encoded integer -> and
    the "struct"/"pack"/"unpack"/"<I"/"<f" text needed to get there is
    itself hidden via _hidden_import_attr/_hidden_str_expr rather than
    sitting in the clear."""
    if n < 0 or n > 0xFFFFFFFF:
        return None
    try:
        f = struct.unpack("<f", struct.pack("<I", n))[0]
    except (OverflowError, struct.error):
        return None
    if not math.isfinite(f):
        return None
    pack_call   = _hidden_import_attr("struct", "pack", rng)
    unpack_call = _hidden_import_attr("struct", "unpack", rng)
    fmt_f = _hidden_str_expr("<f", rng)
    fmt_i = _hidden_str_expr("<I", rng)
    return f"{unpack_call}({fmt_i},{pack_call}({fmt_f},{f!r}))[0]"


def _dialect_fraction(n: int, rng: random.Random) -> str | None:
    """Represents "n" as the numerator of a Fraction that auto-reduces
    to it: Fraction(n*d, d) always simplifies its numerator back to "n"
    regardless of the random multiplier "d", so neither operand alone
    is "n". "fractions"/"Fraction"/"numerator" are hidden the same way
    as in _dialect_bitfloat."""
    if n < 0 or n > 0xFFFFFFF:
        return None
    d = rng.randint(2, 97)
    frac_cls = _hidden_import_attr("fractions", "Fraction", rng)
    numerator_attr = _hidden_str_expr("numerator", rng)
    return f"getattr({frac_cls}({n * d},{d}), {numerator_attr})"


def _dialect_bool_math(n: int, rng: random.Random) -> str:
    return _bool_int_expr(n, rng)


# bitfloat/fraction moved out of the cheap tier: hiding their module and
# attribute names (above) makes each call noticeably larger than plain
# xor_lambda. It's fine for the low-volume, high-visibility sites that opt
# into expensive_ok, not fine for the once-per-character volume the
# cheap tier has to survive. _dialect_nested_xor fills that slot instead.
# Same size class as xor_lambda, no strings/imports at all.
_CHEAP_DIALECTS = (_dialect_xor_lambda, _dialect_nested_xor)
_ALL_DIALECTS = _CHEAP_DIALECTS + (_dialect_bitfloat, _dialect_fraction, _dialect_bool_math)


def _render_int(n: int, rng: random.Random | None = None, expensive_ok: bool = False,
                 expensive_frac: float = 1.0) -> str:
    """
    Picks a random applicable dialect and renders "n" with it. "n" may be
    negative. Dialects that don't support negative/oversized inputs
    return None and are skipped automatically, so callers never need to
    know which dialects apply to which ranges.
    """
    if rng is None:
        rng = random.Random(secrets.randbits(64))
    use_expensive = expensive_ok and (expensive_frac >= 1.0 or rng.random() < expensive_frac)
    pool = list(_ALL_DIALECTS if use_expensive else _CHEAP_DIALECTS)
    rng.shuffle(pool)
    for dialect in pool:
        try:
            out = dialect(n, rng)
        except Exception:
            out = None
        if out is not None:
            return out
    return _dialect_xor_lambda(n, rng)  # always applicable, ultimate fallback


def _obf_int_lambda(n: int, bool_math: bool = False) -> str:
    """
    Represents a single int as a lambda call that computes it via one of
    a few different small reversible arithmetic formulas, randomly chosen
    per call.

    When "bool_math" is set, every literal operand in that
    formula is itself rendered as boolean-shift arithmetic via
    _bool_int_expr() instead of a plain digit.

    Off by default here because this function is called once
    per "character" of every encoded string/bytes value in the stub
    (thousands of times in a typical build). bool_math's ~15-20x size
    cost per literal is fine for the much smaller set of call sites that
    opt into it explicitly (see gnolly.flatten's state tokens) but would
    make the stub enormous if applied unconditionally here.
    """
    k = secrets.randbelow(0xFFFF) + 1
    choice = secrets.randbelow(5)
    rng = random.Random(secrets.randbits(64))
    B = (lambda x: _bool_int_expr(x, rng)) if bool_math else (lambda x: str(x))
    if choice == 0:
        body = f"({B(n ^ k)} ^ {B(k)})"
    elif choice == 1:
        body = f"({B(n + k)} - {B(k)})"
    elif choice == 2:
        body = f"({B(n - k)} + {B(k)})"
    elif choice == 3:
        body = f"(({B(n * k)}) // {B(k)})"
    else:
        r = secrets.randbelow(k)
        body = f"({B(n * k + r)} // {B(k)})"
    return f"(lambda: {body})()"


def _split_int_list_expr(target: list) -> str:
    """
    Returns a Python expression, as source text, that evaluates to
    "target" at runtime. Two independent axes of variation, both
    re-rolled on every call: which dialect renders each individual
    mask/other number, and which of several
    equally-valid shapes recombines the two component lists back into
    the target list.
    """
    if not target:
        return "[]"
    mask  = [secrets.randbelow(256) for _ in target]
    other = [t ^ m for t, m in zip(target, mask)]
    rng = random.Random(secrets.randbits(64))
    used: set = set()
    pa, pb, va, vb = (random_confusable_name(rng, used, 1) for _ in range(4))
    mask_exprs  = ", ".join(_render_int(m, rng) for m in mask)
    other_exprs = ", ".join(_render_int(o, rng) for o in other)
    mask_l, other_l = f"[{mask_exprs}]", f"[{other_exprs}]"

    style = rng.randrange(4)
    if style == 0:
        # lambda call inside a zip()-based comprehension (the original shape)
        return (f"[(lambda {pa}, {pb}: {pa} ^ {pb})({va}, {vb}) "
                f"for {va}, {vb} in zip({mask_l}, {other_l})]")
    elif style == 1:
        # plain comprehension, no lambda wrapper
        return f"[{va} ^ {vb} for {va}, {vb} in zip({mask_l}, {other_l})]"
    elif style == 2:
        # map() over a lambda instead of a comprehension
        return f"list(map(lambda {pa}, {pb}: {pa} ^ {pb}, {mask_l}, {other_l}))"
    else:
        # map() over operator.xor, imported inline (name hidden)
        xor_attr = _hidden_import_attr("operator", "xor", rng)
        return f"list(map({xor_attr}, {mask_l}, {other_l}))"


def _enc_str(s: str, key: bytes) -> str:
    """
    Encode a string as an expression (source text) that evaluates to the
    list of XOR'd ordinals.
    """
    target = [ord(c) ^ key[i % len(key)] for i, c in enumerate(s)]
    return _split_int_list_expr(target)


def _enc_bytes_as_str(b: bytes, key: bytes) -> str:
    """Encode bytes the same way (for binary data decoded as latin-1)."""
    target = [v ^ key[i % len(key)] for i, v in enumerate(b)]
    return _split_int_list_expr(target)


def _str_decoder_lambda(fn_name: str, key: bytes) -> str:
    """
    Returns a lambda that decodes int lists back to strings.

    Parameter names are random confusable single characters rather than
    the conventional _x/_i/_b. The internal recombination shape is one
    of a few equally-valid alternatives, re-rolled per call, so the
    decoder doesn't have one universally-recognizable form from build
    to build.
    """
    kl = len(key)
    rng = random.Random(secrets.randbits(64))
    used: set = set()
    p_in, p_i, p_b = (random_confusable_name(rng, used, 1) for _ in range(3))
    style = rng.randrange(3)
    if style == 0:
        body = (f"''.join(chr({p_b} ^ {repr(key)}[{p_i} % {kl}]) "
                f"for {p_i}, {p_b} in enumerate({p_in}))")
    elif style == 1:
        body = (f"''.join(map(lambda {p_i}, {p_b}: chr({p_b} ^ {repr(key)}[{p_i} % {kl}]), "
                f"range(len({p_in})), {p_in}))")
    else:
        reduce_fn = _hidden_import_attr("functools", "reduce", rng)
        body = (f"{reduce_fn}(lambda {p_b}, {p_i}: "
                f"{p_b} + chr({p_i}[1] ^ {repr(key)}[{p_i}[0] % {kl}]), "
                f"enumerate({p_in}), '')")
    return f"{fn_name} = lambda {p_in}: {body}"


def _bytes_decoder_lambda(fn_name: str, key: bytes) -> str:
    """Returns a lambda that decodes int lists back to bytes, in one of
    a few equally-valid shapes (re-rolled per call)."""
    kl = len(key)
    rng = random.Random(secrets.randbits(64))
    used: set = set()
    p_in, p_i, p_b = (random_confusable_name(rng, used, 1) for _ in range(3))
    style = rng.randrange(3)
    if style == 0:
        body = (f"bytes({p_b} ^ {repr(key)}[{p_i} % {kl}] "
                f"for {p_i}, {p_b} in enumerate({p_in}))")
    elif style == 1:
        body = (f"bytes(bytearray({p_b} ^ {repr(key)}[{p_i} % {kl}] "
                f"for {p_i}, {p_b} in enumerate({p_in})))")
    else:
        body = (f"bytes(map(lambda {p_i}, {p_b}: {p_b} ^ {repr(key)}[{p_i} % {kl}], "
                f"range(len({p_in})), {p_in}))")
    return f"{fn_name} = lambda {p_in}: {body}"
