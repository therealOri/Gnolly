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
`f"{s_fn}({_enc_str(name, key)})"`) exactly as if it were a literal list
-> the return type changed from list to str specifically so every
existing call site keeps working unchanged; only what appears in the
generated output text is different.
"""
from __future__ import annotations
import random
import secrets
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


def _obf_int_lambda(n: int, bool_math: bool = False) -> str:
    """
    Represents a single int as a lambda call that computes it via one of
    a few different small reversible arithmetic formulas, randomly chosen
    per call. 
    
    When "bool_math" is set, every literal operand in that
    formula is itself rendered as boolean-shift arithmetic via
    _bool_int_expr() instead of a plain digit. (See that function's
    docstring.)
    
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
    Returns a Python expression, as source text, that evaluates to "target" at runtime.
    """
    if not target:
        return "[]"
    mask  = [secrets.randbelow(256) for _ in target]
    other = [t ^ m for t, m in zip(target, mask)]
    rng = random.Random(secrets.randbits(64))
    used: set = set()
    pa, pb, va, vb = (random_confusable_name(rng, used, 1) for _ in range(4))
    mask_exprs  = ", ".join(_obf_int_lambda(m) for m in mask)
    other_exprs = ", ".join(_obf_int_lambda(o) for o in other)
    return (f"[(lambda {pa}, {pb}: {pa} ^ {pb})({va}, {vb}) "
            f"for {va}, {vb} in zip([{mask_exprs}], [{other_exprs}])]")


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
    Uses chr().

    Parameter names are random confusable single characters rather than
    the conventional _x/_i/_b.
    """
    kl = len(key)
    rng = random.Random(secrets.randbits(64))
    used: set = set()
    p_in, p_i, p_b = (random_confusable_name(rng, used, 1) for _ in range(3))
    return (f"{fn_name} = lambda {p_in}: ''.join("
            f"chr({p_b} ^ {repr(key)}[{p_i} % {kl}]) "
            f"for {p_i}, {p_b} in enumerate({p_in}))")


def _bytes_decoder_lambda(fn_name: str, key: bytes) -> str:
    """Returns a lambda that decodes int lists back to bytes."""
    kl = len(key)
    rng = random.Random(secrets.randbits(64))
    used: set = set()
    p_in, p_i, p_b = (random_confusable_name(rng, used, 1) for _ in range(3))
    return (f"{fn_name} = lambda {p_in}: bytes("
            f"{p_b} ^ {repr(key)}[{p_i} % {kl}] "
            f"for {p_i}, {p_b} in enumerate({p_in}))")
