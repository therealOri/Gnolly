"""
gnolly.selfhash
~~~~~~~~~~~~~~~
Self-hash of the stub's own source text, checked redundantly at startup.
"""
from __future__ import annotations
import base64
import hashlib
import random
import secrets
from .namegen import random_confusable_name
from .strcodec import _hidden_str_expr, _hidden_import_attr
from .flatten import flatten_source

# 64 literal ASCII '0' chars -> exactly a sha256 hexdigest's width. This
# exact run must appear in the body text ONLY where check blocks put it;
# wrap_with_self_hash() verifies that count before trusting the swap.
PLACEHOLDER_DIGEST = "0" * 64


def _encode_chunk(text: str, rng: random.Random) -> str:
    """
    Self-contained decode expression for one wrapper chunk: single-key
    XOR + base85, mirroring gnolly.modhide's _encode_bulk_source.
    """
    key = rng.randint(1, 250)
    raw = text.encode("utf-8")
    xored = bytes(b ^ key for b in raw)
    literal = base64.b85encode(xored).decode("ascii")
    b85_ref = _hidden_import_attr("base64", "b85decode", rng)
    used_local: set = set()
    bv = random_confusable_name(rng, used_local, 1)
    utf8_expr = _hidden_str_expr("utf-8", rng)
    return f"bytes({bv} ^ {key} for {bv} in {b85_ref}({literal!r})).decode({utf8_expr})"


def _one_check_block(src_var: str, style: int, reserved_names: set) -> list[str]:
    """
    One self-contained self-hash check.

    These blocks are prepended ahead of the main stub body, which means none of the main body's own
    machinery exists yet at this point -> every name/import this block needs has
    to come from strcodec's standalone helpers (_hidden_str_expr,
    _hidden_import_attr), which build a complete, dependency-free
    expression each time rather than assuming a decoder is already
    defined.
    """
    rng = random.Random(secrets.randbits(64))
    used = reserved_names
    v_exp, v_can, v_re = (
        random_confusable_name(rng, used, length=rng.randint(6, 11)) for _ in range(3)
    )

    exit_ref = _hidden_import_attr("sys", "exit", rng)
    lines = []
    a = lines.append

    # v_exp starts life as the literal placeholder; wrap_with_self_hash()
    # substitutes the real digest into every such occurrence afterward.
    a(f"{v_exp} = {PLACEHOLDER_DIGEST!r}")
    # Reconstruct the canonical (pre-substitution) text: put "0"*64 back
    # wherever the digest now sits. Written as an expression, not a
    # literal 64-char run, so the build-time substitution pass can't
    # accidentally touch it.
    a(f'{v_can} = {src_var}.replace({v_exp}, "0" * 64)')
    hash_ref = _hidden_import_attr("hashlib", "sha256", rng)
    utf8_lit = _hidden_str_expr("utf-8", rng)
    a(f"{v_re} = {hash_ref}({v_can}.encode({utf8_lit})).hexdigest()")

    if style == 0:
        a(f"if {v_re} != {v_exp}: {exit_ref}(1)")
    elif style == 1:
        a(f"try:")
        a(f"    if {v_re} != {v_exp}: raise ValueError")
        a(f"except Exception: {exit_ref}(1)")
    else:
        a(f"({exit_ref}(1)) if {v_re} != {v_exp} else None")

    return lines


def _split_chunks(text: str, rng: random.Random) -> list[str]:
    """
    Break "text" into random-length pieces at random cut points,
    targeting a chunk count that scales with body size rather than a
    small fixed count.
    """
    total = len(text)
    n_chunks = max(4, min(300, total // 8000))
    if total < n_chunks * 2:
        return [text] if text else [""]
    points = sorted(set(secrets.randbelow(total - 1) + 1 for _ in range(n_chunks - 1)))
    chunks, prev = [], 0
    for pt in points:
        chunks.append(text[prev:pt])
        prev = pt
    chunks.append(text[prev:])
    return chunks


def _recombine_expr(chunk_vars: list[str], rng: random.Random) -> str:
    """A few equally-valid ways to concatenate the chunks back together,
    re-rolled per build -> mirrors strcodec._split_int_list_expr's own
    "vary the recombination shape" philosophy rather than always using
    the same operator."""
    list_lit = "[" + ", ".join(chunk_vars) + "]"
    style = rng.randrange(3)
    if style == 0:
        return " + ".join(chunk_vars)
    elif style == 1:
        return f"''.join({list_lit})"
    else:
        reduce_ref = _hidden_import_attr("functools", "reduce", rng)
        add_ref = _hidden_import_attr("operator", "add", rng)
        return f"{reduce_ref}({add_ref}, {list_lit})"


def _trigger_lines(src_var: str, rng: random.Random, style: int, reserved_names: set) -> list[str]:
    """
    A few different ways to actually run "src_var" as code, instead of
    always a bare "exec(src_var, globals())" sitting unmistakably in the
    clear. Styles 1/2 reuse the same metaclass-__new__ / descriptor-
    __set_name__ indirection flatten.py's exec-hide already relies on,
    adapted here to run an already-assembled string rather than decode
    one fresh -> triggering exec() as a side effect of ordinary-looking
    class construction rather than a direct call.
    """
    used = reserved_names
    if style == 0:
        return [f"exec({src_var}, globals())"]
    elif style == 1:
        meta_name, cls_name, fn_name = (
            random_confusable_name(rng, used, length=rng.randint(7, 12)) for _ in range(3)
        )
        p_mcs, p_name, p_bases, p_ns = (random_confusable_name(rng, used, 1) for _ in range(4))
        new_str = _hidden_str_expr("__new__", rng)
        return [
            f"class {meta_name}(type):",
            f"    pass",
            f"def {fn_name}({p_mcs}, {p_name}, {p_bases}, {p_ns}):",
            f"    exec({src_var}, globals())",
            f"    return getattr(type, {new_str})({p_mcs}, {p_name}, {p_bases}, {p_ns})",
            f"setattr({meta_name}, {new_str}, {fn_name})",
            f"class {cls_name}(metaclass={meta_name}):",
            f"    pass",
        ]
    else:
        desc_name, cls_name, attr_name, fn_name = (
            random_confusable_name(rng, used, length=rng.randint(6, 12)) for _ in range(4)
        )
        p_self, p_owner, p_ownname = (random_confusable_name(rng, used, 1) for _ in range(3))
        set_name_str = _hidden_str_expr("__set_name__", rng)
        return [
            f"class {desc_name}:",
            f"    pass",
            f"def {fn_name}({p_self}, {p_owner}, {p_ownname}):",
            f"    exec({src_var}, globals())",
            f"setattr({desc_name}, {set_name_str}, {fn_name})",
            f"class {cls_name}:",
            f"    {attr_name} = {desc_name}()",
        ]


def _build_wrapper(final_body: str, src_var: str, reserved_names: set) -> str:
    """
    Lay "final_body" out as several chunk assignments + a recombination
    expression + an exec trigger, then run the whole thing through
    flatten_source() for structural scatter.
    """
    rng = random.Random(secrets.randbits(64))
    used = reserved_names

    chunks = _split_chunks(final_body, rng)
    chunk_vars = [random_confusable_name(rng, used, length=rng.randint(8, 13)) for _ in chunks]

    lines = []
    a = lines.append
    for cv, chunk in zip(chunk_vars, chunks):
        a(f"{cv} = {_encode_chunk(chunk, rng)}")
    a(f"{src_var} = {_recombine_expr(chunk_vars, rng)}")
    for cv in chunk_vars:
        a(f"{cv} = None")
    lines.extend(_trigger_lines(src_var, rng, rng.randrange(3), used))

    wrapper_text = "\n".join(lines)
    try:
        flattened = flatten_source(wrapper_text)
        compile(flattened, "<selfhash_wrapper_check>", "exec")
        return flattened
    except Exception:
        return wrapper_text


def wrap_with_self_hash(
    body_text: str, src_var: str, n_checks: int = 3, reserved_names: set | None = None,
) -> str:
    """
    Prepend n_checks independent self-hash check blocks to body_text,
    then wrap the whole thing so the checks can see their own exact
    source text via <src_var> at runtime.
    """
    reserved_names = set(reserved_names) if reserved_names else set()
    try:
        checks: list[str] = []
        for i in range(n_checks):
            checks.extend(_one_check_block(src_var, style=i % 3, reserved_names=reserved_names))

        pre_sub = "\n".join(checks) + "\n" + body_text

        if pre_sub.count(PLACEHOLDER_DIGEST) != n_checks:
            return body_text  # something's off; retrun unwrapped rather than guess

        digest = hashlib.sha256(pre_sub.encode("utf-8")).hexdigest()
        final_body = pre_sub.replace(PLACEHOLDER_DIGEST, digest)

        # Correctness sanity check on the digest scheme itself, independent of how the wrapper below chooses to lay the text out.
        reconstructed = final_body.replace(digest, PLACEHOLDER_DIGEST)
        if hashlib.sha256(reconstructed.encode("utf-8")).hexdigest() != digest:
            return body_text

        wrapped = _build_wrapper(final_body, src_var, reserved_names)
        compile(wrapped, "<selfhash_wrapper>", "exec")
        return wrapped
    except Exception:
        return body_text
