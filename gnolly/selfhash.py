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
from .strcodec import _hidden_str_expr, _hidden_import_attr, _render_int, _hidden_exec_ref

# 64 literal ASCII '0' chars -> exactly a sha256 hexdigest's width. This
# exact run must appear in the body text ONLY where check blocks put it;
# wrap_with_self_hash() verifies that count before trusting the swap.
PLACEHOLDER_DIGEST = "0" * 64


def _shared_chunk_decode_refs(rng: random.Random) -> tuple[str, str, str]:
    return (
        _hidden_import_attr("base64", "b85decode", rng),
        _hidden_str_expr("utf-8", rng),
        _hidden_str_expr("decode", rng),
    )


def _encode_chunk(text: str, rng: random.Random, b85_var: str, u8_var: str, dec_var: str) -> str:
    """
    Self-contained decode expression for one wrapper chunk: single-key
    XOR + base85, mirroring gnolly.modhide's _encode_bulk_source.
    b85_var/u8_var/dec_var are plain variable names the caller already
    assigned via _shared_chunk_decode_refs.
    """
    key = rng.randint(1, 250)
    raw = text.encode("utf-8")
    xored = bytes(b ^ key for b in raw)
    literal = base64.b85encode(xored).decode("ascii")
    used_local: set = set()
    bv = random_confusable_name(rng, used_local, 1)
    return f"getattr(bytes({bv} ^ {key} for {bv} in {b85_var}({literal!r})), {dec_var})({u8_var})"


def _one_check_block(src_var: str, style: int, reserved_names: set) -> list[str]:
    """
    One self-contained self-hash check.

    These blocks are prepended ahead of the main stub body, which
    means none of the main body's own machinery exists yet at this
    point -> every name/import this block needs has to come from
    strcodec's standalone helpers (_hidden_str_expr, _hidden_import_attr),
    which build a complete, dependency-free expression each time
    rather than assuming a decoder is already defined.
    """
    rng = random.Random(secrets.randbits(64))
    used = reserved_names
    v_exp, v_can, v_re = (
        random_confusable_name(rng, used, length=rng.randint(6, 11)) for _ in range(3)
    )

    exit_ref = _hidden_import_attr("os", "exit", rng)
    lines = []
    a = lines.append

    # v_exp starts life as the literal placeholder; wrap_with_self_hash()
    # substitutes the real digest into every such occurrence afterward.
    a(f"{v_exp} = {PLACEHOLDER_DIGEST!r}")
    # Reconstruct the canonical (pre-substitution) text: put "0"*64 back
    # wherever the digest now sits. Written as an expression, not a
    # literal 64-char run, so the build-time substitution pass can't
    # accidentally touch it.
    replace_str = _hidden_str_expr("replace", rng)
    a(f'{v_can} = getattr({src_var}, {replace_str})({v_exp}, "0" * 64)')
    hash_ref = _hidden_import_attr("hashlib", "sha256", rng)
    utf8_lit = _hidden_str_expr("utf-8", rng)
    encode_str = _hidden_str_expr("encode", rng)
    hexdigest_str = _hidden_str_expr("hexdigest", rng)
    a(f"{v_re} = getattr({hash_ref}(getattr({v_can}, {encode_str})({utf8_lit})), {hexdigest_str})()")

    if style == 0:
        a(f"if {v_re} != {v_exp}: {exit_ref}(1)")
    elif style == 1:
        a(f"try:")
        a(f"    if {v_re} != {v_exp}: raise ValueError")
        a(f"except Exception: {exit_ref}(1)")
    else:
        a(f"({exit_ref}(1)) if {v_re} != {v_exp} else None")

    return lines



# ---------------------------------------------------------------------------
# Cross-checking ("ring") self-hash checks
# ---------------------------------------------------------------------------
# The blocks above (_one_check_block) are independent: every one of
# them hashes the SAME thing (the whole pre_sub body) against the SAME
# expected digest. And that means an attacker only has to find and patch ONE
# of them -> whichever copy they happen to hit first -> since the other
# copies don't know or care that a sibling exists.
#
# With a ring check, block i doesn't hash the whole body and
# doesn't know its own expected digest is shared with anyone; instead it
# hashes the EXACT source region belonging to block (i+1) % n_checks and
# compares that against a digest computed from that region alone. And then the
# last block wraps back around to block 0. Disabling block i changes the
# bytes block (i-1) is watching, so block (i-1) now trips -> and patching
# block (i-1) too just pushes the mismatch one block further back around
# the ring. An attacker has to find every block AND patch all of them
# (plus every neighbor's recorded expectation of its target) in one
# atomic edit.

_RING_DIGEST_WIDTH = 64
_RING_OFFSET_WIDTH = 10  # decimal digits -> room for ~10 GB of source


def _fixed_digits(n: int, width: int = _RING_OFFSET_WIDTH) -> str:
    s = str(n)
    if len(s) > width:
        raise ValueError("ring offset too large for its fixed-width slot")
    return s.zfill(width)


def _ring_field(name: str, width: int) -> tuple[str, int]:
    """
    name = '<width zero chars>', plus the offset of that zero run
    within the returned line. Deliberately plain/unobfuscated text (no
    string-hiding here) -> later passes locate and positionally
    overwrite this exact span, so it has to stay byte-for-byte
    predictable rather than going through an expression that might
    render differently next time it's touched.
    """
    prefix = f"{name} = '"
    return prefix + ("0" * width) + "'", len(prefix)


def _positional_patch(text: str, offset: int, new_value: str) -> str:
    return text[:offset] + new_value + text[offset + len(new_value):]


def _one_ring_block(src_var: str, style: int, reserved_names: set) -> dict:
    """
    One ring-check block, with all six dynamic fields still zeroed.
    Returns {"text": ..., "offsets": {field: local_char_offset, ...}}
    """
    rng = random.Random(secrets.randbits(64))
    used = reserved_names
    (v_exp, v_start, v_end, v_rel_exp, v_rel_start, v_rel_end,
     v_region, v_canon, v_actual) = (
        random_confusable_name(rng, used, length=rng.randint(6, 11)) for _ in range(9)
    )

    lines: list[str] = []
    offsets: dict[str, int] = {}
    cursor = 0

    def add(line: str, field: str | None = None, field_off: int | None = None) -> None:
        nonlocal cursor
        if field is not None:
            offsets[field] = cursor + field_off
        lines.append(line)
        cursor += len(line) + 1  # +1 for the "\n" this block will be joined with

    for field, name, width in (
        ("exp", v_exp, _RING_DIGEST_WIDTH),
        ("start", v_start, _RING_OFFSET_WIDTH),
        ("end", v_end, _RING_OFFSET_WIDTH),
        ("rel_exp", v_rel_exp, _RING_OFFSET_WIDTH),
        ("rel_start", v_rel_start, _RING_OFFSET_WIDTH),
        ("rel_end", v_rel_end, _RING_OFFSET_WIDTH),
    ):
        line, off = _ring_field(name, width)
        add(line, field, off)

    hash_ref = _hidden_import_attr("hashlib", "sha256", rng)
    exit_ref = _hidden_import_attr("os", "exit", rng)
    utf8_lit = _hidden_str_expr("utf-8", rng)
    encode_str = _hidden_str_expr("encode", rng)
    hexdigest_str = _hidden_str_expr("hexdigest", rng)

    add(f"{v_region} = {src_var}[int({v_start}):int({v_end})]")
    add(f"{v_canon} = {v_region}[:int({v_rel_exp})] + '{'0' * _RING_DIGEST_WIDTH}' "
        f"+ {v_region}[int({v_rel_exp}) + {_RING_DIGEST_WIDTH}:]")
    add(f"{v_canon} = {v_canon}[:int({v_rel_start})] + '{'0' * _RING_OFFSET_WIDTH}' "
        f"+ {v_canon}[int({v_rel_start}) + {_RING_OFFSET_WIDTH}:]")
    add(f"{v_canon} = {v_canon}[:int({v_rel_end})] + '{'0' * _RING_OFFSET_WIDTH}' "
        f"+ {v_canon}[int({v_rel_end}) + {_RING_OFFSET_WIDTH}:]")
    add(f"{v_actual} = getattr({hash_ref}(getattr({v_canon}, {encode_str})({utf8_lit})), {hexdigest_str})()")

    style = style % 3
    if style == 0:
        add(f"if {v_actual} != {v_exp}: {exit_ref}(1)")
    elif style == 1:
        add("try:")
        add(f"    if {v_actual} != {v_exp}: raise ValueError")
        add(f"except Exception: {exit_ref}(1)")
    else:
        add(f"({exit_ref}(1)) if {v_actual} != {v_exp} else None")

    return {"text": "\n".join(lines), "offsets": offsets}


def build_ring_checks(src_var: str, n_checks: int, reserved_names: set) -> str | None:
    """
    Build n_checks ring-wired self-hash blocks.
    Returns None -> caller treats this the same as any other
    "don't wrap" signal -> if n_checks can't form a ring (<2) or
    anything about the generated layout fails to round-trip.
    """
    if n_checks < 2:
        return None
    try:
        blocks = [_one_ring_block(src_var, i % 3, reserved_names) for i in range(n_checks)]
        texts = [b["text"] for b in blocks]

        starts: list[int] = []
        cursor = 0
        for t in texts:
            starts.append(cursor)
            cursor += len(t) + 1
        lengths = [len(t) for t in texts]

        # Step 3: rel_* trios -> pure layout facts, no ordering hazard.
        for i in range(n_checks):
            tgt = blocks[(i + 1) % n_checks]
            texts[i] = _positional_patch(texts[i], blocks[i]["offsets"]["rel_exp"],
                                          _fixed_digits(tgt["offsets"]["exp"]))
            texts[i] = _positional_patch(texts[i], blocks[i]["offsets"]["rel_start"],
                                          _fixed_digits(tgt["offsets"]["start"]))
            texts[i] = _positional_patch(texts[i], blocks[i]["offsets"]["rel_end"],
                                          _fixed_digits(tgt["offsets"]["end"]))

        # Step 4: hash each target's current (rel_*-filled, exp/start/end
        # still zero) text -> the canonical form runtime reconstructs.
        digests = [
            hashlib.sha256(texts[(i + 1) % n_checks].encode("utf-8")).hexdigest()
            for i in range(n_checks)
        ]

        # Step 5: fill in exp (the digest above) and start/end (the layout).
        for i in range(n_checks):
            tgt_idx = (i + 1) % n_checks
            texts[i] = _positional_patch(texts[i], blocks[i]["offsets"]["exp"], digests[i])
            texts[i] = _positional_patch(texts[i], blocks[i]["offsets"]["start"],
                                          _fixed_digits(starts[tgt_idx]))
            texts[i] = _positional_patch(texts[i], blocks[i]["offsets"]["end"],
                                          _fixed_digits(starts[tgt_idx] + lengths[tgt_idx]))

        assembled = "\n".join(texts)

        # Sanity check: reconstruct the same canonical form a runtime check would,
        # straight from the assembled text and confirm it matches what got
        # embedded. If this doesn't hold, the ring's math is wrong and
        # every build using it would brick itself at startup.
        for i in range(n_checks):
            tgt_idx = (i + 1) % n_checks
            region = assembled[starts[tgt_idx]: starts[tgt_idx] + lengths[tgt_idx]]
            off = blocks[tgt_idx]["offsets"]
            canon = (region[:off["exp"]] + "0" * _RING_DIGEST_WIDTH
                     + region[off["exp"] + _RING_DIGEST_WIDTH:])
            canon = (canon[:off["start"]] + "0" * _RING_OFFSET_WIDTH
                     + canon[off["start"] + _RING_OFFSET_WIDTH:])
            canon = (canon[:off["end"]] + "0" * _RING_OFFSET_WIDTH
                     + canon[off["end"] + _RING_OFFSET_WIDTH:])
            if hashlib.sha256(canon.encode("utf-8")).hexdigest() != digests[i]:
                return None

        compile(assembled, "<ring_check_wrapper_check>", "exec")
        return assembled
    except Exception:
        return None


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
        join_str = _hidden_str_expr("join", rng)
        return f"getattr('', {join_str})({list_lit})"
    else:
        reduce_ref = _hidden_import_attr("functools", "reduce", rng)
        add_ref = _hidden_import_attr("operator", "add", rng)
        return f"{reduce_ref}({add_ref}, {list_lit})"


def _chunk_guard_lines(
    chunk_vars: list[str], idx: int, expected_len: int, rng: random.Random, used: set,
) -> list[str]:
    """
    A real per-chunk length check, run right after that chunk is
    decoded.
    """
    cv = chunk_vars[idx]
    v_len = random_confusable_name(rng, used, length=rng.randint(6, 11))
    style = rng.randrange(3)
    lines = []
    a = lines.append

    if idx > 0:
        victim = chunk_vars[rng.randrange(idx)]
        response = f"{victim} = {victim}[:0]"
    else:
        exit_ref = _hidden_import_attr("os", "exit", rng)
        response = f"{exit_ref}(1)"

    len_lit = _render_int(expected_len, rng)
    if style == 0:
        a(f"{v_len} = len({cv})")
        a(f"if {v_len} != {len_lit}:")
        a(f"    {response}")
    elif style == 1:
        a(f"if len({cv}) - ({len_lit}):")
        a(f"    {response}")
    else:
        a(f"try:")
        a(f"    if len({cv}) != {len_lit}: raise ValueError")
        a(f"except ValueError:")
        a(f"    {response}")
    return lines


def _trigger_lines(src_var: str, rng: random.Random, style: int, reserved_names: set) -> list[str]:
    """
    A few different ways to actually run "src_var" as code. All three
    styles trigger exec() as a side effect of ordinary-looking
    class construction rather than a direct, bare call.
    """
    used = reserved_names
    style = style % 3
    exec_ref = _hidden_exec_ref(rng)
    if style == 0:
        meta_name, cls_name, fn_name = (
            random_confusable_name(rng, used, length=rng.randint(7, 12)) for _ in range(3)
        )
        p_mcs, p_name, p_bases, p_ns = (random_confusable_name(rng, used, 1) for _ in range(4))
        new_str = _hidden_str_expr("__new__", rng)
        return [
            f"class {meta_name}(type):",
            f"    pass",
            f"def {fn_name}({p_mcs}, {p_name}, {p_bases}, {p_ns}):",
            f"    ({exec_ref})({src_var}, globals())",
            f"    return getattr(type, {new_str})({p_mcs}, {p_name}, {p_bases}, {p_ns})",
            f"setattr({meta_name}, {new_str}, {fn_name})",
            f"class {cls_name}(metaclass={meta_name}):",
            f"    pass",
        ]
    elif style == 1:
        desc_name, cls_name, attr_name, fn_name = (
            random_confusable_name(rng, used, length=rng.randint(6, 12)) for _ in range(4)
        )
        p_self, p_owner, p_ownname = (random_confusable_name(rng, used, 1) for _ in range(3))
        set_name_str = _hidden_str_expr("__set_name__", rng)
        return [
            f"class {desc_name}:",
            f"    pass",
            f"def {fn_name}({p_self}, {p_owner}, {p_ownname}):",
            f"    ({exec_ref})({src_var}, globals())",
            f"setattr({desc_name}, {set_name_str}, {fn_name})",
            f"class {cls_name}:",
            f"    {attr_name} = {desc_name}()",
        ]
    else:
        base_name, sub_name, fn_name = (
            random_confusable_name(rng, used, length=rng.randint(7, 12)) for _ in range(3)
        )
        p_cls, p_kw = (random_confusable_name(rng, used, 1) for _ in range(2))
        init_sub_str = _hidden_str_expr("__init_subclass__", rng)
        classmethod_ref = _hidden_import_attr("builtins", "classmethod", rng)
        return [
            f"class {base_name}:",
            f"    pass",
            f"def {fn_name}({p_cls}, **{p_kw}):",
            f"    ({exec_ref})({src_var}, globals())",
            f"setattr({base_name}, {init_sub_str}, {classmethod_ref}({fn_name}))",
            f"class {sub_name}({base_name}):",
            f"    pass",
        ]


def _build_wrapper(final_body: str, src_var: str, reserved_names: set, encode_chunks: bool = True) -> str:
    """
    Lay "final_body" out as several chunk assignments (each followed
    by a real length-verification guard) + a
    recombination expression + an exec trigger.

    encode_chunks: whether each chunk is XOR+base85 encoded (see
    _encode_chunk) or stored as a plain repr(). Plain repr() is much
    cheaper to build AND, critically, stays highly compressible (it's
    still the original, repetitive obfuscated source) -> the right
    choice whenever pack_source() is going to compress this whole
    result afterward anyway, since at that point nothing here is
    directly visible in the shipped file regardless of which form it
    takes, and encoding first actively hurts: XOR+base85 and destroys the
    redundancy pack_source()'s compressor needs.
    """
    rng = random.Random(secrets.randbits(64))
    used = reserved_names

    chunks = _split_chunks(final_body, rng)
    chunk_vars = [random_confusable_name(rng, used, length=rng.randint(8, 13)) for _ in chunks]

    lines = []
    a = lines.append
    if encode_chunks:
        b85_var, u8_var, dec_var = (
            random_confusable_name(rng, used, length=rng.randint(6, 10)) for _ in range(3)
        )
        b85_expr, utf8_expr, dec_expr = _shared_chunk_decode_refs(rng)
        a(f"{b85_var} = {b85_expr}")
        a(f"{u8_var} = {utf8_expr}")
        a(f"{dec_var} = {dec_expr}")

    for idx, (cv, chunk) in enumerate(zip(chunk_vars, chunks)):
        rendered = _encode_chunk(chunk, rng, b85_var, u8_var, dec_var) if encode_chunks else repr(chunk)
        a(f"{cv} = {rendered}")
        # Guard every chunk when encoded (this is where tampering would
        # actually need catching); skip when plain repr(), since pack=True
        # already compresses this and there's nothing to defend here.
        if encode_chunks:
            lines.extend(_chunk_guard_lines(chunk_vars, idx, len(chunk), rng, used))

    a(f"{src_var} = {_recombine_expr(chunk_vars, rng)}")

    # Null out chunk references so they're eligible for GC as soon as
    # possible rather than lingering.
    all_null = ([b85_var, u8_var, dec_var] if encode_chunks else []) + chunk_vars
    for i in range(0, len(all_null), 6):
        batch = all_null[i : i + 6]
        a(" = ".join(batch) + " = None")

    lines.extend(_trigger_lines(src_var, rng, rng.randrange(3), used))

    wrapper_text = "\n".join(lines)
    try:
        compile(wrapper_text, "<selfhash_wrapper_check>", "exec")
    except Exception:
        pass  # caller's own compile() sanity check in wrap_with_self_hash will catch real problems
    return wrapper_text


def wrap_with_self_hash(
    body_text: str, src_var: str, n_checks: int = 4, reserved_names: set | None = None,
    encode_chunks: bool = True, ring: bool = True,
) -> str:
    """
    Prepend n_checks self-hash check blocks to body_text, then wrap the
    whole thing so the checks can see their own exact source text via
    <src_var> at runtime.

    ring: when True (the default) and n_checks >= 2, the checks are
    wired into a ring -> block i verifies block
    (i+1) % n_checks's own exact region, wrapping back to block 0, so
    disabling any single block changes bytes a DIFFERENT block is
    watching. When False (or n_checks < 2), falls back to the original
    scheme: n_checks independent copies that each hash the whole body
    against one shared digest -> still redundant, but an attacker who
    finds any one copy has found all the protection there is. (not reccomended)

    encode_chunks: see _build_wrapper. Pass False when the caller
    knows pack_source() will compress this result afterward -> the
    default of True is the safe choice for direct/standalone callers
    who might ship this text as-is.
    """
    reserved_names = set(reserved_names) if reserved_names else set()
    try:
        if ring and n_checks >= 2:
            checks_text = build_ring_checks(src_var, n_checks, reserved_names)
            if checks_text is None:
                return body_text
            final_body = checks_text + "\n" + body_text
        else:
            checks: list[str] = []
            for i in range(n_checks):
                checks.extend(_one_check_block(src_var, style=i % 3, reserved_names=reserved_names))

            pre_sub = "\n".join(checks) + "\n" + body_text

            if pre_sub.count(PLACEHOLDER_DIGEST) != n_checks:
                return body_text  # something's off; return unwrapped rather than guess

            digest = hashlib.sha256(pre_sub.encode("utf-8")).hexdigest()
            final_body = pre_sub.replace(PLACEHOLDER_DIGEST, digest)

            # Correctness sanity check on the digest scheme itself, independent of how the wrapper below chooses to lay the text out.
            reconstructed = final_body.replace(digest, PLACEHOLDER_DIGEST)
            if hashlib.sha256(reconstructed.encode("utf-8")).hexdigest() != digest:
                return body_text

        wrapped = _build_wrapper(final_body, src_var, reserved_names, encode_chunks=encode_chunks)
        compile(wrapped, "<selfhash_wrapper>", "exec")
        return wrapped
    except Exception:
        return body_text
