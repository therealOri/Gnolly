"""
gnolly.flatten
~~~~~~~~~~~~~~
Control-flow flattening for generated stub source.

What this does
------------------------
generate_stub() (see gnolly/stub.py) assembles the loader as a flat,
top-to-bottom sequence of Python statements: decoders, imports, blob
chunks, the base64-ish decode function, the opcode-unshuffle function,
anti-debug checks, the key/KDF dance, the .so import hooks, the final
call into the native core. Even with every *name* replaced by a
confusable homoglyph, that shape is still completely legible: a reader
scrolls down and sees "here's where a function starts", "here's the
try/except", "here's the if/else", in the same order every single time.

flatten_source() takes the fully-assembled stub text and rewrites it as
nested dispatch loops, all the way down.
"""
from __future__ import annotations

import ast
import random
import secrets

from .namegen import random_confusable_name
from .strcodec import _enc_str

__all__ = ["flatten_source"]


# ---------------------------------------------------------------------------
# Opaque token expressions
# ---------------------------------------------------------------------------

def _tok_value(rng: random.Random) -> int:
    return rng.randrange(0x1000, 0xFFFFFF)


def _tok_expr(n: int, rng: random.Random) -> str:
    """Render an int as a small reversible arithmetic expression, in the
    same spirit as the rest of the stub's number obfuscation, so state
    tokens don't stick out as bare integer literals."""
    k = secrets.randbelow(0xFFFF) + 1
    choice = secrets.randbelow(3)
    if choice == 0:
        return f"({n ^ k} ^ {k})"
    elif choice == 1:
        return f"({n + k} - {k})"
    else:
        return f"({n - k} + {k})"


def _junk_line(rng: random.Random, used: set) -> str:
    name = random_confusable_name(rng, used, length=rng.randint(6, 11))
    a = secrets.randbelow(0xEFFF) + 0x1000
    b = secrets.randbelow(0xEFFF) + 0x1000
    return f"{name} = {a} ^ {b}"


def _line_indent(line: str) -> str:
    return " " * (len(line) - len(line.lstrip(" ")))


def _dedent_block(block: list[str]) -> list[str]:
    if not block:
        return block
    base = len(block[0]) - len(block[0].lstrip(" "))
    out = []
    for line in block:
        if not line.strip():
            out.append(line)
            continue
        cur = len(line) - len(line.lstrip(" "))
        cut = min(base, cur)
        out.append(line[cut:])
    return out


# ---------------------------------------------------------------------------
# Exec-string hiding: a fraction of small top-level branches get replaced
# with an opaque encoded blob that's decoded and exec()'d only at the
# moment the dispatcher reaches that state -> nothing about what it does
# is present as readable Python source in the file.
# ---------------------------------------------------------------------------

_MAX_HIDE_CHARS = 260  # keep the per-character encoding cost bounded


def _exec_hide(block: list[str], s_fn: str, str_key: bytes) -> list[str] | None:
    dedented = _dedent_block(block)
    text = "\n".join(dedented)
    if not text.strip() or len(text) > _MAX_HIDE_CHARS:
        return None
    try:
        encoded_expr = _enc_str(text, str_key)
    except Exception:
        return None
    return [f"exec({s_fn}({encoded_expr}), globals())"]


# ---------------------------------------------------------------------------
# Core block -> dispatch-loop emitter
# ---------------------------------------------------------------------------

def _emit_dispatch(
    blocks: list[list[str]],
    indent: str,
    rng: random.Random,
    used_names: set,
    n_decoys: int = 0,
    exec_hide_frac: float = 0.0,
    s_fn: str | None = None,
    str_key: bytes | None = None,
    exec_hide_eligible: list[bool] | None = None,
) -> list[str]:
    """
    blocks: ordered list of statement-groups (each a list of lines, at
            their original absolute indentation) that must execute in
            this exact order.
    indent: the indentation prefix the emitted skeleton (STATE=/while/if)
            itself sits at. Block content is indented 8 spaces deeper.
    exec_hide_eligible: parallel to "blocks" -> only blocks flagged True
            may be replaced with an exec()-hidden form. This exists so
            callers can exclude any block that executes before `s_fn`
            itself is defined.
    Returns the full replacement lines, at `indent` level.
    """
    n = len(blocks)
    if n == 0:
        return []
    if n == 1 and n_decoys == 0:
        return blocks[0]
    if exec_hide_eligible is None:
        exec_hide_eligible = [True] * n

    state_var = random_confusable_name(rng, used_names, length=rng.randint(8, 13))

    values: set = set()
    while len(values) < n + 1:
        values.add(_tok_value(rng))
    values = list(values)
    rng.shuffle(values)
    tokens = values[:n]
    done_token = values[n]

    body_indent = indent + " " * 8

    branches = []  # (token_value, rendered_lines)
    for i, block in enumerate(blocks):
        next_tok = tokens[i + 1] if i + 1 < n else done_token
        dedented = _dedent_block(block)
        content = None
        if (s_fn and str_key and exec_hide_frac > 0 and exec_hide_eligible[i]
                and rng.random() < exec_hide_frac):
            hidden = _exec_hide(block, s_fn, str_key)
            if hidden is not None:
                content = [body_indent + line for line in hidden]
        if content is None:
            content = [body_indent + line if line.strip() else line for line in dedented]
        content.append(f"{body_indent}{state_var} = {_tok_expr(next_tok, rng)}")
        branches.append((tokens[i], content))

    for _ in range(n_decoys):
        decoy_tok = _tok_value(rng)
        while decoy_tok in values:
            decoy_tok = _tok_value(rng)
        values.append(decoy_tok)
        n_junk = rng.randint(1, 3)
        decoy_body = [body_indent + _junk_line(rng, used_names) for _ in range(n_junk)]
        branches.append((decoy_tok, decoy_body))

    rng.shuffle(branches)

    out = [f"{indent}{state_var} = {_tok_expr(tokens[0], rng)}"]
    out.append(f"{indent}while {state_var} != {_tok_expr(done_token, rng)}:")
    kw = "if"
    for tok, content in branches:
        out.append(f"{body_indent[:-4]}{kw} {state_var} == {_tok_expr(tok, rng)}:")
        out.extend(content)
        kw = "elif"
    out.append(f"{body_indent[:-4]}else:")
    out.append(f"{body_indent}break")
    return out


# ---------------------------------------------------------------------------
# AST-driven recursive descent
# ---------------------------------------------------------------------------

_COMPOUND_TYPES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try,
                   ast.With, ast.AsyncWith, ast.FunctionDef, ast.AsyncFunctionDef)
if hasattr(ast, "TryStar"):
    _COMPOUND_TYPES = _COMPOUND_TYPES + (ast.TryStar,)


def _suite_lists(node: ast.stmt):
    if isinstance(node, (ast.If,)):
        if node.body:
            yield node.body
        if node.orelse:
            yield node.orelse
    elif isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
        if node.body:
            yield node.body
        if node.orelse:
            yield node.orelse
    elif isinstance(node, (ast.Try,)) or (hasattr(ast, "TryStar") and isinstance(node, ast.TryStar)):
        if node.body:
            yield node.body
        for h in node.handlers:
            if h.body:
                yield h.body
        if node.orelse:
            yield node.orelse
        if node.finalbody:
            yield node.finalbody
    elif isinstance(node, (ast.With, ast.AsyncWith)):
        if node.body:
            yield node.body
    elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        if node.body:
            yield node.body


def _slice(src_lines: list[str], node: ast.stmt) -> list[str]:
    return src_lines[node.lineno - 1: node.end_lineno]


def _flatten_stmt(
    node: ast.stmt,
    src_lines: list[str],
    rng: random.Random,
    used_names: set,
    min_stmts: int,
    base_decoys: int,
    depth: int,
    max_depth: int,
) -> list[str]:
    """Return this statement's full replacement text, at its original
    absolute indentation, with every qualifying nested suite recursively
    flattened first (bottom-up)."""
    full = _slice(src_lines, node)
    if depth >= max_depth or not isinstance(node, _COMPOUND_TYPES):
        return full

    local = list(full)
    base_line = node.lineno
    spans = []
    for suite in _suite_lists(node):
        s_start = suite[0].lineno - base_line
        s_end = suite[-1].end_lineno - base_line + 1
        new_lines = _process_suite(
            suite, src_lines, rng, used_names, min_stmts, base_decoys,
            depth + 1, max_depth,
        )
        spans.append((s_start, s_end, new_lines))

    for s_start, s_end, new_lines in sorted(spans, key=lambda t: t[0], reverse=True):
        local[s_start:s_end] = new_lines
    return local


def _process_suite(
    suite_stmts: list[ast.stmt],
    src_lines: list[str],
    rng: random.Random,
    used_names: set,
    min_stmts: int,
    base_decoys: int,
    depth: int,
    max_depth: int,
) -> list[str]:
    blocks = [
        _flatten_stmt(s, src_lines, rng, used_names, min_stmts, base_decoys, depth, max_depth)
        for s in suite_stmts
    ]
    if len(suite_stmts) >= min_stmts and depth <= max_depth:
        suite_indent = _line_indent(src_lines[suite_stmts[0].lineno - 1])
        n_decoys_here = max(0, base_decoys - depth)
        return _emit_dispatch(blocks, suite_indent, rng, used_names, n_decoys=n_decoys_here)
    out: list[str] = []
    for b in blocks:
        out.extend(b)
    return out


def _exec_hide_eligibility(top_stmts: list[ast.stmt], s_fn: str | None) -> list[bool]:
    """A block may only be replaced by an exec()-hidden form if it
    executes after the statement that defines s_fn. An
    exec-hidden block needs s_fn to decode its own body, so hiding
    something that runs earlier than that definition would reference
    a name that doesn't exist yet."""
    n = len(top_stmts)
    if not s_fn:
        return [True] * n
    define_idx = None
    for idx, node in enumerate(top_stmts):
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and t.id == s_fn:
                    define_idx = idx
                    break
        if define_idx is not None:
            break
    if define_idx is None:
        # Couldn't find it, be conservative and disallow hiding entirely rather than risk a forward reference.
        return [False] * n
    return [i > define_idx for i in range(n)]


def flatten_source(
    source: str,
    *,
    seed: int | None = None,
    min_stmts: int = 3,
    max_depth: int = 6,
    top_decoys: int = 4,
    exec_hide_frac: float = 0.25,
    s_fn: str | None = None,
    str_key: bytes | None = None,
) -> str:
    """
    Rewrite source as nested, opaque dispatch-loop state machines.
    at module top level

    Falls back to returning source unchanged if anything about the
    input can't be parsed/flattened safely.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source

    rng = random.Random(seed if seed is not None else secrets.randbits(64))
    used_names: set = set()
    src_lines = source.splitlines()

    try:
        blocks = [
            _flatten_stmt(node, src_lines, rng, used_names, min_stmts, top_decoys, 0, max_depth)
            for node in tree.body
        ]
        if len(tree.body) < min_stmts:
            result = "\n".join("\n".join(b) for b in blocks)
        else:
            eligible = _exec_hide_eligibility(tree.body, s_fn)
            final_lines = _emit_dispatch(
                blocks, "", rng, used_names, n_decoys=top_decoys,
                exec_hide_frac=exec_hide_frac, s_fn=s_fn, str_key=str_key,
                exec_hide_eligible=eligible,
            )
            result = "\n".join(final_lines)
        ast.parse(result)  # Sanity check
        return result
    except Exception:
        return source
