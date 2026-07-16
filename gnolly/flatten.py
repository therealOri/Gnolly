"""
gnolly.flatten
~~~~~~~~~~~~~~
Control-flow flattening for the generated stub source.

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

flatten_source() takes the fully-assembled stub text and re-emits it as
a single dispatch loop keyed by an opaque integer "state" variable
"""
from __future__ import annotations

import ast
import random
import secrets

from .namegen import random_confusable_name

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


def _junk_line(rng: random.Random, used: set) -> str:
    name = random_confusable_name(rng, used, length=rng.randint(6, 11))
    a = secrets.randbelow(0xEFFF) + 0x1000
    b = secrets.randbelow(0xEFFF) + 0x1000
    return f"{name} = {a} ^ {b}"


# ---------------------------------------------------------------------------
# Core block -> dispatch-loop emitter
# ---------------------------------------------------------------------------

def _emit_dispatch(
    blocks: list[list[str]],
    indent: str,
    rng: random.Random,
    used_names: set,
    n_decoys: int = 0,
) -> list[str]:
    """
    blocks: ordered list of statement-groups (each a list of already
            correctly-relative-indented lines) that must execute in
            this exact order.
    indent: the indentation prefix the emitted skeleton (STATE=/while/if)
            itself sits at. Block content is indented 8 spaces deeper.
    Returns the full replacement lines, at "indent" level.
    """
    n = len(blocks)
    if n == 0:
        return []
    if n == 1:
        if n_decoys == 0:
            return blocks[0]

    state_var = random_confusable_name(rng, used_names, length=rng.randint(8, 13))

    # n+1 unique tokens: one per block, plus a terminal DONE token.
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
        block = _dedent_block(block)
        content = [body_indent + line if line.strip() else line for line in block]
        content.append(f"{body_indent}{state_var} = {_tok_expr(next_tok, rng)}")
        branches.append((tokens[i], content))

    # Decoy branches
    for _ in range(n_decoys):
        decoy_tok = _tok_value(rng)
        while decoy_tok in values:
            decoy_tok = _tok_value(rng)
        values.append(decoy_tok)
        n_junk = rng.randint(1, 3)
        decoy_body = [body_indent + _junk_line(rng, used_names) for _ in range(n_junk)]
        branches.append((decoy_tok, decoy_body))

    # Shuffle textual order -> dispatch is by value, not position.
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
# AST-driven block extraction
# ---------------------------------------------------------------------------

def _slice(src_lines: list[str], node: ast.stmt) -> list[str]:
    return src_lines[node.lineno - 1: node.end_lineno]


def _flatten_function(node: ast.FunctionDef, src_lines: list[str], rng: random.Random,
                       used_names: set, min_stmts: int, decoys: int) -> list[str]:
    """Return the full replacement text (header line(s) + flattened body)
    for a single top-level function definition."""
    header_end = node.body[0].lineno - 1  # last header line index (1 before first body stmt)
    header_lines = src_lines[node.lineno - 1: header_end]
    if not header_lines:
        header_lines = src_lines[node.lineno - 1: node.lineno]

    body_stmts = node.body
    if len(body_stmts) < min_stmts:
        body_lines = src_lines[body_stmts[0].lineno - 1: body_stmts[-1].end_lineno]
        return header_lines + body_lines

    blocks = [_slice(src_lines, s) for s in body_stmts]
    base_indent = " " * (len(src_lines[body_stmts[0].lineno - 1])
                          - len(src_lines[body_stmts[0].lineno - 1].lstrip(" ")))
    flattened_body = _emit_dispatch(blocks, base_indent, rng, used_names, n_decoys=decoys)
    return header_lines + flattened_body


def flatten_source(
    source: str,
    *,
    seed: int | None = None,
    min_top_stmts: int = 4,
    min_fn_stmts: int = 3,
    top_decoys: int = 4,
    fn_decoys: int = 2,
) -> str:
    """
    Rewrite `source` as an opaque dispatch-loop state machine, both at module top level and,
    recursively, inside each top-level function efinition.
    Falls back to returning "source" unchanged if anything
    about the input can't be parsed/flattened safely.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source

    rng = random.Random(seed if seed is not None else secrets.randbits(64))
    used_names: set = set()
    src_lines = source.splitlines()

    top_blocks: list[list[str]] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            try:
                top_blocks.append(_flatten_function(
                    node, src_lines, rng, used_names,
                    min_stmts=min_fn_stmts, decoys=fn_decoys,
                ))
                continue
            except Exception:
                pass
        top_blocks.append(_slice(src_lines, node))

    if len(tree.body) < min_top_stmts:
        return "\n".join("\n".join(b) for b in top_blocks)

    try:
        final_lines = _emit_dispatch(top_blocks, "", rng, used_names, n_decoys=top_decoys)
        result = "\n".join(final_lines)
        # Sanity check
        ast.parse(result)
        return result
    except Exception:
        return source
