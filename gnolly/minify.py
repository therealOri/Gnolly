"""
gnolly.minify
~~~~~~~~~~~~~
Best-effort, safety-first minifier for the generated stub source.

"""
from __future__ import annotations

import ast
import io
import tokenize

__all__ = ["minify_source"]

_BLOCK_KEYWORDS = (
    "if ", "elif ", "else", "for ", "while ", "try", "except", "except*",
    "finally", "def ", "class ", "with ", "async def ", "async for ",
    "async with ", "match ", "case ",
)

_SKIP_TYPES = {
    tokenize.INDENT, tokenize.DEDENT, tokenize.COMMENT, tokenize.NL,
    tokenize.ENDMARKER, tokenize.ENCODING,
}

_OP_CHARS = set("+-*/%@&|^~<>=!:")


def _is_word_char(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def _needs_space(prev: tokenize.TokenInfo, cur: tokenize.TokenInfo) -> bool:
    p, c = prev.string, cur.string
    if not p or not c:
        return False
    if _is_word_char(p[-1]) and _is_word_char(c[0]):
        # e.g. "not" + "in" -> "notin", "return" + "x" -> "returnx",
        # "1" + "if" -> "1if". Any word/number/keyword token butting
        # up against another word/number/keyword token needs a gap.
        return True
    if p[-1] in _OP_CHARS and c[0] in _OP_CHARS:
        # Conservative: never let two operator characters from
        # different tokens sit next to each other, since some
        # combinations (==, <=, >=, !=, **, //, ->, :=, **=, ...) would
        # silently re-tokenize into a single, different operator.
        return True
    if prev.type == tokenize.NAME and cur.type == tokenize.STRING:
        # Guards against accidentally forming a string-prefix token,
        # e.g. a bare name "r" directly followed by a string literal
        # would parse as a raw-string prefix instead of two tokens.
        return True
    return False


def _logical_lines(src: str) -> list[list[tokenize.TokenInfo]]:
    """Group tokens into logical lines (each ending at a NEWLINE token),
    dropping structural/whitespace-only tokens."""
    lines: list[list[tokenize.TokenInfo]] = []
    current: list[tokenize.TokenInfo] = []
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type in _SKIP_TYPES:
            continue
        if tok.type == tokenize.NEWLINE:
            if current:
                lines.append(current)
                current = []
            continue
        current.append(tok)
    if current:
        lines.append(current)
    return lines


def _render_line(tokens: list[tokenize.TokenInfo]) -> tuple[int, str]:
    """Return (indent_level, minimally-spaced text) for one logical line."""
    indent_level = tokens[0].start[1] // 4
    parts: list[str] = []
    prev = None
    for tok in tokens:
        if prev is not None and _needs_space(prev, tok):
            parts.append(" ")
        parts.append(tok.string)
        prev = tok
    return indent_level, "".join(parts)


def _is_simple(stmt_text: str) -> bool:
    s = stmt_text.rstrip()
    if s.endswith(":"):
        return False
    for kw in _BLOCK_KEYWORDS:
        if s == kw.strip() or s.startswith(kw):
            return False
    return True


def _join_simple_runs(lines: list[tuple[int, str]]) -> list[str]:
    joined: list[str] = []
    i, n = 0, len(lines)
    while i < n:
        cur_indent, cur_body = lines[i]
        if _is_simple(cur_body):
            group = [cur_body]
            j = i + 1
            while j < n:
                nxt_indent, nxt_body = lines[j]
                if nxt_indent == cur_indent and _is_simple(nxt_body):
                    group.append(nxt_body)
                    j += 1
                else:
                    break
            joined.append(" " * cur_indent + "; ".join(group))
            i = j
        else:
            joined.append(" " * cur_indent + cur_body)
            i += 1
    return joined


def minify_source(source: str) -> str:
    """Return the smallest, safest rewrite of "source" we can produce.
    Falls back to "source" unchanged on any failure."""
    try:
        tree = ast.parse(source)
        canonical = ast.unparse(tree)
        rendered = [_render_line(toks) for toks in _logical_lines(canonical)]
        lines = _join_simple_runs(rendered)
        result = "\n".join(lines)
        compile(result, "<minify>", "exec")  # Sanity check
        return result
    except Exception:
        return source
