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


_DANGEROUS_OP_PAIRS = {
    "!=", "%=", "&=", "**", "*=", "+=", "-=", "->", "//", "/=",
    ":=", "<<", "<=", "<>", "==", ">=", ">>", "@=", "^=", "|=",
}

_OP_CHARS = set("+-*/%@&|^~<>=!:")


def _is_word_char(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def _needs_space(prev: tokenize.TokenInfo, cur: tokenize.TokenInfo) -> bool:
    p, c = prev.string, cur.string
    if not p or not c:
        return False
    if _is_word_char(p[-1]) and _is_word_char(c[0]):
        return True
    if p[-1] in _OP_CHARS and c[0] in _OP_CHARS and (p[-1] + c[0]) in _DANGEROUS_OP_PAIRS:
        return True
    if prev.type == tokenize.NAME and cur.type == tokenize.STRING:
        return True
    return False


def _logical_lines(src: str) -> list[str]:
    """
    Split into physical lines. ast.unparse() never soft-wraps a long
    expression across multiple physical lines, it only introduces
    newlines for block structure so each non-blank physical line
    here is exactly one complete independently-tokenizable statement.
    (or a compound-statement header/suite line) Never a fragment of
    one that continues on the next line.
    """
    return [ln for ln in src.split("\n") if ln.strip()]


_MAX_TOKENIZE_LEN = 20000


def _render_physical_line(line: str) -> tuple[int, str]:
    """Return (indent_level, minimally-spaced text) for one physical
    line, tokenized in isolation from the rest of the file."""
    stripped = line.lstrip(" ")
    indent_level = (len(line) - len(stripped)) // 4
    if len(line) > _MAX_TOKENIZE_LEN:
        return indent_level, stripped
    try:
        toks = [
            t for t in tokenize.generate_tokens(io.StringIO(stripped + "\n").readline)
            if t.type not in _SKIP_TYPES and t.type != tokenize.NEWLINE
        ]
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return indent_level, stripped
    if not toks:
        return indent_level, stripped
    parts: list[str] = []
    prev = None
    for tok in toks:
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
        rendered = [_render_physical_line(ln) for ln in _logical_lines(canonical)]
        lines = _join_simple_runs(rendered)
        result = "\n".join(lines)
        compile(result, "<minify>", "exec")  # Sanity check
        return result
    except Exception:
        return source
