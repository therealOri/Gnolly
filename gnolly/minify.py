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
_MAX_COMMAS_INLINE = 40


def _scan_out_of_string_commas(s: str) -> list[tuple[int, int]]:
    """Return (index, bracket_depth) for every comma in "s" that's
    outside a string literal, tracking bracket depth (and skipping over
    string contents, including escapes) in a single linear pass."""
    positions = []
    in_str = None
    depth = 0
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if in_str:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in ("\"", "'"):
            in_str = c
            i += 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == ",":
            positions.append((i, depth))
        i += 1
    return positions


def _find_bracket_open(s: str, before_idx: int, target_depth: int) -> int | None:
    """Index just after the bracket character that first brings depth
    to "target_depth", scanning only up to "before_idx"."""
    depth = 0
    in_str = None
    i = 0
    open_pos = None
    while i < before_idx:
        c = s[i]
        if in_str:
            if c == "\\" and i + 1 < len(s):
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in ("\"", "'"):
            in_str = c
            i += 1
            continue
        if c in "([{":
            depth += 1
            if depth == target_depth:
                open_pos = i + 1
        elif c in ")]}":
            depth -= 1
        i += 1
    return open_pos


def _find_bracket_close(s: str, after_idx: int, target_depth: int) -> int | None:
    """Index of the bracket character that brings depth back down from
    "target_depth", scanning forward from "after_idx"."""
    depth = target_depth
    in_str = None
    i, n = after_idx, len(s)
    while i < n:
        c = s[i]
        if in_str:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in ("\"", "'"):
            in_str = c
            i += 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == target_depth:
                return i
            depth -= 1
        i += 1
    return None


def _tokenize_minify_fragment(fragment: str) -> str:
    """Minimal-spacing pass for a fragment that may not be a complete
    statement on its own (e.g. one element out of a list literal).
    """
    fragment = fragment.strip()
    if not fragment:
        return fragment
    try:
        toks = [
            t for t in tokenize.generate_tokens(io.StringIO(fragment + "\n").readline)
            if t.type not in _SKIP_TYPES and t.type != tokenize.NEWLINE
        ]
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return fragment
    if not toks:
        return fragment
    parts: list[str] = []
    prev = None
    for tok in toks:
        if prev is not None and _needs_space(prev, tok):
            parts.append(" ")
        parts.append(tok.string)
        prev = tok
    return "".join(parts)


def _non_string_length(s: str) -> int:
    """Length of "s" with the *contents* of every string literal
    collapsed down to just their quote characters."""
    n = len(s)
    i = 0
    count = 0
    in_str = None
    while i < n:
        c = s[i]
        if in_str:
            if c == "\\" and i + 1 < n:
                i += 2
                continue
            if c == in_str:
                in_str = None
                count += 1
            i += 1
            continue
        if c in ("\"", "'"):
            in_str = c
            count += 1
            i += 1
            continue
        count += 1
        i += 1
    return count


def _minify_long_line(stripped: str) -> str:
    """
    Minify a single (already left-stripped) physical line too long to
    safely tokenize in one pass, by splitting it into pieces small
    enough to tokenize individually and reassembling.
    """
    comma_depths = _scan_out_of_string_commas(stripped)
    if not comma_depths:
        if _non_string_length(stripped) <= _MAX_TOKENIZE_LEN:
            return _tokenize_minify_fragment(stripped)
        return stripped

    target_depth = min(d for _, d in comma_depths)
    split_positions = [pos for pos, d in comma_depths if d == target_depth]

    open_pos = _find_bracket_open(stripped, split_positions[0], target_depth)
    close_pos = _find_bracket_close(stripped, split_positions[-1] + 1, target_depth)
    if open_pos is None or close_pos is None or open_pos >= close_pos:
        return stripped

    bracket_char = stripped[open_pos - 1]
    prefix = stripped[:open_pos - 1]
    inner = stripped[open_pos:close_pos]
    suffix = stripped[close_pos:]

    elements = []
    start = 0
    for pos in (p - open_pos for p in split_positions):
        elements.append(inner[start:pos])
        start = pos + 1
    elements.append(inner[start:])

    prefix_min = _tokenize_minify_fragment(prefix)
    suffix_min = _tokenize_minify_fragment(suffix)
    elements_min = [_tokenize_minify_fragment(e) for e in elements]

    return prefix_min + bracket_char + ",".join(elements_min) + suffix_min


def _render_physical_line(line: str) -> tuple[int, str]:
    """Return (indent_level, minimally-spaced text) for one physical
    line, tokenized in isolation from the rest of the file."""
    stripped = line.lstrip(" ")
    indent_level = (len(line) - len(stripped)) // 4
    if len(stripped) > _MAX_TOKENIZE_LEN:
        return indent_level, _minify_long_line(stripped)
    if len(_scan_out_of_string_commas(stripped)) > _MAX_COMMAS_INLINE:
        return indent_level, _minify_long_line(stripped)
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
            joined.append(" " * cur_indent + ";".join(group))
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
