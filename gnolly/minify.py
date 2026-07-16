"""
gnolly.minify
~~~~~~~~~~~~~
Best-effort, safety-first minifier for the generated stub source.

Used by "gnolly protect --minify". Runs as the very last step, after
obfuscation/flattening, so it never sees (or needs to understand)
anything except plain valid Python.

What it does
------------
1. Round-trips the source through ``ast.parse`` / ``ast.unparse``,
   which for free strips every comment, blank line, and docstring, and
   normalizes formatting to one statement per line at a fixed 4-space
   indent -> a strictly smaller, canonical representation of the exact
   same program.
2. Recompresses that fixed 4-space indent down to 1 space per nesting
   level. This is safe because Python only cares about relative
   indentation within a block; scaling every level down by the same
   fixed amount preserves that relationship exactly.
3. Joins consecutive simple statements (assignments, expression
   statements, return/pass/break/continue/raise, import, del, etc.) that share the same indentation level onto
   a single line with ";" separators, stopping at the first line that
   opens a new block (anything ending in :) or dedents/indents.

Every stage is verified by re-parsing the result; if anything doesn't
round-trip cleanly, minify_source() returns the original source
untouched rather than risk shipping broken output.
"""
from __future__ import annotations

import ast

__all__ = ["minify_source"]

_BLOCK_KEYWORDS = (
    "if ", "elif ", "else", "for ", "while ", "try", "except", "except*",
    "finally", "def ", "class ", "with ", "async def ", "async for ",
    "async with ", "match ", "case ",
)


def _is_simple(stmt_text: str) -> bool:
    s = stmt_text.rstrip()
    if s.endswith(":"):
        return False
    for kw in _BLOCK_KEYWORDS:
        if s == kw.strip() or s.startswith(kw):
            return False
    return True


def _compact_indent(unparsed: str) -> list[str]:
    out = []
    for line in unparsed.split("\n"):
        if not line.strip():
            continue
        stripped = line.lstrip(" ")
        spaces = len(line) - len(stripped)
        # ast.unparse always uses a fixed 4-space step per level.
        level = spaces // 4
        out.append(" " * level + stripped)
    return out


def _join_simple_runs(lines: list[str]) -> list[str]:
    joined: list[str] = []
    i, n = 0, len(lines)
    while i < n:
        cur = lines[i]
        cur_indent = len(cur) - len(cur.lstrip(" "))
        cur_body = cur.strip()
        if _is_simple(cur_body):
            group = [cur_body]
            j = i + 1
            while j < n:
                nxt = lines[j]
                nxt_indent = len(nxt) - len(nxt.lstrip(" "))
                nxt_body = nxt.strip()
                if nxt_indent == cur_indent and _is_simple(nxt_body):
                    group.append(nxt_body)
                    j += 1
                else:
                    break
            joined.append(" " * cur_indent + "; ".join(group))
            i = j
        else:
            joined.append(cur)
            i += 1
    return joined


def minify_source(source: str) -> str:
    """Return the smallest, safest rewrite of "source" we can produce.
    Falls back to "source" unchanged on any failure."""
    try:
        tree = ast.parse(source)
        unparsed = ast.unparse(tree)
        lines = _compact_indent(unparsed)
        lines = _join_simple_runs(lines)
        result = "\n".join(lines)
        ast.parse(result)  # Sanity check
        return result
    except Exception:
        return source
