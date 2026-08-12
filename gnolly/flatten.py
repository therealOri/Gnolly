"""
gnolly.flatten
~~~~~~~~~~~~~~
Control-flow flattening for generated stub source.

What this does
------------------------
generate_stub() (see gnolly/stub.py) assembles the loader as a flat,
top-to-bottom sequence of Python statements: decoders, imports, blob
chunks, the base64-ish decode function, anti-debug checks, the key/KDF dance, the .so import hooks, the final
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
from .strcodec import _enc_str, _bool_int_expr, _render_int, _hidden_exec_ref
from .minify import minify_source

__all__ = ["flatten_source"]


# ---------------------------------------------------------------------------
# Opaque token expressions
# ---------------------------------------------------------------------------

def _tok_value(rng: random.Random) -> int:
    return rng.randrange(0x1000, 0xFFFFFF)


def _tok_expr(n: int, rng: random.Random) -> str:
    """Render a state token using the shared dialect registry."""
    return _render_int(n, rng, expensive_ok=True, expensive_frac=0.15)


def _junk_line(rng: random.Random, used: set) -> str:
    name = random_confusable_name(rng, used, length=rng.randint(6, 11))
    a = secrets.randbelow(0xEFFF) + 0x1000
    b = secrets.randbelow(0xEFFF) + 0x1000
    return f"{name} = {_bool_int_expr(a, rng)} ^ {_bool_int_expr(b, rng)}"


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


def _exec_hide(block: list[str], s_fn: str, str_key: bytes,
                rng: random.Random, used_names: set) -> list[str] | None:
    """
    Returns lines that decode and run the block's text
    without it ever appearing as parseable Python source in the file.
    """
    dedented = _dedent_block(block)
    text = "\n".join(dedented)
    if not text.strip():
        return None
    try:
        minified = minify_source(text)
        if minified.strip():
            text = minified
    except Exception:
        pass
    if len(text) > _MAX_HIDE_CHARS:
        return None
    try:
        encoded_expr = _enc_str(text, str_key)
    except Exception:
        return None

    decode_call = f"{s_fn}({encoded_expr})"
    style = rng.randrange(3)
    exec_ref = _hidden_exec_ref(rng)

    if style == 0:
        return [f"({exec_ref})({decode_call}, globals())"]

    elif style == 1:
        meta_name = random_confusable_name(rng, used_names, length=rng.randint(7, 12))
        cls_name = random_confusable_name(rng, used_names, length=rng.randint(7, 12))
        fn_name = random_confusable_name(rng, used_names, length=rng.randint(7, 12))
        local_used: set = set()
        p_mcs, p_name, p_bases, p_ns = (random_confusable_name(rng, local_used, 1) for _ in range(4))
        try:
            new_enc = _enc_str("__new__", str_key)
        except Exception:
            return [f"({exec_ref})({decode_call}, globals())"]
        return [
            f"class {meta_name}(type):",
            f"    pass",
            f"def {fn_name}({p_mcs}, {p_name}, {p_bases}, {p_ns}):",
            f"    ({exec_ref})({decode_call}, globals())",
            f"    return getattr(type, {s_fn}({new_enc}))({p_mcs}, {p_name}, {p_bases}, {p_ns})",
            f"setattr({meta_name}, {s_fn}({new_enc}), {fn_name})",
            f"class {cls_name}(metaclass={meta_name}):",
            f"    pass",
        ]

    else:
        desc_name = random_confusable_name(rng, used_names, length=rng.randint(7, 12))
        cls_name = random_confusable_name(rng, used_names, length=rng.randint(7, 12))
        attr_name = random_confusable_name(rng, used_names, length=rng.randint(6, 10))
        fn_name = random_confusable_name(rng, used_names, length=rng.randint(7, 12))
        local_used = set()
        p_self, p_owner, p_ownname = (random_confusable_name(rng, local_used, 1) for _ in range(3))
        try:
            set_name_enc = _enc_str("__set_name__", str_key)
        except Exception:
            return [f"({exec_ref})({decode_call}, globals())"]
        return [
            f"class {desc_name}:",
            f"    pass",
            f"def {fn_name}({p_self}, {p_owner}, {p_ownname}):",
            f"    ({exec_ref})({decode_call}, globals())",
            f"setattr({desc_name}, {s_fn}({set_name_enc}), {fn_name})",
            f"class {cls_name}:",
            f"    {attr_name} = {desc_name}()",
        ]



# ---------------------------------------------------------------------------
# Core block -> dispatch-loop emitter
#
# Five genuinely different control-flow mechanisms produce the same
# observable behavior (run these blocks, in this order) via different
# underlying constructs, so a reader (or a script) that's fully solved
# one still has more to work out -> they don't share bytecode ops, and
# most don't even share the "STATE = ..." transition idiom the others
# rely on. generator_frame goes a step further than the rest: there is
# no state variable to find at all, visible or otherwise -> "which
# block runs next" lives purely in a suspended generator frame's
# instruction pointer, something CPython tracks internally and that
# never appears as an inspectable value anywhere in the file. It's
# only offered where doing so is actually safe -> see the module_scope
# parameter threaded through _flatten_stmt/_process_suite below.
# ---------------------------------------------------------------------------

_MECHANISMS = ("while_if", "match_case", "try_except", "dict_next")
_MECHANISMS_MODULE_SCOPE = _MECHANISMS + ("generator_frame",)

# A single elif chain reliably compiles up to ~5,900-5,950 branches before
# CPython's parser fails with a MemoryError. This threshold sits well
# below that with a wide safety margin and is large enough that it's never
# hit by ordinary suites, yet is small enough that even a very large protected
# file's biggest single suite can't realistically approach the real
# limit before this kicks in and forces useage of the one mechanism that has no
# such ceiling.
_LARGE_BRANCH_THRESHOLD = 1500


def _build_branches(
    blocks: list[list[str]],
    body_indent: str,
    rng: random.Random,
    used_names: set,
    n_decoys: int,
    exec_hide_frac: float,
    s_fn: str | None,
    str_key: bytes | None,
    exec_hide_eligible: list[bool],
) -> tuple[list[int], int, list[tuple[int, list[str], int]]]:
    """Shared across all mechanisms: pick tokens, decide exec-hiding,
    build decoys. Returns (tokens, done_token, branches) where each
    branch is (token, content_lines, next_token). content_lines does
    NOT include the state transition itself; each mechanism's renderer
    adds its own version of that."""
    n = len(blocks)
    values: set = set()
    while len(values) < n + 1:
        values.add(_tok_value(rng))
    values = list(values)
    rng.shuffle(values)
    tokens = values[:n]
    done_token = values[n]

    branches: list[tuple[int, list[str], int]] = []
    for i, block in enumerate(blocks):
        next_tok = tokens[i + 1] if i + 1 < n else done_token
        dedented = _dedent_block(block)
        content = None
        if (s_fn and str_key and exec_hide_frac > 0 and exec_hide_eligible[i]
                and rng.random() < exec_hide_frac):
            hidden = _exec_hide(block, s_fn, str_key, rng, used_names)
            if hidden is not None:
                content = [body_indent + line for line in hidden]
        if content is None:
            content = [body_indent + line if line.strip() else line for line in dedented]
        branches.append((tokens[i], content, next_tok))

    for _ in range(n_decoys):
        decoy_tok = _tok_value(rng)
        while decoy_tok in values:
            decoy_tok = _tok_value(rng)
        values.append(decoy_tok)
        n_junk = rng.randint(1, 3)
        decoy_body = [body_indent + _junk_line(rng, used_names) for _ in range(n_junk)]
        # A decoy's "next token" is itself. It's never reached by any
        # real transition, so what it would transition to is moot; this
        # just keeps every branch's shape (content + transition) uniform.
        branches.append((decoy_tok, decoy_body, decoy_tok))

    rng.shuffle(branches)
    return tokens, done_token, branches


def _render_while_if(state_var, tokens, done_token, branches, indent, body_indent, rng) -> list[str]:
    out = [f"{indent}{state_var} = {_tok_expr(tokens[0], rng)}"]
    out.append(f"{indent}while {state_var} != {_tok_expr(done_token, rng)}:")
    kw = "if"
    for tok, content, next_tok in branches:
        out.append(f"{body_indent[:-4]}{kw} {state_var} == {_tok_expr(tok, rng)}:")
        out.extend(content)
        out.append(f"{body_indent}{state_var} = {_tok_expr(next_tok, rng)}")
        kw = "elif"
    out.append(f"{body_indent[:-4]}else:")
    out.append(f"{body_indent}break")
    return out


def _render_match_case(state_var, tokens, done_token, branches, indent, body_indent, rng) -> list[str]:
    out = [f"{indent}{state_var} = {_tok_expr(tokens[0], rng)}"]
    out.append(f"{indent}while {state_var} != {_tok_expr(done_token, rng)}:")
    out.append(f"{body_indent[:-4]}match {state_var}:")
    for tok, content, next_tok in branches:
        out.append(f"{body_indent}case _ if {state_var} == {_tok_expr(tok, rng)}:")
        out.extend(body_indent + "    " + line[len(body_indent):] if line.startswith(body_indent) else line
                    for line in content)
        out.append(f"{body_indent}    {state_var} = {_tok_expr(next_tok, rng)}")
    out.append(f"{body_indent}case _:")
    out.append(f"{body_indent}    break")
    return out


def _render_try_except(state_var, tokens, done_token, branches, indent, body_indent, rng, used_names) -> list[str]:
    exc_name = random_confusable_name(rng, used_names, length=rng.randint(7, 12))
    exc_var = random_confusable_name(rng, used_names, length=rng.randint(4, 9))
    out = [f"{indent}class {exc_name}(Exception):"]
    out.append(f"{indent}    pass")
    out.append(f"{indent}{state_var} = {_tok_expr(tokens[0], rng)}")
    out.append(f"{indent}while {state_var} != {_tok_expr(done_token, rng)}:")
    out.append(f"{body_indent[:-4]}try:")
    kw = "if"
    for tok, content, next_tok in branches:
        out.append(f"{body_indent}{kw} {state_var} == {_tok_expr(tok, rng)}:")
        out.extend(body_indent + "    " + line[len(body_indent):] if line.startswith(body_indent) else line
                    for line in content)
        out.append(f"{body_indent}    raise {exc_name}({_tok_expr(next_tok, rng)})")
        kw = "elif"
    out.append(f"{body_indent}else:")
    out.append(f"{body_indent}    raise {exc_name}({_tok_expr(done_token, rng)})")
    out.append(f"{body_indent[:-4]}except {exc_name} as {exc_var}:")
    out.append(f"{body_indent}{state_var} = {exc_var}.args[0]")
    return out


def _render_dict_next(state_var, tokens, done_token, branches, indent, body_indent, rng, used_names) -> list[str]:
    table_var = random_confusable_name(rng, used_names, length=rng.randint(8, 13))
    out = [f"{indent}{table_var} = {{}}"]
    for tok, _, nxt in branches:
        out.append(f"{indent}{table_var}[{_tok_expr(tok, rng)}] = {_tok_expr(nxt, rng)}")
    out.append(f"{indent}{state_var} = {_tok_expr(tokens[0], rng)}")
    out.append(f"{indent}while {state_var} != {_tok_expr(done_token, rng)}:")
    kw = "if"
    for tok, content, next_tok in branches:
        out.append(f"{body_indent[:-4]}{kw} {state_var} == {_tok_expr(tok, rng)}:")
        out.extend(content)
        kw = "elif"
    out.append(f"{body_indent[:-4]}else:")
    out.append(f"{body_indent}break")
    out.append(f"{body_indent[:-4]}{state_var} = {table_var}[{state_var}]")
    return out


def _collect_assigned_names(stmts_text: str) -> set[str]:
    """
    Names bound (assignment targets, for-loop targets, with-as,
    except-as, walrus, augmented assignment) at the TOP LEVEL of
    stmts_text's own scope -> i.e. NOT inside a nested function/class/
    lambda body, which has its own real scope and needs no help here.
    """
    try:
        tree = ast.parse(stmts_text)
    except SyntaxError:
        return set()

    names: set[str] = set()

    class _Collector(ast.NodeVisitor):
        def visit_FunctionDef(self, node):
            pass  # own real scope; don't descend

        def visit_AsyncFunctionDef(self, node):
            pass

        def visit_ClassDef(self, node):
            pass

        def visit_Lambda(self, node):
            pass

        def visit_Name(self, node):
            if isinstance(node.ctx, ast.Store):
                names.add(node.id)

        def visit_ExceptHandler(self, node):
            if node.name:
                names.add(node.name)
            self.generic_visit(node)

    _Collector().visit(tree)
    return names


def _render_generator_frame(
    blocks: list[list[str]],
    indent: str,
    rng: random.Random,
    used_names: set,
    n_decoys: int,
) -> list[str]:
    """
    Genuinely different from the others: there's no state value
    being compared/dispatched on anywhere. Real block content becomes
    ordinary sequential statements inside a generator function body,
    separated by "yield" -> which block runs next is purely "wherever
    this generator's frame is currently suspended", tracked by CPython
    internally (the frame's instruction pointer), never a Python-level
    value a reader or script can point at.

    Unlike the token-dispatch mechanisms, this can't shuffle real
    blocks' physical order -> a generator has no "jump to arbitrary
    point" operation, only "resume where you left off", so execution
    order here has to match textual order. Decoys are still mixed in,
    just as dead branches gated on an impossible condition instead of
    as unreachable dispatch-table entries.
    """
    gen_name = random_confusable_name(rng, used_names, length=rng.randint(9, 14))
    gv       = random_confusable_name(rng, used_names, length=rng.randint(6, 11))
    inner    = indent + "    "

    body_lines: list[str] = []
    assigned: set[str] = set()

    def _emit_decoy() -> None:
        a1, a2 = _tok_value(rng), _tok_value(rng)
        body_lines.append(f"{inner}if {_tok_expr(a1, rng)} == {_tok_expr(a2, rng)}:")
        for _ in range(rng.randint(1, 3)):
            junk = _junk_line(rng, used_names)
            body_lines.append(f"{inner}    {junk}")
            assigned |= _collect_assigned_names(junk)

    remaining_decoys = n_decoys
    for block in blocks:
        if remaining_decoys > 0 and rng.random() < 0.5:
            _emit_decoy()
            remaining_decoys -= 1

        content = _dedent_block(block)
        assigned |= _collect_assigned_names("\n".join(content))
        for line in content:
            body_lines.append(inner + line if line.strip() else line)
        body_lines.append(f"{inner}yield")

    while remaining_decoys > 0:
        _emit_decoy()
        remaining_decoys -= 1

    out = [f"{indent}def {gen_name}():"]
    if assigned:
        out.append(f"{inner}global {', '.join(sorted(assigned))}")
    out.extend(body_lines)

    out.append(f"{indent}{gv} = {gen_name}()")
    out.append(f"{indent}for _ in range({_render_int(len(blocks), rng)}):")
    out.append(f"{indent}    next({gv})")
    out.append(f"{indent}    globals().update({gv}.gi_frame.f_locals)")
    return out


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
    mechanism: str | None = None,
    module_scope: bool = True,
    gen_safe: bool = True,
) -> list[str]:
    """
    blocks: ordered list of statement-groups that must execute in this exact order.
    indent: the indentation prefix the emitted skeleton itself sits at.
            Block content is indented 8 spaces deeper.
    exec_hide_eligible: parallel to blocks & only blocks that are flagged True
            may be replaced with an exec()-hidden form.
    mechanism: one of "while_if" / "match_case" / "try_except" /
            "dict_next" / "generator_frame", or None to pick randomly.
            Overridden regardless (see _LARGE_BRANCH_THRESHOLD below)
            once branch count gets large enough that the choice stops
            being safe.
    module_scope: whether this dispatch's surrounding scope is still
            module-level globals (true at the top level and for suites
            nested only inside if/for/while/try/with, which don't
            introduce new scopes) as opposed to inside an actual
            function body. Only when true is "generator_frame" a safe
            choice -> see _render_generator_frame for why.
    gen_safe: whether this suite is free of a break/continue that
            targets a loop OUTSIDE the suite itself (see
            _has_unbound_break_continue). Gates ALL FIVE mechanisms,
            not just generator_frame: while_if, match_case, try_except,
            and dict_next all wrap their branches in their OWN while
            loop, so a break/continue meant for an outer loop gets
            silently captured by that wrapper instead of reaching it
            -> Python's break/continue always target the nearest
            enclosing loop syntactically, and there's no way to make a
            nested while loop "transparent" to them for any of these
            mechanisms. When False, dispatch is skipped entirely for
            this suite -> it returns as plain sequential code, with no
            structural obfuscation at this level.
    Returns the full replacement lines, at "indent" level.
    """
    n = len(blocks)
    if n == 0:
        return []
    if n == 1 and n_decoys == 0:
        return blocks[0]
    if exec_hide_eligible is None:
        exec_hide_eligible = [True] * n

    if not gen_safe:
        out: list[str] = []
        for b in blocks:
            out.extend(b)
        return out

    # generator_frame and exec-hide are mutually exclusive within one flatten_source() call.
    exec_hide_possible = bool(s_fn and str_key and exec_hide_frac > 0)
    pool = _MECHANISMS_MODULE_SCOPE if (module_scope and not exec_hide_possible) else _MECHANISMS
    if n + n_decoys > _LARGE_BRANCH_THRESHOLD:
        mechanism = "match_case"
    elif mechanism is None:
        mechanism = rng.choice(pool)
    elif mechanism == "generator_frame" and not (module_scope and not exec_hide_possible):
        mechanism = rng.choice(_MECHANISMS)  # caller-requested but unsafe here

    if mechanism == "generator_frame":
        try:
            return _render_generator_frame(blocks, indent, rng, used_names, n_decoys)
        except Exception:
            mechanism = "while_if"  # fall back to a known-safe mechanism

    state_var = random_confusable_name(rng, used_names, length=rng.randint(8, 13))
    body_indent = indent + " " * 8

    tokens, done_token, branches = _build_branches(
        blocks, body_indent, rng, used_names, n_decoys,
        exec_hide_frac, s_fn, str_key, exec_hide_eligible,
    )

    if mechanism == "match_case":
        return _render_match_case(state_var, tokens, done_token, branches, indent, body_indent, rng)
    elif mechanism == "try_except":
        return _render_try_except(state_var, tokens, done_token, branches, indent, body_indent, rng, used_names)
    elif mechanism == "dict_next":
        return _render_dict_next(state_var, tokens, done_token, branches, indent, body_indent, rng, used_names)
    else:
        return _render_while_if(state_var, tokens, done_token, branches, indent, body_indent, rng)


# ---------------------------------------------------------------------------
# AST-driven recursive descent
# ---------------------------------------------------------------------------

_COMPOUND_TYPES = (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try,
                   ast.With, ast.AsyncWith, ast.FunctionDef, ast.AsyncFunctionDef)
if hasattr(ast, "TryStar"):
    _COMPOUND_TYPES = _COMPOUND_TYPES + (ast.TryStar,)


def _has_unbound_break_continue(node: ast.stmt) -> bool:
    """
    True if node's subtree contains a break/continue that targets a
    loop OUTSIDE node itself -> i.e. not nested inside a for/while
    that's also inside this subtree. Doesn't descend into nested
    function/class defs: a break/continue directly inside one of
    those was already invalid Python in the original source.

    Needed specifically for generator_frame: wrapping a suite in a
    nested "def gen(): ... yield ..." moves its statements into a new
    function scope, and break/continue can't cross a function
    boundary to reach a loop that used to be a plain, scope-transparent
    enclosing for/while (while/if/try/with don't introduce a new scope,
    so this was never a problem for the other four mechanisms).
    """
    def walk(n: ast.AST, in_own_loop: bool) -> bool:
        if isinstance(n, (ast.Break, ast.Continue)):
            return not in_own_loop
        if isinstance(n, (ast.For, ast.AsyncFor, ast.While)):
            return any(walk(c, True) for c in ast.iter_child_nodes(n))
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
            return False
        return any(walk(c, in_own_loop) for c in ast.iter_child_nodes(n))
    return walk(node, False)


class _BreakContinueRewriter:
    """
    Rewrites break/continue that target a given loop into sentinel-flag
    assignments, with guard statements inserted at every nesting level
    in between.

    Sentinel name & values are drawn from the same
    random_confusable_name/_tok_value/_tok_expr machinery the dispatch
    mechanisms themselves already use.
    """

    def __init__(self, flag: str, normal_expr: str, break_expr: str, cont_expr: str):
        self.flag = flag
        self.normal_expr = normal_expr
        self.break_expr = break_expr
        self.cont_expr = cont_expr

    def _assign(self, value_expr: str) -> ast.stmt:
        node = ast.parse(f"{self.flag} = {value_expr}").body[0]
        return node

    def _guard(self, stmts: list[ast.stmt]) -> ast.stmt:
        test = ast.parse(f"{self.flag} == {self.normal_expr}", mode="eval").body
        node = ast.If(test=test, body=stmts, orelse=[])
        return node

    def rewrite_stmt_list(self, stmts: list[ast.stmt]) -> list[ast.stmt]:
        """Process a sequential list of statements and convert any direct
        break/continue and, once a statement is found that could have
        set the flag, wrap everything after it in a single "if flag == normal:" guard."""
        out: list[ast.stmt] = []
        for i, stmt in enumerate(stmts):
            out.append(self._rewrite_stmt(stmt))
            if _has_unbound_break_continue(stmt):
                rest = stmts[i + 1:]
                if rest:
                    out.append(self._guard(self.rewrite_stmt_list(rest)))
                break
        return out

    def _rewrite_stmt(self, stmt: ast.stmt) -> ast.stmt:
        if isinstance(stmt, ast.Break):
            return self._assign(self.break_expr)
        if isinstance(stmt, ast.Continue):
            return self._assign(self.cont_expr)
        if isinstance(stmt, ast.If):
            return ast.If(
                test=stmt.test,
                body=self.rewrite_stmt_list(stmt.body),
                orelse=self.rewrite_stmt_list(stmt.orelse) if stmt.orelse else [],
            )
        if isinstance(stmt, ast.Try) or (hasattr(ast, "TryStar") and isinstance(stmt, ast.TryStar)):
            new_handlers = [
                ast.ExceptHandler(type=h.type, name=h.name, body=self.rewrite_stmt_list(h.body))
                for h in stmt.handlers
            ]
            return type(stmt)(
                body=self.rewrite_stmt_list(stmt.body),
                handlers=new_handlers,
                orelse=self.rewrite_stmt_list(stmt.orelse) if stmt.orelse else [],
                finalbody=self.rewrite_stmt_list(stmt.finalbody) if stmt.finalbody else [],
            )
        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            return type(stmt)(items=stmt.items, body=self.rewrite_stmt_list(stmt.body))
        # For/AsyncFor/While/FunctionDef/AsyncFunctionDef/ClassDef: their
        # own break/continue (if any) already correctly targets
        # themselves (loops) or was already invalid (defs) -> leave
        # completely untouched.
        return stmt


def _try_flag_rewrite_loop(node: ast.stmt, rng: random.Random, used_names: set):
    """
    Attempt sentinel-flag rewrite for a For/AsyncFor/While node
    whose body _has_unbound_break_continue. On success, returns
    (fresh_node, fresh_src_lines, flag, break_expr)

    Returns None if the rewrite doesn't apply, or on ANY failure along
    the way.
    """
    if not isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
        return None
    if not any(_has_unbound_break_continue(s) for s in node.body):
        return None
    try:
        used_local: set = set()
        flag = random_confusable_name(rng, used_local, length=rng.randint(8, 13))
        normal_v, break_v, cont_v = (_tok_value(rng) for _ in range(3))
        normal_e, break_e, cont_e = (_tok_expr(v, rng) for v in (normal_v, break_v, cont_v))

        rewriter = _BreakContinueRewriter(flag, normal_e, break_e, cont_e)
        new_body = rewriter.rewrite_stmt_list(list(node.body))

        reset = ast.parse(f"{flag} = {normal_e}").body[0]
        full_body = [reset] + new_body  # NOT + [trailing] -> see docstring

        if isinstance(node, ast.While):
            new_node: ast.stmt = ast.While(test=node.test, body=full_body, orelse=[])
        elif isinstance(node, ast.AsyncFor):
            new_node = ast.AsyncFor(target=node.target, iter=node.iter, body=full_body,
                                     orelse=[], type_comment=None)
        else:
            new_node = ast.For(target=node.target, iter=node.iter, body=full_body,
                                orelse=[], type_comment=None)

        ast.fix_missing_locations(new_node)
        new_src = ast.unparse(new_node)
        compile(new_src, "<flag_rewrite_check>", "exec")

        fresh_tree = ast.parse(new_src)
        fresh_node = fresh_tree.body[0]
        if any(_has_unbound_break_continue(s) for s in fresh_node.body):
            return None  # didn't eliminate the hazard; bail safely
        return fresh_node, new_src.split("\n"), flag, break_e
    except Exception:
        return None


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
    module_scope: bool = True,
) -> list[str]:
    """
    Return this statement's full replacement text, at its original
    absolute indentation, with every qualifying nested suite recursively
    flattened first (bottom-up).
    """
    full = _slice(src_lines, node)
    if depth >= max_depth or not isinstance(node, _COMPOUND_TYPES):
        return full

    if isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
        rewrite_result = _try_flag_rewrite_loop(node, rng, used_names)
        if rewrite_result is not None:
            fresh_node, fresh_src_lines, flag, break_e = rewrite_result
            orig_indent = _line_indent(src_lines[node.lineno - 1])
            inner_lines = _flatten_compound(
                fresh_node, fresh_src_lines, rng, used_names,
                min_stmts, base_decoys, depth, max_depth, module_scope,
            )
            body_indent = "    "
            for l in inner_lines[1:]:
                if l.strip():
                    body_indent = _line_indent(l)
                    break
            trailing = [f"{body_indent}if {flag} == {break_e}:", f"{body_indent}    break"]
            rewritten_part = [orig_indent + l if l.strip() else l for l in (inner_lines + trailing)]

            if node.orelse:
                orelse_lines = _process_suite(
                    node.orelse, src_lines, rng, used_names, min_stmts, base_decoys,
                    depth + 1, max_depth, module_scope,
                )
                rewritten_part = rewritten_part + [f"{orig_indent}else:"] + orelse_lines

            return rewritten_part

    return _flatten_compound(node, src_lines, rng, used_names, min_stmts, base_decoys, depth, max_depth, module_scope)


def _flatten_compound(
    node: ast.stmt,
    src_lines: list[str],
    rng: random.Random,
    used_names: set,
    min_stmts: int,
    base_decoys: int,
    depth: int,
    max_depth: int,
    module_scope: bool,
) -> list[str]:
    """The normal (no break/continue rewrite involved) recursive
    descent into a compound statement's nested suites. Factored out of
    _flatten_stmt so the rewrite path above can call it directly on an
    already-rewritten node without re-triggering the rewrite check."""
    full = _slice(src_lines, node)
    child_scope = module_scope and not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))

    local = list(full)
    base_line = node.lineno
    spans = []
    for suite in _suite_lists(node):
        s_start = suite[0].lineno - base_line
        s_end = suite[-1].end_lineno - base_line + 1
        new_lines = _process_suite(
            suite, src_lines, rng, used_names, min_stmts, base_decoys,
            depth + 1, max_depth, child_scope,
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
    module_scope: bool = True,
) -> list[str]:
    blocks = [
        _flatten_stmt(s, src_lines, rng, used_names, min_stmts, base_decoys, depth, max_depth, module_scope)
        for s in suite_stmts
    ]
    if len(suite_stmts) >= min_stmts and depth <= max_depth:
        suite_indent = _line_indent(src_lines[suite_stmts[0].lineno - 1])
        n_decoys_here = max(0, base_decoys - depth)
        gen_safe = not any(_has_unbound_break_continue(s) for s in suite_stmts)
        return _emit_dispatch(blocks, suite_indent, rng, used_names, n_decoys=n_decoys_here,
                               module_scope=module_scope, gen_safe=gen_safe)
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
            _flatten_stmt(node, src_lines, rng, used_names, min_stmts, top_decoys, 0, max_depth, True)
            for node in tree.body
        ]
        if len(tree.body) < min_stmts:
            result = "\n".join("\n".join(b) for b in blocks)
        else:
            eligible = _exec_hide_eligibility(tree.body, s_fn)
            top_gen_safe = not any(_has_unbound_break_continue(s) for s in tree.body)
            final_lines = _emit_dispatch(
                blocks, "", rng, used_names, n_decoys=top_decoys,
                exec_hide_frac=exec_hide_frac, s_fn=s_fn, str_key=str_key,
                exec_hide_eligible=eligible, module_scope=True, gen_safe=top_gen_safe,
            )
            result = "\n".join(final_lines)
        ast.parse(result)  # Sanity check
        return result
    except Exception:
        return source
