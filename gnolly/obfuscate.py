"""
gnolly.obfuscate
~~~~~~~~~~~~~~~~
Multi-pass AST obfuscation pipeline.

  Pass 1  Name collection    — build rename map for safe-to-rename names only
  Pass 2  Full renaming      — apply rename map (definitions + loads)
  Pass 3  String encryption  — literals -> bytes.fromhex().decode()
  Pass 4  Constant encryption — int→XOR, float -> arithmetic, bytes -> hex
  Pass 5  Import obfuscation — import/from -> __import__+getattr chains
  Pass 6  Control-flow flat  — state-machine dispatch loop in functions
  Pass 7  Dead code injection — inert stmts scattered through bodies
  Pass 8  Docstring removal
  Pass 9  Polymorphic noise  — unique per-run junk at module top
  Pass 10 Hierarchy + aliasing — bogus class hierarchy (also
                      diversifies the opaque-True token used by passes
                      6/7/9) + per-call expression aliasing

What is and isn't renamed
--------------------------
RENAMED:   module-level functions, classes, local variables, function
           parameters (including, any keyword-argument name
           at a call site that provably targets that exact parameter.
NOT RENAMED: method names (accessed via .attr -> can't know the type),
             a call's keyword-argument name (UNLESS it resolves to a
             locally-defined function's own renamed parameter),
             import names/aliases (obfuscated via __import__ instead),
             __dunder__ names, and builtins

Random policy
--------------
random.SystemRandom() — structural choices (flatten state values order,
                         dead-code injection positions) are cryptographically
                         random every run. There is no way, internal or
                         external, to reproduce the same structural layout
                         twice.
secrets               — all actual embedded numeric values (XOR keys, state
                         numbers, noise constants) use crypto-random every run.
"""
from __future__ import annotations
import ast
import random
import secrets
from .namegen import random_confusable_name
from .strcodec import (
    _render_int as _strcodec_render_int,
    _bool_int_expr as _bool_int_expr_text,
    _obf_int_lambda as _obf_int_lambda_text,
    _hidden_import_attr as _hidden_import_attr_text,
)


# ─────────────────────────────────────────────────────────────────────────────
# Name generation -> random, collision-checked, confusable identifiers
# (see gnolly.namegen for the character set and rationale)
# ─────────────────────────────────────────────────────────────────────────────

_NAME_LEN = 12


class _NamePool:
    def __init__(self):
        self._rng = random.SystemRandom()
        self._used: set = set()
        self.map: dict[str, str] = {}

    def get(self, name: str) -> str:
        if name not in self.map:
            self.map[name] = random_confusable_name(self._rng, self._used, _NAME_LEN)
        return self.map[name]

    def fresh(self) -> str:
        return random_confusable_name(self._rng, self._used, _NAME_LEN)


_PROTECTED = frozenset({
    "print","range","len","int","str","bytes","bytearray","list","dict",
    "set","tuple","type","bool","float","complex","object","super",
    "isinstance","issubclass","hasattr","getattr","setattr","delattr",
    "open","property","staticmethod","classmethod","repr","hash","id",
    "iter","next","enumerate","zip","map","filter","sorted","reversed",
    "min","max","sum","abs","round","divmod","pow","hex","oct","bin",
    "chr","ord","input","exit","quit","vars","dir","callable","format",
    "any","all","slice","memoryview","breakpoint","compile","eval","exec",
    "globals","locals","__import__","__builtins__","__name__","__file__",
    "__doc__","__package__","__spec__","__all__","__version__","__author__",
    "Exception","BaseException","ValueError","TypeError","RuntimeError",
    "KeyError","IndexError","AttributeError","NotImplementedError",
    "OSError","IOError","FileNotFoundError","PermissionError","ImportError",
    "ModuleNotFoundError","StopIteration","GeneratorExit","SystemExit",
    "KeyboardInterrupt","OverflowError","ZeroDivisionError","MemoryError",
    "RecursionError","UnicodeError","UnicodeDecodeError","UnicodeEncodeError",
    "AssertionError","NameError","UnboundLocalError","LookupError",
    "ArithmeticError","BufferError","EOFError","ConnectionError","TimeoutError",
    "True","False","None","self","cls","args","kwargs",
    # common param names that appear as keyword args at call sites
    "key","default","sep","end","file","flush","encoding","errors",
    "mode","buffering","newline","reverse","iterable","start","stop","step",
})

def _renameable(name: str) -> bool:
    return (name not in _PROTECTED
            and not (name.startswith("__") and name.endswith("__")))


# ─────────────────────────────────────────────────────────────────────────────
# Pass 1 -> Name collection (read-only walk)
#   Only collect: module-level function names, class names, local variables.
#   NOT collected: method names (inside class bodies), parameters, imports.
# ─────────────────────────────────────────────────────────────────────────────

class _Collector(ast.NodeVisitor):
    def __init__(self, pool: _NamePool, preserve_toplevel: bool = False):
        self._pool = pool
        self._in_class = 0        # depth (inside a class body, skip method names)
        self._class_body_depth = 0  # >0 only while directly at class-body statement
                                     # level (not inside a nested method/function)
        self._func_depth = 0        # depth inside function/method bodies -> used
                                     # together with _in_class to detect "true"
                                     # module top-level
        self._preserve_toplevel = preserve_toplevel
        # preserve_toplevel: when True, names bound directly at module scope
        # are never registered for renaming -> they keep their original spelling.
        # This is required for module_mode (gnolly.package /
        # gnolly.wheel), name mangling them would break the public API of an otherwise-normal importable package.
        # Everything else (locals, nested functions, method internals) is still mangled.

        # function's original name -> set of ITS OWN parameter original
        # names that are individually renameable. 
        # Built here and independent of whether the function's own name gets renamed. 
        # Consumed by _Transformer.visit_Call so that a
        # call's keyword argument name is renamed when it's tied back to a specific,
        # locally-defined function's own renamed parameter of that exact name.
        # never for a call that dives into external code such as stdlib, builtins, etc. (anything not defined in this
        # source).
        self.func_params: dict[str, set] = {}

        # ClassName(...) dispatches to that class's __init__, so a keyword
        # at a class-instantiation call site needs the exact same
        # treatment as a plain function call and merged into
        # func_params by resolve_class_init_params() once the whole tree
        # has been walked, so base-class chains (collected along the way)
        # are available for classes that don't define their own
        # __init__/__new__ and inherit one instead.
        self._class_own_init_params: dict[str, set] = {}
        self._class_bases: dict[str, list] = {}

    def _at_toplevel(self) -> bool:
        return self._func_depth == 0 and self._in_class == 0

    def _reg(self, name: str):
        if _renameable(name):
            self._pool.get(name)

    def visit_FunctionDef(self, node):
        # Register function name only if NOT inside a class body, and (when
        # preserve_toplevel is on) not a true module-level def either.
        if self._in_class == 0 and not (self._preserve_toplevel and self._at_toplevel()):
            self._reg(node.name)

        # Record this function's own parameter names, regardless of
        # whether ITS name got renamed above.
        _params = (node.args.posonlyargs + node.args.args + node.args.kwonlyargs)
        _names = {p.arg for p in _params if _renameable(p.arg)}
        if _names:
            self.func_params.setdefault(node.name, set()).update(_names)

        saved = self._class_body_depth
        self._class_body_depth = 0
        self._func_depth += 1
        self.generic_visit(node)
        self._func_depth -= 1
        self._class_body_depth = saved

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        if not (self._preserve_toplevel and self._at_toplevel()):
            self._reg(node.name)

        # Own (not inherited) __init__/__new__, if this class defines
        # one directly in its body.
        for _stmt in node.body:
            if isinstance(_stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                    and _stmt.name in ('__init__', '__new__'):
                _params = (_stmt.args.posonlyargs + _stmt.args.args + _stmt.args.kwonlyargs)
                _names = {p.arg for p in _params if _renameable(p.arg)}
                if _names:
                    self._class_own_init_params.setdefault(node.name, set()).update(_names)

        # Base names, Name-only (an Attribute base like "module.Base" is
        # an external class -> its __init__ isn't ours to know about or
        # rename, so it's simply not recorded and that branch stops there.
        self._class_bases[node.name] = [b.id for b in node.bases if isinstance(b, ast.Name)]

        self._in_class += 1
        self._class_body_depth += 1
        self.generic_visit(node)
        self._class_body_depth -= 1
        self._in_class -= 1

    def resolve_class_init_params(self) -> None:
        """
        Call once after .visit(tree) has walked the whole module. For
        every class seen, finds the renameable __init__/__new__
        parameter names that actually apply to "ClassName(...)" (its
        own, if it defines one, else the first one found walking up its
        base-class chain) and merges the result into func_params under the class's own name,
        so _Transformer.visit_Call's lookup (keyed by the call target's
        name) finds it the same way it finds a plain function.
        """
        for _cname in self._class_bases:
            _seen: set = set()
            _cur = _cname
            while _cur is not None and _cur not in _seen:
                _seen.add(_cur)
                _own = self._class_own_init_params.get(_cur)
                if _own:
                    self.func_params.setdefault(_cname, set()).update(_own)
                    break
                _bases = self._class_bases.get(_cur) or []
                _cur = _bases[0] if _bases else None

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Store):
            if self._class_body_depth > 0:
                return
            if self._preserve_toplevel and self._at_toplevel():
                return
            self._reg(node.id)

    def visit_Import(self, node):
        pass   # handled via __import__ obfuscation

    def visit_ImportFrom(self, node):
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Passes 3 & 4 -> Constant encryption helpers
# ─────────────────────────────────────────────────────────────────────────────

def _render_int_ast(n: int, rng: random.Random | None = None, expensive_ok: bool = False) -> ast.expr:
    """
    AST equivalent of gnolly.strcodec._render_int: rather than
    re-implementing every dialect twice, this renders "n" via the exact
    same dialect registry (as source text) and parses that text back
    into a real AST subtree. One source of truth for every dialect
    means the AST-side obfuscation and the stub-generator-side obfuscation
    always stay in sync. A new dialect added
    to strcodec.py is available on both sides automatically.
    """
    text = _strcodec_render_int(n, rng, expensive_ok=expensive_ok)
    return ast.parse(text, mode="eval").body


def _bool_int_ast(n: int, rng: random.Random | None = None) -> ast.expr:
    """AST equivalent of gnolly.strcodec._bool_int_expr (parses that
    function's text output -> see _render_int_ast)."""
    return ast.parse(_bool_int_expr_text(n, rng), mode="eval").body


def _obf_int_lambda_ast(n: int) -> ast.expr:
    """AST equivalent of gnolly.strcodec._obf_int_lambda (parses that
    function's text output -> see _render_int_ast)."""
    return ast.parse(_obf_int_lambda_text(n), mode="eval").body


def _split_int_list_ast(target: list) -> ast.expr:
    """
    AST equivalent of gnolly.strcodec._split_int_list_expr
    (see _render_int_ast -> adjacent numbers in the same list may use
    different dialects), and the two lists are recombined via one of a
    few equally-valid shapes, re-rolled per call.
    """
    if not target:
        return ast.List(elts=[], ctx=ast.Load())
    mask  = [secrets.randbelow(256) for _ in target]
    other = [t ^ m for t, m in zip(target, mask)]
    rng = random.Random(secrets.randbits(64))
    used: set = set()
    pa, pb, va, vb = (random_confusable_name(rng, used, 1) for _ in range(4))

    mask_list  = ast.List(elts=[_render_int_ast(m, rng) for m in mask], ctx=ast.Load())
    other_list = ast.List(elts=[_render_int_ast(o, rng) for o in other], ctx=ast.Load())
    zip_call = ast.Call(func=ast.Name(id="zip", ctx=ast.Load()),
                         args=[mask_list, other_list], keywords=[])
    va_load, vb_load = ast.Name(id=va, ctx=ast.Load()), ast.Name(id=vb, ctx=ast.Load())
    pair_target = ast.Tuple(
        elts=[ast.Name(id=va, ctx=ast.Store()), ast.Name(id=vb, ctx=ast.Store())],
        ctx=ast.Store())

    style = rng.randrange(3)
    if style == 0:
        # (lambda pa, pb: pa ^ pb)(va, vb) inside a zip()-based comprehension
        combine_lam = ast.Lambda(
            args=ast.arguments(
                posonlyargs=[], args=[ast.arg(arg=pa), ast.arg(arg=pb)],
                vararg=None, kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]),
            body=ast.BinOp(left=ast.Name(id=pa, ctx=ast.Load()), op=ast.BitXor(),
                            right=ast.Name(id=pb, ctx=ast.Load())))
        elt = ast.Call(func=combine_lam, args=[va_load, vb_load], keywords=[])
        return ast.ListComp(elt=elt, generators=[
            ast.comprehension(target=pair_target, iter=zip_call, ifs=[], is_async=0)])
    elif style == 1:
        # plain comprehension, no lambda wrapper
        elt = ast.BinOp(left=va_load, op=ast.BitXor(), right=vb_load)
        return ast.ListComp(elt=elt, generators=[
            ast.comprehension(target=pair_target, iter=zip_call, ifs=[], is_async=0)])
    else:
        # list(map(operator.xor, mask, other)) -> module/attr names hidden
        # by building via the text-based helper and parsing it back into
        # an AST subtree (same trick _render_int_ast uses).
        xor_attr = ast.parse(_hidden_import_attr_text("operator", "xor"), mode="eval").body
        map_call = ast.Call(func=ast.Name(id="map", ctx=ast.Load()),
                             args=[xor_attr, mask_list, other_list], keywords=[])
        return ast.Call(func=ast.Name(id="list", ctx=ast.Load()), args=[map_call], keywords=[])


def _make_decoder_def(dec_name: str, key: bytes) -> ast.stmt:
    """
    Builds, as real AST nodes, the per-module string decoder:

        dec_name = lambda L: ''.join(chr(B ^ KEY[I % len(KEY)]) for I, B in enumerate(L))

    KEY is embedded as a plain bytes literal, same as the stub-level
    decoder (gnolly.strcodec._str_decoder_lambda)
    """
    rng = random.Random(secrets.randbits(64))
    used: set = set()
    p_in, p_i, p_b = (random_confusable_name(rng, used, 1) for _ in range(3))
    kl = len(key)

    xor_expr = ast.BinOp(
        left=ast.Name(id=p_b, ctx=ast.Load()), op=ast.BitXor(),
        right=ast.Subscript(
            value=ast.Constant(value=key),
            slice=ast.BinOp(left=ast.Name(id=p_i, ctx=ast.Load()), op=ast.Mod(),
                             right=ast.Constant(value=kl)),
            ctx=ast.Load()))
    chr_call = ast.Call(func=ast.Name(id="chr", ctx=ast.Load()),
                         args=[xor_expr], keywords=[])

    genexp = ast.GeneratorExp(
        elt=chr_call,
        generators=[ast.comprehension(
            target=ast.Tuple(
                elts=[ast.Name(id=p_i, ctx=ast.Store()), ast.Name(id=p_b, ctx=ast.Store())],
                ctx=ast.Store()),
            iter=ast.Call(func=ast.Name(id="enumerate", ctx=ast.Load()),
                          args=[ast.Name(id=p_in, ctx=ast.Load())], keywords=[]),
            ifs=[], is_async=0)])

    join_call = ast.Call(
        func=ast.Attribute(value=ast.Constant(value=""), attr="join", ctx=ast.Load()),
        args=[genexp], keywords=[])

    lam = ast.Lambda(
        args=ast.arguments(posonlyargs=[], args=[ast.arg(arg=p_in)], vararg=None,
                            kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]),
        body=join_call)

    return ast.Assign(targets=[ast.Name(id=dec_name, ctx=ast.Store())], value=lam)


def _enc_str(s: str, key: bytes, dec_getter) -> ast.expr:
    """
    Encode a string as a call to the per-module decoder function
    (dec_getter()), applied to the AST for the split-lambda-comprehension
    representation of its XOR'd ordinals.
    """
    target = [ord(c) ^ key[i % len(key)] for i, c in enumerate(s)]
    list_expr = _split_int_list_ast(target)
    return ast.Call(func=ast.Name(id=dec_getter(), ctx=ast.Load()),
                     args=[list_expr], keywords=[])

def _enc_int(n: int) -> ast.expr:
    """
    Encode an int as one of the exact arithmetic identities below over two
    rendered constants.

        xor    : (n ^ k) ^ k
        add    : (n - k) + k
        muldiv : (n * m) // m          (m != 0, division is exact here)
        shift  : (n << s) >> s         (arithmetic shift round-trips)
    """
    k = secrets.randbelow(0xFFFF) + 1
    rng = random.Random(secrets.randbits(64))
    family = secrets.randbelow(4)
    if family == 0:
        return ast.BinOp(
            left=_render_int_ast(n ^ k, rng, expensive_ok=True),
            op=ast.BitXor(),
            right=_render_int_ast(k, rng, expensive_ok=True))
    if family == 1:
        return ast.BinOp(
            left=_render_int_ast(n - k, rng, expensive_ok=True),
            op=ast.Add(),
            right=_render_int_ast(k, rng, expensive_ok=True))
    if family == 2:
        m = secrets.randbelow(0xFE) + 2
        return ast.BinOp(
            left=_render_int_ast(n * m, rng, expensive_ok=True),
            op=ast.FloorDiv(),
            right=_render_int_ast(m, rng, expensive_ok=True))
    s = secrets.randbelow(12) + 1
    inner = ast.BinOp(
        left=_render_int_ast(n, rng, expensive_ok=True),
        op=ast.LShift(),
        right=_render_int_ast(s, rng, expensive_ok=True))
    return ast.BinOp(
        left=inner,
        op=ast.RShift(),
        right=_render_int_ast(s, rng, expensive_ok=True))

def _enc_float(f: float, key: bytes, dec_getter) -> ast.expr:
    return ast.Call(
        func=ast.Attribute(
            value=ast.Name(id="float", ctx=ast.Load()),
            attr="fromhex", ctx=ast.Load()),
        args=[_enc_str(f.hex(), key, dec_getter)],
        keywords=[])

def _enc_bytes(b: bytes, key: bytes, dec_getter) -> ast.expr:
    """
    Encode bytes the same way as _enc_str, then .encode('latin-1') the
    decoded string back to bytes.
    """
    target = [v ^ key[i % len(key)] for i, v in enumerate(b)]
    list_expr = _split_int_list_ast(target)
    decode_call = ast.Call(func=ast.Name(id=dec_getter(), ctx=ast.Load()),
                            args=[list_expr], keywords=[])
    return ast.Call(
        func=ast.Attribute(value=decode_call, attr="encode", ctx=ast.Load()),
        args=[ast.Constant(value="latin-1")], keywords=[])


# ─────────────────────────────────────────────────────────────────────────────
# Pass 5 -> Import obfuscation
# ─────────────────────────────────────────────────────────────────────────────

def _hidden_import_call_ast(key: bytes, dec_getter) -> ast.expr:
    """
    AST equivalent of gnolly.strcodec._hidden_import_call
    """
    b = "__builtins__"
    i = "__import__"
    builtins_key = _enc_str(b, key, dec_getter)
    import_attr = _enc_str(i, key, dec_getter)
    globals_call = ast.Call(func=ast.Name(id="globals", ctx=ast.Load()), args=[], keywords=[])
    builtins_obj = ast.Subscript(value=globals_call, slice=builtins_key, ctx=ast.Load())

    param = "B"
    param_load = ast.Name(id=param, ctx=ast.Load())
    getattr_branch = ast.Call(func=ast.Name(id="getattr", ctx=ast.Load()),
                               args=[param_load, import_attr], keywords=[])
    subscript_branch = ast.Subscript(value=param_load, slice=import_attr, ctx=ast.Load())
    isinstance_call = ast.Call(func=ast.Name(id="isinstance", ctx=ast.Load()),
                                args=[param_load, ast.Name(id="dict", ctx=ast.Load())], keywords=[])
    body = ast.IfExp(test=ast.UnaryOp(op=ast.Not(), operand=isinstance_call),
                      body=getattr_branch, orelse=subscript_branch)
    lam = ast.Lambda(
        args=ast.arguments(posonlyargs=[], args=[ast.arg(arg=param)], vararg=None,
                            kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[]),
        body=body)
    return ast.Call(func=lam, args=[builtins_obj], keywords=[])


def _obf_import(node: ast.Import, pool: _NamePool, key: bytes, dec_getter) -> list[ast.stmt]:
    stmts = []
    for alias in node.names:
        mod  = alias.name
        bind = alias.asname or mod.split(".")[0]
        target = pool.map.get(bind, bind)
        stmts.append(ast.Assign(
            targets=[ast.Name(id=target, ctx=ast.Store())],
            value=ast.Call(
                func=_hidden_import_call_ast(key, dec_getter),
                args=[_enc_str(mod, key, dec_getter)],
                keywords=[],
            ),
            lineno=node.lineno, col_offset=node.col_offset,
        ))
    return stmts

def _obf_import_from(node: ast.ImportFrom, pool: _NamePool, key: bytes, dec_getter) -> list[ast.stmt]:
    if node.level != 0:           # relative imports: leave alone
        return [node]
    if any(a.name == "*" for a in node.names):
        return [node]

    mod = node.module or ""
    stmts = []
    tmp = pool.fresh()

    stmts.append(ast.Assign(
        targets=[ast.Name(id=tmp, ctx=ast.Store())],
        value=ast.Call(
            func=_hidden_import_call_ast(key, dec_getter),
            args=[_enc_str(mod, key, dec_getter)],
            keywords=[ast.keyword(arg="fromlist",
                                  value=ast.List(
                                      elts=[ast.Constant(value="")],
                                      ctx=ast.Load()))],
        ),
        lineno=node.lineno, col_offset=node.col_offset,
    ))

    for alias in node.names:
        attr = alias.name
        bind = alias.asname or attr
        target = pool.map.get(bind, bind)
        stmts.append(ast.Assign(
            targets=[ast.Name(id=target, ctx=ast.Store())],
            value=ast.Call(
                func=ast.Name(id="getattr", ctx=ast.Load()),
                args=[ast.Name(id=tmp, ctx=ast.Load()), _enc_str(attr, key, dec_getter)],
                keywords=[],
            ),
            lineno=node.lineno, col_offset=node.col_offset,
        ))

    return stmts


# ─────────────────────────────────────────────────────────────────────────────
# Pass 6 -> Control-flow flattening (state-machine dispatch)
# ─────────────────────────────────────────────────────────────────────────────

def _flatten(body: list[ast.stmt], pool: _NamePool, rng: random.Random, bi_getter, enc_fn,
             true_fn=None) -> list[ast.stmt]:
    """
    Flatten a function body into a while-True dispatch loop.
    Skip if body has fewer than 3 stmts or no branching:  not worth it.
    Also skip if body contains a bare Return in a non-tail position
    (those get handled naturally since we emit state transitions before them).
    > There is room for improvemnt here.

    bi_getter: see _noise() -> routes the loop's True through the same
    getattr(builtins, "...") obfuscation as everywhere else.
    """
    has_branch = any(isinstance(s, (ast.If, ast.For, ast.While, ast.Try))
                     for s in body)
    if not has_branch or len(body) < 3:
        return body

    sv = pool.fresh()   # state variable name
    n  = len(body)

    # Crypto-random state values. (non-sequential, harder to read)
    used: set[int] = set()
    states: list[int] = []
    for _ in range(n + 1):
        while True:
            s = (secrets.randbelow(0x6FFF) + 0x1000)
            if s not in used:
                used.add(s); states.append(s); break

    def _transition(next_st: int) -> ast.Assign:
        return ast.Assign(
            targets=[ast.Name(id=sv, ctx=ast.Store())],
            value=ast.Constant(value=next_st),
            lineno=1, col_offset=0)

    # Build elif chain
    root_if: ast.If | None = None
    last_if: ast.If | None = None

    for i, stmt in enumerate(body):
        cur_st  = states[i]
        next_st = states[i + 1]
        is_last = (i == n - 1)

        # Body of this case
        case_body: list[ast.stmt] = [stmt]

        # After terminal stmts (return/raise/break/continue) don't add transition
        if isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
            pass
        elif is_last:
            case_body.append(ast.Break())
        else:
            case_body.append(_transition(next_st))

        branch = ast.If(
            test=ast.Compare(
                left=ast.Name(id=sv, ctx=ast.Load()),
                ops=[ast.Eq()],
                comparators=[ast.Constant(value=cur_st)]),
            body=case_body,
            orelse=[])

        if root_if is None:
            root_if = branch
            last_if = branch
        else:
            last_if.orelse = [branch]   # type: ignore[union-attr]
            last_if = branch

    init   = ast.Assign(
        targets=[ast.Name(id=sv, ctx=ast.Store())],
        value=ast.Constant(value=states[0]),
        lineno=1, col_offset=0)
    if true_fn is not None:
        loop_test = true_fn()
    else:
        loop_test = ast.Call(
            func=ast.Name(id="getattr", ctx=ast.Load()),
            args=[ast.Name(id=bi_getter(), ctx=ast.Load()), enc_fn("True")],
            keywords=[])
    loop   = ast.While(test=loop_test, body=[root_if], orelse=[])

    return [init, loop]


# ─────────────────────────────────────────────────────────────────────────────
# Pass 7 -> Dead code helpers
# ─────────────────────────────────────────────────────────────────────────────
# > Room for improvemnt here
def _empty_args() -> ast.arguments:
    return ast.arguments(posonlyargs=[], args=[], vararg=None, kwonlyargs=[],
                         kw_defaults=[], kwarg=None, defaults=[])


def _dead(bi_getter, enc_fn, true_fn=None, fresh=None) -> ast.stmt:
    """bi_getter: see _noise() -> routes True/False here through the same
    getattr(builtins, "...") obfuscation as everywhere else.

    fresh: optional and when supplied, four extra
    decoy shapes become available. Without it only the
    original four shapes are emitted."""
    def _t(name):
        return ast.Call(
            func=ast.Name(id="getattr", ctx=ast.Load()),
            args=[ast.Name(id=bi_getter(), ctx=ast.Load()), enc_fn(name)],
            keywords=[])
    c = secrets.randbelow(4 if fresh is None else 8)
    if c >= 4:
        if c == 4:
            a, b = secrets.randbelow(0xFFFF), secrets.randbelow(0xFFFF)
            return ast.Assign(
                targets=[ast.Name(id=fresh(), ctx=ast.Store())],
                value=ast.Tuple(elts=[ast.Constant(value=a), ast.Constant(value=b)],
                                ctx=ast.Load()),
                lineno=1, col_offset=0)
        if c == 5:
            return ast.Assign(
                targets=[ast.Name(id=fresh(), ctx=ast.Store())],
                value=ast.Lambda(args=_empty_args(),
                                 body=ast.Constant(value=secrets.randbelow(0xFFFF))),
                lineno=1, col_offset=0)
        if c == 6:
            return ast.For(
                target=ast.Name(id=fresh(), ctx=ast.Store()),
                iter=ast.Tuple(elts=[], ctx=ast.Load()),
                body=[ast.Pass()], orelse=[])
        # c == 7: raise and immediately catch, both classes fetched via builtins
        return ast.Try(
            body=[ast.Raise(exc=_t("ValueError"), cause=None)],
            handlers=[ast.ExceptHandler(type=_t("ValueError"), name=None,
                                        body=[ast.Pass()])],
            orelse=[], finalbody=[])
    if c == 0:
        return ast.While(test=_t("False"), body=[ast.Pass()], orelse=[])
    elif c == 1:
        return ast.Assert(test=(true_fn() if true_fn is not None else _t("True")), msg=None)
    elif c == 2:
        a = secrets.randbelow(0xFF)
        b = secrets.randbelow(0xFF) + 0x100
        return ast.If(
            test=ast.Compare(left=ast.Constant(value=a),
                             ops=[ast.NotEq()],
                             comparators=[ast.Constant(value=b)]),
            body=[ast.Pass()], orelse=[])
    else:
        return ast.Try(
            body=[ast.Pass()],
            handlers=[ast.ExceptHandler(type=None, name=None, body=[ast.Pass()])],
            orelse=[], finalbody=[])


# ─────────────────────────────────────────────────────────────────────────────
# Pass 10 -> Bogus class hierarchies + expression aliasing
# ─────────────────────────────────────────────────────────────────────────────

def _build_hierarchy(pool: _NamePool, rng: random.Random, bi_getter, enc_fn) -> tuple[list[ast.stmt], str, str]:
    """
    Builds a short chain of fake classes (2-4 levels deep, each deriving
    from the previous one), giving each a couple of inert methods and an
    opaque-int class attribute, then instantiate the deepest class once.
    """
    depth = rng.randint(2, 4)
    class_names = [pool.fresh() for _ in range(depth)]
    stmts: list[ast.stmt] = []
    prev: str | None = None

    for cname in class_names:
        bases = [ast.Name(id=prev, ctx=ast.Load())] if prev else []
        body: list[ast.stmt] = []
        for _ in range(rng.randint(1, 2)):
            mname = pool.fresh()
            body.append(ast.FunctionDef(
                name=mname,
                args=ast.arguments(posonlyargs=[], args=[ast.arg(arg="self")],
                                    vararg=None, kwonlyargs=[], kw_defaults=[],
                                    kwarg=None, defaults=[]),
                body=[_dead(bi_getter, enc_fn, fresh=pool.fresh),
                      ast.Return(value=ast.Constant(value=None))],
                decorator_list=[]))
        aname = pool.fresh()
        body.append(ast.Assign(
            targets=[ast.Name(id=aname, ctx=ast.Store())],
            value=_bool_int_ast(secrets.randbelow(0xFFFF) + 1, rng),
            lineno=1, col_offset=0))
        stmts.append(ast.ClassDef(name=cname, bases=bases, keywords=[],
                                   body=body, decorator_list=[]))
        prev = cname

    inst_name = pool.fresh()
    stmts.append(ast.Assign(
        targets=[ast.Name(id=inst_name, ctx=ast.Store())],
        value=ast.Call(func=ast.Name(id=class_names[-1], ctx=ast.Load()),
                        args=[], keywords=[]),
        lineno=1, col_offset=0))
    return stmts, inst_name, class_names[0]


def _class_alias_ast(value: ast.expr, pool: _NamePool, rng: random.Random,
                      base_name: str, label_expr: ast.expr) -> ast.expr:
    """
    Stash an already-computed value as a class attribute for a
    class minted with a type(), deriving from the bogus hierarchy's base code,
    then read it straight back via attribute access.
    """
    attr = pool.fresh()
    ns = ast.Dict(keys=[ast.Constant(value=attr)], values=[value])
    type_call = ast.Call(
        func=ast.Name(id="type", ctx=ast.Load()),
        args=[label_expr,
              ast.Tuple(elts=[ast.Name(id=base_name, ctx=ast.Load())], ctx=ast.Load()),
              ns],
        keywords=[])
    return ast.Attribute(value=type_call, attr=attr, ctx=ast.Load())


def _lambda_alias_ast(value: ast.expr, param: str) -> ast.expr:
    """a value tucked away as a default argument, read back by name"""
    lam = ast.Lambda(
        args=ast.arguments(posonlyargs=[], args=[ast.arg(arg=param)], vararg=None,
                            kwonlyargs=[], kw_defaults=[], kwarg=None, defaults=[value]),
        body=ast.Name(id=param, ctx=ast.Load()))
    return ast.Call(func=lam, args=[], keywords=[])


def _dict_alias_ast(value: ast.expr, decoy: ast.expr, true_expr: ast.expr) -> ast.expr:
    """a value hidden behind a {True: ..., False: ...}[opaque_true] pick."""
    d = ast.Dict(keys=[ast.Constant(value=True), ast.Constant(value=False)],
                 values=[value, decoy])
    return ast.Subscript(value=d, slice=true_expr, ctx=ast.Load())


# ─────────────────────────────────────────────────────────────────────────────
# Pass 9 -> Polymorphic module-level noise
# ─────────────────────────────────────────────────────────────────────────────

def _noise(pool: _NamePool, count: int, bi_getter, enc_fn, true_fn=None) -> list[ast.stmt]:
    """
    bi_getter: zero-arg callable returning the name of the (lazily
    created) local builtins handle -> lets the True/False used here go
    through the same getattr(builtins, "...") obfuscation as every other
    True/False/None in the protected source, instead of leaking as bare
    keyword constants just because this is scaffolding rather than
    user code.
    enc_fn: see _flatten() -> keyed string encoding for "True"/"False".
    """
    stmts: list[ast.stmt] = []
    for _ in range(count):
        tmp = pool.fresh()
        c   = secrets.randbelow(3)
        if c == 0:
            k = secrets.randbelow(0xFFFF) + 1
            v = secrets.randbelow(0xFFFF)
            stmts += [
                ast.Assign(
                    targets=[ast.Name(id=tmp, ctx=ast.Store())],
                    value=ast.BinOp(left=ast.Constant(value=v ^ k),
                                    op=ast.BitXor(),
                                    right=ast.Constant(value=k)),
                    lineno=1, col_offset=0),
                ast.Delete(targets=[ast.Name(id=tmp, ctx=ast.Del())]),
            ]
        elif c == 1:
            if true_fn is not None:
                true_expr = true_fn()
            else:
                true_expr = ast.Call(
                    func=ast.Name(id="getattr", ctx=ast.Load()),
                    args=[ast.Name(id=bi_getter(), ctx=ast.Load()), enc_fn("True")],
                    keywords=[])
            stmts.append(ast.Assert(test=true_expr, msg=None))
        else:
            false_expr = ast.Call(
                func=ast.Name(id="getattr", ctx=ast.Load()),
                args=[ast.Name(id=bi_getter(), ctx=ast.Load()), enc_fn("False")],
                keywords=[])
            stmts.append(ast.If(test=false_expr,
                                body=[ast.Pass()], orelse=[]))
    return stmts


# ─────────────────────────────────────────────────────────────────────────────
# Main transformer (Passes 2–9)
# ─────────────────────────────────────────────────────────────────────────────

class _Transformer(ast.NodeTransformer):
    # Probability that a given Call node's result gets threaded through
    # one more layer of expression-aliasing indirection.
    # This runs on every call site, so values higher will balloon the output size fast for little marginal benefit.
    _ALIAS_CALL_P = 0.08

    def __init__(self, pool: _NamePool,
                 obf_strings, obf_constants, obf_imports,
                 inject_dead, flatten_flow,
                 bogus_hierarchy: bool = True, alias_exprs: bool = True,
                 func_params: dict | None = None):
        self._pool         = pool
        # function original-name -> set of its own renameable parameter
        # original-names, from _Collector's Pass 1 walk.
        self._func_params  = func_params or {}
        self._rng          = random.SystemRandom()
        self._obf_str      = obf_strings
        self._obf_const    = obf_constants
        self._obf_imp      = obf_imports
        self._dead         = inject_dead
        self._flatten      = flatten_flow
        self._bogus_hier   = bogus_hierarchy
        self._alias        = alias_exprs
        self._fstr_depth   = 0
        self._pattern_depth = 0  # track whether we're inside a match-case pattern
        self._class_depth  = 0   # track whether we're inside a class
        self._bi_var       = None  # lazily-created builtins module handle used to obfuscate None/True/False (see _singleton() and visit_Module)
        self._str_key      = secrets.token_bytes(16)  # per-module XOR key for string/bytes encoding
        self._dec_var      = None  # lazily-created per-module string decoder function (see _dec()/_enc() and visit_Module)
        self._hier_stmts   = None  # lazily-built bogus class hierarchy (see _hier())
        self._hier_names   = None  # (instance_name, base_class_name) once built

    def _bi(self) -> str:
        """Name of the (lazily created) local builtins module handle."""
        if self._bi_var is None:
            self._bi_var = self._pool.fresh()
        return self._bi_var

    def _dec(self) -> str:
        """Name of the (lazily created) per-module string decoder function."""
        if self._dec_var is None:
            self._dec_var = self._pool.fresh()
        return self._dec_var

    def _enc(self, s: str) -> ast.expr:
        """Encode a string the same keyed way as _enc_str, bound to this
        transformer's own key/decoder."""
        return _enc_str(s, self._str_key, self._dec)

    def _hier(self) -> tuple[str, str]:
        """Lazily build the module's bogus class hierarchy and return (instance_name, base_class_name)."""
        if self._hier_names is None:
            stmts, inst_name, base_name = _build_hierarchy(
                self._pool, self._rng, self._bi, self._enc)
            self._hier_stmts = stmts
            self._hier_names = (inst_name, base_name)
        return self._hier_names

    def _true_expr(self) -> ast.expr:
        """A syntactically-varied, semantically-guaranteed-True expression.
        This diversifies the "opaque true" token used across _flatten's loop
        guard, _dead's assert, and _noise -> instead of one fixed
        getattr(builtins, "True") shape repeating identically at every
        site."""
        styles = [0, 2]
        if self._bogus_hier:
            styles.append(1)
        style = self._rng.choice(styles)
        if style == 0:
            return ast.Call(
                func=ast.Name(id="getattr", ctx=ast.Load()),
                args=[ast.Name(id=self._bi(), ctx=ast.Load()), self._enc("True")],
                keywords=[])
        elif style == 1:
            inst, base = self._hier()
            return ast.Call(
                func=ast.Name(id="isinstance", ctx=ast.Load()),
                args=[ast.Name(id=inst, ctx=ast.Load()), ast.Name(id=base, ctx=ast.Load())],
                keywords=[])
        else:
            n = secrets.randbelow(0xFFFF) + 1
            left  = _render_int_ast(n, self._rng, expensive_ok=True)
            right = _render_int_ast(n, self._rng, expensive_ok=True)
            return ast.Compare(left=left, ops=[ast.Eq()], comparators=[right])

    def _alias_wrap(self, node: ast.expr) -> ast.expr:
        """Thread an already-transformed expression through one more
        layer of indirection, chosen at random."""
        styles = [1, 2, 3, 4]
        if self._bogus_hier:
            styles.append(0)
        style = self._rng.choice(styles)
        if style == 0:
            _, base = self._hier()
            label = self._enc(self._pool.fresh())
            wrapped = _class_alias_ast(node, self._pool, self._rng, base, label)
        elif style == 1:
            p = self._pool.fresh()
            wrapped = _lambda_alias_ast(node, p)
        elif style == 2:
            decoy = _bool_int_ast(secrets.randbelow(0xFFFF) + 1, self._rng)
            wrapped = _dict_alias_ast(node, decoy, self._true_expr())
        elif style == 3:
            decoy = _bool_int_ast(secrets.randbelow(0xFFFF) + 1, self._rng)
            wrapped = ast.Subscript(
                value=ast.Tuple(elts=[decoy, node], ctx=ast.Load()),
                slice=self._true_expr(), ctx=ast.Load())
        else:
            decoy = _bool_int_ast(secrets.randbelow(0xFFFF) + 1, self._rng)
            wrapped = ast.IfExp(test=self._true_expr(), body=node, orelse=decoy)
        return ast.copy_location(wrapped, node)

    def _singleton(self, name: str, node: ast.AST) -> ast.expr:
        return ast.copy_location(
            ast.Call(
                func=ast.Name(id="getattr", ctx=ast.Load()),
                args=[ast.Name(id=self._bi(), ctx=ast.Load()), self._enc(name)],
                keywords=[]),
            node)

    def _strip_doc(self, body):
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)):
            return body[1:]
        return body

    def _scatter_dead(self, body):
        if not self._dead or len(body) < 2:
            return body
        out = []
        for stmt in body:
            out.append(stmt)
            if self._rng.random() < 0.35:
                out.append(_dead(self._bi, self._enc, true_fn=self._true_expr,
                                 fresh=self._pool.fresh))
        return out

    # Module
    def visit_Module(self, node):
        node.body = self._strip_doc(node.body)
        self.generic_visit(node)
        cnt = self._rng.randint(2, 5)
        noise_stmts = _noise(self._pool, cnt, self._bi, self._enc, true_fn=self._true_expr)
        preamble = []
        if self._dec_var is not None:
            preamble.append(_make_decoder_def(self._dec_var, self._str_key))
        if self._bi_var is not None:
            preamble.append(ast.Assign(
                targets=[ast.Name(id=self._bi_var, ctx=ast.Store())],
                value=ast.Call(
                    func=_hidden_import_call_ast(self._str_key, self._dec),
                    args=[self._enc("builtins")], keywords=[])))

        if self._hier_stmts is not None:
            preamble.extend(self._hier_stmts)
        node.body = preamble + noise_stmts + node.body
        return node

    # Classes -> increment depth so method names aren't registered
    def visit_ClassDef(self, node):
        node.name = self._pool.map.get(node.name, node.name)
        node.body = self._strip_doc(node.body)
        self._class_depth += 1
        self.generic_visit(node)
        self._class_depth -= 1
        return node

    # Functions
    def visit_FunctionDef(self, node):
        # Only rename if NOT a method (not inside a class body)
        if self._class_depth == 0:
            node.name = self._pool.map.get(node.name, node.name)
        node.body = self._strip_doc(node.body)
        self.generic_visit(node)
        if self._flatten:
            node.body = _flatten(node.body, self._pool, self._rng, self._bi, self._enc,
                                  true_fn=self._true_expr)
        node.body = self._scatter_dead(node.body)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    # Calls -> keyword-argument matching + expression aliasing (Pass 10). 
    # Keywords are handled directly here, not via a standalone visit_keyword, 
    # because deciding whether a given keyword's name is safe to rename is a property of the ENCLOSING
    # call, not of the keyword node in isolation.
    def visit_Call(self, node):
        # Capture the call target's ORIGINAL (pre-rename) name before
        # anything below renames node.func, so it can be looked up in
        # _func_params, which is keyed by original names from Pass 1.
        orig_func_name = node.func.id if isinstance(node.func, ast.Name) else None
        eligible = self._func_params.get(orig_func_name) if orig_func_name else None

        node.func = self.visit(node.func)
        node.args = [self.visit(a) for a in node.args]
        for kw in node.keywords:
            if kw.arg is not None and eligible is not None \
                    and kw.arg in eligible and _renameable(kw.arg):
                kw.arg = self._pool.get(kw.arg)
            kw.value = self.visit(kw.value)

        if self._alias and self._rng.random() < self._ALIAS_CALL_P:
            return self._alias_wrap(node)
        return node

    # Names
    def visit_Name(self, node):
        node.id = self._pool.map.get(node.id, node.id)
        return node

    def visit_arg(self, node):
        if _renameable(node.arg):
            node.arg = self._pool.get(node.arg)
        return node

    def visit_Attribute(self, node):
        node.value = self.visit(node.value)
        return node   # .attr never renamed

    def visit_Global(self, node):
        node.names = [self._pool.map.get(n, n) for n in node.names]
        return node

    def visit_Nonlocal(self, node):
        node.names = [self._pool.map.get(n, n) for n in node.names]
        return node

    # Imports
    def visit_Import(self, node):
        if not self._obf_imp:
            return node
        return _obf_import(node, self._pool, self._str_key, self._dec)

    def visit_ImportFrom(self, node):
        if not self._obf_imp:
            return node
        return _obf_import_from(node, self._pool, self._str_key, self._dec)

    # f-strings -> don't touch embedded constants
    def visit_JoinedStr(self, node):
        self._fstr_depth += 1
        self.generic_visit(node)
        self._fstr_depth -= 1
        return node

    # match/case -> pattern literals (case 1:, case {"k": 2}, case Point(x=0),
    # etc.) must stay literal per the grammar. Rewriting an int/float/bytes
    # literal into a BinOp/Call inside a pattern produces invalid syntax.
    # So constants are left untouched anywhere inside a pattern while the
    # subject expression, guard, and case bodies are still obfuscated
    # normally.
    def visit_Match(self, node):
        node.subject = self.visit(node.subject)
        for case in node.cases:
            self._pattern_depth += 1
            case.pattern = self.visit(case.pattern)
            self._pattern_depth -= 1
            if case.guard is not None:
                case.guard = self.visit(case.guard)
            case.body = [self.visit(stmt) for stmt in case.body]
            if self._flatten:
                case.body = _flatten(case.body, self._pool, self._rng, self._bi, self._enc,
                                      true_fn=self._true_expr)
            case.body = self._scatter_dead(case.body)
        return node

    # Constants
    def visit_Constant(self, node):
        if self._fstr_depth > 0 or self._pattern_depth > 0:
            return node
        v = node.value
        if isinstance(v, str) and self._obf_str and v:
            try:    return ast.copy_location(self._enc(v), node)
            except: return node
        if isinstance(v, bool):
            if self._obf_const:
                return self._singleton("True" if v else "False", node)
            return node
        if v is None:
            if self._obf_const:
                return self._singleton("None", node)
            return node
        if isinstance(v, int) and self._obf_const and abs(v) <= 0xFFFFFF:
            return ast.copy_location(_enc_int(v), node)
        if isinstance(v, float) and self._obf_const and abs(v) < 1e12:
            return ast.copy_location(_enc_float(v, self._str_key, self._dec), node)
        if isinstance(v, bytes) and self._obf_const and v:
            return ast.copy_location(_enc_bytes(v, self._str_key, self._dec), node)
        return node


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def obfuscate_source(
    source: str,
    obf_strings:   bool = True,
    obf_constants: bool = True,
    obf_imports:   bool = True,
    inject_dead:   bool = True,
    flatten_flow:  bool = True,
    preserve_toplevel: bool = False,
    bogus_hierarchy: bool = True,
    alias_exprs:   bool = True,
) -> str:
    """
    Apply all obfuscation passes to source.
    Returns valid Python source that compiles and executes identically to the original.

    preserve_toplevel : when True, names bound directly at module scope are
        never renamed -> required for module_mode (see gnolly.package /
        gnolly.wheel), where these names are the public API a real importer
        does `from mod import name` against. (one shouldn't have to do from abcd... instead of from mod...)
    bogus_hierarchy : toggle Pass 10's fake inherited class hierarchy,
        used both as a standalone decoy and as an extra always-True
        source pattern.
    alias_exprs     : toggle Pass 10's expression aliasing -> call results
        get randomly threaded through one or more extra layer(s) of indirection.
    """
    tree = ast.parse(source)

    pool = _NamePool()
    collector = _Collector(pool, preserve_toplevel=preserve_toplevel)
    collector.visit(tree)
    collector.resolve_class_init_params()

    xfm = _Transformer(pool,
                        obf_strings, obf_constants, obf_imports,
                        inject_dead, flatten_flow,
                        bogus_hierarchy=bogus_hierarchy, alias_exprs=alias_exprs,
                        func_params=collector.func_params)
    new_tree = xfm.visit(tree)
    ast.fix_missing_locations(new_tree)
    return ast.unparse(new_tree)
