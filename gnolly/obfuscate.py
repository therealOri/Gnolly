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

What is and isn't renamed
--------------------------
RENAMED:   module-level functions, classes, local variables
NOT RENAMED: method names (accessed via .attr -> can't know the type),
             function parameters (keyword call compatibility),
             import names/aliases (obfuscated via __import__ instead),
             __dunder__ names, builtins

Random policy
--------------
random.Random(seed) — deterministic structural choices (flatten state values
                       order, dead-code injection positions) so --seed N gives
                       reproducible output.
secrets             — all actual embedded numeric values (XOR keys, state
                       numbers, noise constants) use crypto-random every run.
"""
from __future__ import annotations
import ast
import random
import secrets
from .namegen import random_confusable_name


# ─────────────────────────────────────────────────────────────────────────────
# Name generation -> random, collision-checked, confusable identifiers
# (see gnolly.namegen for the character set and rationale)
# ─────────────────────────────────────────────────────────────────────────────

_NAME_LEN = 12


class _NamePool:
    def __init__(self, seed: int = 0):
        self._rng = random.Random(seed)
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
    def __init__(self, pool: _NamePool):
        self._pool = pool
        self._in_class = 0   # depth (inside a class body, skip method names)

    def _reg(self, name: str):
        if _renameable(name):
            self._pool.get(name)

    def visit_FunctionDef(self, node):
        # Register function name only if NOT inside a class body
        if self._in_class == 0:
            self._reg(node.name)
        # Always recurse into body (but at class depth 0 for nested functions)
        self.generic_visit(node)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self._reg(node.name)
        self._in_class += 1
        self.generic_visit(node)
        self._in_class -= 1

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Store):
            self._reg(node.id)

    def visit_Import(self, node):
        pass   # handled via __import__ obfuscation

    def visit_ImportFrom(self, node):
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Passes 3 & 4 -> Constant encryption helpers
# ─────────────────────────────────────────────────────────────────────────────

def _enc_str(s: str) -> ast.expr:
    hex_s = s.encode("utf-8").hex()
    # Polymorphic: alternate between bytes and bytearray
    use_bytes = secrets.randbelow(2) == 0
    obj_name  = "bytes" if use_bytes else "bytearray"
    decode_args = [ast.Constant(value="utf-8")] if use_bytes else []
    return ast.Call(
        func=ast.Attribute(
            value=ast.Call(
                func=ast.Attribute(
                    value=ast.Name(id=obj_name, ctx=ast.Load()),
                    attr="fromhex", ctx=ast.Load()),
                args=[ast.Constant(value=hex_s)], keywords=[]),
            attr="decode", ctx=ast.Load()),
        args=decode_args, keywords=[])

def _enc_int(n: int) -> ast.expr:
    k = secrets.randbelow(0xFFFF) + 1
    return ast.BinOp(
        left=ast.Constant(value=n ^ k),
        op=ast.BitXor(),
        right=ast.Constant(value=k))

def _enc_float(f: float) -> ast.expr:
    return ast.Call(
        func=ast.Attribute(
            value=ast.Name(id="float", ctx=ast.Load()),
            attr="fromhex", ctx=ast.Load()),
        args=[_enc_str(f.hex())],
        keywords=[])

def _enc_bytes(b: bytes) -> ast.expr:
    return ast.Call(
        func=ast.Attribute(
            value=ast.Name(id="bytes", ctx=ast.Load()),
            attr="fromhex", ctx=ast.Load()),
        args=[ast.Constant(value=b.hex())], keywords=[])


# ─────────────────────────────────────────────────────────────────────────────
# Pass 5 -> Import obfuscation
# ─────────────────────────────────────────────────────────────────────────────

def _hex_str_node(s: str) -> ast.expr:
    """bytes.fromhex(hex).decode() -> hides the string literal."""
    return ast.Call(
        func=ast.Attribute(
            value=ast.Call(
                func=ast.Attribute(
                    value=ast.Name(id="bytes", ctx=ast.Load()),
                    attr="fromhex", ctx=ast.Load()),
                args=[ast.Constant(value=s.encode().hex())], keywords=[]),
            attr="decode", ctx=ast.Load()),
        args=[], keywords=[])

def _obf_import(node: ast.Import, pool: _NamePool) -> list[ast.stmt]:
    stmts = []
    for alias in node.names:
        mod  = alias.name
        bind = alias.asname or mod.split(".")[0]
        target = pool.map.get(bind, bind)
        stmts.append(ast.Assign(
            targets=[ast.Name(id=target, ctx=ast.Store())],
            value=ast.Call(
                func=ast.Name(id="__import__", ctx=ast.Load()),
                args=[_hex_str_node(mod)],
                keywords=[],
            ),
            lineno=node.lineno, col_offset=node.col_offset,
        ))
    return stmts

def _obf_import_from(node: ast.ImportFrom, pool: _NamePool) -> list[ast.stmt]:
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
            func=ast.Name(id="__import__", ctx=ast.Load()),
            args=[_hex_str_node(mod)],
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
                args=[ast.Name(id=tmp, ctx=ast.Load()), _hex_str_node(attr)],
                keywords=[],
            ),
            lineno=node.lineno, col_offset=node.col_offset,
        ))

    return stmts


# ─────────────────────────────────────────────────────────────────────────────
# Pass 6 -> Control-flow flattening (state-machine dispatch)
# ─────────────────────────────────────────────────────────────────────────────

def _flatten(body: list[ast.stmt], pool: _NamePool, rng: random.Random, bi_getter) -> list[ast.stmt]:
    """
    Flatten a function body into a while-True dispatch loop.
    Skip if body has fewer than 3 stmts or no branching:  not worth it.
    Also skip if body contains a bare Return in a non-tail position
    (those get handled naturally since we emit state transitions before them).
    There is room for improvemnt here.

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
    loop   = ast.While(
        test=ast.Call(
            func=ast.Name(id="getattr", ctx=ast.Load()),
            args=[ast.Name(id=bi_getter(), ctx=ast.Load()), _enc_str("True")],
            keywords=[]),
        body=[root_if],
        orelse=[])

    return [init, loop]


# ─────────────────────────────────────────────────────────────────────────────
# Pass 7 -> Dead code helpers
# ─────────────────────────────────────────────────────────────────────────────
# > Room for improvemnt here
def _dead(bi_getter) -> ast.stmt:
    """bi_getter: see _noise() -> routes True/False here through the same
    getattr(builtins, "...") obfuscation as everywhere else."""
    def _t(name):
        return ast.Call(
            func=ast.Name(id="getattr", ctx=ast.Load()),
            args=[ast.Name(id=bi_getter(), ctx=ast.Load()), _enc_str(name)],
            keywords=[])
    c = secrets.randbelow(4)
    if c == 0:
        return ast.While(test=_t("False"), body=[ast.Pass()], orelse=[])
    elif c == 1:
        return ast.Assert(test=_t("True"), msg=None)
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
# Pass 9 -> Polymorphic module-level noise
# ─────────────────────────────────────────────────────────────────────────────

def _noise(pool: _NamePool, count: int, bi_getter) -> list[ast.stmt]:
    """
    bi_getter: zero-arg callable returning the name of the (lazily
    created) local builtins handle -> lets the True/False used here go
    through the same getattr(builtins, "...") obfuscation as every other
    True/False/None in the protected source, instead of leaking as bare
    keyword constants just because this is scaffolding rather than
    user code.
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
            true_expr = ast.Call(
                func=ast.Name(id="getattr", ctx=ast.Load()),
                args=[ast.Name(id=bi_getter(), ctx=ast.Load()), _enc_str("True")],
                keywords=[])
            stmts.append(ast.Assert(test=true_expr, msg=None))
        else:
            false_expr = ast.Call(
                func=ast.Name(id="getattr", ctx=ast.Load()),
                args=[ast.Name(id=bi_getter(), ctx=ast.Load()), _enc_str("False")],
                keywords=[])
            stmts.append(ast.If(test=false_expr,
                                body=[ast.Pass()], orelse=[]))
    return stmts


# ─────────────────────────────────────────────────────────────────────────────
# Main transformer (Passes 2–9)
# ─────────────────────────────────────────────────────────────────────────────

class _Transformer(ast.NodeTransformer):
    def __init__(self, pool: _NamePool, seed: int,
                 obf_strings, obf_constants, obf_imports,
                 inject_dead, flatten_flow):
        self._pool         = pool
        self._rng          = random.Random(seed)
        self._obf_str      = obf_strings
        self._obf_const    = obf_constants
        self._obf_imp      = obf_imports
        self._dead         = inject_dead
        self._flatten      = flatten_flow
        self._fstr_depth   = 0
        self._pattern_depth = 0  # track whether we're inside a match-case pattern
        self._class_depth  = 0   # track whether we're inside a class
        self._bi_var       = None  # lazily-created builtins module handle used to obfuscate None/True/False (see _singleton() and visit_Module)

    def _bi(self) -> str:
        """Name of the (lazily created) local builtins module handle."""
        if self._bi_var is None:
            self._bi_var = self._pool.fresh()
        return self._bi_var

    def _singleton(self, name: str, node: ast.AST) -> ast.expr:
        return ast.copy_location(
            ast.Call(
                func=ast.Name(id="getattr", ctx=ast.Load()),
                args=[ast.Name(id=self._bi(), ctx=ast.Load()), _enc_str(name)],
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
                out.append(_dead(self._bi))
        return out

    # Module
    def visit_Module(self, node):
        node.body = self._strip_doc(node.body)
        self.generic_visit(node)
        cnt = self._rng.randint(2, 5)
        noise_stmts = _noise(self._pool, cnt, self._bi)
        preamble = []
        if self._bi_var is not None:
            preamble.append(ast.Assign(
                targets=[ast.Name(id=self._bi_var, ctx=ast.Store())],
                value=ast.Call(
                    func=ast.Name(id="__import__", ctx=ast.Load()),
                    args=[_enc_str("builtins")], keywords=[])))
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
            node.body = _flatten(node.body, self._pool, self._rng, self._bi)
        node.body = self._scatter_dead(node.body)
        return node

    visit_AsyncFunctionDef = visit_FunctionDef

    # Names
    def visit_Name(self, node):
        node.id = self._pool.map.get(node.id, node.id)
        return node

    def visit_arg(self, node):
        if _renameable(node.arg):
            node.arg = self._pool.get(node.arg)
        return node

    def visit_keyword(self, node):
        # Companion to the visit_arg above: if f's parameter "p" got
        # renamed (because "p" collided with some unrelated name
        # elsewhere), a call like "f(p=1)" needs its keyword name renamed
        # the exact same way, or the call breaks with an unexpected-
        # keyword-argument error.
        if node.arg is not None and _renameable(node.arg):
            node.arg = self._pool.get(node.arg)
        node.value = self.visit(node.value)
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
        return _obf_import(node, self._pool)

    def visit_ImportFrom(self, node):
        if not self._obf_imp:
            return node
        return _obf_import_from(node, self._pool)

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
                case.body = _flatten(case.body, self._pool, self._rng, self._bi)
            case.body = self._scatter_dead(case.body)
        return node

    # Constants
    def visit_Constant(self, node):
        if self._fstr_depth > 0 or self._pattern_depth > 0:
            return node
        v = node.value
        if isinstance(v, str) and self._obf_str and v:
            try:    return ast.copy_location(_enc_str(v), node)
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
            return ast.copy_location(_enc_float(v), node)
        if isinstance(v, bytes) and self._obf_const and v:
            return ast.copy_location(_enc_bytes(v), node)
        return node


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def obfuscate_source(
    source: str,
    seed: int = 0,
    obf_strings:   bool = True,
    obf_constants: bool = True,
    obf_imports:   bool = True,
    inject_dead:   bool = True,
    flatten_flow:  bool = True,
) -> str:
    """
    Apply all obfuscation passes to source.
    Returns valid Python source that compiles and executes identically to the original.
    """
    tree = ast.parse(source)

    pool = _NamePool(seed=seed)
    _Collector(pool).visit(tree)

    xfm = _Transformer(pool, seed,
                        obf_strings, obf_constants, obf_imports,
                        inject_dead, flatten_flow)
    new_tree = xfm.visit(tree)
    ast.fix_missing_locations(new_tree)
    return ast.unparse(new_tree)
