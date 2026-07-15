"""
gnolly.vm_translate
~~~~~~~~~~~~~~~~~~~~

Translates a CPython 3.14 code object (after AST obfuscation) into a gnolly.vm_serialize.GIRCode tree.

This is a mechanical, mostly-1:1 pass: GIR opcodes were chosen
specifically to mirror CPython 3.11-3.14 stack-machine semantics for the
operations we support, so the translator's job is mostly renaming and
"de-specialising" super-instructions, plus a few structural rewrites:

  * Jump operands (byte offsets) -> GIR instruction indices.
  * KW_NAMES + CALL  ->  LOAD_CONST + CALL_KW  (unifies the 3.12 and
    3.13+ keyword-call conventions into one GIR form).
  * MAKE_FUNCTION with the legacy flags-on-stack convention (3.11/3.12)
    -> MAKE_FUNCTION(0) + a sequence of SET_FUNCTION_ATTRIBUTE (the
    3.13+ convention, which GIR always uses).
  * LOAD_DEREF / STORE_DEREF / DELETE_DEREF / LOAD_CLOSURE /
    LOAD_FROM_DICT_OR_DEREF are re-indexed by name into Gnolly's own
    cellvars+freevars ordering, independent of CPython's internal
    unified fast-locals numbering (which has changed across versions).
  * EXTENDED_ARG, MAKE_CELL and COPY_FREE_VARS are dropped -> GIR uses
    varint operands (no EXTENDED_ARG needed) and the interpreter sets up
    cells for every cell/free variable automatically when a frame is
    created.
  * FORMAT_VALUE (3.11/3.12) is split into CONVERT_VALUE +
    FORMAT_SIMPLE/FORMAT_WITH_SPEC (the 3.13+/3.14 convention).

Unsupported constructs raise VMUnsupportedError. The pipeline catches
this and raises an error -> see gnolly.pipeline.
"""
from __future__ import annotations
import dis
import secrets
import types

from .vm_isa import GIR_OPS, CMP_OPS as _CMP_OPS
from .vm_serialize import GIRCode, CO_VARARGS, CO_VARKEYWORDS, CO_NESTED, CO_HAS_FREE


class VMUnsupportedError(Exception):
    """Raised when a code object uses a construct the GIR VM cannot represent."""


_UNSUPPORTED_OPS = frozenset([
    # deprecated / specialised
    "JUMP_IF_TRUE_OR_POP", "JUMP_IF_FALSE_OR_POP",
    "DELETE_FAST_RANGE",
])

# CO_FLAGS masks that indicate generator / coroutine / async-generator functions.
_CO_GENERATOR  = 0x20
_CO_COROUTINE  = 0x80
_CO_ASYNC_GEN  = 0x200


# ---------------------------------------------------------------------------
# Junk opcode injection
# ---------------------------------------------------------------------------
# Real GIR-level junk, distinct from the AST-level dead code obfuscate.py
# already injects before compilation. This operates directly on the
# translated instruction stream, in two ways:
#
#   1. "Dead zone" filler, placed immediately after instructions that
#      unconditionally end a control-flow path (return, unconditional
#      jump, raise/reraise). The interpreter never falls through past
#      any of these -> return/raise unconditionally exit run_frame, and
#      an unconditional jump overwrites the instruction pointer outright
#      -> so this filler can genuinely never execute, and can be as
#      liberal as we like (NOPs or junk blocks) with zero runtime cost.
#
#   2. Reachable junk, interspersed between ordinary instructions at a
#      low, randomised rate. This DOES execute for real on every run, so
#      it's deliberately built from operations that can be proven safe
#      without knowing the exact stack contents at that point: every
#      variant only ever pushes a value it just created itself (a fresh
#      constant, or an empty/one-item container built from nothing) and
#      immediately discards it with POP_TOP. None of them read, in any
#      way, whatever was already on the stack -> so correctness doesn't
#      depend on tracking stack depth at each injection point, only on
#      each block's own net stack effect being exactly zero, which is
#      true by construction for all six shapes below.
#
# Junk instructions are emitted via ctx.emit() only, never ctx.mark() ->
# they get no entry in offset_to_index, so they're invisible to jump
# target and exception table resolution. The next real instruction's own
# ctx.mark() call naturally records its position *after* any injected
# junk, so every existing jump/exception-range computation stays correct
# without any special-casing.
#
# Both injection rates are intentionally well under 100% and the exact
# shape used is randomised -> a uniform "there's always a junk block
# between every two real instructions" pattern would itself be a trivial
# signature to filter out programmatically. Varying both whether and what
# means there's no single fixed pattern to strip.

_TERMINAL_OPS = frozenset([
    "RETURN_VALUE", "RETURN_CONST",
    "JUMP", "JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_BACKWARD_NO_INTERRUPT",
    "RAISE_VARARGS", "RERAISE",
])

_JUNK_REACHABLE_RATE = 0.15    # chance of injecting after any given real instruction
_JUNK_DEADZONE_RATE  = 0.55    # chance of injecting after a terminal instruction
_JUNK_DEADZONE_MAX   = 5       # max chained junk blocks in one dead zone


def _junk_const():
    """A small throwaway constant, added fresh to the pool -> only ever
    pushed by injected junk and immediately discarded again, never
    observed by any real instruction."""
    c = secrets.randbelow(4)
    if c == 0:
        return secrets.randbelow(2_000_000) - 1_000_000
    elif c == 1:
        return secrets.token_hex(secrets.randbelow(6) + 2)
    elif c == 2:
        return secrets.token_bytes(secrets.randbelow(6) + 2)
    else:
        return round(secrets.randbelow(2_000_000) / 997.0, 4)


def _emit_junk_block(ctx):
    """
    Emit one net-zero-stack-effect, side-effect-free instruction sequence.
    Every shape only pushes values it just created and immediately pops
    them -> never reads pre-existing stack content, so it's safe
    regardless of the actual stack depth/contents at this point.
    """
    shape = secrets.randbelow(6)
    if shape == 0:
        ctx.emit("BUILD_TUPLE", 0); ctx.emit("POP_TOP")
    elif shape == 1:
        ctx.emit("BUILD_LIST", 0); ctx.emit("POP_TOP")
    elif shape == 2:
        ctx.emit("BUILD_MAP", 0); ctx.emit("POP_TOP")
    elif shape == 3:
        idx = len(ctx.consts); ctx.consts.append(_junk_const())
        ctx.emit("LOAD_CONST", idx); ctx.emit("POP_TOP")
    elif shape == 4:
        i1 = len(ctx.consts); ctx.consts.append(_junk_const())
        i2 = len(ctx.consts); ctx.consts.append(_junk_const())
        ctx.emit("LOAD_CONST", i1); ctx.emit("LOAD_CONST", i2)
        ctx.emit("BUILD_TUPLE", 2); ctx.emit("POP_TOP")
    else:
        idx = len(ctx.consts); ctx.consts.append(_junk_const())
        ctx.emit("LOAD_CONST", idx)
        ctx.emit("BUILD_LIST", 1); ctx.emit("POP_TOP")


def _maybe_inject_reachable(ctx):
    if secrets.randbelow(1000) < int(_JUNK_REACHABLE_RATE * 1000):
        _emit_junk_block(ctx)


def _maybe_inject_deadzone(ctx):
    if secrets.randbelow(1000) < int(_JUNK_DEADZONE_RATE * 1000):
        n = secrets.randbelow(_JUNK_DEADZONE_MAX) + 1
        for _ in range(n):
            if secrets.randbelow(3) == 0:
                ctx.emit("NOP")
            else:
                _emit_junk_block(ctx)



_ARG_PASSTHROUGH = {
    "COPY": "COPY",
    "SWAP": "SWAP",
    "LOAD_CONST": "LOAD_CONST",
    "RETURN_CONST": "RETURN_CONST",
    "STORE_FAST": "STORE_FAST",
    "DELETE_FAST": "DELETE_FAST",
    "LOAD_FAST": "LOAD_FAST",
    "LOAD_FAST_CHECK": "LOAD_FAST",
    "LOAD_FAST_BORROW": "LOAD_FAST",
    "LOAD_FAST_AND_CLEAR": "LOAD_FAST_AND_CLEAR",
    "LOAD_GLOBAL": "LOAD_GLOBAL",
    "STORE_GLOBAL": "STORE_GLOBAL",
    "DELETE_GLOBAL": "DELETE_GLOBAL",
    "LOAD_NAME": "LOAD_NAME",
    "STORE_NAME": "STORE_NAME",
    "DELETE_NAME": "DELETE_NAME",
    "LOAD_ATTR": "LOAD_ATTR",
    "STORE_ATTR": "STORE_ATTR",
    "DELETE_ATTR": "DELETE_ATTR",
    "LOAD_SUPER_ATTR": "LOAD_SUPER_ATTR",
    "MATCH_CLASS": "MATCH_CLASS",
    "LOAD_FROM_DICT_OR_GLOBALS": "LOAD_FROM_DICT_OR_GLOBALS",
    "BUILD_TUPLE": "BUILD_TUPLE",
    "BUILD_LIST": "BUILD_LIST",
    "BUILD_SET": "BUILD_SET",
    "BUILD_MAP": "BUILD_MAP",
    "BUILD_STRING": "BUILD_STRING",
    "BUILD_SLICE": "BUILD_SLICE",
    "LIST_APPEND": "LIST_APPEND",
    "SET_ADD": "SET_ADD",
    "MAP_ADD": "MAP_ADD",
    "LIST_EXTEND": "LIST_EXTEND",
    "SET_UPDATE": "SET_UPDATE",
    "DICT_UPDATE": "DICT_UPDATE",
    "DICT_MERGE": "DICT_MERGE",
    "UNPACK_SEQUENCE": "UNPACK_SEQUENCE",
    "UNPACK_EX": "UNPACK_EX",
    "BINARY_OP": "BINARY_OP",
    "COMPARE_OP": "COMPARE_OP",
    "IS_OP": "IS_OP",
    "CONTAINS_OP": "CONTAINS_OP",
    "IMPORT_NAME": "IMPORT_NAME",
    "IMPORT_FROM": "IMPORT_FROM",
    "RAISE_VARARGS": "RAISE_VARARGS",
    "RERAISE": "RERAISE",
    "CHECK_EXC_MATCH": "CHECK_EXC_MATCH",
    "CALL": "CALL",
    "CALL_KW": "CALL_KW",
    "CALL_FUNCTION_EX": "CALL_FUNCTION_EX",
    "CONVERT_VALUE": "CONVERT_VALUE",
    "FORMAT_SIMPLE": "FORMAT_SIMPLE",
    "FORMAT_WITH_SPEC": "FORMAT_WITH_SPEC",
    "SET_FUNCTION_ATTRIBUTE": "SET_FUNCTION_ATTRIBUTE",
    "RESUME": "RESUME",
    "YIELD_VALUE": "YIELD_VALUE",
    "GET_AWAITABLE": "GET_AWAITABLE",
    "CALL_INTRINSIC_1": "CALL_INTRINSIC_1",
    "CALL_INTRINSIC_2": "CALL_INTRINSIC_2",
}

_DIRECT = {
    "NOP": "NOP",
    "RESUME_CHECK": "RESUME",
    "POP_TOP": "POP_TOP",
    "END_FOR": "POP_TOP",
    "PUSH_NULL": "PUSH_NULL",
    "RETURN_VALUE": "RETURN_VALUE",
    "GET_ITER": "GET_ITER",
    "LOAD_BUILD_CLASS": "LOAD_BUILD_CLASS",
    "UNARY_NOT": "UNARY_NOT",
    "UNARY_NEGATIVE": "UNARY_NEGATIVE",
    "UNARY_INVERT": "UNARY_INVERT",
    "BINARY_SUBSCR": "LOAD_SUBSCR",
    "STORE_SUBSCR": "STORE_SUBSCR",
    "DELETE_SUBSCR": "DELETE_SUBSCR",
    "BINARY_SLICE": "BINARY_SLICE",
    "LIST_TO_TUPLE": "LIST_TO_TUPLE",
    "IMPORT_STAR": "IMPORT_STAR",
    "PUSH_EXC_INFO": "PUSH_EXC_INFO",
    "POP_EXCEPT": "POP_EXCEPT",
    "WITH_EXCEPT_START": "WITH_EXCEPT_START",
    "BEFORE_WITH": "BEFORE_WITH",
    "RETURN_GENERATOR": "RETURN_GENERATOR",
    "END_SEND": "END_SEND",
    "GET_AITER": "GET_AITER",
    "GET_ANEXT": "GET_ANEXT",
    "CLEANUP_THROW": "CLEANUP_THROW",
    "END_ASYNC_FOR": "END_ASYNC_FOR",
    "ASYNC_GEN_WRAP": "ASYNC_GEN_ASEND",
    "GET_LEN": "GET_LEN",
    "MATCH_MAPPING": "MATCH_MAPPING",
    "MATCH_SEQUENCE": "MATCH_SEQUENCE",
    "MATCH_KEYS": "MATCH_KEYS",
    "CHECK_EG_MATCH": "CHECK_EG_MATCH",
}

_JUMP_MAP = {
    "FOR_ITER": "FOR_ITER",
    "SEND": "SEND",
    "JUMP": "JUMP",
    "JUMP_FORWARD": "JUMP",
    "JUMP_BACKWARD": "JUMP",
    "JUMP_BACKWARD_NO_INTERRUPT": "JUMP",
    "POP_JUMP_IF_TRUE": "POP_JUMP_IF_TRUE",
    "POP_JUMP_IF_FALSE": "POP_JUMP_IF_FALSE",
    "POP_JUMP_IF_NONE": "POP_JUMP_IF_NONE",
    "POP_JUMP_IF_NOT_NONE": "POP_JUMP_IF_NOT_NONE",
    # SEND has a jump target (offset to jump when sub-iterator exhausted)
    "SEND_JUMP": "_SEND_JUMP",   # internal use
}


def _strip_jump_suffix(opname):
    for suffix in ("_BACKWARD_NO_INTERRUPT", "_FORWARD", "_BACKWARD"):
        if opname.endswith(suffix):
            return opname[: -len(suffix)]
    return opname


class _JumpRef:
    """Placeholder operand for a jump instruction and is resolved in pass 2."""
    __slots__ = ("target_offset",)

    def __init__(self, target_offset):
        self.target_offset = target_offset


def _translate_const(value, inject_junk=True):
    if isinstance(value, types.CodeType) or type(value).__name__ == 'code':
        return translate_code(value, inject_junk=inject_junk)
    if isinstance(value, tuple):
        return tuple(_translate_const(v, inject_junk) for v in value)
    if isinstance(value, frozenset):
        return frozenset(_translate_const(v, inject_junk) for v in value)
    return value


class _FuncCtx:
    def __init__(self, code, inject_junk=True):
        self.code = code
        self.inject_junk = inject_junk
        self.gir = []
        self.offset_to_index = {}
        self._pending_offsets = []
        self.consts = [_translate_const(c, inject_junk) for c in code.co_consts]
        self.names = list(code.co_names)
        self.varnames = list(code.co_varnames)
        self.cellvars = list(code.co_cellvars)
        self.freevars = list(code.co_freevars)
        self.cellfree = self.cellvars + self.freevars
        self.line_map = []
        self.exc_table = []
        self._last_line = None
        self._kw_names_idx = None

    def mark(self, offset):
        idx = len(self.gir)
        for off in self._pending_offsets:
            self.offset_to_index[off] = idx
        self._pending_offsets.clear()
        self.offset_to_index[offset] = idx

    def defer(self, offset):
        self._pending_offsets.append(offset)

    def emit(self, opname, arg=0):
        self.gir.append([GIR_OPS[opname], arg])
        return len(self.gir) - 1

    def add_line(self, lineno):
        if lineno is None or lineno == self._last_line:
            return
        self._last_line = lineno
        self.line_map.append((len(self.gir), lineno))


def _instr_lineno(instr):
    lineno = getattr(instr, "starts_line", None)
    if lineno is not None:
        return lineno
    positions = getattr(instr, "positions", None)
    if positions is not None:
        return positions.lineno
    return None


def _translate_one(ctx, instr):
    op = instr.opname

    if op == "KW_NAMES":
        ctx._kw_names_idx = instr.arg
        return

    if op in _UNSUPPORTED_OPS:
        raise VMUnsupportedError("unsupported opcode " + op + " in " + repr(ctx.code.co_qualname))

    if op in _DIRECT:
        ctx.emit(_DIRECT[op], 0)
        return

    if op == "COMPARE_OP":
        try:
            cmp_idx = _CMP_OPS.index(instr.argval)
        except ValueError:
            raise VMUnsupportedError("unsupported comparison operator " + repr(instr.argval))
        ctx.emit("COMPARE_OP", cmp_idx)
        return

    if op in _ARG_PASSTHROUGH:
        if op == "CALL" and ctx._kw_names_idx is not None:
            ctx.emit("LOAD_CONST", ctx._kw_names_idx)
            ctx.emit("CALL_KW", instr.arg)
            ctx._kw_names_idx = None
        else:
            ctx.emit(_ARG_PASSTHROUGH[op], instr.arg if instr.arg is not None else 0)
        return

    base = _strip_jump_suffix(op)
    if base in _JUMP_MAP:
        ctx.emit(_JUMP_MAP[base], _JumpRef(instr.argval))
        return

    if op in ("LOAD_FAST_LOAD_FAST", "LOAD_FAST_BORROW_LOAD_FAST_BORROW"):
        idx1, idx2 = instr.arg >> 4, instr.arg & 0xF
        ctx.emit("LOAD_FAST", idx1)
        ctx.emit("LOAD_FAST", idx2)
        return

    if op == "STORE_FAST_LOAD_FAST":
        idx1, idx2 = instr.arg >> 4, instr.arg & 0xF
        ctx.emit("STORE_FAST", idx1)
        ctx.emit("LOAD_FAST", idx2)
        return

    if op == "STORE_FAST_STORE_FAST":
        idx1, idx2 = instr.arg >> 4, instr.arg & 0xF
        ctx.emit("STORE_FAST", idx1)
        ctx.emit("STORE_FAST", idx2)
        return

    if op in ("LOAD_DEREF", "STORE_DEREF", "DELETE_DEREF", "LOAD_CLOSURE",
              "LOAD_FROM_DICT_OR_DEREF"):
        name = instr.argval
        try:
            cf_idx = ctx.cellfree.index(name)
        except ValueError:
            raise VMUnsupportedError("unresolvable cell/free variable " + repr(name))
        ctx.emit(op, cf_idx)
        return

    if op in ("MAKE_CELL", "COPY_FREE_VARS"):
        return

    if op == "EXTENDED_ARG":
        return

    if op == "FORMAT_VALUE":
        conv = instr.arg & 0x3
        has_spec = bool(instr.arg & 0x4)
        if conv:
            ctx.emit("CONVERT_VALUE", conv)
        if has_spec:
            ctx.emit("FORMAT_WITH_SPEC")
        else:
            ctx.emit("FORMAT_SIMPLE")
        return

    if op == "MAKE_FUNCTION":
        flags = instr.arg or 0
        ctx.emit("MAKE_FUNCTION", 0)
        for bit in (8, 4, 2, 1):
            if flags & bit:
                ctx.emit("SET_FUNCTION_ATTRIBUTE", bit)
        return

    if op == "BUILD_CONST_KEY_MAP":
        # TOS = tuple of keys, below it instr.arg values.
        # Emit BUILD_MAP with flag 0x8000 to signal const-key-map mode.
        ctx.emit("BUILD_MAP", instr.arg | 0x8000)
        return

    if op == "GET_YIELD_FROM_ITER":
        # 3.11: equivalent to GET_ITER for our purposes (already an iterator)
        ctx.emit("GET_ITER", 0)
        return

    raise VMUnsupportedError(
        "unsupported opcode " + op + " (arg=" + repr(instr.arg) + ") in "
        + repr(ctx.code.co_qualname)
    )


def _fix_jumps(ctx):
    for instr in ctx.gir:
        operand = instr[1]
        if isinstance(operand, _JumpRef):
            off = operand.target_offset
            if off not in ctx.offset_to_index:
                raise VMUnsupportedError("unresolved jump target offset " + str(off))
            instr[1] = ctx.offset_to_index[off]


def _map_offset(ctx, offset, floor):
    if offset in ctx.offset_to_index:
        return ctx.offset_to_index[offset]
    keys = sorted(ctx.offset_to_index)
    if floor:
        candidates = [k for k in keys if k <= offset]
        return ctx.offset_to_index[candidates[-1]] if candidates else 0
    else:
        candidates = [k for k in keys if k >= offset]
        return ctx.offset_to_index[candidates[0]] if candidates else len(ctx.gir)


def _build_exc_table(ctx):
    try:
        entries = dis._parse_exception_table(ctx.code)
    except Exception:
        entries = []
    table = []
    for e in entries:
        start = _map_offset(ctx, e.start, True)
        end = _map_offset(ctx, e.end, False)
        target = _map_offset(ctx, e.target, True)
        table.append((start, end, target, e.depth, bool(e.lasti)))
    ctx.exc_table = table


def _compute_flags(code):
    flags = 0
    if code.co_flags & 0x04:   flags |= CO_VARARGS
    if code.co_flags & 0x08:   flags |= CO_VARKEYWORDS
    if code.co_flags & 0x10:   flags |= CO_NESTED
    if code.co_freevars:       flags |= CO_HAS_FREE
    # Generator / coroutine / async-generator — pass through to GIR flags
    if code.co_flags & _CO_GENERATOR:  flags |= _CO_GENERATOR    # 0x20
    if code.co_flags & _CO_COROUTINE:  flags |= _CO_COROUTINE    # 0x80
    if code.co_flags & _CO_ASYNC_GEN:  flags |= _CO_ASYNC_GEN    # 0x200
    return flags


def translate_code(code, inject_junk=True):
    """Translate one CPython code object (and all nested code objects) to GIR."""
    ctx = _FuncCtx(code, inject_junk)
    instrs = list(dis.get_instructions(code, show_caches=False))

    # Reachable junk is restricted to non-generator/coroutine/async-generator
    # code objects. Injecting into said generators made things inconsistent or break.
    is_gen = bool(code.co_flags & (_CO_GENERATOR | _CO_COROUTINE | _CO_ASYNC_GEN))

    for instr in instrs:
        if instr.opname == "EXTENDED_ARG":
            ctx.defer(instr.offset)
            continue
        ctx.mark(instr.offset)
        ctx.add_line(_instr_lineno(instr))
        _translate_one(ctx, instr)
        if inject_junk:
            if instr.opname in _TERMINAL_OPS:
                _maybe_inject_deadzone(ctx)
            elif not is_gen:
                _maybe_inject_reachable(ctx)

    _fix_jumps(ctx)
    _build_exc_table(ctx)

    # Junk sequences transiently touch the stack (peak +2, always back to
    # net 0) beyond whatever CPython's own co_stacksize accounted for.
    # The VM doesn't actually pre-allocate a fixed-capacity stack from
    # this value (it's a plain growable list), so this isn't a
    # correctness requirement.
    stacksize = max(code.co_stacksize, 1) + (2 if inject_junk else 0)

    return GIRCode(
        argcount=code.co_argcount,
        posonlyargcount=code.co_posonlyargcount,
        kwonlyargcount=code.co_kwonlyargcount,
        nlocals=len(ctx.varnames),
        stacksize=stacksize,
        flags=_compute_flags(code),
        firstlineno=code.co_firstlineno,
        name=code.co_name,
        qualname=getattr(code, "co_qualname", code.co_name),
        filename=code.co_filename,
        varnames=ctx.varnames,
        names=ctx.names,
        freevars=ctx.freevars,
        cellvars=ctx.cellvars,
        consts=ctx.consts,
        instructions=[tuple(instr) for instr in ctx.gir],
        exc_table=ctx.exc_table,
        line_map=ctx.line_map,
    )


# Module-level code objects (compile(..., "exec")) are translated the same way.
translate_module = translate_code
