# cython: language_level=3
# cython: boundscheck=True
# cython: wraparound=True


"""
gnolly/_gnolly_vm.pyx  -> Gnolly Instruction Set (GIR) interpreter
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This is the "custom C eval loop" half of the true-VM feature.  It:

  1. Deserialises the custom GIR binary format (see gnolly.vm_serialize)
     directly from bytes -> no marshal call anywhere.
  2. Un-shuffles each instruction's opcode value using the per-file
     65536-entry (16-bit) reverse table (see gnolly.vm_isa).
  3. Interprets the resulting GIR instruction stream with its own
     stack machine, re-implementing CPython's documented bytecode
     semantics using CPython's C-API (via Cython) for every operation.

CPython's own eval loop (ceval.c) never executes a single instruction
of user code -> everything here is Gnolly's interpreter, compiled to a
native extension module.  A reverse-engineer who dumps this .so sees
generic deserialisation + stack-machine dispatch over byte streams;
the *meaning* of any given opcode number is fixed only by the per-file
table shipped alongside the encrypted payload.
"""

import builtins as _builtins_mod
import importlib as _importlib
import operator as _op
import struct as _struct
import types as _types_mod
import collections.abc as _abc_mod
import os as _os_mod
import hashlib as _hashlib_mod
import secrets as _secrets_mod

# GIR_TABLE_SIZE must match gnolly.vm_isa.GIR_TABLE_SIZE exactly.
# (protect-time and runtime must agree on the reverse-table size).
cdef int GIR_TABLE_SIZE = 65536
cdef int GIR_FORMAT_VERSION = 1

# ---------------------------------------------------------------------------
# Sentinels
# ---------------------------------------------------------------------------

cdef object _UNSET = object()    # unbound fast-local / cell
cdef object _NULL  = object()    # "no bound self/method" marker on the stack


# ---------------------------------------------------------------------------
# Constant tags (mirrors gnolly.vm_serialize)
# ---------------------------------------------------------------------------

cdef int K_NONE = 0x00
cdef int K_TRUE = 0x01
cdef int K_FALSE = 0x02
cdef int K_ELLIPSIS = 0x03
cdef int K_INT = 0x04
cdef int K_FLOAT = 0x05
cdef int K_COMPLEX = 0x06
cdef int K_STR = 0x07
cdef int K_BYTES = 0x08
cdef int K_TUPLE = 0x09
cdef int K_FROZENSET = 0x0A
cdef int K_CODE = 0x0B

cdef int CO_VARARGS = 0x01
cdef int CO_VARKEYWORDS = 0x02
cdef int CO_NESTED = 0x04
cdef int CO_HAS_FREE = 0x08


# ---------------------------------------------------------------------------
# Varint reader over a bytes buffer
# ---------------------------------------------------------------------------

cdef class _Reader:
    # A read-only typed memoryview rather than bytes that accepts bytes,
    # bytearray, or a memoryview as-is via the buffer protocol
    # This matters for callers that keep the decrypted GIR blob in
    # a bytearray specifically so it can be explicitly zeroed after use.
    # And if this reader forced it into bytes first, that would silently
    # create one more immutable, unwipeable copy of the blob right at the
    # call boundary.
    cdef const unsigned char[:] buf
    cdef Py_ssize_t pos

    def __init__(self, buf not None, Py_ssize_t pos=0):
        self.buf = buf
        self.pos = pos

    cdef unsigned long long read_uvarint(self):
        cdef unsigned long long result = 0
        cdef int shift = 0
        cdef unsigned char b
        while True:
            b = self.buf[self.pos]
            self.pos += 1
            result |= <unsigned long long>(b & 0x7F) << shift
            if not (b & 0x80):
                return result
            shift += 7

    cdef long long read_svarint(self):
        cdef unsigned long long raw = self.read_uvarint()
        if raw & 1:
            return -<long long>(raw >> 1) - 1
        return <long long>(raw >> 1)

    cdef bytes read_bytes(self, Py_ssize_t n):
        # Materialises an independent bytes object for just this
        # one slice without ever copying the whole underlying buffer.
        cdef bytes out = bytes(self.buf[self.pos:self.pos + n])
        self.pos += n
        return out

    cdef str read_str(self):
        cdef unsigned long long n = self.read_uvarint()
        cdef bytes raw = self.read_bytes(<Py_ssize_t>n)
        return raw.decode("utf-8")

    cdef list read_strvec(self):
        cdef unsigned long long n = self.read_uvarint()
        cdef list out = []
        cdef unsigned long long i
        for i in range(n):
            out.append(self.read_str())
        return out

    cdef unsigned char read_u8(self):
        cdef unsigned char b = self.buf[self.pos]
        self.pos += 1
        return b


# ---------------------------------------------------------------------------
# GIR code object
# ---------------------------------------------------------------------------

cdef class GIRCodeObj:
    cdef public int argcount
    cdef public int posonlyargcount
    cdef public int kwonlyargcount
    cdef public int nlocals
    cdef public int stacksize
    cdef public unsigned int flags
    cdef public long firstlineno
    cdef public str name
    cdef public str qualname
    cdef public str filename
    cdef public list varnames
    cdef public list names
    cdef public list freevars
    cdef public list cellvars
    cdef public list cellfree
    cdef public list consts
    cdef public list instructions     # list of (op, arg) tuples, op already unshuffled
    cdef public list exc_table        # list of (start, end, target, depth, lasti)
    cdef public list line_map
    cdef bytes _ichk                  # continuous-integrity baseline digest, see _code_digest()



# ---------------------------------------------------------------------------
# Continuous integrity re-verification
# ---------------------------------------------------------------------------
#
# The design here mirrors gnolly.poison's detection/reaction split and is adapted to this
# layer: by the time code is executing inside run_frame(), AES-GCM
# decryption has already happened and there's no key material left to
# fold a failure into.
# So the reaction here is a direct, silent os._exit(1) at the check site
# -> which means there is no try/except Exception (or even bare except:) in the PROTECTED program
# itself that can be intercepted, logged, or way to swallow a detected tamper the way it
# could if this were a normal raised exception routed through the exc_table.
#
# _CHECK_PERIOD is chosen once per process start (not a fixed build-time
# constant) so the exact cadence isn't the same across every run.
cdef unsigned long long _CHECK_PERIOD = <unsigned long long> _secrets_mod.choice(
    (2048, 3072, 4096, 6144, 8192)
)
cdef unsigned long long _tick_counter = 0


cdef bytes _code_digest(GIRCodeObj code):
    """
    Snapshot digest over everything the dispatch loop actually reads for
    this code object: the decoded (op, arg) instruction stream (post
    opcode-table-unshuffle) plus its scalar constants. Nested GIRCodeObj
    consts fold in their OWN already-computed digest rather than being
    walked again here.

    Called exactly twice per code object under normal operation: once at
    decode time (the trusted baseline, via _read_code) and then
    repeatedly from inside the dispatch loop (_tick_and_maybe_check)
    while it runs. Same function both times, on purpose -> what gets
    checked at load and what gets checked at runtime can never drift
    apart from each other.
    """
    cdef list instructions = code.instructions
    cdef list consts = code.consts
    cdef Py_ssize_t i, n = len(instructions), m = len(consts)
    cdef int op
    cdef long long arg
    cdef bytearray buf = bytearray(n * 10)
    cdef Py_ssize_t off = 0
    cdef tuple item
    for i in range(n):
        item = instructions[i]
        op = item[0]
        arg = item[1]
        buf[off]     = (op >> 8) & 0xFF
        buf[off + 1] = op & 0xFF
        buf[off + 2] = (arg >> 56) & 0xFF
        buf[off + 3] = (arg >> 48) & 0xFF
        buf[off + 4] = (arg >> 40) & 0xFF
        buf[off + 5] = (arg >> 32) & 0xFF
        buf[off + 6] = (arg >> 24) & 0xFF
        buf[off + 7] = (arg >> 16) & 0xFF
        buf[off + 8] = (arg >> 8) & 0xFF
        buf[off + 9] = arg & 0xFF
        off += 10

    h = _hashlib_mod.blake2b(bytes(buf), digest_size=16)
    cdef object cv
    for i in range(m):
        cv = consts[i]
        if isinstance(cv, GIRCodeObj):
            if (<GIRCodeObj> cv)._ichk is not None:
                h.update((<GIRCodeObj> cv)._ichk)
        elif isinstance(cv, str):
            h.update(cv.encode("utf-8", "surrogateescape"))
        elif isinstance(cv, (bytes, bytearray)):
            h.update(bytes(cv))
        elif isinstance(cv, (int, float, complex, bool, tuple, frozenset)):
            h.update(repr(cv).encode("utf-8", "surrogateescape"))
        # None / Ellipsis / other singletons: position in consts is
        # already implied by the instructions that reference this index.
    return h.digest()


cdef inline void _tick_and_maybe_check(GIRCodeObj code):
    """
    Called once per executed instruction, from inside the hot dispatch
    loop. This re-hashing of the code object on the 1-in-N
    iterations where the counter lands on the period.

    A global counter rather than per-frame, it will keep
    accumulating across calls/recursion/generator resumes. So a
    function that's individually too short to ever hit the threshold on
    its own still gets checked once the process's cumulative instruction
    count crosses it.
    """
    global _tick_counter
    _tick_counter += 1
    if (_tick_counter % _CHECK_PERIOD) != 0:
        return
    if code._ichk is None:
        return
    if _code_digest(code) != code._ichk:
        _os_mod._exit(1)



def _read_const(_Reader r, dict table):
    cdef int tag = r.read_u8()
    cdef unsigned long long n, nbytes
    cdef unsigned char sign
    cdef bytes mag
    cdef double re, im
    if tag == K_NONE:
        return None
    if tag == K_TRUE:
        return True
    if tag == K_FALSE:
        return False
    if tag == K_ELLIPSIS:
        return Ellipsis
    if tag == K_INT:
        sign = r.read_u8()
        nbytes = r.read_uvarint()
        mag = r.read_bytes(<Py_ssize_t>nbytes)
        value = int.from_bytes(mag, "big") if nbytes else 0
        return -value if sign else value
    if tag == K_FLOAT:
        return _struct.unpack(">d", r.read_bytes(8))[0]
    if tag == K_COMPLEX:
        re, im = _struct.unpack(">dd", r.read_bytes(16))
        return complex(re, im)
    if tag == K_STR:
        return r.read_str()
    if tag == K_BYTES:
        n = r.read_uvarint()
        return r.read_bytes(<Py_ssize_t>n)
    if tag == K_TUPLE:
        n = r.read_uvarint()
        return tuple(_read_const(r, table) for _ in range(n))
    if tag == K_FROZENSET:
        n = r.read_uvarint()
        return frozenset(_read_const(r, table) for _ in range(n))
    if tag == K_CODE:
        return _read_code(r, table)
    raise ValueError("unknown GIR constant tag %d" % tag)


def _read_code(_Reader r, dict table):
    cdef GIRCodeObj code = GIRCodeObj()
    code.argcount = <int>r.read_uvarint()
    code.posonlyargcount = <int>r.read_uvarint()
    code.kwonlyargcount = <int>r.read_uvarint()
    code.nlocals = <int>r.read_uvarint()
    code.stacksize = <int>r.read_uvarint()
    code.flags = _struct.unpack(">I", r.read_bytes(4))[0]
    code.firstlineno = <long>r.read_uvarint()
    code.name = r.read_str()
    code.qualname = r.read_str()
    code.filename = r.read_str()
    code.varnames = r.read_strvec()
    code.names = r.read_strvec()
    code.freevars = r.read_strvec()
    code.cellvars = r.read_strvec()
    code.cellfree = code.cellvars + code.freevars

    cdef unsigned long long n_consts = r.read_uvarint()
    code.consts = [_read_const(r, table) for _ in range(n_consts)]

    cdef unsigned long long n_instr = r.read_uvarint()
    cdef list instructions = []
    cdef unsigned long long shuffled_op
    cdef int real_op
    cdef unsigned long long arg
    cdef unsigned long long i
    for i in range(n_instr):
        shuffled_op = r.read_uvarint()
        real_op = table.get(shuffled_op, shuffled_op)
        arg = r.read_uvarint()
        instructions.append((real_op, <long long>arg))
    code.instructions = instructions

    cdef unsigned long long n_exc = r.read_uvarint()
    cdef list exc_table = []
    cdef unsigned long long start, end, target, depth
    cdef unsigned char lasti
    for i in range(n_exc):
        start = r.read_uvarint()
        end = r.read_uvarint()
        target = r.read_uvarint()
        depth = r.read_uvarint()
        lasti = r.read_u8()
        exc_table.append((<long long>start, <long long>end, <long long>target,
                          <long long>depth, lasti != 0))
    code.exc_table = exc_table

    cdef unsigned long long n_lines = r.read_uvarint()
    cdef list line_map = []
    cdef long long prev_line = code.firstlineno
    cdef unsigned long long idx
    cdef long long delta
    for i in range(n_lines):
        idx = r.read_uvarint()
        delta = r.read_svarint()
        prev_line += delta
        line_map.append((<long long>idx, prev_line))
    code.line_map = line_map

    # Baseline snapshot, taken the instant this code object is fully
    # decoded -> the earliest point its post-table-unshuffle
    # opcodes exist in memory at all. If any divergence from this snapshot is found
    # later in _tick_and_maybe_check() means something done to this
    # object's instructions/consts that wasn't us after the fact.
    code._ichk = _code_digest(code)
    return code


def deserialize_vm_blob(blob, table_blob):
    """
    Deserialise a GIR module blob.

    blob, table_blob: any bytes-like object (bytes, bytearray, or
        memoryview) is accepted as-is via the buffer protocol, not copied
        up front. Callers that hold these in a bytearray so they can be
        explicitly wiped after use can pass said bytearray straight through.

    table_blob: 2*GIR_TABLE_SIZE-byte reverse opcode table, big-endian u16
                pairs (index = shuffled opcode value -> value = real GIR
                opcode).
    """
    if len(table_blob) < GIR_TABLE_SIZE * 2:
        raise ValueError("vm opcode table too short")
    cdef dict table = {}
    cdef Py_ssize_t ti
    for ti in range(GIR_TABLE_SIZE):
        table[ti] = (table_blob[2 * ti] << 8) | table_blob[2 * ti + 1]
    if not blob:
        raise ValueError("empty GIR blob")
    if blob[0] != GIR_FORMAT_VERSION:
        raise ValueError(
            "unsupported GIR format version %d (expected %d)" % (blob[0], GIR_FORMAT_VERSION)
        )
    cdef _Reader r = _Reader(blob, 1)   # skip format-version byte
    return _read_code(r, table)


# ---------------------------------------------------------------------------
# Cells / closures
# ---------------------------------------------------------------------------

cdef class Cell:
    cdef public object value

    def __init__(self, value=_UNSET):
        self.value = value


# ---------------------------------------------------------------------------
# Operator dispatch tables
# ---------------------------------------------------------------------------

cdef dict _BINOPS = {
    0:  _op.add,       1:  _op.and_,      2:  _op.floordiv,  3:  _op.lshift,
    4:  _op.matmul,    5:  _op.mul,       6:  _op.mod,       7:  _op.or_,
    8:  _op.pow,       9:  _op.rshift,    10: _op.sub,       11: _op.truediv,
    12: _op.xor,
    13: _op.iadd,      14: _op.iand,      15: _op.ifloordiv, 16: _op.ilshift,
    17: _op.imatmul,   18: _op.imul,      19: _op.imod,      20: _op.ior,
    21: _op.ipow,      22: _op.irshift,   23: _op.isub,      24: _op.itruediv,
    25: _op.ixor,
}

cdef list _CMPOPS = [_op.lt, _op.le, _op.eq, _op.ne, _op.gt, _op.ge]


# ---------------------------------------------------------------------------
# GIR opcode numbers (kept in sync with gnolly.vm_isa.GIR_OPS)
# ---------------------------------------------------------------------------

cdef enum:
    OP_NOP = 0
    OP_RESUME = 1
    OP_POP_TOP = 2
    OP_PUSH_NULL = 3
    OP_COPY = 4
    OP_SWAP = 5
    OP_RETURN_VALUE = 6
    OP_RETURN_CONST = 7
    OP_LOAD_CONST = 8
    OP_LOAD_FAST = 9
    OP_STORE_FAST = 10
    OP_DELETE_FAST = 11
    OP_LOAD_FAST_AND_CLEAR = 12
    OP_LOAD_GLOBAL = 13
    OP_STORE_GLOBAL = 14
    OP_DELETE_GLOBAL = 15
    OP_LOAD_NAME = 16
    OP_STORE_NAME = 17
    OP_DELETE_NAME = 18
    OP_LOAD_DEREF = 19
    OP_STORE_DEREF = 20
    OP_DELETE_DEREF = 21
    OP_LOAD_CLOSURE = 22
    OP_LOAD_FROM_DICT_OR_DEREF = 23
    OP_LOAD_FROM_DICT_OR_GLOBALS = 24
    OP_LOAD_ATTR = 25
    OP_STORE_ATTR = 26
    OP_DELETE_ATTR = 27
    OP_LOAD_SUBSCR = 28
    OP_STORE_SUBSCR = 29
    OP_DELETE_SUBSCR = 30
    OP_BINARY_SLICE = 31
    OP_STORE_SLICE = 32
    OP_LOAD_BUILD_CLASS = 33
    OP_UNARY_NOT = 34
    OP_UNARY_NEGATIVE = 35
    OP_UNARY_INVERT = 36
    OP_BINARY_OP = 37
    OP_COMPARE_OP = 38
    OP_IS_OP = 39
    OP_CONTAINS_OP = 40
    OP_BUILD_TUPLE = 41
    OP_BUILD_LIST = 42
    OP_BUILD_SET = 43
    OP_BUILD_MAP = 44
    OP_BUILD_STRING = 45
    OP_BUILD_SLICE = 46
    OP_LIST_APPEND = 47
    OP_SET_ADD = 48
    OP_MAP_ADD = 49
    OP_LIST_EXTEND = 50
    OP_SET_UPDATE = 51
    OP_DICT_UPDATE = 52
    OP_DICT_MERGE = 53
    OP_LIST_TO_TUPLE = 54
    OP_UNPACK_SEQUENCE = 55
    OP_UNPACK_EX = 56
    OP_GET_ITER = 57
    OP_FOR_ITER = 58
    OP_JUMP = 59
    OP_POP_JUMP_IF_TRUE = 60
    OP_POP_JUMP_IF_FALSE = 61
    OP_POP_JUMP_IF_NONE = 62
    OP_POP_JUMP_IF_NOT_NONE = 63
    OP_CALL = 64
    OP_CALL_KW = 65
    OP_CALL_FUNCTION_EX = 66
    OP_MAKE_FUNCTION = 67
    OP_SET_FUNCTION_ATTRIBUTE = 68
    OP_IMPORT_NAME = 69
    OP_IMPORT_FROM = 70
    OP_IMPORT_STAR = 71
    OP_RAISE_VARARGS = 72
    OP_RERAISE = 73
    OP_PUSH_EXC_INFO = 74
    OP_POP_EXCEPT = 75
    OP_CHECK_EXC_MATCH = 76
    OP_BEFORE_WITH = 77
    OP_WITH_EXCEPT_START = 78
    OP_CONVERT_VALUE = 79
    OP_FORMAT_SIMPLE = 80
    OP_FORMAT_WITH_SPEC = 81
    OP_GET_LEN = 82
    OP_MATCH_KEYS = 83
    OP_MATCH_MAPPING = 84
    OP_MATCH_SEQUENCE = 85
    OP_MATCH_CLASS = 86


# ---------------------------------------------------------------------------
# Function objects produced by MAKE_FUNCTION
# ---------------------------------------------------------------------------

cdef class GIRFunction:
    cdef public GIRCodeObj code
    cdef public dict globals
    cdef public tuple closure
    cdef public tuple defaults
    cdef public dict kwdefaults
    cdef public object annotations
    cdef public str name
    cdef public str qualname
    cdef public dict builtins

    def __init__(self, GIRCodeObj code, dict globals, dict builtins):
        self.code = code
        self.globals = globals
        self.builtins = builtins
        self.closure = ()
        self.defaults = ()
        self.kwdefaults = {}
        self.annotations = None
        self.name = code.name
        self.qualname = code.qualname

    @property
    def __name__(self):
        return self.name

    @property
    def __qualname__(self):
        return self.qualname

    def __repr__(self):
        return "<gnolly-vm function %s at 0x%x>" % (self.qualname, id(self))

    def __get__(self, obj, objtype):
        if obj is None:
            return self
        return _BoundGIRMethod(self, obj)

    def __call__(self, *args, **kwargs):
        cdef list fastlocals = _bind_args(self.code, args, kwargs, self.defaults, self.kwdefaults)
        cdef list cells = _make_cells(self.code, fastlocals, self.closure)
        return run_frame(self.code, fastlocals, cells, self.globals, self.builtins, fastlocals)



# ---------------------------------------------------------------------------
# Function factory -> uses module-level var updated after gen classes are defined
# ---------------------------------------------------------------------------

_gir_fn_class = None  # will be set to _GIRFunctionWithGenSupport at module end

def _make_gir_function(GIRCodeObj code, dict globs, dict builtins_ns):
    # Pure-Python def (not cdef) so it can use the late-bound _gir_fn_class
    cls = _gir_fn_class
    if cls is not None:
        return cls(code, globs, builtins_ns)
    return GIRFunction(code, globs, builtins_ns)


cdef class _BoundGIRMethod:
    cdef public GIRFunction func
    cdef public object instance

    def __init__(self, GIRFunction func, object instance):
        self.func = func
        self.instance = instance

    def __repr__(self):
        return "<bound gnolly-vm method %s of %r>" % (self.func.qualname, self.instance)

    def __call__(self, *args, **kwargs):
        return self.func(self.instance, *args, **kwargs)


# ---------------------------------------------------------------------------
# Argument binding (CPython-equivalent)
# ---------------------------------------------------------------------------

cdef list _bind_args(GIRCodeObj code, tuple args, dict kwargs, tuple defaults, dict kwdefaults):
    cdef int nargs = code.argcount
    cdef int nkw = code.kwonlyargcount
    cdef bint has_varargs = bool(code.flags & CO_VARARGS)
    cdef bint has_varkw = bool(code.flags & CO_VARKEYWORDS)
    cdef list fastlocals = [_UNSET] * code.nlocals
    cdef Py_ssize_t nposargs = len(args)
    cdef Py_ssize_t n_fill = nargs if nposargs > nargs else nposargs
    cdef Py_ssize_t i

    for i in range(n_fill):
        fastlocals[i] = args[i]

    kwargs = dict(kwargs) if kwargs else {}

    cdef int varargs_idx = nargs + nkw

    if nposargs > nargs:
        if has_varargs:
            fastlocals[varargs_idx] = tuple(args[n_fill:])
        else:
            raise TypeError(
                "%s() takes %d positional argument(s) but %d were given"
                % (code.name, nargs, nposargs)
            )
    elif has_varargs:
        fastlocals[varargs_idx] = ()

    for i in range(nargs):
        if fastlocals[i] is _UNSET:
            pname = code.varnames[i]
            if pname in kwargs:
                fastlocals[i] = kwargs.pop(pname)

    for i in range(nkw):
        pname = code.varnames[nargs + i]
        if pname in kwargs:
            fastlocals[nargs + i] = kwargs.pop(pname)
        elif kwdefaults is not None and pname in kwdefaults:
            fastlocals[nargs + i] = kwdefaults[pname]
        else:
            raise TypeError(
                "%s() missing required keyword-only argument: '%s'" % (code.name, pname)
            )

    if has_varkw:
        kwidx = nargs + nkw + (1 if has_varargs else 0)
        fastlocals[kwidx] = kwargs
    elif kwargs:
        raise TypeError(
            "%s() got an unexpected keyword argument '%s'" % (code.name, next(iter(kwargs)))
        )

    if defaults:
        ndef = len(defaults)
        for i in range(nargs - ndef, nargs):
            if fastlocals[i] is _UNSET:
                fastlocals[i] = defaults[i - (nargs - ndef)]

    cdef list missing = []
    for i in range(nargs):
        if fastlocals[i] is _UNSET:
            missing.append(code.varnames[i])
    if missing:
        raise TypeError(
            "%s() missing required positional argument(s): %s"
            % (code.name, ", ".join("'%s'" % m for m in missing))
        )

    return fastlocals


cdef list _make_cells(GIRCodeObj code, list fastlocals, tuple closure):
    cdef list cells = []
    cdef Py_ssize_t i
    cdef str cname
    for i, cname in enumerate(code.cellvars):
        cell = Cell()
        # If this cellvar is also a parameter, seed the cell with its
        # initial value (mirrors CPython's MAKE_CELL for captured params).
        try:
            vidx = code.varnames.index(cname)
        except ValueError:
            vidx = -1
        if 0 <= vidx < len(fastlocals) and fastlocals[vidx] is not _UNSET:
            cell.value = fastlocals[vidx]
        cells.append(cell)
    for i in range(len(code.freevars)):
        cells.append(closure[i] if i < len(closure) else Cell())
    return cells


# ---------------------------------------------------------------------------
# match statement support
# ---------------------------------------------------------------------------

cdef tuple _SELF_MATCH_TYPES = (bool, bytearray, bytes, dict, float,
                                  frozenset, int, list, set, str, tuple)


def _match_class(subject, cls, Py_ssize_t ncount, tuple kwd_names):
    """
    Implements MATCH_CLASS(count): given a subject, a class, the count of
    positional sub-patterns and a tuple of keyword attribute names, returns
    either a tuple of extracted attribute values (positional first, then
    keyword, in order) or None if the subject doesn't match.
    """
    if not isinstance(cls, type):
        raise TypeError("called match pattern must be a type")
    if not isinstance(subject, cls):
        return None

    cdef list attrs = []
    if ncount:
        match_args = getattr(cls, "__match_args__", None)
        if match_args is None:
            if cls in _SELF_MATCH_TYPES:
                if ncount != 1:
                    raise TypeError(
                        "%s() accepts 1 positional sub-pattern (%d given)"
                        % (cls.__name__, ncount))
                attrs.append(subject)
                ncount = 0
            else:
                raise TypeError(
                    "%s() accepts 0 positional sub-patterns (%d given)"
                    % (cls.__name__, ncount))
        else:
            if not isinstance(match_args, tuple):
                raise TypeError(
                    "%s.__match_args__ must be a tuple (got %s)"
                    % (cls.__name__, type(match_args).__name__))
            if ncount > len(match_args):
                raise TypeError(
                    "%s() accepts %d positional sub-pattern%s (%d given)"
                    % (cls.__name__, len(match_args),
                       "" if len(match_args) == 1 else "s", ncount))
            for i in range(ncount):
                name = match_args[i]
                if not isinstance(name, str):
                    raise TypeError(
                        "__match_args__ elements must be strings (got %s)"
                        % type(name).__name__)
                try:
                    attrs.append(getattr(subject, name))
                except AttributeError:
                    return None

    for name in kwd_names:
        try:
            attrs.append(getattr(subject, name))
        except AttributeError:
            return None

    return tuple(attrs)


# ---------------------------------------------------------------------------
# except* / exception group support
# ---------------------------------------------------------------------------

def _eg_split(exc_value, match_type):
    """
    Implements the split() half of CHECK_EG_MATCH: given the exception
    currently being matched and the except* clause's type (or tuple of
    types), returns (match, rest) -> the portion that matched (or None) and
    the portion that didn't (or None).

    exc_value is None once a prior except* clause has already consumed the
    whole exception (nothing left for later clauses to match against).
    """
    if exc_value is None:
        return None, None
    if isinstance(exc_value, BaseExceptionGroup):
        return exc_value.split(match_type)
    if isinstance(exc_value, match_type):
        return ExceptionGroup("", [exc_value]), None
    return None, exc_value


def _prep_reraise_star(orig, list excs):
    """
    Implements CALL_INTRINSIC_2's INTRINSIC_PREP_RERAISE_STAR: given the
    list of exceptions still needing to be raised (unmatched leftovers plus
    anything newly raised inside except* bodies, with None entries for
    clauses that fully consumed their share), reconstructs the single
    exception (or exception group) to re-raise, or None if nothing remains.
    """
    cdef list raised = [e for e in excs if e is not None]
    if not raised:
        return None
    if len(raised) == 1:
        return raised[0]
    return ExceptionGroup("", raised)


# ---------------------------------------------------------------------------
# __build_class__ replacement
# ---------------------------------------------------------------------------

def _gir_build_class(body_func, str name, *bases, **kwds):
    cdef GIRCodeObj code = body_func.code
    metaclass = kwds.pop("metaclass", None)
    if metaclass is None:
        if bases:
            metaclass = type(bases[0])
        else:
            metaclass = type

    if hasattr(metaclass, "__prepare__"):
        ns = metaclass.__prepare__(name, bases, **kwds)
    else:
        ns = {}

    cdef list fastlocals = [_UNSET] * code.nlocals
    cdef list cells = _make_cells(code, fastlocals, body_func.closure)

    run_frame(code, fastlocals, cells, body_func.globals, body_func.builtins, ns)

    if "__classcell__" in ns:
        ns["__classcell__"] = _types_mod.CellType()

    cls = metaclass(name, bases, ns, **kwds)

    if "__class__" in code.cellvars:
        idx = code.cellvars.index("__class__")
        (<Cell>cells[idx]).value = cls

    return cls


# ---------------------------------------------------------------------------
# Exception table lookup
# ---------------------------------------------------------------------------

cdef tuple _find_handler(list exc_table, long long ip):
    cdef tuple entry
    cdef long long start, end, target, depth
    for entry in exc_table:
        start, end, target, depth, lasti = entry
        if start <= ip < end:
            return entry
    return None


# ---------------------------------------------------------------------------
# The interpreter loop
# ---------------------------------------------------------------------------

def run_frame(GIRCodeObj code, list fastlocals, list cells, dict globs, dict builtins_ns, object locals_dict):
    """
    Execute one GIR code object.  Returns the function's return value
    (or None for module-level / fall-off-the-end execution).
    """
    cdef list stack = []
    cdef list instructions = code.instructions
    cdef list consts = code.consts
    cdef list names = code.names
    cdef list varnames = code.varnames
    cdef list cellfree = code.cellfree
    cdef list exc_table = code.exc_table
    cdef Py_ssize_t n = len(instructions)
    cdef long long ip = 0
    cdef long long cur_ip
    cdef object current_exception = None

    cdef int op
    cdef long long arg

    while ip < n:
        cur_ip = ip
        op = instructions[ip][0]
        arg = instructions[ip][1]
        ip += 1

        _tick_and_maybe_check(code)

        try:
            if op == OP_NOP or op == OP_RESUME:
                pass

            elif op == OP_POP_TOP:
                stack.pop()

            elif op == OP_PUSH_NULL:
                stack.append(_NULL)

            elif op == OP_COPY:
                stack.append(stack[-arg])

            elif op == OP_SWAP:
                stack[-1], stack[-arg] = stack[-arg], stack[-1]

            elif op == OP_RETURN_VALUE:
                return stack.pop()

            elif op == OP_RETURN_CONST:
                return consts[arg]

            elif op == OP_LOAD_CONST:
                stack.append(consts[arg])

            elif op == OP_LOAD_FAST:
                val = fastlocals[arg]
                if val is _UNSET:
                    raise UnboundLocalError(
                        "local variable '%s' referenced before assignment" % varnames[arg]
                    )
                stack.append(val)

            elif op == OP_STORE_FAST:
                fastlocals[arg] = stack.pop()

            elif op == OP_DELETE_FAST:
                if fastlocals[arg] is _UNSET:
                    raise UnboundLocalError(
                        "local variable '%s' referenced before assignment" % varnames[arg]
                    )
                fastlocals[arg] = _UNSET

            elif op == OP_LOAD_FAST_AND_CLEAR:
                val = fastlocals[arg]
                stack.append(None if val is _UNSET else val)
                fastlocals[arg] = _UNSET

            elif op == OP_LOAD_GLOBAL:
                namei = arg >> 1
                if arg & 1:
                    stack.append(_NULL)
                nm = names[namei]
                if nm in globs:
                    stack.append(globs[nm])
                elif nm in builtins_ns:
                    stack.append(builtins_ns[nm])
                else:
                    raise NameError("name '%s' is not defined" % nm)

            elif op == OP_STORE_GLOBAL:
                globs[names[arg]] = stack.pop()

            elif op == OP_DELETE_GLOBAL:
                try:
                    del globs[names[arg]]
                except KeyError:
                    raise NameError("name '%s' is not defined" % names[arg])

            elif op == OP_LOAD_NAME:
                nm = names[arg]
                if nm in locals_dict:
                    stack.append(locals_dict[nm])
                elif nm in globs:
                    stack.append(globs[nm])
                elif nm in builtins_ns:
                    stack.append(builtins_ns[nm])
                else:
                    raise NameError("name '%s' is not defined" % nm)

            elif op == OP_STORE_NAME:
                locals_dict[names[arg]] = stack.pop()

            elif op == OP_DELETE_NAME:
                try:
                    del locals_dict[names[arg]]
                except KeyError:
                    raise NameError("name '%s' is not defined" % names[arg])

            elif op == OP_LOAD_DEREF:
                cell = <Cell>cells[arg]
                if cell.value is _UNSET:
                    raise NameError(
                        "free variable '%s' referenced before assignment" % cellfree[arg]
                    )
                stack.append(cell.value)

            elif op == OP_STORE_DEREF:
                (<Cell>cells[arg]).value = stack.pop()

            elif op == OP_DELETE_DEREF:
                (<Cell>cells[arg]).value = _UNSET

            elif op == OP_LOAD_CLOSURE:
                stack.append(cells[arg])

            elif op == OP_LOAD_ATTR:
                namei = arg >> 1
                method_flag = arg & 1
                obj = stack.pop()
                val = getattr(obj, names[namei])
                if method_flag:
                    stack.append(val)   # callable (deeper)
                    stack.append(_NULL) # self_or_null = NULL (method already bound)
                else:
                    stack.append(val)

            elif op == OP_LOAD_SUPER_ATTR:
                namei = arg >> 2
                method_flag = arg & 1
                self_obj = stack.pop()
                klass = stack.pop()
                global_super = stack.pop()
                sup = global_super(klass, self_obj)
                val = getattr(sup, names[namei])
                if method_flag:
                    stack.append(val)   # callable (deeper)
                    stack.append(_NULL) # self_or_null = NULL (method already bound)
                else:
                    stack.append(val)

            elif op == OP_STORE_ATTR:
                obj = stack.pop()
                val = stack.pop()
                setattr(obj, names[arg], val)

            elif op == OP_DELETE_ATTR:
                obj = stack.pop()
                delattr(obj, names[arg])

            elif op == OP_LOAD_SUBSCR:
                key = stack.pop()
                container = stack.pop()
                stack.append(container[key])

            elif op == OP_STORE_SUBSCR:
                key = stack.pop()
                container = stack.pop()
                val = stack.pop()
                container[key] = val

            elif op == OP_DELETE_SUBSCR:
                key = stack.pop()
                container = stack.pop()
                del container[key]

            elif op == OP_BINARY_SLICE:
                stop = stack.pop()
                start = stack.pop()
                container = stack.pop()
                stack.append(container[start:stop])

            elif op == OP_LOAD_BUILD_CLASS:
                stack.append(_gir_build_class)

            elif op == OP_UNARY_NOT:
                stack.append(not stack.pop())

            elif op == OP_UNARY_NEGATIVE:
                stack.append(_op.neg(stack.pop()))

            elif op == OP_UNARY_INVERT:
                stack.append(_op.invert(stack.pop()))

            elif op == OP_BINARY_OP:
                rhs = stack.pop()
                lhs = stack.pop()
                stack.append(_BINOPS[arg](lhs, rhs))

            elif op == OP_COMPARE_OP:
                rhs = stack.pop()
                lhs = stack.pop()
                stack.append(_CMPOPS[arg](lhs, rhs))

            elif op == OP_IS_OP:
                rhs = stack.pop()
                lhs = stack.pop()
                stack.append((lhs is not rhs) if arg else (lhs is rhs))

            elif op == OP_CONTAINS_OP:
                container = stack.pop()
                item = stack.pop()
                result = item in container
                stack.append((not result) if arg else result)

            elif op == OP_BUILD_TUPLE:
                if arg:
                    items = stack[-arg:]
                    del stack[len(stack) - arg:]
                else:
                    items = []
                stack.append(tuple(items))

            elif op == OP_BUILD_LIST:
                if arg:
                    items = stack[-arg:]
                    del stack[len(stack) - arg:]
                else:
                    items = []
                stack.append(list(items))

            elif op == OP_BUILD_SET:
                if arg:
                    items = stack[-arg:]
                    del stack[len(stack) - arg:]
                else:
                    items = []
                stack.append(set(items))

            elif op == OP_BUILD_MAP:
                d = {}
                if arg & 0x8000:
                    n2 = arg & 0x7FFF
                    keys = stack.pop()
                    vals = stack[-n2:]
                    del stack[len(stack) - n2:]
                    d = dict(zip(keys, vals))
                elif arg:
                    items = stack[-(2 * arg):]
                    del stack[len(stack) - 2 * arg:]
                    for i in range(0, len(items), 2):
                        d[items[i]] = items[i + 1]
                stack.append(d)

            elif op == OP_BUILD_STRING:
                if arg:
                    items = stack[-arg:]
                    del stack[len(stack) - arg:]
                else:
                    items = []
                stack.append("".join(items))

            elif op == OP_BUILD_SLICE:
                if arg == 3:
                    step = stack.pop()
                    stop = stack.pop()
                    start = stack.pop()
                    stack.append(slice(start, stop, step))
                else:
                    stop = stack.pop()
                    start = stack.pop()
                    stack.append(slice(start, stop))

            elif op == OP_LIST_APPEND:
                val = stack.pop()
                stack[-arg].append(val)

            elif op == OP_SET_ADD:
                val = stack.pop()
                stack[-arg].add(val)

            elif op == OP_MAP_ADD:
                val = stack.pop()
                key = stack.pop()
                stack[-arg][key] = val

            elif op == OP_LIST_EXTEND:
                val = stack.pop()
                stack[-arg].extend(val)

            elif op == OP_SET_UPDATE:
                val = stack.pop()
                stack[-arg].update(val)

            elif op == OP_DICT_UPDATE:
                val = stack.pop()
                stack[-arg].update(val)

            elif op == OP_DICT_MERGE:
                val = stack.pop()
                target = stack[-arg]
                dup = set(target) & set(val)
                if dup:
                    raise TypeError(
                        "%s() got multiple values for keyword argument '%s'"
                        % (code.name, next(iter(dup)))
                    )
                target.update(val)

            elif op == OP_LIST_TO_TUPLE:
                stack.append(tuple(stack.pop()))

            elif op == OP_UNPACK_SEQUENCE:
                seq = list(stack.pop())
                if len(seq) != arg:
                    raise ValueError(
                        "%s %d values to unpack (expected %d)"
                        % ("not enough" if len(seq) < arg else "too many", len(seq), arg)
                    )
                for v in reversed(seq):
                    stack.append(v)

            elif op == OP_UNPACK_EX:
                before = arg & 0xFF
                after = arg >> 8
                seq = list(stack.pop())
                if len(seq) < before + after:
                    raise ValueError("not enough values to unpack")
                head = seq[:before]
                star = seq[before:len(seq) - after]
                tail = seq[len(seq) - after:]
                for v in reversed(tail):
                    stack.append(v)
                stack.append(star)
                for v in reversed(head):
                    stack.append(v)

            elif op == OP_GET_ITER:
                stack.append(iter(stack.pop()))

            elif op == OP_FOR_ITER:
                it = stack[-1]
                try:
                    stack.append(next(it))
                except StopIteration:
                    ip = arg

            elif op == OP_JUMP:
                ip = arg

            elif op == OP_POP_JUMP_IF_TRUE:
                if stack.pop():
                    ip = arg

            elif op == OP_POP_JUMP_IF_FALSE:
                if not stack.pop():
                    ip = arg

            elif op == OP_POP_JUMP_IF_NONE:
                if stack.pop() is None:
                    ip = arg

            elif op == OP_POP_JUMP_IF_NOT_NONE:
                if stack.pop() is not None:
                    ip = arg

            elif op == OP_CALL:
                if arg:
                    cargs = stack[-arg:]
                    del stack[len(stack) - arg:]
                else:
                    cargs = []
                self_or_null = stack.pop()
                func = stack.pop()
                if func is _NULL:
                    stack.append(self_or_null(*cargs))
                elif self_or_null is _NULL:
                    stack.append(func(*cargs))
                else:
                    stack.append(func(self_or_null, *cargs))

            elif op == OP_CALL_KW:
                kwnames = stack.pop()
                if arg:
                    allargs = stack[-arg:]
                    del stack[len(stack) - arg:]
                else:
                    allargs = []
                nkw = len(kwnames)
                posargs = allargs[:len(allargs) - nkw]
                kwvals = allargs[len(allargs) - nkw:]
                kwargs = dict(zip(kwnames, kwvals))
                self_or_null = stack.pop()
                func = stack.pop()
                if func is _NULL:
                    stack.append(self_or_null(*posargs, **kwargs))
                elif self_or_null is not _NULL:
                    posargs = [self_or_null] + posargs
                    stack.append(func(*posargs, **kwargs))
                else:
                    stack.append(func(*posargs, **kwargs))

            elif op == OP_CALL_FUNCTION_EX:
                kwargs = stack.pop() if (arg & 1) else {}
                callargs = stack.pop()
                self_or_null = stack.pop()
                func = stack.pop()
                if func is _NULL:
                    stack.append(self_or_null(*callargs, **kwargs))
                elif self_or_null is not _NULL:
                    callargs = (self_or_null,) + tuple(callargs)
                    stack.append(func(*callargs, **kwargs))
                else:
                    stack.append(func(*callargs, **kwargs))

            elif op == OP_MAKE_FUNCTION:
                fn_code = <GIRCodeObj>stack.pop()
                stack.append(_make_gir_function(fn_code, globs, builtins_ns))

            elif op == OP_SET_FUNCTION_ATTRIBUTE:
                fn = <GIRFunction>stack.pop()
                value = stack.pop()
                if arg == 1:
                    fn.defaults = tuple(value)
                elif arg == 2:
                    fn.kwdefaults = dict(value)
                elif arg == 4:
                    fn.annotations = value
                elif arg == 8:
                    fn.closure = tuple(value)
                stack.append(fn)

            elif op == OP_IMPORT_NAME:
                fromlist = stack.pop()
                level = stack.pop()
                mod_name = names[arg]
                stack.append(builtins_ns["__import__"](mod_name, globs, globs, fromlist, level))

            elif op == OP_IMPORT_FROM:
                mod = stack[-1]
                attr = names[arg]
                try:
                    stack.append(getattr(mod, attr))
                except AttributeError:
                    full = getattr(mod, "__name__", "") + "." + attr
                    submod = _importlib.import_module(full)
                    stack.append(submod)

            elif op == OP_IMPORT_STAR:
                mod = stack.pop()
                export = getattr(mod, "__all__", None)
                if export is None:
                    export = [n for n in vars(mod) if not n.startswith("_")]
                for nm2 in export:
                    globs[nm2] = getattr(mod, nm2)

            elif op == OP_RAISE_VARARGS:
                if arg == 0:
                    if current_exception is None:
                        raise RuntimeError("No active exception to re-raise")
                    raise current_exception
                elif arg == 1:
                    exc = stack.pop()
                    if isinstance(exc, type):
                        exc = exc()
                    raise exc
                else:
                    cause = stack.pop()
                    exc = stack.pop()
                    if isinstance(exc, type):
                        exc = exc()
                    if isinstance(cause, type):
                        cause = cause()
                    raise exc from cause

            elif op == OP_RERAISE:
                exc = stack.pop()
                if arg:
                    stack.pop()
                raise exc

            elif op == OP_PUSH_EXC_INFO:
                exc = stack.pop()
                stack.append(current_exception)
                stack.append(exc)
                current_exception = exc

            elif op == OP_POP_EXCEPT:
                current_exception = stack.pop()

            elif op == OP_CHECK_EXC_MATCH:
                exc_type = stack.pop()
                exc = stack[-1]
                stack.append(isinstance(exc, exc_type))

            elif op == OP_CHECK_EG_MATCH:
                match_type = stack.pop()
                exc = stack.pop()
                match_part, rest_part = _eg_split(exc, match_type)
                stack.append(rest_part)
                stack.append(match_part)

            elif op == OP_CALL_INTRINSIC_2:
                if arg == INTRINSIC_PREP_RERAISE_STAR:
                    excs = stack.pop()
                    orig = stack.pop()
                    stack.append(_prep_reraise_star(orig, excs))
                else:
                    stack.pop(); stack.pop()   # unknown intrinsic -> drop args, push nothing meaningful
                    stack.append(None)

            elif op == OP_END_ASYNC_FOR:
                exc = stack.pop()
                stack.pop()  # the async iterator/awaitable, discarded either way
                if not isinstance(exc, StopAsyncIteration):
                    raise exc

            elif op == OP_CONVERT_VALUE:
                val = stack.pop()
                if arg == 1:
                    stack.append(str(val))
                elif arg == 2:
                    stack.append(repr(val))
                elif arg == 3:
                    stack.append(ascii(val))
                else:
                    stack.append(val)

            elif op == OP_FORMAT_SIMPLE:
                val = stack.pop()
                stack.append(val if isinstance(val, str) else format(val, ""))

            elif op == OP_FORMAT_WITH_SPEC:
                spec = stack.pop()
                val = stack.pop()
                stack.append(format(val, spec))

            elif op == OP_GET_LEN:
                # Peek, don't pop -> the length check is one of several
                # conditions chained against the still-live subject/sequence.
                stack.append(len(stack[-1]))

            elif op == OP_MATCH_MAPPING:
                stack.append(isinstance(stack[-1], _abc_mod.Mapping))

            elif op == OP_MATCH_SEQUENCE:
                subj = stack[-1]
                stack.append(isinstance(subj, _abc_mod.Sequence)
                              and not isinstance(subj, (str, bytes, bytearray)))

            elif op == OP_MATCH_KEYS:
                # TOS = tuple of keys to look up, TOS1 = mapping subject.
                # Neither is popped; push a tuple of values (subject has
                # every key) or None (it doesn't).
                keys = stack[-1]
                subj = stack[-2]
                values = []
                found = True
                for k in keys:
                    try:
                        values.append(subj[k])
                    except (KeyError, TypeError):
                        found = False
                        break
                stack.append(tuple(values) if found else None)

            elif op == OP_MATCH_CLASS:
                kwd_names = stack.pop()
                cls = stack.pop()
                subj = stack.pop()
                stack.append(_match_class(subj, cls, arg, kwd_names))

            elif op == OP_BEFORE_WITH:
                cm = stack.pop()
                stack.append(cm.__exit__)
                stack.append(cm.__enter__())

            elif op == OP_WITH_EXCEPT_START:
                exc = stack[-1]
                exit_fn = stack[-4]
                res = exit_fn(type(exc), exc, exc.__traceback__)
                stack.append(res)

            else:
                raise RuntimeError("gnolly VM: unimplemented opcode %d" % op)

        except Exception as exc:
            handler = _find_handler(exc_table, cur_ip)
            if handler is None:
                raise
            h_start, h_end, h_target, h_depth, h_lasti = handler
            del stack[h_depth:]
            if h_lasti:
                stack.append(cur_ip)
            stack.append(exc)
            ip = h_target

    return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def vm_exec_module(blob, table_blob, dict globs=None):
    """
    Deserialise and execute a GIR module blob.

    Equivalent to "exec(compile(source, ..., 'exec'), globs)" but the
    "compile" step is gnolly.vm_translate (done at protect-time) and
    the "exec" step is this interpreter -> CPython's eval loop is never invoked on the protected code.

    blob, table_blob: bytes, bytearray, or memoryview is taken as-is
        and is deliberately NOT typed as bytes so the
        caller can pass a bytearray it intends to zero afterward without
        this call forcing one more un-wipeable immutable copy into existence.
    """
    cdef GIRCodeObj code = deserialize_vm_blob(blob, table_blob)

    if globs is None:
        globs = {
            "__name__": "__main__",
            "__builtins__": _builtins_mod,
            "__doc__": None,
            "__package__": None,
            "__spec__": None,
        }

    bmod = globs.get("__builtins__", _builtins_mod)
    if isinstance(bmod, dict):
        builtins_ns = bmod
    else:
        builtins_ns = vars(bmod)

    cdef list fastlocals = [_UNSET] * code.nlocals
    cdef list cells = _make_cells(code, fastlocals, ())

    run_frame(code, fastlocals, cells, globs, builtins_ns, globs)


# ===========================================================================
# Generator / Coroutine / Async-Generator Support
# ===========================================================================
#
# Design
# ------
# Generators in the GIR VM work via suspended frame state:
#
#   1. When GIRFunction.__call__() sees CO_GENERATOR / CO_COROUTINE / CO_ASYNC_GEN
#      in code.flags, it creates a GIRGenerator / GIRCoroutine / GIRAsyncGenerator
#      object instead of calling run_frame() directly.
#
#   2. The generator object stores: code, fastlocals, cells, globs, builtins,
#      locals_dict, current_stack (list), current_ip (int), current_exception.
#      This is exactly the frame state that run_frame() needs.
#
#   3. run_gen_frame() is a variant of run_frame() that:
#      - Starts from saved_ip (not 0) with saved_stack
#      - On YIELD_VALUE: saves state and raises _GIRYield(value) internally;
#        the generator object catches it, saves state, returns yielded value.
#      - On RETURN_VALUE / RETURN_CONST: raises StopIteration(value).
#      - On unhandled exception: propagates normally.
#
#   4. SEND semantics: send(value) puts value into the frame by storing it
#      as the "resume value" which YIELD_VALUE then pushes onto the stack
#      (replacing itself as the push target -> see CPython's RESUME opcode
#      with arg=1 following every YIELD_VALUE).
#
# Coroutines / async generators use the same machinery; the difference is
# in the type of object created and how the event loop drives them.

# ---------------------------------------------------------------------------
# New GIR opcode numbers (must match vm_isa.py)
# ---------------------------------------------------------------------------
cdef enum:
    OP_RETURN_GENERATOR  = 89
    OP_YIELD_VALUE       = 90
    OP_SEND              = 91
    OP_END_SEND          = 92
    OP_GET_AWAITABLE     = 93
    OP_GET_AITER         = 94
    OP_GET_ANEXT         = 95
    OP_ASYNC_GEN_ASEND   = 96
    OP_CLEANUP_THROW     = 97
    OP_CALL_INTRINSIC_1  = 98
    OP_LOAD_SUPER_ATTR   = 99
    OP_CHECK_EG_MATCH    = 100
    OP_CALL_INTRINSIC_2  = 101
    OP_END_ASYNC_FOR     = 102

# Internal sentinel -> raised by run_gen_frame() to signal a yield.
# Never escapes to user code.
class _GIRYield(BaseException):
    __slots__ = ("value",)
    def __init__(self, value):
        self.value = value

# CO_FLAGS values
cdef int CO_GENERATOR_FLAG = 0x20
cdef int CO_COROUTINE_FLAG = 0x80
cdef int CO_ASYNC_GEN_FLAG = 0x200

# CALL_INTRINSIC_1 arg values
cdef int INTRINSIC_STOPITERATION_ERROR = 3
cdef int INTRINSIC_ASYNC_GEN_ASEND     = 4

# CALL_INTRINSIC_2 arg values
cdef int INTRINSIC_PREP_RERAISE_STAR   = 1


# ---------------------------------------------------------------------------
# Suspended frame state (shared between generator/coroutine/async-gen)
# ---------------------------------------------------------------------------

cdef class _GIRFrameState:
    """
    Frozen snapshot of a GIR interpreter frame, used to suspend and resume
    generator / coroutine / async-generator execution.
    """
    cdef public GIRCodeObj code
    cdef public list fastlocals
    cdef public list cells
    cdef public dict globs
    cdef public dict builtins_ns
    cdef public object locals_dict
    cdef public list stack
    cdef public long long ip
    cdef public object current_exception
    cdef public bint started
    cdef public bint exhausted
    cdef public bint is_async_gen

    def __init__(self, GIRCodeObj code, list fastlocals, list cells,
                 dict globs, dict builtins_ns, object locals_dict):
        self.code = code
        self.fastlocals = fastlocals
        self.cells = cells
        self.globs = globs
        self.builtins_ns = builtins_ns
        self.locals_dict = locals_dict
        self.stack = []
        self.ip = 0
        self.current_exception = None
        self.started = False
        self.exhausted = False
        self.is_async_gen = bool(code.flags & 0x200)


# ---------------------------------------------------------------------------
# Generator object
# ---------------------------------------------------------------------------

cdef class GIRGenerator:
    """
    Iterator produced by a GIR generator function (co_flags & 0x20).
    Implements: __iter__, __next__, send, throw, close.
    """
    cdef _GIRFrameState _frame
    cdef public str gi_name
    cdef public str gi_qualname

    def __init__(self, _GIRFrameState frame):
        self._frame = frame
        self.gi_name = frame.code.name
        self.gi_qualname = frame.code.qualname

    def __repr__(self):
        state = "running" if self._frame.started and not self._frame.exhausted else \
                ("closed" if self._frame.exhausted else "created")
        return "<gnolly-generator object %s at 0x%x (%s)>" % (
            self.gi_qualname, id(self), state)

    def __iter__(self):
        return self

    def __next__(self):
        return self.send(None)

    def send(self, value):
        if self._frame.exhausted:
            raise StopIteration
        if not self._frame.started and value is not None:
            raise TypeError("can't send non-None value to a just-started generator")
        self._frame.started = True
        return _resume_gen_frame(self._frame, value)

    def throw(self, typ, val=None, tb=None):
        if self._frame.exhausted:
            raise StopIteration
        if isinstance(typ, type):
            if val is None:
                val = typ()
            elif not isinstance(val, typ):
                val = typ(val)
        else:
            val = typ
        return _resume_gen_frame_throw(self._frame, val)

    def close(self):
        try:
            self.throw(GeneratorExit)
        except (GeneratorExit, StopIteration):
            pass
        except Exception:
            raise
        self._frame.exhausted = True


# ---------------------------------------------------------------------------
# Coroutine object
# ---------------------------------------------------------------------------

cdef class GIRCoroutine:
    """
    Awaitable produced by an async def GIR function (co_flags & 0x80).
    Implements the coroutine protocol: __await__, send, throw, close.
    """
    cdef _GIRFrameState _frame
    cdef public str cr_name
    cdef public str cr_qualname

    def __init__(self, _GIRFrameState frame):
        self._frame = frame
        self.cr_name = frame.code.name
        self.cr_qualname = frame.code.qualname

    def __repr__(self):
        return "<gnolly-coroutine object %s at 0x%x>" % (self.cr_qualname, id(self))

    def __await__(self):
        return _GIRCoroutineIter(self)

    def send(self, value):
        if self._frame.exhausted:
            raise StopIteration
        self._frame.started = True
        return _resume_gen_frame(self._frame, value)

    def throw(self, typ, val=None, tb=None):
        if self._frame.exhausted:
            raise StopIteration
        if isinstance(typ, type):
            val = typ() if val is None else typ(val)
        else:
            val = typ
        return _resume_gen_frame_throw(self._frame, val)

    def close(self):
        try:
            self.throw(GeneratorExit)
        except (GeneratorExit, StopIteration):
            pass
        self._frame.exhausted = True


cdef class _GIRCoroutineIter:
    """Iterator wrapper so GIRCoroutine can be used in 'await' expressions."""
    cdef GIRCoroutine _coro

    def __init__(self, GIRCoroutine coro):
        self._coro = coro

    def __iter__(self):
        return self

    def __next__(self):
        return self._coro.send(None)

    def send(self, value):
        return self._coro.send(value)

    def throw(self, *args):
        return self._coro.throw(*args)


# ---------------------------------------------------------------------------
# Async-generator object
# ---------------------------------------------------------------------------

cdef class GIRAsyncGenerator:
    """
    Async iterable produced by an async generator function (co_flags & 0x200).
    Implements __aiter__ and __anext__.
    """
    cdef _GIRFrameState _frame
    cdef public str ag_name
    cdef public str ag_qualname

    def __init__(self, _GIRFrameState frame):
        self._frame = frame
        self.ag_name = frame.code.name
        self.ag_qualname = frame.code.qualname

    def __repr__(self):
        return "<gnolly-async_generator object %s at 0x%x>" % (self.ag_qualname, id(self))

    def __aiter__(self):
        return self

    def __anext__(self):
        return _GIRAsyncGenASend(self, None)

    def asend(self, value):
        return _GIRAsyncGenASend(self, value)

    def athrow(self, typ, val=None, tb=None):
        return _GIRAsyncGenAThrow(self, typ, val, tb)


cdef class _GIRAsyncGenASend:
    """Awaitable that drives one step of an async generator."""
    cdef GIRAsyncGenerator _agen
    cdef object _value

    def __init__(self, GIRAsyncGenerator agen, value):
        self._agen = agen
        self._value = value

    def __await__(self):
        return self

    def __iter__(self):
        return self

    def __next__(self):
        return self.send(None)

    def send(self, value):
        cdef _GIRFrameState frame = self._agen._frame
        if frame.exhausted:
            raise StopAsyncIteration
        frame.started = True
        cdef object result
        cdef bint did_return = False
        cdef long long resume_ip
        cdef int resume_arg
        cdef list instrs
        try:
            result = _resume_gen_frame(frame, self._value)
            did_return = True
        except StopIteration as e:
            frame.exhausted = True
            raise StopAsyncIteration from e
        except StopAsyncIteration:
            raise
        except BaseException:
            frame.exhausted = True
            raise
        if did_return:
            resume_ip = frame.ip
            resume_arg = -1
            instrs = frame.code.instructions
            if 0 <= resume_ip < len(instrs):
                resume_arg = instrs[resume_ip][1]
            if resume_arg == 1:
                # Generator yield: deliver value to async for consumer.
                raise StopIteration(result)
            else:
                # Awaiting something: propagate to event loop.
                return result


cdef class _GIRAsyncGenAThrow:
    """Awaitable that throws into an async generator."""
    cdef GIRAsyncGenerator _agen
    cdef object _typ, _val, _tb

    def __init__(self, GIRAsyncGenerator agen, typ, val, tb):
        self._agen = agen; self._typ = typ; self._val = val; self._tb = tb

    def __await__(self):
        return self

    def __iter__(self):
        return self

    def __next__(self):
        return self.send(None)

    def send(self, ignored):
        return self._agen._frame and _resume_gen_frame_throw(
            self._agen._frame, self._typ if not isinstance(self._typ, type) else self._typ())


# ---------------------------------------------------------------------------
# The suspended-frame interpreter
# ---------------------------------------------------------------------------

cdef object _resume_gen_frame(_GIRFrameState frame, object send_value):
    """
    Resume a suspended generator/coroutine frame.

    Runs run_gen_frame() with the saved state.  If a YIELD_VALUE is hit,
    saves the state and returns the yielded value.  If the function returns
    (RETURN_VALUE / RETURN_CONST), raises StopIteration(return_value).
    """
    if frame.exhausted:
        raise StopIteration

    cdef object result
    try:
        result = run_gen_frame(frame, send_value)
    except _GIRYield as y:
        # Generator yielded -> state already saved inside run_gen_frame
        return y.value
    except StopIteration:
        frame.exhausted = True
        raise
    except GeneratorExit:
        frame.exhausted = True
        raise
    except BaseException:
        frame.exhausted = True
        raise

    # run_gen_frame returned normally -> generator is exhausted
    frame.exhausted = True
    raise StopIteration(result)


cdef object _resume_gen_frame_throw(_GIRFrameState frame, object exc):
    """Throw an exception into a suspended generator frame."""
    if frame.exhausted:
        raise exc

    # Inject the exception as the current_exception and run
    frame.current_exception = exc
    try:
        result = run_gen_frame(frame, None, throw_exc=exc)
    except _GIRYield as y:
        return y.value
    except StopIteration:
        frame.exhausted = True
        raise
    except BaseException:
        frame.exhausted = True
        raise

    frame.exhausted = True
    raise StopIteration(result)


def run_gen_frame(
    _GIRFrameState frame,
    object send_value,
    object throw_exc=None,
):
    """
    Generator-aware frame interpreter.

    Note: The _GIRFrameState is NOT passed directly here; instead, the caller
    (_resume_gen_frame) updates the frame's fields after _GIRYield is caught.
    The stack list is shared by reference so mutations here are visible.
    """
    cdef GIRCodeObj code = frame.code
    cdef list fastlocals = frame.fastlocals
    cdef list cells = frame.cells
    cdef dict globs = frame.globs
    cdef dict builtins_ns = frame.builtins_ns
    cdef object locals_dict = frame.locals_dict
    cdef list stack = frame.stack
    cdef list instructions = code.instructions
    cdef list consts = code.consts
    cdef list names = code.names
    cdef list varnames = code.varnames
    cdef list cellfree = code.cellfree
    cdef list exc_table = code.exc_table
    cdef Py_ssize_t n = len(instructions)
    cdef long long ip = frame.ip
    cdef long long cur_ip
    cdef object current_exception = frame.current_exception
    cdef bint resume_pending = (frame.ip > 2)

    cdef object _send_value = send_value

    cdef int op
    cdef long long arg

    # If there's an exception to throw, handle it at the current ip
    if throw_exc is not None:
        handler = _find_handler(exc_table, ip)
        if handler is not None:
            h_start, h_end, h_target, h_depth, h_lasti = handler
            del stack[h_depth:]
            if h_lasti:
                stack.append(ip)
            stack.append(throw_exc)
            ip = h_target
            current_exception = throw_exc
        else:
            raise throw_exc

    while ip < n:
        cur_ip = ip
        op = instructions[ip][0]
        arg = instructions[ip][1]
        ip += 1

        _tick_and_maybe_check(code)

        try:
            # ── Generator-specific opcodes ─────────────────────────────────
            if op == OP_RETURN_GENERATOR:
                pass

            elif op == OP_YIELD_VALUE:
                yielded = stack.pop()
                frame.ip = ip   # save position for next resume
                raise _GIRYield(yielded)

            elif op == OP_SEND:
                send_val = stack.pop()
                sub_iter = stack[-1]
                try:
                    if send_val is None:
                        sub_result = next(sub_iter)
                    else:
                        sub_result = sub_iter.send(send_val)

                    stack.append(sub_result)
                except StopIteration as e:
                    # Sub-iterator exhausted: pop it, push return value, jump past loop.
                    stack.pop()  # pop sub_iter
                    stack.append(e.value if e.args else None)
                    ip = arg

            elif op == OP_END_SEND:
                # Result of SEND is already on stack; nothing to do.
                pass

            elif op == OP_GET_AWAITABLE:
                # TOS must be a coroutine or have __await__. Wrap it.
                aw = stack.pop()
                if hasattr(aw, "__await__"):
                    stack.append(aw.__await__())
                else:
                    stack.append(aw)  # already an iterator

            elif op == OP_GET_AITER:
                obj = stack.pop()
                stack.append(obj.__aiter__())

            elif op == OP_GET_ANEXT:
                ait = stack[-1]
                stack.append(ait.__anext__())

            elif op == OP_ASYNC_GEN_ASEND:
                # Wrap async gen value in an asend awaitable
                val = stack.pop()
                stack.append(val)  # pass through; handled by async_gen machinery

            elif op == OP_CLEANUP_THROW:
                # Exception cleanup after throw into sub-generator.
                # The stack has the exception; re-raise it.
                exc = stack.pop() if stack else None
                if exc is not None:
                    raise exc

            elif op == OP_CALL_INTRINSIC_1:
                if arg == INTRINSIC_STOPITERATION_ERROR:
                    exc_val = stack.pop() if stack else None
                    if isinstance(exc_val, StopIteration):
                        msg = ("async generator raised StopIteration"
                               if frame.is_async_gen else
                               "generator raised StopIteration")
                        new_exc = RuntimeError(msg)
                        new_exc.__cause__ = exc_val
                        new_exc.__context__ = exc_val
                        stack.append(new_exc)
                    else:
                        stack.append(exc_val)
                elif arg == INTRINSIC_ASYNC_GEN_ASEND:
                    # Wrap TOS in async gen asend marker -> pass through for our runtime.
                    pass  # value stays on stack
                else:
                    pass  # unknown intrinsic -> treat as nop

            # ── RESUME in generator context ────────────────────────────────
            elif op == OP_RESUME:
                if arg > 0 and resume_pending:
                    # Push the value that was sent into the generator
                    stack.append(_send_value)
                    _send_value = None   # consume it
                    resume_pending = False

            # ── Control-flow opcodes (need ip in scope) ───────────────────
            elif op == OP_JUMP:
                ip = arg

            elif op == OP_POP_JUMP_IF_TRUE:
                if stack.pop(): ip = arg

            elif op == OP_POP_JUMP_IF_FALSE:
                if not stack.pop(): ip = arg

            elif op == OP_POP_JUMP_IF_NONE:
                if stack.pop() is None: ip = arg

            elif op == OP_POP_JUMP_IF_NOT_NONE:
                if stack.pop() is not None: ip = arg

            elif op == OP_FOR_ITER:
                it = stack[-1]
                try:
                    stack.append(next(it))
                except StopIteration:
                    ip = arg  # jump past loop; END_FOR will pop iterator

            # ── All other opcodes: delegate to shared dispatch ─────────────
            else:
                _run_one_op(op, arg, stack, fastlocals, cells, consts, names,
                            varnames, cellfree, globs, builtins_ns, locals_dict,
                            code)

        except _GIRYield:
            raise  # let _resume_gen_frame catch this

        except StopIteration:
            raise

        except GeneratorExit:
            raise

        except Exception as exc:
            handler = _find_handler(exc_table, cur_ip)
            if handler is None:
                raise
            h_start, h_end, h_target, h_depth, h_lasti = handler
            del stack[h_depth:]
            if h_lasti:
                stack.append(cur_ip)
            stack.append(exc)
            ip = h_target
            current_exception = exc

    return None


# ---------------------------------------------------------------------------
# Shared opcode dispatcher (extracted from run_frame to avoid duplication)
# ---------------------------------------------------------------------------

cdef void _run_one_op(
    int op, long long arg,
    list stack,
    list fastlocals,
    list cells,
    list consts,
    list names,
    list varnames,
    list cellfree,
    dict globs,
    dict builtins_ns,
    object locals_dict,
    GIRCodeObj code,
):
    """Execute a single non-generator GIR opcode, modifying stack in-place."""
    # Mirror of the run_frame dispatch; duplicated here for gen frames.
    # Only the opcodes that can appear in generator/coroutine bodies are needed,
    # but for completeness we include all of them.

    if op == OP_NOP or op == OP_RESUME:
        pass

    elif op == OP_POP_TOP:
        stack.pop()

    elif op == OP_PUSH_NULL:
        stack.append(_NULL)

    elif op == OP_COPY:
        stack.append(stack[-arg])

    elif op == OP_SWAP:
        stack[-1], stack[-arg] = stack[-arg], stack[-1]

    elif op == OP_RETURN_VALUE:
        val = stack.pop()
        raise StopIteration(val)

    elif op == OP_RETURN_CONST:
        raise StopIteration(consts[arg])

    elif op == OP_LOAD_CONST:
        stack.append(consts[arg])

    elif op == OP_LOAD_FAST:
        val = fastlocals[arg]
        if val is _UNSET:
            raise UnboundLocalError(
                "local variable '%s' referenced before assignment" % varnames[arg])
        stack.append(val)

    elif op == OP_STORE_FAST:
        fastlocals[arg] = stack.pop()

    elif op == OP_DELETE_FAST:
        fastlocals[arg] = _UNSET

    elif op == OP_LOAD_FAST_AND_CLEAR:
        val = fastlocals[arg]
        stack.append(None if val is _UNSET else val)
        fastlocals[arg] = _UNSET

    elif op == OP_LOAD_GLOBAL:
        namei = arg >> 1
        if arg & 1:
            stack.append(_NULL)
        nm = names[namei]
        if nm in globs:
            stack.append(globs[nm])
        elif nm in builtins_ns:
            stack.append(builtins_ns[nm])
        else:
            raise NameError("name '%s' is not defined" % nm)

    elif op == OP_STORE_GLOBAL:
        globs[names[arg]] = stack.pop()

    elif op == OP_LOAD_NAME:
        nm = names[arg]
        if nm in locals_dict:
            stack.append(locals_dict[nm])
        elif nm in globs:
            stack.append(globs[nm])
        elif nm in builtins_ns:
            stack.append(builtins_ns[nm])
        else:
            raise NameError("name '%s' is not defined" % nm)

    elif op == OP_STORE_NAME:
        locals_dict[names[arg]] = stack.pop()

    elif op == OP_LOAD_DEREF:
        cell = <Cell>cells[arg]
        if cell.value is _UNSET:
            raise NameError("free variable '%s' referenced before assignment" % cellfree[arg])
        stack.append(cell.value)

    elif op == OP_STORE_DEREF:
        (<Cell>cells[arg]).value = stack.pop()

    elif op == OP_LOAD_CLOSURE:
        stack.append(cells[arg])

    elif op == OP_LOAD_ATTR:
        namei = arg >> 1; method_flag = arg & 1
        obj = stack.pop(); val = getattr(obj, names[namei])
        if method_flag:
            stack.append(val)   # callable (deeper)
            stack.append(_NULL) # self_or_null sentinel (TOS)
        else:
            stack.append(val)

    elif op == OP_LOAD_SUPER_ATTR:
        # See run_frame's OP_LOAD_SUPER_ATTR for the full explanation; same
        # stack layout and semantics apply here for generator/coroutine frames.
        namei = arg >> 2; method_flag = arg & 1
        self_obj = stack.pop(); klass = stack.pop(); global_super = stack.pop()
        sup = global_super(klass, self_obj)
        val = getattr(sup, names[namei])
        if method_flag:
            stack.append(val)   # callable (deeper)
            stack.append(_NULL) # self_or_null sentinel (TOS)
        else:
            stack.append(val)

    elif op == OP_STORE_ATTR:
        obj = stack.pop(); val = stack.pop()
        setattr(obj, names[arg], val)

    elif op == OP_LOAD_SUBSCR:
        key = stack.pop(); container = stack.pop()
        stack.append(container[key])

    elif op == OP_STORE_SUBSCR:
        key = stack.pop(); container = stack.pop(); val = stack.pop()
        container[key] = val

    elif op == OP_BINARY_SLICE:
        stop = stack.pop(); start = stack.pop(); container = stack.pop()
        stack.append(container[start:stop])

    elif op == OP_LOAD_BUILD_CLASS:
        stack.append(_gir_build_class)

    elif op == OP_UNARY_NOT:
        stack.append(not stack.pop())
    elif op == OP_UNARY_NEGATIVE:
        stack.append(_op.neg(stack.pop()))
    elif op == OP_UNARY_INVERT:
        stack.append(_op.invert(stack.pop()))

    elif op == OP_BINARY_OP:
        rhs = stack.pop(); lhs = stack.pop()
        stack.append(_BINOPS[arg](lhs, rhs))

    elif op == OP_COMPARE_OP:
        rhs = stack.pop(); lhs = stack.pop()
        stack.append(_CMPOPS[arg](lhs, rhs))

    elif op == OP_IS_OP:
        rhs = stack.pop(); lhs = stack.pop()
        stack.append((lhs is not rhs) if arg else (lhs is rhs))

    elif op == OP_CONTAINS_OP:
        container = stack.pop(); item = stack.pop()
        result = item in container
        stack.append((not result) if arg else result)

    elif op == OP_BUILD_TUPLE:
        items = stack[-arg:] if arg else []; del stack[len(stack)-arg:]
        stack.append(tuple(items))

    elif op == OP_BUILD_LIST:
        items = stack[-arg:] if arg else []; del stack[len(stack)-arg:]
        stack.append(list(items))

    elif op == OP_BUILD_SET:
        items = stack[-arg:] if arg else []; del stack[len(stack)-arg:]
        stack.append(set(items))

    elif op == OP_BUILD_MAP:
        d = {}
        if arg & 0x8000:
            n = arg & 0x7FFF
            keys = stack.pop()
            vals = stack[-n:]; del stack[len(stack)-n:]
            d = dict(zip(keys, vals))
        elif arg:
            items = stack[-(2*arg):]; del stack[len(stack)-2*arg:]
            for i in range(0, len(items), 2):
                d[items[i]] = items[i+1]
        stack.append(d)

    elif op == OP_BUILD_STRING:
        items = stack[-arg:] if arg else []; del stack[len(stack)-arg:]
        stack.append("".join(items))

    elif op == OP_LIST_APPEND:
        val = stack.pop(); stack[-arg].append(val)
    elif op == OP_SET_ADD:
        val = stack.pop(); stack[-arg].add(val)
    elif op == OP_MAP_ADD:
        val = stack.pop(); key = stack.pop(); stack[-arg][key] = val
    elif op == OP_LIST_EXTEND:
        val = stack.pop(); stack[-arg].extend(val)
    elif op == OP_SET_UPDATE:
        val = stack.pop(); stack[-arg].update(val)
    elif op == OP_DICT_UPDATE:
        val = stack.pop(); stack[-arg].update(val)
    elif op == OP_LIST_TO_TUPLE:
        stack.append(tuple(stack.pop()))

    elif op == OP_UNPACK_SEQUENCE:
        seq = list(stack.pop())
        if len(seq) != arg:
            raise ValueError("wrong number of values to unpack (expected %d)" % arg)
        for v in reversed(seq):
            stack.append(v)

    elif op == OP_UNPACK_EX:
        before = arg & 0xFF; after = arg >> 8
        seq = list(stack.pop())
        head = seq[:before]; star = seq[before:len(seq)-after]; tail = seq[len(seq)-after:]
        for v in reversed(tail): stack.append(v)
        stack.append(star)
        for v in reversed(head): stack.append(v)

    elif op == OP_GET_ITER:
        stack.append(iter(stack.pop()))

    elif op == OP_FOR_ITER:
        it = stack[-1]
        try:
            stack.append(next(it))
        except StopIteration:
            ip = arg  # note: ip not in scope here; handled by caller

    elif op == OP_JUMP:
        pass  # handled by caller

    elif op == OP_POP_JUMP_IF_TRUE:
        pass

    elif op == OP_POP_JUMP_IF_FALSE:
        pass

    elif op == OP_POP_JUMP_IF_NONE:
        pass

    elif op == OP_POP_JUMP_IF_NOT_NONE:
        pass

    elif op == OP_CALL:
        cargs = stack[-arg:] if arg else []; del stack[len(stack)-arg:]
        self_or_null = stack.pop()
        func = stack.pop()
        if func is _NULL:
            stack.append(self_or_null(*cargs))
        elif self_or_null is _NULL:
            stack.append(func(*cargs))
        else:
            stack.append(func(self_or_null, *cargs))

    elif op == OP_CALL_KW:
        kwnames = stack.pop()
        allargs = stack[-arg:] if arg else []; del stack[len(stack)-arg:]
        nkw = len(kwnames)
        posargs = allargs[:len(allargs)-nkw]; kwvals = allargs[len(allargs)-nkw:]
        kwargs = dict(zip(kwnames, kwvals))
        self_or_null = stack.pop(); func = stack.pop()
        if func is _NULL:
            stack.append(self_or_null(*posargs, **kwargs))
        elif self_or_null is not _NULL:
            posargs = [self_or_null] + posargs
            stack.append(func(*posargs, **kwargs))
        else:
            stack.append(func(*posargs, **kwargs))

    elif op == OP_CALL_FUNCTION_EX:
        kwargs = stack.pop() if (arg & 1) else {}
        callargs = stack.pop(); self_or_null = stack.pop(); func = stack.pop()
        if func is _NULL:
            stack.append(self_or_null(*callargs, **kwargs))
        elif self_or_null is not _NULL:
            callargs = (self_or_null,) + tuple(callargs)
            stack.append(func(*callargs, **kwargs))
        else:
            stack.append(func(*callargs, **kwargs))

    elif op == OP_MAKE_FUNCTION:
        fn_code = <GIRCodeObj>stack.pop()
        stack.append(_make_gir_function(fn_code, globs, builtins_ns))

    elif op == OP_SET_FUNCTION_ATTRIBUTE:
        fn = <GIRFunction>stack.pop(); value = stack.pop()
        if arg == 1:   fn.defaults   = tuple(value)
        elif arg == 2: fn.kwdefaults = dict(value)
        elif arg == 4: fn.annotations = value
        elif arg == 8: fn.closure     = tuple(value)
        stack.append(fn)

    elif op == OP_IMPORT_NAME:
        fromlist = stack.pop(); level = stack.pop()
        stack.append(builtins_ns["__import__"](names[arg], globs, globs, fromlist, level))

    elif op == OP_IMPORT_FROM:
        mod = stack[-1]; attr = names[arg]
        try:
            stack.append(getattr(mod, attr))
        except AttributeError:
            stack.append(_importlib.import_module(getattr(mod, "__name__", "") + "." + attr))

    elif op == OP_RAISE_VARARGS:
        if arg == 0:
            raise RuntimeError("No active exception to re-raise")
        elif arg == 1:
            exc = stack.pop()
            raise (exc() if isinstance(exc, type) else exc)
        else:
            cause = stack.pop(); exc = stack.pop()
            raise (exc() if isinstance(exc, type) else exc) from (cause() if isinstance(cause, type) else cause)

    elif op == OP_RERAISE:
        exc = stack.pop()
        if arg: stack.pop()
        raise exc

    elif op == OP_PUSH_EXC_INFO:
        exc = stack.pop()
        stack.append(None)
        stack.append(exc)

    elif op == OP_POP_EXCEPT:
        stack.pop()

    elif op == OP_CHECK_EXC_MATCH:
        exc_type = stack.pop(); exc = stack[-1]
        stack.append(isinstance(exc, exc_type))

    elif op == OP_CHECK_EG_MATCH:
        match_type = stack.pop(); exc = stack.pop()
        match_part, rest_part = _eg_split(exc, match_type)
        stack.append(rest_part)
        stack.append(match_part)

    elif op == OP_CALL_INTRINSIC_2:
        if arg == INTRINSIC_PREP_RERAISE_STAR:
            excs = stack.pop(); orig = stack.pop()
            stack.append(_prep_reraise_star(orig, excs))
        else:
            stack.pop(); stack.pop()
            stack.append(None)

    elif op == OP_END_ASYNC_FOR:
        exc = stack.pop()
        stack.pop()
        if not isinstance(exc, StopAsyncIteration):
            raise exc

    elif op == OP_BEFORE_WITH:
        cm = stack.pop()
        stack.append(cm.__exit__)
        stack.append(cm.__enter__())

    elif op == OP_WITH_EXCEPT_START:
        exc = stack[-1]; exit_fn = stack[-4]
        res = exit_fn(type(exc), exc, exc.__traceback__)
        stack.append(res)

    elif op == OP_CONVERT_VALUE:
        val = stack.pop()
        if arg == 1: stack.append(str(val))
        elif arg == 2: stack.append(repr(val))
        elif arg == 3: stack.append(ascii(val))
        else: stack.append(val)

    elif op == OP_FORMAT_SIMPLE:
        val = stack.pop()
        stack.append(val if isinstance(val, str) else format(val, ""))

    elif op == OP_FORMAT_WITH_SPEC:
        spec = stack.pop(); val = stack.pop()
        stack.append(format(val, spec))

    elif op == OP_GET_LEN:
        stack.append(len(stack[-1]))

    elif op == OP_MATCH_MAPPING:
        stack.append(isinstance(stack[-1], _abc_mod.Mapping))

    elif op == OP_MATCH_SEQUENCE:
        subj = stack[-1]
        stack.append(isinstance(subj, _abc_mod.Sequence)
                      and not isinstance(subj, (str, bytes, bytearray)))

    elif op == OP_MATCH_KEYS:
        keys = stack[-1]; subj = stack[-2]
        values = []; found = True
        for k in keys:
            try:
                values.append(subj[k])
            except (KeyError, TypeError):
                found = False
                break
        stack.append(tuple(values) if found else None)

    elif op == OP_MATCH_CLASS:
        kwd_names = stack.pop(); cls = stack.pop(); subj = stack.pop()
        stack.append(_match_class(subj, cls, arg, kwd_names))

    # Generator opcodes handled by run_gen_frame; shouldn't appear here
    # but are silently ignored if they do.


# ---------------------------------------------------------------------------
# Update GIRFunction.__call__ to create generator/coroutine objects
# ---------------------------------------------------------------------------
# We need to override the __call__ method defined earlier to check co_flags.
# In Cython we can't easily patch the method, so we use a module-level init
# that replaces the dispatch. Instead, we override by extending GIRFunction.

# This is the updated __call__ that checks for generator/coroutine:
cdef class _GIRFunctionWithGenSupport(GIRFunction):
    """Extended GIRFunction that returns generator/coroutine objects."""

    def __call__(self, *args, **kwargs):
        cdef GIRCodeObj code = self.code
        cdef list fastlocals = _bind_args(code, args, kwargs, self.defaults, self.kwdefaults)
        cdef list cells = _make_cells(code, fastlocals, self.closure)

        # Check if this is a generator, coroutine, or async-generator
        if code.flags & CO_GENERATOR_FLAG:
            frame = _GIRFrameState(code, fastlocals, cells, self.globals, self.builtins, fastlocals)
            frame.ip = 2
            return GIRGenerator(frame)

        elif code.flags & CO_COROUTINE_FLAG:
            frame = _GIRFrameState(code, fastlocals, cells, self.globals, self.builtins, fastlocals)
            frame.ip = 2
            return GIRCoroutine(frame)

        elif code.flags & CO_ASYNC_GEN_FLAG:
            frame = _GIRFrameState(code, fastlocals, cells, self.globals, self.builtins, fastlocals)
            frame.ip = 2
            return GIRAsyncGenerator(frame)

        else:
            # Normal function -> run immediately
            return run_frame(code, fastlocals, cells, self.globals, self.builtins, fastlocals)


# Monkey-patch We update the OP_MAKE_FUNCTION handler in run_frame and run_gen_frame to always create _GIRFunctionWithGenSupport.

# Override run_frame's MAKE_FUNCTION to use the extended class:
# (We'll patch via a module-level replacement of GIRFunction used in run_frame)

# Initialize the function factory with the generator-aware class
_gir_fn_class = _GIRFunctionWithGenSupport
