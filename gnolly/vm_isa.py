"""
gnolly.vm_isa
~~~~~~~~~~~~~

Defines the Gnolly Instruction Set Architecture (GIR) -> a private,
stack-based bytecode format with CPython-equivalent semantics but its
own opcode numbering, its own operand encoding, and its own jump model
(instruction-index targets instead of byte offsets).

This is the foundation of the "opcode remapping VM":

  * GIR opcodes are NOT CPython opcodes. "dis" cannot decode a GIR
    stream -> there is only a custom binary blob (see gnolly.vm_serialize).
  * The 0-102 internal GIR opcode numbers are additionally shuffled
    per-file via a SHAKE-256 + Fisher-Yates permutation over the full
    256-entry byte space. The reverse
    table travels with the encrypted payload.
  * Execution happens entirely inside a custom Cython interpreter
    ("gnolly._gnolly_vm") that walks the GIR instruction stream and
    re-implements each operation using CPython's C-API.  CPython's own
    eval loop (``ceval.c``) never runs on user code.

Design notes
------------
GIR mirrors CPython 3.14 bytecode semantics closely (same stack effects
for the opcodes it supports) so the translator
("gnolly.vm_translate") can stay a largely mechanical 1:1 pass. (I will work on a proper implementation eventually)

Differences from CPython bytecode:
  * No inline cache / specialisation words
  * Jump operands are GIR instruction indices, not byte offsets. No "EXTENDED_ARG" needed; operands are variable-length varints.
  * "RESUME" is kept however as a documented no-op (non operational) for structural parity but
    carries no meaning at runtime.

Unsupported constructs (cause protection to ABORT with a clear error -> there is no fallback to a less-protected execution mode):
  any opcode not listed in GIR_OPS below.
"""
from __future__ import annotations
import hashlib
import struct


# ---------------------------------------------------------------------------
# GIR opcode table
# ---------------------------------------------------------------------------
# Numbers are arbitrary internal IDs (0..N-1).  They are NOT exposed in the
# serialized stream directly -> "build_vm_shuffle_table()" permutes them per
# file before the stream is written, and the interpreter un-permutes them
# using the stored reverse table before dispatch.

GIR_OPS: dict[str, int] = {
    # ── misc / stack ──────────────────────────────────────────────────────
    "NOP":                  0,
    "RESUME":               1,
    "POP_TOP":              2,
    "END_FOR":              2,   # alias: identical semantics to POP_TOP
    "PUSH_NULL":            3,
    "COPY":                 4,
    "SWAP":                 5,

    # ── return ────────────────────────────────────────────────────────────
    "RETURN_VALUE":         6,
    "RETURN_CONST":         7,

    # ── constants / fast locals ──────────────────────────────────────────
    "LOAD_CONST":           8,
    "LOAD_FAST":            9,
    "STORE_FAST":          10,
    "DELETE_FAST":         11,
    "LOAD_FAST_AND_CLEAR": 12,

    # ── globals / module names ──────────────────────────────────────────
    "LOAD_GLOBAL":         13,   # arg: (name_idx << 1) | push_null
    "STORE_GLOBAL":        14,
    "DELETE_GLOBAL":       15,
    "LOAD_NAME":           16,
    "STORE_NAME":          17,
    "DELETE_NAME":         18,

    # ── closures ─────────────────────────────────────────────────────────
    "LOAD_DEREF":          19,
    "STORE_DEREF":         20,
    "DELETE_DEREF":        21,
    "LOAD_CLOSURE":        22,
    "LOAD_FROM_DICT_OR_DEREF":   23,
    "LOAD_FROM_DICT_OR_GLOBALS": 24,

    # ── attributes / subscript ──────────────────────────────────────────
    "LOAD_ATTR":           25,   # arg: (name_idx << 1) | method_flag
    "STORE_ATTR":          26,
    "DELETE_ATTR":         27,
    "LOAD_SUBSCR":         28,
    "STORE_SUBSCR":        29,
    "DELETE_SUBSCR":       30,
    "BINARY_SLICE":        31,
    "STORE_SLICE":         32,
    "LOAD_BUILD_CLASS":    33,

    # ── operators ────────────────────────────────────────────────────────
    "UNARY_NOT":           34,
    "UNARY_NEGATIVE":      35,
    "UNARY_INVERT":        36,
    "BINARY_OP":           37,
    "COMPARE_OP":          38,
    "IS_OP":               39,
    "CONTAINS_OP":         40,

    # ── containers ───────────────────────────────────────────────────────
    "BUILD_TUPLE":         41,
    "BUILD_LIST":          42,
    "BUILD_SET":           43,
    "BUILD_MAP":           44,
    "BUILD_STRING":        45,
    "BUILD_SLICE":         46,
    "LIST_APPEND":         47,
    "SET_ADD":             48,
    "MAP_ADD":             49,
    "LIST_EXTEND":         50,
    "SET_UPDATE":          51,
    "DICT_UPDATE":         52,
    "DICT_MERGE":          53,
    "LIST_TO_TUPLE":       54,
    "UNPACK_SEQUENCE":     55,
    "UNPACK_EX":           56,

    # ── iteration / jumps ───────────────────────────────────────────────
    "GET_ITER":            57,
    "FOR_ITER":            58,
    "JUMP":                59,
    "POP_JUMP_IF_TRUE":    60,
    "POP_JUMP_IF_FALSE":   61,
    "POP_JUMP_IF_NONE":    62,
    "POP_JUMP_IF_NOT_NONE": 63,

    # ── calls / functions ───────────────────────────────────────────────
    "CALL":                64,
    "CALL_KW":             65,
    "CALL_FUNCTION_EX":    66,
    "MAKE_FUNCTION":       67,
    "SET_FUNCTION_ATTRIBUTE": 68,

    # ── classes / imports ───────────────────────────────────────────────
    "IMPORT_NAME":         69,
    "IMPORT_FROM":         70,
    "IMPORT_STAR":         71,

    # ── exceptions ───────────────────────────────────────────────────────
    "RAISE_VARARGS":       72,
    "RERAISE":             73,
    "PUSH_EXC_INFO":       74,
    "POP_EXCEPT":          75,
    "CHECK_EXC_MATCH":     76,

    # ── with-statements ─────────────────────────────────────────────────
    "BEFORE_WITH":         77,
    "WITH_EXCEPT_START":   78,

    # ── f-strings ────────────────────────────────────────────────────────
    "CONVERT_VALUE":       79,
    "FORMAT_SIMPLE":       80,
    "FORMAT_WITH_SPEC":    81,

    # ── misc ─────────────────────────────────────────────────────────────
    "GET_LEN":             82,
    "MATCH_KEYS":          83,
    "MATCH_MAPPING":       84,
    "MATCH_SEQUENCE":      85,
    "MATCH_CLASS":         86,
    "EXTENDED_ARG":        87,   # never emitted; varints make this unneeded
    "DELETE_FAST_RANGE":   88,
}


GIR_OPNAMES: dict[int, str] = {}
for _name, _num in GIR_OPS.items():
    GIR_OPNAMES.setdefault(_num, _name)

GIR_OP_COUNT = max(GIR_OPS.values()) + 1   # 89

GIR_JUMP_OPS = frozenset({
    GIR_OPS["JUMP"],
    GIR_OPS["FOR_ITER"],
    GIR_OPS["POP_JUMP_IF_TRUE"],
    GIR_OPS["POP_JUMP_IF_FALSE"],
    GIR_OPS["POP_JUMP_IF_NONE"],
    GIR_OPS["POP_JUMP_IF_NOT_NONE"],
})


# ---------------------------------------------------------------------------
# Per-file opcode permutation (GIR opcode space)
# ---------------------------------------------------------------------------
# SHAKE-256 + Fisher-Yates over a *256*-entry space -> the full range of a
# single byte. GIR itself only defines ~103 real opcodes (0..GIR_OP_COUNT-1);
# every remaining slot in the table is a decoy/invalid entry that a real
# instruction stream never emits. Those decoys still round-trip through the
# permutation and the serialized reverse table, so a reverse-engineer staring
# at the 256-entry reverse table can't tell real opcode mappings from noise
# without also recovering GIR_OPS itself.
#
# NOTE: this constant must be mirrored exactly in gnolly._gnolly_vm
# (GIR_TABLE_SIZE at the top of _gnolly_vm.pyx) -> protect-time and
# runtime must always agree on the table size, so bumping this requires
# rebuilding the Cython extension.

GIR_TABLE_SIZE = 256


def build_vm_shuffle_table(key: bytes) -> tuple[dict[int, int], dict[int, int]]:
    """
    Derive a stable GIR_TABLE_SIZE-entry bijection from *key*.

    Returns (forward, reverse):
      forward[gir_opcode]      -> shuffled byte written to the stream
      reverse[shuffled_byte]   -> gir_opcode (used by the interpreter)
    """
    stream = bytearray(hashlib.shake_256(b"gnolly-vm-opcode:" + key).digest(512))
    perm = list(range(GIR_TABLE_SIZE))
    idx = 0
    for i in range(GIR_TABLE_SIZE - 1, 0, -1):
        word = struct.unpack_from(">H", stream, idx % (len(stream) - 1))[0]
        idx += 2
        j = word % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    forward = {i: perm[i] for i in range(GIR_TABLE_SIZE)}
    reverse = {v: k for k, v in forward.items()}
    return forward, reverse


def serialise_vm_table(reverse: dict[int, int]) -> bytes:
    """GIR_TABLE_SIZE-byte reverse table: index = shuffled byte -> value = GIR opcode."""
    return bytes(reverse[i] for i in range(GIR_TABLE_SIZE))


# ---------------------------------------------------------------------------
# CPython operator code passthrough tables (for documentation / validation)
# ---------------------------------------------------------------------------
# BINARY_OP and COMPARE_OP operands are passed through verbatim from the
# CPython bytecode we translate from -> they're small enumerations baked
# into CPython's C-API (PyNumber_*, PyObject_RichCompare) and are stable
# across 3.11-3.14.
# Listed here purely for reference / interpreter dispatch tables.

NB_OPS = {
    0:  "+",   1:  "&",   2:  "//",  3:  "<<",  4:  "@",
    5:  "*",   6:  "%",   7:  "|",   8:  "**",  9:  ">>",
    10: "-",   11: "/",   12: "^",
    # in-place variants (13-25) mirror 0-12 with augmented assignment
    13: "+=",  14: "&=",  15: "//=", 16: "<<=", 17: "@=",
    18: "*=",  19: "%=",  20: "|=",  21: "**=", 22: ">>=",
    23: "-=",  24: "/=",  25: "^=",
}

CMP_OPS = ["<", "<=", "==", "!=", ">", ">="]


# ---------------------------------------------------------------------------
# Generator / coroutine / async opcodes
# ---------------------------------------------------------------------------

GIR_OPS.update({
    "RETURN_GENERATOR":     89,   # creates generator/coroutine/async-gen object
    "YIELD_VALUE":          90,   # suspends current generator frame
    "SEND":                 91,   # send value into sub-generator / awaitable
    "END_SEND":             92,   # pop awaitable result after SEND completion
    "GET_AWAITABLE":        93,   # wrap coroutine in awaitable (arg=0/1/2)
    "GET_AITER":            94,   # call __aiter__
    "GET_ANEXT":            95,   # call __anext__ -> awaitable
    "ASYNC_GEN_ASEND":      96,   # wrap async-gen value for iteration
    "CLEANUP_THROW":        97,   # generator throw cleanup
    "CALL_INTRINSIC_1":     98,   # CPython intrinsic dispatch (arg=3: StopIteration wrap, arg=4: async_gen wrap)
    "LOAD_SUPER_ATTR":      99,   # arg: (name_idx << 2) | (two_arg << 1) | method_flag
    "CHECK_EG_MATCH":      100,   # except* type match: pop(match_type, exc_value) -> push(rest, match)
    "CALL_INTRINSIC_2":    101,   # arg=1: INTRINSIC_PREP_RERAISE_STAR (used to implement except*)
    "END_ASYNC_FOR":       102,   # pop(awaitable, exc): if isinstance(exc, StopAsyncIteration) -> discard both, else re-raise exc
})

# Update opname reverse map
for _name, _num in GIR_OPS.items():
    GIR_OPNAMES.setdefault(_num, _name)

GIR_OP_COUNT = max(GIR_OPS.values()) + 1   # 99

# CO_FLAGS for generators/coroutines (used by translator and interpreter)
CO_FLAGS_GENERATOR  = 0x20
CO_FLAGS_COROUTINE  = 0x80
CO_FLAGS_ASYNC_GEN  = 0x200
