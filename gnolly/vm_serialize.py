"""
gnolly.vm_serialize
~~~~~~~~~~~~~~~~~~~

Custom binary format for class GIRCode objects -> the "custom serialiser"
half of the VM feature.

The format below is bespoke to Gnolly and is only meaningful
to gnolly._gnolly_vm.  A reverse-engineer who fully recovers this
format still only gets the GIR instruction stream -> semantically
equivalent to CPython bytecode, but numbered, ordered and packed
differently.

Container format (top-level blob, AFTER the GIR opcode shuffle has been
applied to every instruction stream -> see gnolly.vm_isa):

    u8      FORMAT_VERSION
    <CodeObject>                 - the module-level code object

<CodeObject> (recursive nested functions/comprehensions/lambdas are
stored as constants of `kind == K_CODE`):

    varint  argcount
    varint  posonlyargcount
    varint  kwonlyargcount
    varint  nlocals
    varint  stacksize
    u32     flags                - bit0 VARARGS, bit1 VARKEYWORDS,
                                     bit2 NESTED, bit3 has-free-vars
    varint  firstlineno
    str     name
    str     qualname
    str     filename
    strvec  varnames              - argnames + locals, in frame-slot order
    strvec  names                 - global/attr/name references
    strvec  freevars
    strvec  cellvars
    constvec consts
    varint  n_instr
    n_instr * (varint shuffled_opcode, varint operand)
    varint  n_exc
    n_exc   * (varint start, varint end, varint target, varint depth, u8 lasti)
    varint  n_lines
    n_lines * (varint instr_index, zigzag delta_lineno)   - sparse line map

Primitive value tags (`constvec` entries):

    0x00 None
    0x01 True
    0x02 False
    0x03 Ellipsis
    0x04 int      - u8 sign(0/1) + varint nbytes + big-endian magnitude
    0x05 float    - 8 bytes, IEEE-754 big-endian
    0x06 complex  - 16 bytes (real, imag), each IEEE-754 big-endian
    0x07 str      - varint length + UTF-8 bytes
    0x08 bytes    - varint length + raw bytes
    0x09 tuple    - varint count + N constvec entries
    0x0A frozenset- varint count + N constvec entries
    0x0B code     - recursive <CodeObject>

All integers are unsigned LEB128 varints unless noted;
jump/line deltas that may be negative use zigzag encoding (`(n << 1) ^ (n >> 63)`).
"""
from __future__ import annotations
import struct
from dataclasses import dataclass, field

from .vm_isa import GIR_TABLE_SIZE

FORMAT_VERSION = 1

# Constant tags
K_NONE, K_TRUE, K_FALSE, K_ELLIPSIS = 0x00, 0x01, 0x02, 0x03
K_INT, K_FLOAT, K_COMPLEX = 0x04, 0x05, 0x06
K_STR, K_BYTES = 0x07, 0x08
K_TUPLE, K_FROZENSET, K_CODE = 0x09, 0x0A, 0x0B

# CodeType flags (subset we care about for the VM frame builder)
CO_VARARGS    = 0x01
CO_VARKEYWORDS = 0x02
CO_NESTED     = 0x04
CO_HAS_FREE   = 0x08


@dataclass
class GIRCode:
    argcount: int
    posonlyargcount: int
    kwonlyargcount: int
    nlocals: int
    stacksize: int
    flags: int
    firstlineno: int
    name: str
    qualname: str
    filename: str
    varnames: list[str]
    names: list[str]
    freevars: list[str]
    cellvars: list[str]
    consts: list
    instructions: list[tuple[int, int]]          # (opcode, operand) -> opcode is the unshuffled GIR id
    exc_table: list[tuple[int, int, int, int, int]] = field(default_factory=list)
    line_map: list[tuple[int, int]] = field(default_factory=list)  # (instr_index, lineno)


# ---------------------------------------------------------------------------
# Varint helpers
# ---------------------------------------------------------------------------

def write_uvarint(out: bytearray, value: int) -> None:
    if value < 0:
        raise ValueError("write_uvarint requires a non-negative value")
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return


def write_svarint(out: bytearray, value: int) -> None:
    write_uvarint(out, (value << 1) ^ (value >> 63) if value < 0
                   else (value << 1))


def read_uvarint(buf: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7


def read_svarint(buf: bytes, pos: int) -> tuple[int, int]:
    raw, pos = read_uvarint(buf, pos)
    return (raw >> 1) ^ -(raw & 1), pos


def write_str(out: bytearray, s: str) -> None:
    data = s.encode("utf-8")
    write_uvarint(out, len(data))
    out.extend(data)


def read_str(buf: bytes, pos: int) -> tuple[str, int]:
    n, pos = read_uvarint(buf, pos)
    s = buf[pos:pos + n].decode("utf-8")
    return s, pos + n


def write_strvec(out: bytearray, items: list[str]) -> None:
    write_uvarint(out, len(items))
    for s in items:
        write_str(out, s)


def read_strvec(buf: bytes, pos: int) -> tuple[list[str], int]:
    n, pos = read_uvarint(buf, pos)
    items = []
    for _ in range(n):
        s, pos = read_str(buf, pos)
        items.append(s)
    return items, pos


# ---------------------------------------------------------------------------
# Constant (de)serialisation
# ---------------------------------------------------------------------------

def _write_const(out: bytearray, value) -> None:
    if value is None:
        out.append(K_NONE)
    elif value is True:
        out.append(K_TRUE)
    elif value is False:
        out.append(K_FALSE)
    elif value is Ellipsis:
        out.append(K_ELLIPSIS)
    elif isinstance(value, int):
        out.append(K_INT)
        sign = 1 if value < 0 else 0
        out.append(sign)
        mag = abs(value)
        nbytes = (mag.bit_length() + 7) // 8
        write_uvarint(out, nbytes)
        if nbytes:
            out.extend(mag.to_bytes(nbytes, "big"))
    elif isinstance(value, float):
        out.append(K_FLOAT)
        out.extend(struct.pack(">d", value))
    elif isinstance(value, complex):
        out.append(K_COMPLEX)
        out.extend(struct.pack(">dd", value.real, value.imag))
    elif isinstance(value, str):
        out.append(K_STR)
        write_str(out, value)
    elif isinstance(value, (bytes, bytearray)):
        out.append(K_BYTES)
        write_uvarint(out, len(value))
        out.extend(value)
    elif isinstance(value, tuple):
        out.append(K_TUPLE)
        write_uvarint(out, len(value))
        for item in value:
            _write_const(out, item)
    elif isinstance(value, frozenset):
        out.append(K_FROZENSET)
        items = list(value)
        write_uvarint(out, len(items))
        for item in items:
            _write_const(out, item)
    elif type(value).__name__ == 'GIRCode' or isinstance(value, GIRCode):
        out.append(K_CODE)
        _write_code(out, value)
    else:
        raise TypeError(f"Unsupported constant type for GIR serialisation: {type(value)!r}")


def _read_const(buf: bytes, pos: int):
    tag = buf[pos]
    pos += 1
    if tag == K_NONE:
        return None, pos
    if tag == K_TRUE:
        return True, pos
    if tag == K_FALSE:
        return False, pos
    if tag == K_ELLIPSIS:
        return Ellipsis, pos
    if tag == K_INT:
        sign = buf[pos]; pos += 1
        nbytes, pos = read_uvarint(buf, pos)
        mag = int.from_bytes(buf[pos:pos + nbytes], "big") if nbytes else 0
        pos += nbytes
        return (-mag if sign else mag), pos
    if tag == K_FLOAT:
        val = struct.unpack_from(">d", buf, pos)[0]
        return val, pos + 8
    if tag == K_COMPLEX:
        re, im = struct.unpack_from(">dd", buf, pos)
        return complex(re, im), pos + 16
    if tag == K_STR:
        return read_str(buf, pos)
    if tag == K_BYTES:
        n, pos = read_uvarint(buf, pos)
        return bytes(buf[pos:pos + n]), pos + n
    if tag == K_TUPLE:
        n, pos = read_uvarint(buf, pos)
        items = []
        for _ in range(n):
            item, pos = _read_const(buf, pos)
            items.append(item)
        return tuple(items), pos
    if tag == K_FROZENSET:
        n, pos = read_uvarint(buf, pos)
        items = []
        for _ in range(n):
            item, pos = _read_const(buf, pos)
            items.append(item)
        return frozenset(items), pos
    if tag == K_CODE:
        return _read_code(buf, pos)
    raise ValueError(f"Unknown constant tag {tag:#x} at offset {pos - 1}")


# ---------------------------------------------------------------------------
# CodeObject (de)serialisation
# ---------------------------------------------------------------------------

def _write_code(out: bytearray, code: GIRCode) -> None:
    write_uvarint(out, code.argcount)
    write_uvarint(out, code.posonlyargcount)
    write_uvarint(out, code.kwonlyargcount)
    write_uvarint(out, code.nlocals)
    write_uvarint(out, code.stacksize)
    out.extend(struct.pack(">I", code.flags))
    write_uvarint(out, code.firstlineno)
    write_str(out, code.name)
    write_str(out, code.qualname)
    write_str(out, code.filename)
    write_strvec(out, code.varnames)
    write_strvec(out, code.names)
    write_strvec(out, code.freevars)
    write_strvec(out, code.cellvars)

    write_uvarint(out, len(code.consts))
    for c in code.consts:
        _write_const(out, c)

    write_uvarint(out, len(code.instructions))
    for op, arg in code.instructions:
        if not (0 <= op < GIR_TABLE_SIZE):
            raise ValueError(f"GIR opcode {op} out of range 0..{GIR_TABLE_SIZE - 1}")
        write_uvarint(out, op)
        write_uvarint(out, arg)

    write_uvarint(out, len(code.exc_table))
    for start, end, target, depth, lasti in code.exc_table:
        write_uvarint(out, start)
        write_uvarint(out, end)
        write_uvarint(out, target)
        write_uvarint(out, depth)
        out.append(1 if lasti else 0)

    write_uvarint(out, len(code.line_map))
    prev_line = code.firstlineno
    for idx, line in code.line_map:
        write_uvarint(out, idx)
        write_svarint(out, line - prev_line)
        prev_line = line


def _read_code(buf: bytes, pos: int) -> tuple[GIRCode, int]:
    argcount, pos = read_uvarint(buf, pos)
    posonly, pos = read_uvarint(buf, pos)
    kwonly, pos = read_uvarint(buf, pos)
    nlocals, pos = read_uvarint(buf, pos)
    stacksize, pos = read_uvarint(buf, pos)
    flags = struct.unpack_from(">I", buf, pos)[0]; pos += 4
    firstlineno, pos = read_uvarint(buf, pos)
    name, pos = read_str(buf, pos)
    qualname, pos = read_str(buf, pos)
    filename, pos = read_str(buf, pos)
    varnames, pos = read_strvec(buf, pos)
    names, pos = read_strvec(buf, pos)
    freevars, pos = read_strvec(buf, pos)
    cellvars, pos = read_strvec(buf, pos)

    n_consts, pos = read_uvarint(buf, pos)
    consts = []
    for _ in range(n_consts):
        c, pos = _read_const(buf, pos)
        consts.append(c)

    n_instr, pos = read_uvarint(buf, pos)
    instructions = []
    for _ in range(n_instr):
        op, pos = read_uvarint(buf, pos)
        arg, pos = read_uvarint(buf, pos)
        instructions.append((op, arg))

    n_exc, pos = read_uvarint(buf, pos)
    exc_table = []
    for _ in range(n_exc):
        start, pos = read_uvarint(buf, pos)
        end, pos = read_uvarint(buf, pos)
        target, pos = read_uvarint(buf, pos)
        depth, pos = read_uvarint(buf, pos)
        lasti = buf[pos]; pos += 1
        exc_table.append((start, end, target, depth, bool(lasti)))

    n_lines, pos = read_uvarint(buf, pos)
    line_map = []
    prev_line = firstlineno
    for _ in range(n_lines):
        idx, pos = read_uvarint(buf, pos)
        delta, pos = read_svarint(buf, pos)
        prev_line += delta
        line_map.append((idx, prev_line))

    return GIRCode(
        argcount=argcount, posonlyargcount=posonly, kwonlyargcount=kwonly,
        nlocals=nlocals, stacksize=stacksize, flags=flags,
        firstlineno=firstlineno, name=name, qualname=qualname, filename=filename,
        varnames=varnames, names=names, freevars=freevars, cellvars=cellvars,
        consts=consts, instructions=instructions, exc_table=exc_table,
        line_map=line_map,
    ), pos


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def serialize_module(code: GIRCode) -> bytes:
    """Serialise the top-level GIRCode (module body) to bytes."""
    out = bytearray()
    out.append(FORMAT_VERSION)
    _write_code(out, code)
    return bytes(out)


# For gnolly.verify testing
def deserialize_module(blob: bytes) -> GIRCode:
    """
    Inverse of serialize_module.
    Pure-Python reference implementation used for testing the production path deserialing inside the Cython interpreter directly from the shuffled opcode stream.
    """
    if not blob:
        raise ValueError("empty GIR blob")
    version = blob[0]
    if version != FORMAT_VERSION:
        raise ValueError(f"unsupported GIR format version {version}")
    code, pos = _read_code(blob, 1)
    return code
