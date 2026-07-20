"""
gnolly.namegen
~~~~~~~~~~~~~~
Shared confusable-identifier generator.

Used by both the AST obfuscator (obfuscate.py, for renamed source-level
identifiers) and the bootstrap stub generator (stub.py, for its own
scaffolding variables), so every generated name across the whole pipeline
comes from one consistent scheme:

  - Every character position is drawn independently and uniformly at
    random (never a counter, never sequential) from a small set of
    Unicode code points that are visually identical or near-identical to
    each other.
  - Every candidate character is a valid Python identifier character
    (PEP 3131 -> Python source is Unicode-aware, so this is completely
    unremarkable to the interpreter or to "python -m py_compile").
  - Collisions are checked against a shared "used" set and regenerated on
    collision, rather than relying on a bijective counter -> two
    different runs (or two different names within the same run) never
    produce a naming pattern an observer could exploit to correlate
    identifiers with the order they were introduced in the source.
"""
from __future__ import annotations
import random


_SHAPE_I = ('I', '\u0406', '\u0399', '\u04c0', '\u05d5')
_SHAPE_i = ('i', '\u0456', '\u0131', '\u026a', '\u0269')
_SHAPE_L = ('l', '\u04cf', '\u01c0')
_SHAPE_O = ('O', '\u041e', '\u039f', '\u0555', '\u2c9e')
_SHAPE_o = ('o', '\u043e', '\u03bf', '\u0585', '\u2c9f')
_SHAPE_0 = ('0', '\u041e', '\u0555', '\u2c9e')

_SHAPES = (_SHAPE_I, _SHAPE_i, _SHAPE_L, _SHAPE_O, _SHAPE_o, _SHAPE_0)



def _rand_char(rng: random.Random) -> str:
    return rng.choice(rng.choice(_SHAPES))


def _can_start_identifier(ch: str) -> bool:
    return (ch + "x").isidentifier()


def random_confusable_name(rng: random.Random, used: set, length: int = 10) -> str:
    """
    Generate a length-character confusable identifier, retrying on
    collision against "used". Every returned name is added to "used"
    before being returned, so passing the same set across many calls
    guarantees uniqueness across all of them.
    """
    while True:
        chars = [_rand_char(rng) for _ in range(length)]
        if not _can_start_identifier(chars[0]):
            continue
        name = ''.join(chars)
        if name not in used:
            used.add(name)
            return name


def random_confusable_char(rng: random.Random) -> str:
    while True:
        ch = _rand_char(rng)
        if _can_start_identifier(ch):   # excludes anything that can't stand alone as a name
            return ch
