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
    each other. This mixes real Cyrillic and Greek homoglyphs in with the
    Latin/digit originals ('I', 'l', 'O', '0') that gave the scheme its
    name, so two names can render pixel-for-pixel identically on screen
    while being completely different identifiers to the interpreter.
    A human reading the file can no longer visually distinguish them at
    all, let alone recognise a pattern in how they were assigned.
  - Every candidate character is a valid Python identifier character
    (PEP 3131 -> Python source is Unicode-aware, so this is completely
    unremarkable to the interpreter or to `python -m py_compile`).
  - Collisions are checked against a shared `used` set and regenerated on
    collision, rather than relying on a bijective counter -> two
    different runs (or two different names within the same run) never
    produce a naming pattern an observer could exploit to correlate
    identifiers with the order they were introduced in the source.

"""
from __future__ import annotations
import random

_SHAPE_I = ('I', '\u0406', '\u0399')
_SHAPE_L = ('l', '\u04cf', '\u2170')
_SHAPE_O = ('O', '\u041e', '\u039f')
_SHAPE_0 = ('0',)

_SHAPES = (_SHAPE_I, _SHAPE_L, _SHAPE_O, _SHAPE_0)


def _rand_char(rng: random.Random) -> str:
    return rng.choice(rng.choice(_SHAPES))


def random_confusable_name(rng: random.Random, used: set, length: int = 10) -> str:
    """
    Generate a length-character confusable identifier, retrying on
    collision against used. Every returned name is added to used
    before being returned, so passing the same set across many calls
    guarantees uniqueness across all of them.
    """
    while True:
        chars = [_rand_char(rng) for _ in range(length)]
        # Python identifiers can't start with a digit.
        if chars[0] == '0':
            continue
        name = ''.join(chars)
        if name not in used:
            used.add(name)
            return name
