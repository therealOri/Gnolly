"""
toolkit
~~~~~~~
A tiny sample package to use as a protect-package / protect-wheel target.

If protection is working correctly, all of the names below stay importable
under their exact original spelling after protect-dir/protect-wheel,
even though the internals (locals, string literals, numbers, control flow)
are fully obfuscated and only execute through the Gnolly VM.
"""
from .stats import mean, VERSION
from .geometry.shapes import Rectangle, Circle

__all__ = ["mean", "VERSION", "Rectangle", "Circle", "describe"]


def describe(shape):
    """Small top-level function that touches both re-exported symbols."""
    return f"{type(shape).__name__} with area {shape.area():.2f}"
