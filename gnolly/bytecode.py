"""
gnolly.bytecode
~~~~~~~~~~~~~~~
Compiles Python source -> raw marshal'd bytecode blob.
Working at the bytecode level means:
  - No source text survives into the protected output
  - Standard decompilers (uncompyle6, decompile3) get the obfuscated
    bytecode, not clean source
  - The blob is opaque bytes. (no AST, no tokens)
"""
from __future__ import annotations
import ast
import marshal
import types
import sys


def source_to_bytecode(source: str, filename: str = "<gnolly>") -> bytes:
    """
    Compile *source* -> code object -> marshal blob.
    Returns raw bytes suitable for passing to the encrypt pipeline.
    """
    # Compile to a code object
    code_obj = compile(source, filename, "exec",
                       optimize=1,   # strips assert stmts and __debug__ checks
                       dont_inherit=True)
    return marshal.dumps(code_obj)


def bytecode_to_code(blob: bytes) -> types.CodeType:
    """Deserialise a marshal blob back to a code object."""
    return marshal.loads(blob)


def execute_code(code_obj: types.CodeType, globals_dict: dict | None = None) -> None:
    """
    Execute a code object in the given (or fresh) globals dict.
    This is the only place in Gnolly that runs user code. Using exec()
    on a CODE OBJECT (not a string), which is meaningfully different:
      - No source text is passed through exec
      - The code object was compiled from obfuscated source
      - Intercepting exec() here yields only compiled bytecode, not source
    """
    if globals_dict is None:
        globals_dict = {
            "__name__": "__main__",
            "__builtins__": __builtins__,
        }
    exec(code_obj, globals_dict)   # noqa: S102 -> intentional, on code object only
