"""
gnolly.vm_exec
~~~~~~~~~~~~~~

Production dispatch layer for the GIR VM.

SECURITY POLICY -> NO FALLBACK
------------------------------
This module ONLY loads the compiled Cython extension "_gnolly_vm".
If the extension is absent or fails to load, execution is terminated
immediately via ``sys.exit(1)``; there is no pure-Python fallback path
in production.

Rationale
---------
A pure-Python interpreter ("vm_interp.py") was used during development for reference / offline testing.
Shipping it in the protected runtime would be a security regression:

  * An attacker who can trigger an "ImportError" on "_gnolly_vm"
    (e.g. by deleting the ".so", setting the wrong "PYTHONPATH", or
    targeting a mismatched CPython ABI) would cause the fallback to run,
    making the entire GIR bytecode stream visible to pure-Python inspection
    and "sys.settrace"/"sys.setprofile" hooking.

  * Even without triggering the fallback, the existence of a
    Python-readable interpreter in the distributed package gives an
    attacker a complete opcode reference without reverse-engineering the
    compiled ".so".


We no longer have "vm_interp.py"
"""
from __future__ import annotations
import sys as _sys

# ---------------------------------------------------------------------------
# Hard-load the Cython extension -> no fallback
# ---------------------------------------------------------------------------
try:
    from ._gnolly_vm import (  # noqa: F401  (re-exported for callers)
        vm_exec_module as _c_exec,
        deserialize_vm_blob,
        run_frame,
        GIRFunction,
        Cell,
    )
    _VM_LOADED = True
except ImportError as _e:
    _VM_LOADED = False
    _IMPORT_ERR = _e

if not _VM_LOADED:
    # Emit nothing to stdout/stderr that reveals the reason -> the process just stops.
    # Diagnostics belong in the build/install step, not in production.
    _sys.exit(1)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def vm_exec_module(blob: bytes, table_blob: bytes, globs: dict | None = None) -> None:
    """
    Deserialise and execute a GIR module blob inside the compiled C interpreter.

    Parameters
    ----------
    blob:       Encrypted+shuffled GIR bytes (output of vm_pipeline.protect_with_vm).
    table_blob: 256-byte reverse opcode table (index=shuffled -> value=GIR id).
    globs:      Module-level "__dict__"; created fresh if None.

    This function is the only public entry point for protected module execution.
    It always runs inside "_gnolly_vm" -> the compiled Cython extension.
    There is no code path that executes the GIR stream in plain python.
    """
    _c_exec(blob, table_blob, globs)
