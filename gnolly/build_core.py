"""
gnolly.build_core
~~~~~~~~~~~~~~~~~
Build the Cython runtime extension if it is absent or stale.

Called automatically by pipeline.py before the first protect() run.
Also callable directly:
    python -m gnolly.build_core

The extension is REQUIRED for maximum protection.
"""
from __future__ import annotations
import hashlib
import importlib
import os
import sys
import sysconfig
from pathlib import Path


# Path to the .pyx source
_PKG_DIR   = Path(__file__).parent
_PYX_FILE  = _PKG_DIR / "_gnolly_core.pyx"
_STAMP_FILE = _PKG_DIR / "_gnolly_core.stamp"   # records hash of last successful build


def _ext_suffix() -> str:
    return sysconfig.get_config_var("EXT_SUFFIX") or ".so"


def _so_path() -> Path:
    return _PKG_DIR / f"_gnolly_core{_ext_suffix()}"


def _pyx_hash() -> str:
    return hashlib.sha256(_PYX_FILE.read_bytes()).hexdigest()


def core_is_built() -> bool:
    """Return True if the compiled .so exists and is up-to-date."""
    so = _so_path()
    if not so.exists():
        return False
    # Check stamp: if .pyx changed since last build, rebuild
    if _STAMP_FILE.exists():
        try:
            stamp = _STAMP_FILE.read_text().strip()
            return stamp == _pyx_hash()
        except Exception:
            return False
    # .so exists but no stamp -> assume it's current
    return True


def build_core(verbose: bool = True) -> bool:
    """
    Build the Cython extension in-place.

    Returns True on success, False on failure.
    Never raises -> caller decides what to do if build fails.
    """
    if not _PYX_FILE.exists():
        if verbose:
            print("[gnolly] WARNING: _gnolly_core.pyx not found -> "
                  "Cython core unavailable.", file=sys.stderr)
        return False

    try:
        from Cython.Build import cythonize
        from setuptools import Extension, Distribution
        from setuptools.command.build_ext import build_ext as BuildExt
    except ImportError:
        if verbose:
            print("[gnolly] WARNING: Cython not installed -> "
                  "run: pip install cython\n"
                  "         Falling back to pure-Python stub.", file=sys.stderr)
        return False

    if verbose:
        print("[gnolly] Building Cython runtime core …", file=sys.stderr)

    try:
        import tempfile, shutil

        extra_cc  = ["-O2", "-fvisibility=hidden"] if sys.platform != "win32" else ["/O2"]
        extra_ld  = []
        if sys.platform == "darwin":
            extra_cc += ["-mmacosx-version-min=10.9"]

        ext = Extension(
            name="gnolly._gnolly_core",
            sources=[str(_PYX_FILE)],
            extra_compile_args=extra_cc,
            extra_link_args=extra_ld,
        )

        cyth_exts = cythonize(
            [ext],
            compiler_directives={
                "language_level":     "3",
                "boundscheck":        False,
                "wraparound":         False,
                "cdivision":          True,
                "embedsignature":     False,
                "emit_code_comments": False,
            },
            annotate=False,
            quiet=not verbose,
        )

        # Build into a temp dir then copy the .so into the package
        with tempfile.TemporaryDirectory() as tmp:
            dist = Distribution(attrs={
                "name":        "gnolly-core",
                "ext_modules": cyth_exts,
            })
            cmd = BuildExt(dist)
            cmd.build_lib  = tmp
            cmd.build_temp = tmp
            cmd.inplace    = False
            cmd.ensure_finalized()
            cmd.run()

            # Find the built .so and copy it next to the .pyx
            built = list(Path(tmp).rglob(f"_gnolly_core*{_ext_suffix()}"))
            if not built:
                raise RuntimeError("Build produced no .so file")

            dest = _so_path()
            shutil.copy2(built[0], dest)

        # Write stamp
        _STAMP_FILE.write_text(_pyx_hash())

        if verbose:
            print(f"[gnolly] Cython core built -> {_so_path().name}", file=sys.stderr)
        return True

    except Exception as exc:
        if verbose:
            print(f"[gnolly] WARNING: Cython build failed: {exc}\n", file=sys.stderr)
        return False


def ensure_core(verbose: bool = True) -> bool:
    """
    Build the core if it isn't already built. Returns True if core is available.
    """
    if core_is_built():
        return True
    return build_core(verbose=verbose)


def try_import_core():
    """
    Attempt to import the compiled core module.
    Returns the module on success, None on failure.
    """
    try:
        import importlib
        return importlib.import_module("gnolly._gnolly_core")
    except ImportError:
        return None


if __name__ == "__main__":
    success = build_core(verbose=True)
    sys.exit(0 if success else 1)
