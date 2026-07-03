"""
gnolly.vm_build
~~~~~~~~~~~~~~~
Compiles the Cython VM core (_gnolly_core.so / .pyd).
Called automatically by 'gnolly build-vm' or during install.
"""
from __future__ import annotations
import os
import sys
import subprocess
import tempfile
import shutil
from pathlib import Path

_HERE = Path(__file__).parent
_PYX  = _HERE / "vm_core.pyx"


def build_vm_core(output_dir: Path | None = None, verbose: bool = True) -> Path:
    """
    Compile vm_core.pyx -> _gnolly_core.so (Linux/Mac) or _gnolly_core.pyd (Win).

    Parameters
    ----------
    output_dir : where to put the compiled .so (default: same dir as vm_core.pyx)
    verbose    : print build progress

    Returns
    -------
    Path to the compiled extension module
    """
    if not _PYX.exists():
        raise FileNotFoundError(f"vm_core.pyx not found: {_PYX}")

    output_dir = Path(output_dir) if output_dir else _HERE

    # Write a minimal setup.py for Cython compilation
    setup_src = f"""\
from setuptools import setup, Extension
from Cython.Build import cythonize
import sys

ext = Extension(
    name="_gnolly_core",
    sources=[{str(_PYX)!r}],
    extra_compile_args=["-O2", "-fvisibility=hidden"] if sys.platform != "win32" else ["/O2"],
)
setup(
    name="_gnolly_core",
    ext_modules=cythonize(
        [ext],
        compiler_directives={{
            "language_level": "3",
            "boundscheck":    False,
            "wraparound":     False,
        }},
    ),
)
"""
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        setup_file = tmp / "setup_gnolly_vm.py"
        setup_file.write_text(setup_src)

        cmd = [sys.executable, str(setup_file), "build_ext", "--inplace",
               "--build-lib", str(tmp / "lib"),
               "--build-temp", str(tmp / "build")]

        if verbose:
            print("[gnolly] Compiling Cython VM core…", file=sys.stderr)

        result = subprocess.run(
            cmd,
            capture_output=not verbose,
            text=True,
            cwd=str(_HERE),
        )

        if result.returncode != 0:
            if not verbose:
                print(result.stdout, file=sys.stderr)
                print(result.stderr, file=sys.stderr)
            raise RuntimeError("Cython compilation failed -> see output above.")

        # Find the compiled extension
        exts = list(_HERE.glob("_gnolly_core*.so")) + list(_HERE.glob("_gnolly_core*.pyd"))
        if not exts:
            raise RuntimeError("Compiled extension not found after build.")

        out = exts[0]
        if output_dir != _HERE:
            dest = output_dir / out.name
            shutil.copy2(out, dest)
            out = dest

        if verbose:
            print(f"[gnolly] VM core compiled -> {out}", file=sys.stderr)

        return out


def vm_core_available() -> bool:
    """Return True if the compiled VM core is importable."""
    try:
        import _gnolly_core  # noqa: F401
        return True
    except ImportError:
        return False
