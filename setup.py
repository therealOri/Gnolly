"""
setup.py - Gnolly package build

Builds both Cython extensions:
  gnolly._gnolly_core   - AES-GCM decrypt + anti-debug runtime
  gnolly._gnolly_vm     - GIR (Gnolly Instruction Set) interpreter

Both extensions are mandatory for protected files to run.
"""
import os
import sys
from setuptools import setup, Extension, find_packages

if sys.version_info < (3, 11):
    raise RuntimeError("gnolly requires Python >= 3.11")

try:
    from Cython.Build import cythonize
    USE_CYTHON = True
except ImportError:
    USE_CYTHON = False
    print("WARNING: Cython not found; building from pre-generated C files if available.")

PKG_DIR = os.path.join(os.path.dirname(__file__), "gnolly")

# ── Shared compile/link flags ─────────────────────────────────────────────────
_cc_flags = [
    "-O3",
    "-fvisibility=hidden",
    *([] if os.environ.get("GNOLLY_DEBUG") else ["-DNDEBUG"]),
]
_ld_flags = ["-Wl,-z,now"] if sys.platform.startswith("linux") else []

# ── Extension definitions ─────────────────────────────────────────────────────
def _ext(name: str, pyx_or_c: str) -> Extension:
    return Extension(
        f"gnolly.{name}",
        sources=[os.path.join(PKG_DIR, pyx_or_c)],
        extra_compile_args=_cc_flags,
        extra_link_args=_ld_flags,
    )


if USE_CYTHON:
    ext_modules = cythonize(
        [
            _ext("_gnolly_core", "_gnolly_core.pyx"),
            _ext("_gnolly_vm",   "_gnolly_vm.pyx"),
        ],
        compiler_directives={
            "language_level": "3",
            "boundscheck":    False,
            "wraparound":     True,   # needed: GIR eval loop uses negative list indices
            "cdivision":      True,
            "nonecheck":      False,
            "profile":        False,
        },
        annotate=bool(os.environ.get("GNOLLY_ANNOTATE")),
    )
else:
    # Fall back to pre-generated C files if available
    exts = []
    for name in ("_gnolly_core", "_gnolly_vm"):
        c_file = os.path.join(PKG_DIR, f"{name}.c")
        if not os.path.exists(c_file):
            raise RuntimeError(
                f"Cython not installed and no pre-generated {name}.c found.\n"
                "Install Cython with:  pip install cython"
            )
        exts.append(_ext(name, f"{name}.c"))
    ext_modules = exts

setup(
    name="gnolly",
    version="1.0.0",
    description="Professional Python code protection. Free, and with no paywalls.",
    packages=find_packages(),
    ext_modules=ext_modules,
    python_requires=">=3.11",
    install_requires=[
        "pycryptodome>=3.19.0",
        "Cython>=3.2.5",
        "setuptools>=82.0.1",
    ],
    entry_points={
        "console_scripts": [
            "gnolly=gnolly.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Build Tools",
    ],
    zip_safe=False,
)
