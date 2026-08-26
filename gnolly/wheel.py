"""
gnolly.wheel
~~~~~~~~~~~~
Real .whl output for protected packages.

Builds on top of gnolly.package.protect_package (module_mode=True) rather
than replacing it. This module handles proper importable-module naming (already delegated to protect_package),
runtime .so discovery/bundling, and PEP 427-compliant wheel assembly
(METADATA / WHEEL / RECORD + zip) using the standard library. No
"wheel" or "build" package is required to produce the artifact.

Two runtime modes for the wheel output:

  bundle_runtime=False (default)
      The wheel sets dependency on "gnolly" (Requires-Dist),
      and at import time the existing .so search order finds _gnolly_core.so / _gnolly_vm.so
      in gnolly's own site-packages directory. (site-packages/gnolly/)

      Smaller wheel;
      Doing it this way makes the wheel smaller since we wouldn't need to budle _gnolly_core.so and _gnolly_vm.so into the wheel.

  bundle_runtime=True
      The currently-built _gnolly_core*.so / _gnolly_vm*.so are copied
      into <package>/_gnolly_runtime/ inside the wheel.

      Self-contained but larger;
      No separate gnolly install is needed on the target machine since the needed libraries are shiped with the wheel.

Layout (module_mode=True from protect_package) makes:
    <name>-<version>-<tag>.whl
        <name>/
            __init__.py            <- protected, real name, importable
            submodule.py
            _gnolly_runtime/        <- only if bundle_runtime=True
                _gnolly_core*.so
                _gnolly_vm*.so
        <name>-<version>.dist-info/
            METADATA
            WHEEL
            RECORD
"""
from __future__ import annotations
import hashlib
import base64
import shutil
import sys
import sysconfig
import tempfile
import zipfile
from pathlib import Path

from .package import protect_package
from .keymanager import generate_key, save_keyfile, key_to_hex
from .build_core import ensure_core, _so_path as _core_so_path, _ext_suffix


def _normalize_dist_name(name: str) -> str:
    """PEP 503 normalize (for METADATA's Name field)."""
    import re
    return re.sub(r"[-_.]+", "-", name).lower()


def _escape_filename_component(s: str) -> str:
    """PEP 427 filename-escaping: runs of -_. collapse to a single _."""
    import re
    return re.sub(r"[^\w\d.]+", "_", s)


def _vm_so_path() -> Path:
    from .build_core import _PKG_DIR
    return _PKG_DIR / f"_gnolly_vm{_ext_suffix()}"


def _wheel_tag(bundle_runtime: bool) -> str:
    """
    Compute the {python tag}-{abi tag}-{platform tag} portion of the
    wheel filename.
    """
    if not bundle_runtime:
        return "py3-none-any"

    ver = sys.version_info
    py_tag = f"cp{ver.major}{ver.minor}"
    # Standard CPython ABI tag for a release build matches the python tag.
    # (e.g. "cp312").
    abi_tag = py_tag
    plat = sysconfig.get_platform()  # e.g. "linux-x86_64", "macosx-10.9-x86_64"
    plat_tag = _escape_filename_component(plat)
    return f"{py_tag}-{abi_tag}-{plat_tag}"


def _sha256_urlsafe(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def build_wheel(
    input_dir: str | Path,
    output_dir: str | Path,
    password: bytes | None = None,
    *,
    name: str,
    version: str,
    description: str = "",
    author: str = "",
    python_requires: str = ">=3.12",
    requires_dist: list[str] | None = None,
    bundle_runtime: bool = False,
    keyfile: str | Path | None = None,
    exclude: list[str] | None = None,
    verbose: bool = True,
    **protect_kwargs,
) -> tuple[Path, bytes, Path | None]:
    """
    Protect *input_dir* as a package (module_mode=True, via
    gnolly.package.protect_package) and assemble a .whl.

    Parameters
    ----------
    input_dir       : root of the package to protect (the directory that
                       directly contains __init__.py)
    output_dir      : directory the finished .whl is written into
    password        : shared encryption key for all files in the package.
                       If None, a new key is generated (recommended unless
                       you're rebuilding with a previously issued key).
    name            : distribution name (e.g. "mypkg") -> wheel filename
                       and METADATA Name. The importable package directory
                       inside the wheel uses name with '-' -> '_'.
    version         : PEP 440 version string, e.g. "1.0.0"
    description     : one-line Summary for METADATA
    author          : Author field for METADATA
    python_requires : Requires-Python constraint
    requires_dist   : extra Requires-Dist entries. When bundle_runtime is
                       False, "gnly" is added automatically unless
                       already present.
    bundle_runtime  : embed the currently-built gnolly .so files inside
                       the wheel instead of depending on a separate
                       install of gnolly
    keyfile         : reuse an existing keyfile's key instead of
                       generating a new one (mutually exclusive with
                       passing password directly)
    exclude         : glob patterns to exclude, forwarded to
                       protect_package (e.g. ['**/test_*.py'])
    verbose         : print progress
    protect_kwargs  : forwarded to protect_package -> protect_file -> protect
                       (mangle_names, obf_strings, --bind fingerprint, etc.)

    Returns
    -------
    (wheel_path, key_bytes, keyfile_path_or_None)
    """
    input_dir  = Path(input_dir).resolve()
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if not (input_dir / "__init__.py").exists():
        raise ValueError(
            f"{input_dir} does not look like a package root "
            f"(no __init__.py found directly inside it)."
        )

    if password is not None and keyfile is not None:
        raise ValueError("Pass either password or keyfile, not both.")
    if keyfile is not None:
        from .keymanager import load_keyfile
        key = load_keyfile(keyfile)
    elif password is not None:
        key = password
    else:
        key = generate_key()

    dist_name = _normalize_dist_name(name)
    pkg_dirname = input_dir.name  # the actual importable top-level name

    if bundle_runtime:
        if not ensure_core(verbose=verbose):
            raise RuntimeError(
                "bundle_runtime=True requires a built gnolly runtime "
                "(_gnolly_core.so) but the build failed. Run "
                "`python -m gnolly.build_core` to see the error, or use "
                "bundle_runtime=False."
            )
        core_so, vm_so = _core_so_path(), _vm_so_path()
        if not core_so.exists() or not vm_so.exists():
            raise RuntimeError(
                "bundle_runtime=True requires both _gnolly_core.so and "
                "_gnolly_vm.so to be built locally first."
            )

    with tempfile.TemporaryDirectory(prefix="gnly-wheel-") as tmp:
        tmp = Path(tmp)
        staging     = tmp / "staging"
        pkg_out_dir = staging / pkg_dirname
        dist_info   = staging / f"{dist_name.replace('-', '_')}-{version}.dist-info"
        pkg_out_dir.mkdir(parents=True)
        dist_info.mkdir(parents=True)

        if verbose:
            print(f"[gnolly] Protecting package: {input_dir}", file=sys.stderr)
            print(f"[gnolly] Staging:            {pkg_out_dir}", file=sys.stderr)

        protect_package(
            input_dir   = input_dir,
            output_dir  = pkg_out_dir,
            password    = key,
            pattern     = "**/*.py",
            exclude     = exclude,
            verbose     = verbose,
            module_mode = True,
            **protect_kwargs,
        )

        if bundle_runtime:
            rt_dir = pkg_out_dir / "_gnly_runtime"
            rt_dir.mkdir(exist_ok=True)
            shutil.copy2(core_so, rt_dir / core_so.name)
            shutil.copy2(vm_so,   rt_dir / vm_so.name)
            if verbose:
                print(f"[gnolly] Bundled runtime -> {rt_dir}", file=sys.stderr)

        # ── METADATA ──────────────────────────────────────────────────────
        req_dist = list(requires_dist or [])
        if not bundle_runtime and not any(
            r.split()[0].split(";")[0].split("[")[0].strip().lower() == "gnly"
            for r in req_dist
        ):
            req_dist.append("gnly")

        meta_lines = [
            "Metadata-Version: 2.1",
            f"Name: {dist_name}",
            f"Version: {version}",
        ]
        if summary := description:
            meta_lines.append(f"Summary: {summary}")
        if author:
            meta_lines.append(f"Author: {author}")
        meta_lines.append(f"Requires-Python: {python_requires}")
        for r in req_dist:
            meta_lines.append(f"Requires-Dist: {r}")
        meta_lines.append(
            "Description-Content-Type: text/markdown"
        )
        meta_lines.append("")
        meta_lines.append(
            description or f"{dist_name}, protected with Gnolly "
            "(https://github.com/therealOri/Gnolly) -> This source is encrypted and only "
            "executes through the Gnolly VM runtime."
        )
        (dist_info / "METADATA").write_text("\n".join(meta_lines) + "\n", encoding="utf-8")

        # ── WHEEL ─────────────────────────────────────────────────────────
        tag = _wheel_tag(bundle_runtime)
        wheel_lines = [
            "Wheel-Version: 1.0",
            "Generator: gnolly",
            f"Root-Is-Purelib: {'false' if bundle_runtime else 'true'}",
            f"Tag: {tag}",
        ]
        (dist_info / "WHEEL").write_text("\n".join(wheel_lines) + "\n", encoding="utf-8")

        # ── RECORD (all files except RECORD itself, which lists itself
        #    with no hash/size per PEP 376) ──────────────────────────────
        record_lines = []
        all_files = sorted(p for p in staging.rglob("*") if p.is_file())
        for f in all_files:
            rel = f.relative_to(staging).as_posix()
            data = f.read_bytes()
            record_lines.append(f"{rel},{_sha256_urlsafe(data)},{len(data)}")
        record_rel = f"{dist_info.name}/RECORD"
        record_lines.append(f"{record_rel},,")
        (dist_info / "RECORD").write_text("\n".join(record_lines) + "\n", encoding="utf-8")

        # ── Zip it up ─────────────────────────────────────────────────────
        wheel_name = f"{dist_name.replace('-', '_')}-{version}-{tag}.whl"
        wheel_path = output_dir / wheel_name
        if wheel_path.exists():
            wheel_path.unlink()

        with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for f in sorted(staging.rglob("*")):
                if f.is_file():
                    zf.write(f, f.relative_to(staging).as_posix())

    kf_path = None
    if keyfile is None:
        kf_path = output_dir / f"{dist_name}-{version}.gnolly.key"
        save_keyfile(key, kf_path, protected_file=str(input_dir),
                     hint=f"Key for wheel {name} {version}")

    if verbose:
        print(f"\n[gnolly] Wheel built -> {wheel_path}", file=sys.stderr)
        if kf_path:
            print(f"[gnolly] Key saved to  -> {kf_path}", file=sys.stderr)
            print(f"[gnolly] Hex key:         {key_to_hex(key)}", file=sys.stderr)
        if not bundle_runtime:
            print(
                "[gnolly] This wheel depends on `gnolly` being installed "
                "in the target environment (for the .so runtime).",
                file=sys.stderr,
            )
        print(
            f"[gnolly] Runtime: export GNOLLY_KEY={key_to_hex(key)}  "
            f"&&  python -c 'import {pkg_dirname}'",
            file=sys.stderr,
        )

    return wheel_path, key, kf_path
