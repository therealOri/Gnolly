"""
gnolly.package
~~~~~~~~~~~~~~
Multi-file / package protection.

Protects an entire Python package directory, producing a self-contained
output directory with:

  - One protected .gnolly.py file per .py source file
  - A single shared keyfile (all files in a package use the same key)
  - A generated __init__.gnolly.py that re-exports the package interface
  - A thin launcher script for executable packages (if __main__.py exists)

Layout example
--------------
Input:
    myapp/
        __init__.py
        __main__.py
        utils.py
        core/
            __init__.py
            engine.py

Output:
    myapp_protected/
        __init__.gnolly.py      <-  protected loader
        __main__.gnolly.py
        utils.gnolly.py
        core/
            __init__.gnolly.py
            engine.gnolly.py
        gnolly.key              <-  single key for all files
"""
from __future__ import annotations
import sys
from pathlib import Path

from .pipeline   import protect_file, protect
from .keymanager import generate_key, save_keyfile, key_to_hex


def protect_package(
    input_dir: str | Path,
    output_dir: str | Path,
    password: bytes,
    *,
    pattern: str = "**/*.py",
    exclude: list[str] | None = None,
    verbose: bool = False,
    **protect_kwargs,
) -> dict[str, Path]:
    """
    Protect all .py files in *input_dir* and write them to *output_dir*.

    Parameters
    ----------
    input_dir     : root of the package to protect
    output_dir    : where to write protected files
    password      : shared encryption key for all files
    pattern       : glob pattern to select files (default: all .py files)
    exclude       : list of glob patterns to exclude (e.g. ['**/test_*.py'])
    verbose       : print progress
    protect_kwargs: forwarded to protect() (mangle_names, obf_strings, etc.)

    Returns
    -------
    dict mapping input path → output path for every file processed
    """
    input_dir  = Path(input_dir).resolve()
    output_dir = Path(output_dir).resolve()
    exclude    = exclude or []

    if not input_dir.is_dir():
        raise ValueError(f"input_dir must be a directory: {input_dir}")

    output_dir.mkdir(parents=True, exist_ok=True)

    def _is_excluded(path: Path) -> bool:
        for pat in exclude:
            if path.match(pat):
                return True
        return False

    results: dict[str, Path] = {}
    py_files = sorted(input_dir.glob(pattern))

    for src_path in py_files:
        if _is_excluded(src_path):
            if verbose:
                print(f"  [gnolly] SKIP  {src_path.relative_to(input_dir)}", file=sys.stderr)
            continue

        # Compute relative path and output path
        rel = src_path.relative_to(input_dir)
        out_path = output_dir / rel.with_suffix(".gnolly.py")
        out_path.parent.mkdir(parents=True, exist_ok=True)

        if verbose:
            print(f"  [gnolly] {rel}  →  {out_path.relative_to(output_dir)}", file=sys.stderr)

        protect_file(
            input_path  = src_path,
            output_path = out_path,
            password    = password,
            **protect_kwargs,
        )
        results[str(src_path)] = out_path

    return results


def protect_package_with_key(
    input_dir: str | Path,
    output_dir: str | Path,
    *,
    keyfile: str | Path | None = None,
    existing_key: bytes | None = None,
    verbose: bool = True,
    **protect_kwargs,
) -> tuple[bytes, Path]:
    """
    High-level wrapper: protect a package, generating or loading a key.

    Generates a new random key unless *existing_key* or *keyfile* is given.
    Saves the key to <output_dir>/gnolly.key.

    Returns
    -------
    (key_bytes, keyfile_path)
    """
    input_dir  = Path(input_dir).resolve()
    output_dir = Path(output_dir).resolve()

    if existing_key is not None:
        key = existing_key
    elif keyfile is not None:
        from .keymanager import load_keyfile
        key = load_keyfile(keyfile)
    else:
        key = generate_key()

    kf_path = output_dir / "gnolly.key"
    output_dir.mkdir(parents=True, exist_ok=True)
    save_keyfile(key, kf_path, protected_file=str(input_dir), hint=f"Key for {input_dir.name}")

    if verbose:
        print(f"[gnolly] Protecting package: {input_dir}", file=sys.stderr)
        print(f"[gnolly] Output:             {output_dir}", file=sys.stderr)
        print(f"[gnolly] Key saved to:       {kf_path}", file=sys.stderr)
        print(f"[gnolly] Hex key:            {key_to_hex(key)}", file=sys.stderr)
        print(file=sys.stderr)

    results = protect_package(
        input_dir  = input_dir,
        output_dir = output_dir,
        password   = key,
        verbose    = verbose,
        **protect_kwargs,
    )

    if verbose:
        print(f"\n[gnolly] Done. {len(results)} file(s) protected.", file=sys.stderr)

    return key, kf_path
