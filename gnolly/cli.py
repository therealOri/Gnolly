#!/usr/bin/env python3
"""
gnolly -> Python code protection. Free with no paywalls.

Commands:
    protect          Protect a single .py file
    protect-dir      Protect an entire directory
    protect-wheel    Protect a package and build a real .whl
    keygen           Generate a standalone keyfile
"""
from __future__ import annotations
import sys
from pathlib import Path


# ── keygen ────────────────────────────────────────────────────────────────────

def cmd_keygen(args):
    from gnolly.keymanager import generate_key, save_keyfile, key_to_hex
    kf_path = Path(args.keyfile) if args.keyfile else Path("gnly.key")
    key = generate_key()
    save_keyfile(key, kf_path, protected_file=getattr(args, 'for_file', ''), hint=args.hint or "")
    print(f"[gnolly] Key generated --> {kf_path}")
    print(f"[gnolly] Hex key: {key_to_hex(key)}")
    print(f"\n[gnolly] Runtime usage:")
    print(f"           export GNOLLY_KEY={key_to_hex(key)}")
    print(f"           python <protected>.gnly.py")
    print(f"\n[gnolly] Keep {kf_path} safe. There is NO recovery without it.")


# ── protect ───────────────────────────────────────────────────────────────────

def cmd_protect(args):
    from gnolly.pipeline import protect_file
    from gnolly.keymanager import load_keyfile, generate_key, save_keyfile, key_to_hex

    inp = Path(args.input)
    if not inp.exists():
        sys.exit(f"[gnolly] File not found: {inp}")
    if inp.suffix != ".py":
        sys.exit("[gnolly] Input must be a .py file.")

    out = Path(args.output) if args.output else inp.with_suffix(".gnly.py")

    if args.keyfile:
        kf = Path(args.keyfile)
        if not kf.exists():
            sys.exit(f"[gnolly] Keyfile not found: {kf}")
        key = load_keyfile(kf)
        print(f"[gnolly] Using key from: {kf}")
    else:
        auto_kf = out.with_suffix(".key")
        key = generate_key()
        save_keyfile(key, auto_kf, protected_file=str(out))
        print(f"[gnolly] New key generated -> {auto_kf}")
        print(f"[gnolly] Hex key: {key_to_hex(key)}")
        print(f"[gnolly] SAVE THIS KEY. It cannot be recovered.")

    # Resolve machine binding
    _machine_fp = None
    if getattr(args, 'bind_fp', None):
        from gnolly.binding import fingerprint_from_hex
        _machine_fp = fingerprint_from_hex(args.bind_fp)
        print(f"[gnolly] Binding to fingerprint: {args.bind_fp[:16]}...")
    elif getattr(args, 'bind', False):
        from gnolly.binding import collect_fingerprint, fingerprint_hex
        _machine_fp = collect_fingerprint()
        if _machine_fp is None:
            sys.exit("[gnolly] Could not collect machine fingerprint on this platform.")
        print(f"[gnolly] Binding to THIS machine: {fingerprint_hex()[:16]}...")

    print(f"[gnolly] Protecting: {inp}  ->  {out}")
    protect_file(
        input_path          = inp,
        output_path         = out,
        password            = key,
        mangle_names        = not args.no_mangle,
        obf_strings         = not args.no_strings,
        inject_dead         = not args.no_dead,
        obf_numbers         = not args.no_numbers,
        machine_fingerprint = _machine_fp,
        verbose             = args.verbose,
        silent              = not args.verbose_errors,
        flatten             = not args.no_flatten,
        minify              = not args.no_minify,
        pack                = not args.no_pack,
        bogus_hierarchy     = not args.no_hierarchy,
        alias_exprs         = not args.no_alias,
    )
    print(f"\n[gnolly] Done -> {out}")
    print(f"[gnolly] Runtime:")
    print(f"           export GNOLLY_KEY={key_to_hex(key)}")
    print(f"           python {out.name}")


# ── protect-dir ───────────────────────────────────────────────────────────

def cmd_protect_dir(args):
    from gnolly.package import protect_package_with_key
    from gnolly.keymanager import key_to_hex

    inp = Path(args.input)
    if not inp.exists() or not inp.is_dir():
        sys.exit(f"[gnolly] Directory not found: {inp}")

    out = Path(args.output) if args.output else Path(str(inp) + "_protected")

    # Resolve machine binding (same logic as cmd_protect)
    _machine_fp = None
    if getattr(args, 'bind_fp', None):
        from gnolly.binding import fingerprint_from_hex
        _machine_fp = fingerprint_from_hex(args.bind_fp)
        print(f"[gnolly] Binding to fingerprint: {args.bind_fp[:16]}...")
    elif getattr(args, 'bind', False):
        from gnolly.binding import collect_fingerprint, fingerprint_hex
        _machine_fp = collect_fingerprint()
        if _machine_fp is None:
            sys.exit("[gnolly] Could not collect machine fingerprint on this platform.")
        print(f"[gnolly] Binding to THIS machine: {fingerprint_hex()[:16]}...")

    key, kf = protect_package_with_key(
        input_dir           = inp,
        output_dir          = out,
        keyfile             = args.keyfile or None,
        verbose             = True,
        mangle_names        = not args.no_mangle,
        obf_strings         = not args.no_strings,
        inject_dead         = not args.no_dead,
        obf_numbers         = not args.no_numbers,
        machine_fingerprint = _machine_fp,
        flatten             = not args.no_flatten,
        minify              = not args.no_minify,
        pack                = not args.no_pack,
        bogus_hierarchy     = not args.no_hierarchy,
        alias_exprs         = not args.no_alias,
    )
    print(f"\n[gnolly] Runtime:")
    print(f"           export GNOLLY_KEY={key_to_hex(key)}")
    print(f"           python <protected_file>.gnolly.py")


# ── protect-wheel ───────────────────────────────────────────────────────────

def cmd_protect_wheel(args):
    from gnolly.wheel import build_wheel
    from gnolly.keymanager import key_to_hex

    inp = Path(args.input)
    if not inp.exists() or not inp.is_dir():
        sys.exit(f"[gnolly] Directory not found: {inp}")

    out_dir = Path(args.output) if args.output else Path("dist")

    # Resolve machine binding (same logic as cmd_protect)
    _machine_fp = None
    if getattr(args, 'bind_fp', None):
        from gnolly.binding import fingerprint_from_hex
        _machine_fp = fingerprint_from_hex(args.bind_fp)
        print(f"[gnolly] Binding to fingerprint: {args.bind_fp[:16]}...")
    elif getattr(args, 'bind', False):
        from gnolly.binding import collect_fingerprint, fingerprint_hex
        _machine_fp = collect_fingerprint()
        if _machine_fp is None:
            sys.exit("[gnolly] Could not collect machine fingerprint on this platform.")
        print(f"[gnolly] Binding to THIS machine: {fingerprint_hex()[:16]}...")

    wheel_path, key, kf = build_wheel(
        input_dir           = inp,
        output_dir          = out_dir,
        name                = args.name,
        version             = args.version,
        description         = args.description,
        author              = args.author or "",
        python_requires     = args.python_requires,
        requires_dist       = args.requires or None,
        bundle_runtime      = args.bundle_runtime,
        keyfile             = args.keyfile or None,
        exclude             = args.exclude,
        verbose             = True,
        mangle_names        = not args.no_mangle,
        obf_strings         = not args.no_strings,
        inject_dead         = not args.no_dead,
        obf_numbers         = not args.no_numbers,
        machine_fingerprint = _machine_fp,
        flatten             = not args.no_flatten,
        minify              = not args.no_minify,
        pack                = not args.no_pack,
        bogus_hierarchy     = not args.no_hierarchy,
        alias_exprs         = not args.no_alias,
    )
    print(f"\n[gnolly] Wheel:   {wheel_path}")
    print(f"[gnolly] Install: pip install {wheel_path}")


# ── Argument parser ───────────────────────────────────────────────────────────

def _add_obf_flags(p):
    """Add shared obfuscation toggle flags to a subparser."""
    p.add_argument("-K", "--keyfile",    help="Use key from this keyfile")
    p.add_argument("--no-mangle",  action="store_true", help="Disable name mangling")
    p.add_argument("--no-strings", action="store_true", help="Disable string obfuscation")
    p.add_argument("--no-dead",    action="store_true", help="Disable dead-code injection")
    p.add_argument("--no-numbers", action="store_true", help="Disable integer obfuscation")
    p.add_argument("--no-flatten", action="store_true",
                   help="Disable control-flow flattening of the generated stub")
    p.add_argument("--no-hierarchy", action="store_true",
                   help="Disable bogus inherited class hierarchy generation "
                        "(also used to diversify the opaque-True token used "
                        "by dead-code/flatten/noise passes)")
    p.add_argument("--no-alias", action="store_true",
                   help="Disable expression aliasing (routing call results "
                        "through an extra layer of indirection)")
    p.add_argument("--no-minify", action="store_true",
                   help="Disable minification of the protected output (on by default)")
    p.add_argument("--no-pack", action="store_true",
                   help="Disable final compression pass (bootstrap + compressed blob, on by default)")
    p.add_argument("--bind",       action="store_true",
                   help="Bind output to THIS machine (uses current machine fingerprint)")
    p.add_argument("--bind-fp",    default=None, dest="bind_fp",
                   help="Bind to a specific machine fingerprint hex (from 'gnolly fingerprint')")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--verbose-errors", action="store_true", dest="verbose_errors",
                   help="Emit error messages from protected stub on failure (development only; default is silent)")


def build_parser():
    import argparse
    p = argparse.ArgumentParser(
        prog="gnolly",
        description="Gnolly -> Python code protection. Free, with no paywalls.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    # protect
    pp = sub.add_parser("protect", help="Protect a single .py file")
    pp.add_argument("input",  help="Source .py file")
    pp.add_argument("output", nargs="?", help="Output (default: <input>.gnolly.py)")
    _add_obf_flags(pp)

    # protect-dir
    pkg = sub.add_parser("protect-dir", help="Protect an entire directory of files")
    pkg.add_argument("input",  help="Package directory")
    pkg.add_argument("output", nargs="?", help="Output directory (default: <input>_protected)")
    pkg.add_argument("--exclude", nargs="*", default=[], help="Glob patterns to exclude")
    _add_obf_flags(pkg)

    # protect-wheel
    whl = sub.add_parser("protect-wheel", help="Protect a package and build a real .whl")
    whl.add_argument("input", help="Package directory (must contain __init__.py)")
    whl.add_argument("output", nargs="?", help="Output directory for the .whl (default: dist/)")
    whl.add_argument("--name", required=True, help="Distribution name (e.g. mypkg)")
    whl.add_argument("--version", required=True, help="PEP 440 version, e.g. 1.0.0")
    whl.add_argument("--description", default="", help="Short summary for METADATA")
    whl.add_argument("--author", default="", help="Author name for METADATA")
    whl.add_argument("--requires", nargs="*", default=[],
                      help="Extra Requires-Dist entries (e.g. requests>=2.0)")
    whl.add_argument("--python-requires", default=">=3.12", dest="python_requires",
                      help="Requires-Python constraint for METADATA (default: >=3.12)")
    whl.add_argument("--bundle-runtime", action="store_true", dest="bundle_runtime",
                      help="Embed the built gnolly .so runtime in the wheel "
                           "(self-contained, but platform/ABI-specific). "
                           "Default: depend on a separately pip-installed gnolly.")
    whl.add_argument("--exclude", nargs="*", default=[], help="Glob patterns to exclude")
    _add_obf_flags(whl)

    # keygen
    kg = sub.add_parser("keygen", help="Generate a key")
    kg.add_argument("keyfile", nargs="?", help="Where to save (default: gnolly.key)")
    kg.add_argument("--hint",     default="", help="Description stored in keyfile")
    kg.add_argument("--for-file", default="", dest="for_file")

    # fingerprint
    sub.add_parser("fingerprint", help="Print this machine's binding fingerprint")

    return p


def cmd_fingerprint(args):
    from gnolly.binding import fingerprint_hex
    fp = fingerprint_hex()
    if not fp:
        sys.exit("[gnolly] No stable machine identifiers found on this platform.")
    print(fp)
    print(f"\n[gnolly] Use with: gnolly protect --bind-fp {fp[:16]}... <file>")


def main():
    p = build_parser()
    args = p.parse_args()
    if args.command == "protect":
        cmd_protect(args)
    elif args.command == "protect-dir":
        cmd_protect_dir(args)
    elif args.command == "protect-wheel":
        cmd_protect_wheel(args)
    elif args.command == "keygen":
        cmd_keygen(args)
    elif args.command == "fingerprint":
        cmd_fingerprint(args)
    else:
        p.print_help()


if __name__ == "__main__":
    main()
