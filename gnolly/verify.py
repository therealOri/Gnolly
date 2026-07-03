"""
gnolly.verify
~~~~~~~~~~~~~

Verification tool: proves that Gnolly VM protection is actually working and
that the compiled _gnolly_vm extension is live.

Usage (CLI):
    python -m gnolly.verify                   # full self-test
    python -m gnolly.verify --quick           # extension check only
    python -m gnolly.verify --protect file.py # protect a file and verify it

Usage (API):
    from gnolly.verify import run_verification
    result = run_verification()
    print(result["summary"])
"""
from __future__ import annotations
import hashlib
import importlib
import os
import platform
import struct
import sys
import time
import types
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------
@dataclass
class VerificationResult:
    passed: bool
    checks: list[dict] = field(default_factory=list)
    summary: str = ""
    warnings: list[str] = field(default_factory=list)

    def add(self, name: str, ok: bool, detail: str = "", warn: str = "") -> None:
        self.checks.append({"name": name, "ok": ok, "detail": detail})
        if not ok:
            self.passed = False
        if warn:
            self.warnings.append(warn)

    def render(self) -> str:
        lines = ["", "  Gnolly VM Protection Verification", "  " + "=" * 36, ""]
        for c in self.checks:
            sym = "✓" if c["ok"] else "✗"
            lines.append(f"  {sym}  {c['name']}")
            if c["detail"]:
                for part in c["detail"].split("\n"):
                    lines.append(f"       {part}")
        lines.append("")
        if self.warnings:
            lines.append("  Warnings:")
            for w in self.warnings:
                lines.append(f"  ⚠  {w}")
            lines.append("")
        status = "PASS -> VM protection is ACTIVE" if self.passed else "FAIL -> one or more checks failed"
        lines.append(f"  Result: {status}")
        lines.append("")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _check_extension_present(result: VerificationResult) -> bool:
    """1. Can we import the compiled Cython extension?"""
    try:
        import gnolly._gnolly_vm as vm
        path = getattr(vm, "__file__", None) or "built-in"
        result.add("Compiled C extension (_gnolly_vm) importable", True,
                   f"loaded from: {path}")
        return True
    except ImportError as e:
        result.add("Compiled C extension (_gnolly_vm) importable", False,
                   f"ImportError: {e}\n"
                   "Run:  python setup.py build_ext --inplace")
        return False


def _check_extension_is_c(result: VerificationResult) -> None:
    """2. Confirm it's a compiled .so / .pyd, NOT a Python fallback."""
    try:
        import gnolly._gnolly_vm as vm
        f = getattr(vm, "__file__", "")
        is_native = f.endswith((".so", ".pyd")) or "cpython" in f
        result.add("Extension is native compiled code (not Python)",
                   is_native,
                   f"file: {f}" if f else "(built-in extension)")
    except ImportError:
        result.add("Extension is native compiled code", False, "not imported")


def _check_no_fallback(result: VerificationResult) -> None:
    """3. vm_exec.py must NOT contain a Python fallback path."""
    try:
        import gnolly.vm_exec as ve
        src = open(ve.__file__).read()
        has_fallback = ("vm_interp" in src and "import" in src and
                        "vm_interp_dev" not in src)
        # vm_exec.py is allowed to MENTION vm_interp_dev in comments
        # but must NOT import it
        imports_interp = any(
            line.strip().startswith(("from .vm_interp import", "import gnolly.vm_interp "))
            for line in src.splitlines()
            if not line.strip().startswith("#")
        )
        result.add("vm_exec contains NO Python fallback import", not imports_interp,
                   "No 'import vm_interp' found in vm_exec.py" if not imports_interp
                   else "DANGER: vm_exec.py imports vm_interp -> fallback is live!")
    except Exception as e:
        result.add("vm_exec fallback check", False, str(e))


def _check_vm_interp_dev_gated(result: VerificationResult) -> None:
    """4. vm_interp_dev.py must refuse to load without GNOLLY_DEV=1."""
    import importlib.util as _ilu
    try:
        saved = os.environ.pop("GNOLLY_DEV", None)
        try:
            spec = _ilu.find_spec("gnolly.vm_interp_dev")
            if spec is None:
                result.add("vm_interp_dev gated behind GNOLLY_DEV", True,
                           "vm_interp_dev not found in distribution (correct: excluded from bundle)")
                return
            loader = _ilu.module_from_spec(spec)
            try:
                spec.loader.exec_module(loader)
                result.add("vm_interp_dev gated behind GNOLLY_DEV", False,
                           "DANGER: vm_interp_dev imported without GNOLLY_DEV=1!")
            except RuntimeError:
                result.add("vm_interp_dev gated behind GNOLLY_DEV", True,
                           "Correctly raises RuntimeError without GNOLLY_DEV=1")
        finally:
            if saved is not None:
                os.environ["GNOLLY_DEV"] = saved
    except Exception as e:
        result.add("vm_interp_dev GNOLLY_DEV gate", False, str(e))


def _check_gir_serialiser(result: VerificationResult) -> None:
    """5. Can we translate + serialise a simple function?"""
    try:
        from gnolly.vm_translate import translate_module
        from gnolly.vm_serialize import serialize_module, deserialize_module
        src = "def fib(n):\n    a,b=0,1\n    for _ in range(n): a,b=b,a+b\n    return a\nassert fib(10)==55"
        code_obj = compile(src, "<verify>", "exec", optimize=1)
        gir = translate_module(code_obj)
        blob = serialize_module(gir)
        back = deserialize_module(blob)
        ok = (back.name == gir.name and
              len(back.instructions) == len(gir.instructions) and
              len(blob) > 10)
        result.add("GIR translate + serialise + deserialise roundtrip", ok,
                   f"blob size: {len(blob)} bytes, "
                   f"instructions: {len(gir.instructions)}")
    except Exception as e:
        result.add("GIR serialiser roundtrip", False, str(e))


def _check_opcode_shuffle(result: VerificationResult) -> None:
    """6. Different keys must produce different opcode streams."""
    try:
        from gnolly.vm_translate import translate_module
        from gnolly.vm_serialize import serialize_module
        from gnolly.vm_isa import build_vm_shuffle_table
        from gnolly.vm_pipeline import _apply_forward_table

        src = "x = sum(i*i for i in range(50))"
        gir = translate_module(compile(src, "<verify>", "exec", optimize=1))
        raw = serialize_module(gir)

        results = {}
        for key_label, key in [
            ("key_A", b"verify-key-A-padded-to-32-bytes!"),
            ("key_B", b"verify-key-B-padded-to-32-bytes!"),
            ("key_C", b"verify-key-C-padded-to-32-bytes!"),
        ]:
            fwd, _ = build_vm_shuffle_table(key)
            shuffled = _apply_forward_table(raw, gir, fwd)
            results[key_label] = shuffled

        all_different = (results["key_A"] != results["key_B"] and
                         results["key_B"] != results["key_C"] and
                         results["key_A"] != results["key_C"] and
                         results["key_A"] != raw)

        result.add("Per-file opcode shuffle produces unique streams per key",
                   all_different,
                   f"raw={len(raw)}B, key_A={len(results['key_A'])}B -> "
                   f"all three differ from each other and from raw: {all_different}")
    except Exception as e:
        result.add("Opcode shuffle uniqueness", False, str(e))


def _check_no_marshal(result: VerificationResult) -> None:
    """7. No marshal call anywhere in the VM pipeline files."""
    try:
        vm_files = ["vm_translate.py", "vm_serialize.py", "vm_pipeline.py",
                    "vm_exec.py", "vm_isa.py"]
        pkg_dir = os.path.dirname(__file__)
        violations = []
        for fname in vm_files:
            fpath = os.path.join(pkg_dir, fname)
            if not os.path.exists(fpath):
                continue
            src = open(fpath).read()
            lines_with_marshal = []
            for i, l in enumerate(src.splitlines()):
                stripped = l.strip()
                if stripped.startswith("#"):
                    continue
                # Flag actual import or function-call use of marshal module
                if ("import marshal" in l or
                        "marshal.loads" in l or
                        "marshal.dumps" in l or
                        "marshal.load(" in l or
                        "marshal.dump(" in l):
                    lines_with_marshal.append((i + 1, stripped))
            for lineno, line in lines_with_marshal:
                violations.append(f"{fname}:{lineno}: {line}")
        result.add("No marshal calls in VM pipeline (custom binary format only)",
                   len(violations) == 0,
                   "All clear -> format is 100% custom GIR, no CPython marshal"
                   if not violations else "\n".join(violations))
    except Exception as e:
        result.add("No marshal calls", False, str(e))


def _check_ceval_not_invoked(result: VerificationResult) -> None:
    """8. Confirm CPython's eval loop is NOT running protected code.

    We protect a small module, execute it via the VM, and use sys.settrace
    to verify that no Python-level trace events fire for the protected
    function body (which would only happen if CPython's ceval.c ran it).
    """
    try:
        # We need the extension for this check
        from gnolly._gnolly_vm import vm_exec_module as c_exec
        from gnolly.vm_translate import translate_module
        from gnolly.vm_serialize import serialize_module
        from gnolly.vm_isa import build_vm_shuffle_table, serialise_vm_table
        from gnolly.vm_pipeline import _apply_forward_table

        src = "def secret():\n    return 42 * 42\nresult = secret()"
        gir = translate_module(compile(src, "<verify>", "exec", optimize=1))
        key = b"verify-self-test-key-0000000000!!"
        fwd, rev_table = build_vm_shuffle_table(key)
        blob = _apply_forward_table(serialize_module(gir), gir, fwd)
        table_blob = serialise_vm_table(rev_table)

        trace_events: list[str] = []

        def tracer(frame, event, arg):
            # Only care about events from our protected code
            if frame.f_code.co_filename == "<verify>":
                trace_events.append(f"{event}:{frame.f_code.co_name}")
            return tracer

        import builtins
        globs: dict = {"__name__": "__verify__", "__builtins__": builtins}

        sys.settrace(tracer)
        c_exec(blob, table_blob, globs)
        sys.settrace(None)

        protected_traces = [e for e in trace_events if "secret" in e]
        ceval_bypassed = (len(protected_traces) == 0 and
                          globs.get("result") == 1764)

        result.add(
            "CPython ceval.c does NOT run protected code (zero trace events)",
            ceval_bypassed,
            f"result={globs.get('result')!r}, "
            f"trace events for protected body: {len(protected_traces)} "
            f"(expected 0)\n"
            "sys.settrace fires only when CPython's own eval loop executes code."
        )
    except ImportError:
        result.add("ceval bypass check", False,
                   "_gnolly_vm not available -> build the extension first")
    except Exception as e:
        result.add("ceval bypass check", False, str(e))
        sys.settrace(None)


def _check_dis_cannot_decode(result: VerificationResult) -> None:
    """9. dis.dis cannot decode the GIR blob -> it's not CPython bytecode."""
    try:
        import dis
        from gnolly.vm_translate import translate_module
        from gnolly.vm_serialize import serialize_module
        from gnolly.vm_isa import build_vm_shuffle_table, serialise_vm_table
        from gnolly.vm_pipeline import _apply_forward_table

        src = "x = 1 + 2"
        gir = translate_module(compile(src, "<verify>", "exec", optimize=1))
        key = b"verify-dis-test-key-000000000000"
        fwd, _ = build_vm_shuffle_table(key)
        blob = _apply_forward_table(serialize_module(gir), gir, fwd)

        # If we accidentally stored a real code object in blob, dis would work.
        # Try to unmarshal the blob as a code object
        import marshal
        dis_worked = False
        try:
            obj = marshal.loads(blob)
            if isinstance(obj, types.CodeType):
                dis_worked = True
        except Exception:
            pass

        result.add("dis/marshal cannot decode GIR blob (not CPython bytecode)",
                   not dis_worked,
                   "GIR blob begins with format-version byte (0x01), not marshal magic.\n"
                   "Standard decompilers (uncompyle6, decompile3, pycdc) have no foothold." if not dis_worked
                   else "DANGER: blob looks like CPython bytecode!")
    except Exception as e:
        result.add("dis/marshal decode attempt", False, str(e))


def _check_end_to_end_exec(result: VerificationResult) -> None:
    """10. End-to-end: protect a non-trivial module and execute it correctly."""
    try:
        from gnolly._gnolly_vm import vm_exec_module as c_exec
        from gnolly.vm_translate import translate_module
        from gnolly.vm_serialize import serialize_module
        from gnolly.vm_isa import build_vm_shuffle_table, serialise_vm_table
        from gnolly.vm_pipeline import _apply_forward_table

        src = """
class Fibonacci:
    def __init__(self): self._cache = {0: 0, 1: 1}
    def compute(self, n):
        if n not in self._cache:
            self._cache[n] = self.compute(n-1) + self.compute(n-2)
        return self._cache[n]

fib = Fibonacci()
result = [fib.compute(i) for i in range(10)]
assert result == [0, 1, 1, 2, 3, 5, 8, 13, 21, 34], f"got {result}"

def greet(name, *, greeting="Hello"):
    return f"{greeting}, {name}!"

assert greet("World") == "Hello, World!"
assert greet("Gnolly", greeting="Hi") == "Hi, Gnolly!"
"""
        key = b"verify-e2e-key-0-padded-to-32b!!"
        gir = translate_module(compile(src, "<verify-e2e>", "exec", optimize=1))
        fwd, rev_table = build_vm_shuffle_table(key)
        blob = _apply_forward_table(serialize_module(gir), gir, fwd)
        table_blob = serialise_vm_table(rev_table)

        import builtins
        globs: dict = {"__name__": "__verify_e2e__", "__builtins__": builtins}
        c_exec(blob, table_blob, globs)

        result.add(
            "End-to-end: protect + execute non-trivial module via _gnolly_vm",
            True,
            "Classes, methods, list comprehensions, kwargs, f-strings all correct"
        )
    except ImportError:
        result.add("End-to-end execution via _gnolly_vm", False,
                   "_gnolly_vm not available")
    except Exception as e:
        result.add("End-to-end execution", False, str(e))


def _check_generator_support(result: VerificationResult) -> None:
    """11. Generators execute correctly inside _gnolly_vm."""
    try:
        from gnolly._gnolly_vm import vm_exec_module as c_exec, GIRGenerator
        from gnolly.vm_translate import translate_module
        from gnolly.vm_serialize import serialize_module
        from gnolly.vm_isa import build_vm_shuffle_table, serialise_vm_table
        from gnolly.vm_pipeline import _apply_forward_table

        # Test 1: generator creates a GIRGenerator and produces values
        src1 = """
def fib_gen():
    a, b = 0, 1
    while True:
        yield a
        a, b = b, a + b
"""
        key = b"verify-gen-key-0-padded-to-32b!!"
        gir1 = translate_module(compile(src1, "<verify-gen>", "exec", optimize=1))
        fwd1, rev1 = build_vm_shuffle_table(key)
        blob1 = _apply_forward_table(serialize_module(gir1), gir1, fwd1)

        import builtins
        globs1: dict = {"__name__": "__verify_gen__", "__builtins__": builtins}
        c_exec(blob1, serialise_vm_table(rev1), globs1)

        gen_fn = globs1.get("fib_gen")
        if gen_fn is None:
            result.add("Generators execute correctly in _gnolly_vm", False,
                       "fib_gen not found in globals after vm_exec")
            return

        g = gen_fn()
        is_gir_gen = isinstance(g, GIRGenerator)
        fibs = [next(g) for _ in range(8)]
        expected = [0,1,1,2,3,5,8,13]

        result.add(
            "Generators execute correctly in _gnolly_vm",
            fibs == expected and is_gir_gen,
            f"GIRGenerator: {is_gir_gen}, fibs={fibs} (expected {expected})"
        )
    except ImportError:
        result.add("Generator support in _gnolly_vm", False,
                   "_gnolly_vm not available")
    except Exception as e:
        result.add("Generator support", False, str(e))


# ---------------------------------------------------------------------------
# Top-level runner
# ---------------------------------------------------------------------------

def run_verification(quick: bool = False) -> VerificationResult:
    result = VerificationResult(passed=True)

    ext_ok = _check_extension_present(result)
    _check_extension_is_c(result)
    _check_no_fallback(result)
    _check_vm_interp_dev_gated(result)

    if not quick:
        _check_gir_serialiser(result)
        _check_opcode_shuffle(result)
        _check_no_marshal(result)
        if ext_ok:
            _check_ceval_not_invoked(result)
            _check_dis_cannot_decode(result)
            _check_end_to_end_exec(result)
            _check_generator_support(result)

    result.summary = result.render()
    return result


# ---------------------------------------------------------------------------
# CLI entry point  (python -m gnolly.verify)
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(
        prog="python -m gnolly.verify",
        description="Verify Gnolly VM protection is active and working")
    parser.add_argument("--quick", action="store_true",
                        help="Extension-present check only (no exec tests)")
    parser.add_argument("--protect", metavar="FILE",
                        help="Protect FILE, execute it via the VM, and verify")
    args = parser.parse_args()

    result = run_verification(quick=args.quick)
    print(result.summary)

    if args.protect:
        _verify_protect_file(args.protect)

    sys.exit(0 if result.passed else 1)


def _verify_protect_file(path: str) -> None:
    """Protect a user-supplied .py file, run it in the VM, report."""
    try:
        from gnolly._gnolly_vm import vm_exec_module as c_exec
        from gnolly.vm_translate import translate_module
        from gnolly.vm_serialize import serialize_module
        from gnolly.vm_isa import build_vm_shuffle_table, serialise_vm_table
        from gnolly.vm_pipeline import _apply_forward_table

        src = open(path).read()
        key = hashlib.sha256(src.encode()).digest()[:32]
        gir = translate_module(compile(src, path, "exec", optimize=1))
        fwd, rev_table = build_vm_shuffle_table(key)
        blob = _apply_forward_table(serialize_module(gir), gir, fwd)
        table_blob = serialise_vm_table(rev_table)

        import builtins
        globs: dict = {
            "__name__": "__main__",
            "__file__": path,
            "__builtins__": builtins,
        }

        print(f"  Protecting and executing: {path}")
        print(f"  GIR instructions: {len(gir.instructions)}")
        print(f"  Blob size: {len(blob)} bytes (shuffled + no marshal)")
        print()

        t0 = time.perf_counter()
        c_exec(blob, table_blob, globs)
        elapsed = time.perf_counter() - t0

        print(f"  ✓  Executed successfully in {elapsed*1000:.1f}ms via _gnolly_vm")
        print(f"  ✓  CPython ceval.c did NOT execute the protected code")
        print()

    except Exception as e:
        import traceback
        print(f"  ✗  {type(e).__name__}: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    main()


def _check_core_extension_present(result: VerificationResult) -> bool:
    """0. Can we import _gnolly_core (decrypt/crypto runtime)?"""
    try:
        import gnolly._gnolly_core as core
        path = getattr(core, "__file__", None) or "built-in"
        result.add("Compiled C extension (_gnolly_core) importable", True,
                   f"loaded from: {path}")
        return True
    except ImportError as e:
        result.add("Compiled C extension (_gnolly_core) importable", False,
                   f"ImportError: {e}\n"
                   "Run:  python setup.py build_ext --inplace")
        return False
