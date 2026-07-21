"""
Gnolly test suite.
Run with: python -m pytest tests/ -v
NOTE: Requires both compiled core and vm .so files to be in /gnolly with the .pyx files.
TODO: Fix so it can check for if they exist in the site-packages dir for the py environment.
"""
import os
import sys
import hashlib
import random
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# ── Encoding ──────────────────────────────────────────────────────────────────

class TestEncoding:
    def test_roundtrip_empty(self):
        from gnolly.encoding import GnollyCodec
        c = GnollyCodec(key_material=b"test")
        assert c.decode(c.encode(b"")) == b""

    def test_roundtrip_single_byte(self):
        from gnolly.encoding import GnollyCodec
        c = GnollyCodec(key_material=b"test")
        for b in range(256):
            data = bytes([b])
            assert c.decode(c.encode(data)) == data

    def test_roundtrip_all_lengths(self):
        from gnolly.encoding import GnollyCodec
        c = GnollyCodec(key_material=b"gnolly-seed")
        for length in range(0, 200):
            data = os.urandom(length)
            assert c.decode(c.encode(data)) == data, f"Failed at length {length}"

    def test_different_key_material_different_output(self):
        from gnolly.encoding import GnollyCodec
        data = b"hello gnolly"
        c1 = GnollyCodec(key_material=b"material-a")
        c2 = GnollyCodec(key_material=b"material-b")
        assert c1.encode(data) != c2.encode(data)

    def test_no_equals_in_alphabet(self):
        from gnolly.encoding import GnollyCodec
        c = GnollyCodec(key_material=b"test")
        assert "=" not in c._alpha, "= must not be in alphabet (reserved as padding)"

    def test_large_binary_roundtrip(self):
        from gnolly.encoding import GnollyCodec
        c = GnollyCodec(key_material=b"bigtest")
        data = os.urandom(10_000)
        assert c.decode(c.encode(data)) == data


# ── Compression ───────────────────────────────────────────────────────────────

class TestCompression:
    def test_roundtrip_text(self):
        from gnolly.compress import compress, decompress
        data = b"hello world " * 500
        assert decompress(compress(data)) == data

    def test_roundtrip_random(self):
        from gnolly.compress import compress, decompress
        data = os.urandom(1000)
        assert decompress(compress(data)) == data

    def test_roundtrip_empty(self):
        from gnolly.compress import compress, decompress
        assert decompress(compress(b"")) == b""

    def test_compression_reduces_size(self):
        from gnolly.compress import compress
        data = b"aaaa" * 10000
        assert len(compress(data)) < len(data)


# ── Crypto ────────────────────────────────────────────────────────────────────

class TestCrypto:
    def test_roundtrip(self):
        from gnolly.crypto import encrypt, decrypt
        data = b"secret payload"
        key = b"test-password-gnolly"
        assert decrypt(encrypt(data, key), key) == data

    def test_wrong_key_raises(self):
        from gnolly.crypto import encrypt, decrypt
        data = b"secret"
        blob = encrypt(data, b"correct-key")
        with pytest.raises(ValueError):
            decrypt(blob, b"wrong-key")

    def test_tamper_detection(self):
        from gnolly.crypto import encrypt, decrypt
        data = b"secret"
        blob = bytearray(encrypt(data, b"key"))
        blob[-1] ^= 0xFF  # flip a bit in ciphertext
        with pytest.raises(ValueError):
            decrypt(bytes(blob), b"key")

    def test_unique_ciphertexts(self):
        from gnolly.crypto import encrypt
        data = b"same plaintext"
        key = b"same-key"
        # Each encryption uses a fresh random salt+IV → unique output
        assert encrypt(data, key) != encrypt(data, key)

    def test_large_payload(self):
        from gnolly.crypto import encrypt, decrypt
        data = os.urandom(100_000)
        key = b"large-test-key"
        assert decrypt(encrypt(data, key), key) == data


# ── Obfuscation ───────────────────────────────────────────────────────────────

class TestObfuscation:
    def _run_output(self, source: str) -> str:
        """Obfuscate source, exec it, capture stdout."""
        import io, contextlib
        from gnolly.obfuscate import obfuscate_source
        obf = obfuscate_source(source)
        buf = io.StringIO()
        g = {"__builtins__": __builtins__}
        with contextlib.redirect_stdout(buf):
            exec(compile(obf, "<test>", "exec"), g)
        return buf.getvalue().strip()

    def test_string_obfuscated(self):
        from gnolly.obfuscate import obfuscate_source
        src = 'x = "hello world"'
        obf = obfuscate_source(src)
        assert "hello world" not in obf

    def test_integers_obfuscated(self):
        from gnolly.obfuscate import obfuscate_source
        src = "x = 12345"
        obf = obfuscate_source(src)
        assert "12345" not in obf

    def test_docstrings_removed(self):
        from gnolly.obfuscate import obfuscate_source
        src = '"""This is a docstring."""\ndef foo():\n    """Also a docstring."""\n    pass'
        obf = obfuscate_source(src)
        assert "This is a docstring" not in obf
        assert "Also a docstring" not in obf

    def test_simple_execution(self):
        out = self._run_output("print(2 + 2)")
        assert out == "4"

    def test_function_execution(self):
        src = """
def add(a, b):
    return a + b
print(add(3, 4))
"""
        assert self._run_output(src) == "7"

    def test_class_execution(self):
        src = """
class Counter:
    def __init__(self):
        self.n = 0
    def inc(self):
        self.n += 1
c = Counter()
c.inc()
c.inc()
print(c.n)
"""
        assert self._run_output(src) == "2"

    def test_fstring_preserved(self):
        src = 'name = "world"\nprint(f"hello {name}")'
        assert self._run_output(src) == "hello world"

    def test_keyword_args_work(self):
        src = """
def greet(name, greeting="Hello"):
    return f"{greeting}, {name}!"
print(greet(name="Gnolly", greeting="Hi"))
"""
        assert self._run_output(src) == "Hi, Gnolly!"

    def test_produces_valid_python(self):
        import ast as ast_mod
        from gnolly.obfuscate import obfuscate_source
        src = open(os.path.join(os.path.dirname(__file__), "..", "examples", "sample.py")).read()
        obf = obfuscate_source(src)
        ast_mod.parse(obf)  # should not raise


# ── Full Pipeline ─────────────────────────────────────────────────────────────

class TestPipeline:
    def _protect_and_run(self, source: str) -> dict:
        from gnolly.pipeline import protect
        from gnolly.keymanager import generate_key, key_to_hex
        key = generate_key()
        stub = protect(source, key)
        os.environ["GNOLLY_KEY"] = key_to_hex(key)
        g = {"__builtins__": __builtins__}
        exec(compile(stub, "protected.gnolly.py", "exec"), g)
        return g

    def test_simple(self):
        self._protect_and_run("result = 1 + 1")

    def test_output_correct(self):
        import io, contextlib
        from gnolly.pipeline import protect
        from gnolly.keymanager import generate_key, key_to_hex
        src = "print('gnolly works')"
        key = generate_key()
        stub = protect(src, key)
        os.environ["GNOLLY_KEY"] = key_to_hex(key)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            exec(compile(stub, "p.py", "exec"), {"__builtins__": __builtins__})
        assert buf.getvalue().strip() == "gnolly works"

    def test_wrong_key_fails(self):
        from gnolly.pipeline import protect
        from gnolly.keymanager import generate_key, key_to_hex
        src = "print('hello')"
        key = generate_key()
        stub = protect(src, key)
        wrong_key = generate_key()
        os.environ["GNOLLY_KEY"] = key_to_hex(wrong_key)
        with pytest.raises(SystemExit):
            exec(compile(stub, "p.py", "exec"), {"__builtins__": __builtins__})

    def test_full_sample(self):
        import io, contextlib
        from gnolly.pipeline import protect
        from gnolly.keymanager import generate_key, key_to_hex
        src = open(os.path.join(os.path.dirname(__file__), "..", "examples", "sample.py")).read()
        key = generate_key()
        stub = protect(src, key)
        os.environ["GNOLLY_KEY"] = key_to_hex(key)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            exec(compile(stub, "sample.gnolly.py", "exec"), {"__builtins__": __builtins__})
        out = buf.getvalue()
        assert "Hello from a protected script!" in out
        assert "fibonacci(10) = 55" in out
        assert "Hello, World! The answer is 42." in out

    def test_repeated_calls_produce_different_stubs(self):
        """No seed exists anymore -- every protect() call must still be unique."""
        from gnolly.pipeline import protect
        from gnolly.keymanager import generate_key
        src = "x = 1"
        key = generate_key()
        s1 = protect(src, key)
        s2 = protect(src, key)
        assert s1 != s2

    def test_no_source_in_stub(self):
        from gnolly.pipeline import protect
        from gnolly.keymanager import generate_key
        src = 'SECRET_TOKEN = "xK9mP2qR7vL4nW1j"'
        key = generate_key()
        stub = protect(src, key)
        assert "SECRET_TOKEN" not in stub
        assert "xK9mP2qR7vL4nW1j" not in stub

    def test_no_exec_string_in_stub(self):
        """The stub must not exec() a string, but only a code object."""
        from gnolly.pipeline import protect
        from gnolly.keymanager import generate_key
        src = "x = 1"
        key = generate_key()
        stub = protect(src, key)
        # exec() should only appear followed by a variable name (code object),
        # never by a string literal or decode() call
        import re
        # Find all exec( calls
        exec_calls = re.findall(r'exec\(([^)]{1,60})', stub)
        for call in exec_calls:
            assert "decode" not in call, f"exec() on string found: exec({call})"
            assert '"""' not in call and "'''" not in call


# ── Key Manager ───────────────────────────────────────────────────────────────

class TestKeyManager:
    def test_generate_key_length(self):
        from gnolly.keymanager import generate_key
        k = generate_key()
        assert len(k) == 32

    def test_generate_unique(self):
        from gnolly.keymanager import generate_key
        assert generate_key() != generate_key()

    def test_save_load_roundtrip(self, tmp_path):
        from gnolly.keymanager import generate_key, save_keyfile, load_keyfile
        key = generate_key()
        path = tmp_path / "test.key"
        save_keyfile(key, path, protected_file="test.py", hint="test key")
        loaded = load_keyfile(path)
        assert loaded == key

    def test_key_from_env(self):
        from gnolly.keymanager import generate_key, key_to_hex, key_from_env
        key = generate_key()
        os.environ["GNOLLY_KEY"] = key_to_hex(key)
        assert key_from_env() == key

    def test_key_from_env_missing(self):
        from gnolly.keymanager import key_from_env
        os.environ.pop("GNOLLY_KEY", None)
        assert key_from_env() is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])



# ── Full Pipeline (VM mode, always on) ───────────────────────────────────────

class TestPipelineWithShuffle:
    def test_protect_and_run_with_shuffle(self):
        import io, contextlib
        from gnolly.pipeline import protect
        from gnolly.keymanager import generate_key, key_to_hex
        src = open(os.path.join(os.path.dirname(__file__), "..", "examples", "sample.py")).read()
        key = generate_key()
        stub = protect(src, key)
        os.environ["GNOLLY_KEY"] = key_to_hex(key)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            exec(compile(stub, "p.gnolly.py", "exec"), {"__builtins__": __builtins__})
        out = buf.getvalue()
        assert "fibonacci(10) = 55" in out
        assert "Hello from a protected script!" in out

    def test_protect_and_run_without_shuffle(self):
        import io, contextlib
        from gnolly.pipeline import protect
        from gnolly.keymanager import generate_key, key_to_hex
        src = "print('no shuffle')"
        key = generate_key()
        stub = protect(src, key)
        os.environ["GNOLLY_KEY"] = key_to_hex(key)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            exec(compile(stub, "p.gnolly.py", "exec"), {"__builtins__": __builtins__})
        assert buf.getvalue().strip() == "no shuffle"


# ── Package Protection ────────────────────────────────────────────────────────

class TestPackageProtection:
    def test_protect_package(self, tmp_path):
        from gnolly.package import protect_package
        from gnolly.keymanager import generate_key, key_to_hex
        import io, contextlib

        # Create a mini package
        pkg = tmp_path / "mypkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("VALUE = 42\n")
        (pkg / "math_utils.py").write_text(
            "def double(n): return n * 2\n"
            "def triple(n): return n * 3\n"
        )

        out_dir = tmp_path / "mypkg_protected"
        key = generate_key()
        results = protect_package(pkg, out_dir, key)

        assert len(results) == 2
        assert (out_dir / "__init__.gnolly.py").exists()
        assert (out_dir / "math_utils.gnolly.py").exists()

    def test_protected_package_files_execute(self, tmp_path):
        from gnolly.package import protect_package
        from gnolly.keymanager import generate_key, key_to_hex
        import io, contextlib

        pkg = tmp_path / "mypkg"
        pkg.mkdir()
        (pkg / "calc.py").write_text(
            "def add(a, b): return a + b\n"
            "print(add(10, 32))\n"
        )

        out_dir = tmp_path / "out"
        key = generate_key()
        results = protect_package(pkg, out_dir, key)

        os.environ["GNOLLY_KEY"] = key_to_hex(key)
        protected_file = out_dir / "calc.gnolly.py"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            exec(compile(protected_file.read_text(), "calc.gnolly.py", "exec"),
                 {"__builtins__": __builtins__})
        assert buf.getvalue().strip() == "42"

    def test_exclude_pattern(self, tmp_path):
        from gnolly.package import protect_package
        from gnolly.keymanager import generate_key

        pkg = tmp_path / "mypkg"
        pkg.mkdir()
        (pkg / "main.py").write_text("x = 1\n")
        (pkg / "test_main.py").write_text("x = 2\n")

        out_dir = tmp_path / "out"
        key = generate_key()
        results = protect_package(pkg, out_dir, key, exclude=["**/test_*.py"])

        assert len(results) == 1
        assert not (out_dir / "test_main.gnolly.py").exists()


# ── Anti-Debug ────────────────────────────────────────────────────────────────

class TestAntiDebug:
    def _make_stub(self, src="print('x')"):
        from gnolly.pipeline import protect
        from gnolly.keymanager import generate_key, key_to_hex
        key = generate_key()
        stub = protect(src, key)
        os.environ["GNOLLY_KEY"] = key_to_hex(key)
        return stub

    def test_trace_hook_triggers_exit(self):
        """sys.settrace active (debugger attached) -> SystemExit."""
        stub = self._make_stub()
        import sys as _sys
        _sys.settrace(lambda *a: None)
        try:
            with pytest.raises(SystemExit):
                exec(compile(stub, "p.py", "exec"), {"__builtins__": __builtins__})
        finally:
            _sys.settrace(None)

    def test_profile_hook_triggers_exit(self):
        """sys.setprofile active (profiler attached) -> SystemExit."""
        stub = self._make_stub()
        import sys as _sys
        _sys.setprofile(lambda *a: None)
        try:
            with pytest.raises(SystemExit):
                exec(compile(stub, "p.py", "exec"), {"__builtins__": __builtins__})
        finally:
            _sys.setprofile(None)

    def test_pydevd_in_modules_triggers_exit(self):
        """pydevd in sys.modules (PyCharm debugger) -> SystemExit."""
        import types, sys as _sys
        _sys.modules['pydevd'] = types.ModuleType('pydevd')
        stub = self._make_stub()
        try:
            with pytest.raises(SystemExit):
                exec(compile(stub, "p.py", "exec"), {"__builtins__": __builtins__})
        finally:
            del _sys.modules['pydevd']

    def test_debugpy_in_modules_triggers_exit(self):
        """debugpy in sys.modules (VS Code debugger) -> SystemExit."""
        import types, sys as _sys
        _sys.modules['debugpy'] = types.ModuleType('debugpy')
        stub = self._make_stub()
        try:
            with pytest.raises(SystemExit):
                exec(compile(stub, "p.py", "exec"), {"__builtins__": __builtins__})
        finally:
            del _sys.modules['debugpy']

    def test_normal_execution_unaffected(self):
        """No debugger active → runs normally."""
        import io, contextlib
        src = "print('antidebug ok')"
        stub = self._make_stub(src)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            exec(compile(stub, "p.py", "exec"), {"__builtins__": __builtins__})
        assert buf.getvalue().strip() == "antidebug ok"

    def test_antidebug_lines_in_stub(self):
        """Anti-debug checks are present as obfuscated lines in the stub."""
        from gnolly.pipeline import protect
        from gnolly.keymanager import generate_key
        stub = protect("print('x')", generate_key(), pack=False)
        # The stub should contain settrace and gettrace references (encoded)
        # We can't check by name since they're encoded, but we can verify
        # the stub has significantly more lines than a stub without antidebug
        assert len(stub.splitlines()) > 100

    def test_no_plain_debug_strings(self):
        """Debug module names don't appear in plaintext in the stub."""
        stub = self._make_stub()
        for name in ['pydevd', 'debugpy', 'gettrace', 'settrace', 'getprofile']:
            assert name not in stub, f"'{name}' visible in stub"


# ── Machine Binding ───────────────────────────────────────────────────────────

class TestMachineBinding:
    def test_collect_fingerprint_stable(self):
        """Fingerprint is stable across calls."""
        from gnolly.binding import collect_fingerprint
        fp1 = collect_fingerprint()
        fp2 = collect_fingerprint()
        if fp1 is not None:
            assert fp1 == fp2
            assert len(fp1) == 32

    def test_unbound_still_works(self):
        """No machine_fingerprint = normal execution."""
        import io, contextlib
        from gnolly.pipeline import protect
        from gnolly.keymanager import generate_key, key_to_hex
        key = generate_key()
        stub = protect("print('unbound')", key)
        os.environ["GNOLLY_KEY"] = key_to_hex(key)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            exec(compile(stub, "p.py", "exec"), {"__builtins__": __builtins__})
        assert buf.getvalue().strip() == "unbound"

    def test_bound_correct_machine_runs(self):
        """Bound to this machine with correct fingerprint succeeds."""
        import io, contextlib
        from gnolly.pipeline import protect
        from gnolly.keymanager import generate_key, key_to_hex
        from gnolly.binding import collect_fingerprint
        fp = collect_fingerprint()
        if fp is None:
            pytest.skip("No stable fingerprint on this platform")
        key = generate_key()
        stub = protect("print('bound ok')", key, machine_fingerprint=fp)
        os.environ["GNOLLY_KEY"] = key_to_hex(key)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            exec(compile(stub, "p.py", "exec"), {"__builtins__": __builtins__})
        assert buf.getvalue().strip() == "bound ok"

    def test_bound_wrong_machine_fails(self):
        """Bound to wrong fingerprint exits with error."""
        from gnolly.pipeline import protect
        from gnolly.keymanager import generate_key, key_to_hex
        from gnolly.binding import collect_fingerprint
        fp = collect_fingerprint()
        if fp is None:
            pytest.skip("No stable fingerprint on this platform")
        wrong_fp = bytes(b ^ 0xFF for b in fp)
        key = generate_key()
        stub = protect("print('should not run')", key,
                       machine_fingerprint=wrong_fp)
        os.environ["GNOLLY_KEY"] = key_to_hex(key)
        with pytest.raises(SystemExit):
            exec(compile(stub, "p.py", "exec"), {"__builtins__": __builtins__})

    def test_no_gnolly_identifiers_in_stub(self):
        """No Gnolly-specific identifiers visible in stub output."""
        from gnolly.pipeline import protect
        from gnolly.keymanager import generate_key
        stub = protect("x = 1", generate_key())
        for ident in ['gnolly', '_gnolly_core', 'gnolly_run']:
            assert ident not in stub, f"'{ident}' found in stub"

    def test_fingerprint_hex_roundtrip(self):
        """fingerprint_hex() → fingerprint_from_hex() roundtrips correctly."""
        from gnolly.binding import collect_fingerprint, fingerprint_hex, fingerprint_from_hex
        fp = collect_fingerprint()
        if fp is None:
            pytest.skip("No stable fingerprint")
        hexstr = fingerprint_hex()
        assert fingerprint_from_hex(hexstr) == fp


# ── Import Hook ───────────────────────────────────────────────────────────────

class TestImportHook:
    def test_no_gnolly_in_stub(self):
        """Import hook hides all Gnolly identifiers from stub."""
        from gnolly.pipeline import protect
        from gnolly.keymanager import generate_key
        stub = protect("x=1", generate_key())
        for ident in ['gnolly', '_gnolly_core', 'gnolly_run', 'spec_from_file']:
            assert ident not in stub, f"'{ident}' found in stub"

    def test_so_hash_embedded(self):
        """The .so hash is verified against by the stub, but obfuscated --
        not embedded as a bare, grep-able plaintext literal."""
        from gnolly.pipeline import protect
        from gnolly.keymanager import generate_key
        from gnolly.import_hook import get_core_so_hash
        so_hash = get_core_so_hash()
        if so_hash is None:
            pytest.skip("No compiled .so")
        stub = protect("x=1", generate_key())
        assert so_hash not in stub, \
            ".so hash must not appear as a plaintext literal in the stub"

    def test_stub_runs_with_hook(self):
        """Protected file runs correctly using the import hook path."""
        import io, contextlib
        from gnolly.pipeline import protect
        from gnolly.keymanager import generate_key, key_to_hex
        src = open(os.path.join(os.path.dirname(__file__), "..", "examples", "sample.py")).read()
        key = generate_key()
        stub = protect(src, key)
        os.environ["GNOLLY_KEY"] = key_to_hex(key)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            exec(compile(stub, "hook.gnolly.py", "exec"), {"__builtins__": __builtins__})
        assert "fibonacci(10) = 55" in buf.getvalue()
        assert "Hello from a protected script!" in buf.getvalue()
