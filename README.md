Copyright (C) 2026 therealOri

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, version 3.
Do make sure to give credit where credit is due.

__ __

<br>

<div align="center">

<img width="300" height="300" alt="Gnolly logo" src="https://github.com/user-attachments/assets/cd965f74-26f6-4265-a734-fb332d55a1f7" />


# Gnolly

**Professional Python code protection. Free, open-source, no paywalls.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](LICENSE)

</div>

__ __

> This readme and documentation is a WIP, more will be added as updates happen.

<br>

Gnolly encrypts, compresses, and obfuscates your Python source so that only someone holding your key can run it. It is a direct free alternative to PyArmor and similar tools, just without the paywalls, license servers, or activation requirements.
__ __

> [!IMPORTANT]
> The gnolly VM protection currently supports python 3.12 versions. I will work on supporting 3.13+ at a later time. (or you can help too by making a pull request)


<br>

## What Gnolly does

When you protect a file, Gnolly runs your code through five stages:

```
your_script.py
    │
    ├─ [1] AST obfuscation      —   name mangling, string hex-encoding,
    │                               integer XOR expressions, dead-code injection,
    │                               docstring removal
    │
    ├─ [2] GIR VM translation   —   source -> Gnolly Intermediate Representation
    │                               (a custom bytecode format; CPython opcodes
    │                               never exist at runtime)
    │
    ├─ [3] Compression          —   zlib / lzma / bz2, best result is used
    │
    ├─ [4] Encryption           —   AES-256-GCM + PBKDF2-HMAC-SHA256
    │                               (600,000 iterations, random salt+IV per file)
    │
    └─ [5] Stub generation      —   fully obfuscated loader script
              │
              └─ your_script.gnolly.py   <-  distribute this
```

The output is a standalone `.py` that asks for a key before running. No source text, no readable bytecode, no embedded key. Two compiled C extensions (`_gnolly_core.so` for decryption, `_gnolly_vm.so` for execution) perform all of the work in native machine code. **Both are required at runtime.**

### True VM protection

Protected code is never executed by CPython's eval loop (`ceval.c`). It runs entirely inside `_gnolly_vm.pyx`, a full bytecode interpreter implemented in Cython with its own stack machine, frame objects, and dispatch loop. This means:

- `sys.settrace` / `sys.setprofile` fire **zero events** for protected code.
- `dis`, `uncompyle6`, `decompile3`, and `pycdc` have no foothold, the on-disk format is GIR, not CPython bytecode
- GIR opcodes are shuffled per-file using a key-derived permutation; two files with identical source produce different binary blobs
__ __

<br>

## Quickstart

### Install

```bash
pip install pycryptodome cython
git clone https://github.com/therealOri/Gnolly
cd Gnolly
python setup.py build_ext --inplace   # builds _gnolly_core.so and _gnolly_vm.so
pip install .
```
> Assuming you are in a 3.12 pyenv virtualenv.

Or as a one-liner:

```bash
pip install pycryptodome cython && python setup.py build_ext --inplace && pip install .
```

### Protect a file

```bash
gnolly protect your_script.py
```

Gnolly prints the hex key and saves it to `your_script.gnly.key`. **Back this up, without it, the protected file cannot run.**

```bash
# Specify an output path explicitly
gnolly protect your_script.py your_output_file.gnly.py

# Use an existing keyfile
gnolly protect your_script.py -K my.key
```

### Run the protected file

```bash
# Option 1: environment variable (recommended for servers and CI)
export GNOLLY_KEY=<hex key>
python your_script.gnly.py

# Option 2: interactive prompt
python your_script.gnly.py
# Gnolly key: ▌<paste key here>
```

---

<br>

## The .so files, what they are and where they go

Two compiled C extensions are required for every protected file:

| File | Role |
|---|---|
| `_gnolly_core.<suffix>.so` | AES-256-GCM decryption, PBKDF2 key derivation, anti-debug |
| `_gnolly_vm.<suffix>.so` | GIR interpreter: executes protected code without CPython's eval loop |

> Both must be present at runtime. If either is missing, the protected script just exits silently.

The suffix encodes the Python version and platform, e.g. `.cpython-312-x86_64-linux-gnu.so`. **You must rebuild for each target platform and Python version.**

<br>

### Building the .so files

```bash
python setup.py build_ext --inplace
```

This creates both `.so` files inside `gnolly/` locally and installs them in your site-packages library.

### Where to place the .so files when distributing

Gnolly searches for each `.so` in four locations, tried in order:

| Priority | Location | Typical use |
|---|---|---|
| 1 | Same directory as the `.gnolly.py` file | Simplest, just drop both files together |
| 2 | `./gnolly/` relative to current working directory | Running from a project root with gnolly installed locally |
| 3 | The `gnolly` package directory (via `sys.modules`) | gnolly installed in the Python environment |
| 4 | `sys.path` scan for any `gnolly/` subdirectory | Non-standard layouts, virtualenvs |

**Simplest deployment** -> put everything in one folder:

```
your_app/
├── my_script.gnly.py
├── _gnolly_core.cpython-312-x86_64-linux-gnu.so
└── _gnolly_vm.cpython-312-x86_64-linux-gnu.so
```

**Alternativey -> gnolly installed in the environment:**

```bash
pip install gnolly          # installs with pre-built .so files
python my_script.gnolly.py  # finds both .so files via sys.modules
```

### What happens if a .so file is not found

```
Gnolly runtime (_gnolly_vm) not found.
Place _gnolly_vm*.so next to this script, or in ./gnolly/, or install gnolly.
  pip install gnolly
```

The process exits immediately with code 1. No decryption is attempted and no information about the payload is exposed.

---

<br>

## CLI reference

### `gnolly protect`

Protect a single `.py` file.

```
gnolly protect <input.py> [output.py] [options]

  -K, --keyfile FILE      Use an existing keyfile instead of generating a new one
  --no-mangle             Skip AST name mangling
  --no-strings            Skip string literal hex-encoding
  --no-dead               Skip dead-code injection
  --no-numbers            Skip integer XOR obfuscation
  --bind                  Bind output to THIS machine (uses current fingerprint)
  --bind-fp HEX           Bind to a specific machine fingerprint (from 'gnolly fingerprint')
  --seed INT              Fix RNG seed for reproducible output
  -v, --verbose           Show pipeline progress
  --verbose-errors        Emit error messages from the stub on failure (dev only)
```

### `gnolly protect-package`

Protect an entire package directory, recursively.

```
gnolly protect-package <input_dir> [output_dir] [options]

  --exclude GLOB [...]    Glob patterns to skip (e.g. "tests/*" "*.pyi")
  (all protect options above also apply)
```

### `gnolly keygen`

Generate a new key without protecting anything.

```
gnolly keygen [keyfile] [options]

  --hint TEXT             Description stored in the keyfile
  --for-file TEXT         Which script this key belongs to (informational)
```

### `gnolly fingerprint`

Print a machine fingerprint for use with `--bind-fp`.

```bash
gnolly fingerprint
# prints: 3a7f91bc...
# Use with: gnolly protect --bind-fp 3a7f91bc... your_script.py
```

---

<br>

## Python API

```python
from gnolly import protect, protect_file
from gnolly.keymanager import generate_key, save_keyfile, key_to_hex

# Generate a key
key = generate_key()
save_keyfile(key, "myapp.key", protected_file="myapp.py")

# Protect from a source string
stub_source = protect(
    source_code,
    key,
    verbose=True,        # show pipeline stages
    silent=True,         # stub prints no errors on failure (default)
)
with open("myapp.gnolly.py", "w") as f:
    f.write(stub_source)

# Or directly from a file path
protect_file("myapp.py", "myapp.gnly.py", key)
```

Full `protect()` signature:

```python
protect(
    source: str,
    password: bytes,
    *,
    filename: str = "<gnly>",
    mangle_names: bool = True,
    obf_strings: bool = True,
    inject_dead: bool = True,
    obf_numbers: bool = True,
    machine_fingerprint: bytes | None = None,
    seed: int | None = None,
    verbose: bool = False,
    silent: bool = True,
) -> str
```

---

<br>

## Verifying protection is active

```bash
python -m gnolly.verify
```

This runs 11 checks and confirms:

- Both `.so` files are compiled native code
- The GIR translation/serialization round-trips correctly
- GIR opcode shuffles are unique per key (same source -> different blobs)
- No `marshal` calls in the VM pipeline (custom binary only)
- `sys.settrace` fires **zero events** for protected code -> CPython's eval loop never touches it
- `dis` and `marshal` cannot decode the GIR blob (it is not CPython bytecode)
- End-to-end protection of a non-trivial module works correctly
- Generators execute correctly inside the GIR VM

Expected output ends with: `Result: PASS -> VM protection is ACTIVE`

---

<br>

## Machine binding

Bind a protected file so it only decrypts on a specific machine:

```bash
# Bind to the current machine
gnolly protect --bind your_script.py

# Bind to a different machine (get its fingerprint first)
gnolly fingerprint                                    # run on target machine
gnolly protect --bind-fp <hex> your_script.py        # run on build machine
```

The machine fingerprint is folded into the PBKDF2 key derivation. On the wrong machine, AES-GCM authentication fails silently, the protected file exits with code 1 and no information is disclosed.

---

<br>

## Security & Design

| Property | How Gnolly achieves it |
|---|---|
| No source in output | Source is compiled to GIR before encryption; plaintext never written to disk |
| No key in output | Key is always external -> env var or interactive prompt |
| Tamper detection | AES-256-GCM authentication tag; SHA-256 hash of both `.so` files baked into stub |
| Unique per-file encoding | GIR opcode shuffle keyed per file; same source -> different binary blob every run |
| No CPython eval loop | Protected code runs in `_gnolly_vm`'s own Cython stack machine, never via `ceval.c` |
| No `marshal` | GIR is a custom binary format; `marshal.loads` is never called |
| `sys.settrace` blocked | VM execution produces zero trace events -> Python-level debuggers cannot single-step |
| `sys.monitoring` suppressed | 3.12+ monitoring events suppressed around decrypt and dispatch |
| Strong KDF | PBKDF2-HMAC-SHA256, 600,000 iterations (OWASP 2024 recommendation for SHA-256) |
| No `__import__` in stub | All imports routed through an obfuscated `__builtins__` alias |
| No external network calls | Protected file is fully self-contained; no phone-home, no activation |
| Machine binding | `--bind` folds a hardware fingerprint into the KDF — wrong machine -> wrong key -> GCM auth fails |
| Obfuscated `.so` loading | Extensions are loaded by file path under a random fake module name; `gnolly` and `_gnolly_core` do not appear as strings in the stub |
| Anti-debug (Python layer) | Trace/profile hooks, known debugger modules, and timing gates checked before any crypto work |
| Anti-debug (C layer) | A second independent sweep runs inside the compiled `.so` after the stub's checks |

### What Gnolly does NOT do

- **Gnolly is not DRM.** A determined adversary with your key and a C-level debugger (e.g. gdb attached to the Python process) can reconstruct logic by instrumenting the runtime at the C level. Code protection raises the cost and effort of reverse engineering; it does not make it theoretically impossible. 
- Gnolly does not prevent inspection of process memory at runtime. (yet)
- Gnolly does not enforce expiry dates, seat counts, or call home.
> I plan on improving anti-debug and anti-tamper as well as general security hardening eventually. At this point, I can only make things harder :).

<br>

### Known limitations
> What I plan on fixing eventually.

| Construct | Status |
|---|---|
| `match` / `case` statements | The numeric obfuscation pass rewrites integer literals inside `case` patterns, producing invalid syntax. Avoid `match` in protected files for now. |
| `except*` / exception groups | `CHECK_EG_MATCH` is not yet in the GIR ISA. Not supported. |
| Zero-arg `super()` | `LOAD_SUPER_ATTR` is not yet supported. Use `super(ClassName, self)` as a workaround. |
| Floating-point constants | The numeric obfuscator decomposes floats (e.g. `0.5` -> `9.668 - 9.168`) with fresh randomness per run; results are correct to ~14 significant figures but the last 2–4 bits may differ from the original due to floating-point rounding across reconstructed expressions. |

Everything else such as: functions, classes, closures, decorators, generators, `async`/`await`, async generators, context managers, comprehensions, exceptions, `*args`/`**kwargs`, multiple inheritance, and walrus operator are supported currenly.
__ __

<br>

## Comparison: Gnolly vs. alternatives

| | **Gnolly** | **PyArmor** | **Cython** | **Nuitka** | **PyInstaller** |
|---|---|---|---|---|---|
| **Price** | Free, open-source | Free tier limited; Pro ~$100 | Free | Free / €299 Commercial | Free |
| **Encryption** | AES-256-GCM | Varies by version | None | None | None |
| **KDF** | PBKDF2-HMAC-SHA256, 600k rounds | Varies | — | — | — |
| **True VM (not CPython eval)** | ✅ | ✅ Pro only | ❌ | ❌ | ❌ |
| **Anti-debug** | ✅ Python + C layer | ✅ | ❌ | ❌ | ❌ |
| **sys.settrace fires 0 events** | ✅ | ✅ | ❌ | ❌ | ❌ |
| **dis / decompilers blocked** | ✅ (custom GIR format) | ✅ | ❌ | ❌ | ❌ |
| **Requires .so at runtime** | ✅ (2 files) | ✅ | ✅ | ❌ (standalone) | ❌ (bundles runtime) |
| **Source hidden** | ✅ | ✅ | Partial | ✅ | ❌ (.pyc recoverable) |
| **No `__import__` in output** | ✅ | ❌ | — | — | — |
| **Per-file licensing / expiry** | ❌ | ✅ (newer versions) | ❌ | ❌ | ❌ |
| **License server / phone-home** | ❌ Never | ✅ Activation required | ❌ | ❌ | ❌ |
| **Open source** | ✅ AGPLv3 | ❌ | ✅ Apache 2 | ✅ Apache 2 | ✅ MIT |
| **Output is a .py file** | ✅ | ✅ | ❌ (.so) | ❌ | ❌ |
| **Machine binding** | ✅ | ✅ Pro | ❌ | ❌ | ❌ |
| **Tamper detection** | ✅ GCM tag + SHA-256 .so hash | ✅ | ❌ | ❌ | ❌ |

### Key differences

**vs. PyArmor** -> PyArmor is an industry standard for Python obfuscation. Its VM mode (`--advanced 2`) is strong but requires a paid Pro license, per-machine activation, and a connection to PyArmor's license server. Newer versions enforce seat limits and can remotely revoke licenses. Gnolly matches PyArmor's protection level for free, with no activation, no phone-home, and AES-256-GCM (authenticated encryption) rather than PyArmor's older schemes. 
> (Because it is close source idk if what I have is actually better or not, but it does work.)

<br>

**vs. Cython** -> Cython compiles Python to a C extension but the `.so` is fairly reversible with tools like `pycdc`. It provides no encryption and no runtime key requirement. Gnolly provides much stronger protection for scripts that don't need to be compiled to native C.

**vs. Nuitka** -> Nuitka produces a standalone native binary (no Python required to run). The compiled binary can be disassembled; it is a packaging and performance tool rather than an IP-protection tool. The right choice when you want a self-contained executable; Gnolly is the right choice when you want a `.py` file that runs on any Python installation with a key. 
> (Use both for a best of both worlds option.)

<br>

**vs. PyInstaller** -> PyInstaller bundles your script and runtime into a single archive. It provides essentially no protection and the original `.pyc` files are trivially extractable. It is a packaging tool, not a protection tool.
__ __

<br>

## Running tests

```bash
pip install pytest
python -m pytest tests/ -v
```
__ __

<br>

## Project structure

```
Gnolly_Main/
├── gnolly/
│   ├── __init__.py           — public API (protect, protect_file)
│   ├── __main__.py           — python -m gnolly entry point
│   ├── cli.py                — command-line interface
│   ├── pipeline.py           — orchestrates all protection stages
│   ├── obfuscate.py          — AST transformer (name mangling, dead code, etc.)
│   ├── vm_translate.py       — CPython bytecode -> GIR translation
│   ├── vm_isa.py             — GIR instruction set definition and opcode shuffle
│   ├── vm_serialize.py       — GIR serialization/deserialization
│   ├── vm_pipeline.py        — GIR opcode shuffle + blob production
│   ├── compress.py           — zlib/lzma/bz2 with auto-select
│   ├── crypto.py             — AES-256-GCM + PBKDF2
│   ├── encoding.py           — custom seeded-alphabet codec
│   ├── stub.py               — generates the obfuscated loader script
│   ├── import_hook.py        — generates .so search and load code
│   ├── binding.py            — machine fingerprinting for --bind
│   ├── keymanager.py         — key generation, save, load
│   ├── verify.py             — python -m gnolly.verify self-test
│   ├── _gnolly_core.pyx      — Cython: AES-256-GCM decrypt, PBKDF2, anti-debug
│   ├── _gnolly_vm.pyx        — Cython: GIR interpreter (full stack machine)
│   └── _gnolly_{core,vm}.*.so — compiled C extensions (build with setup.py)
├── examples/
│   └── sample.py
├── tests/
│   └── test_gnolly.py
├── setup.py                  — builds both .so files (use this)
└── README.md
```
__ __
