Copyright (C) 2026 therealOri

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, version 3. 
Do make sure to give credit where credit is due.
__ __

<br>

<div align="center">

<img width="300" height="300" alt="Screenshot_20260610_105020" src="https://github.com/user-attachments/assets/cd965f74-26f6-4265-a734-fb332d55a1f7" />


# Gnolly

**Professional Python code protection. Free, open-source, no paywalls.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](LICENSE)

</div>

__ __
> This readme and documentation is a WIP, more will be added as updates happen, etc.

<br>
<br>

Gnolly encrypts, compresses, and obfuscates your Python source so that only someone holding your key can run it. It is a direct free alternative to PyArmor and similar tools. Just, without the paywalls..

---

<br>

## What Gnolly does

When you protect a file, Gnolly runs your code through six stages:

```
your_script.py
    │
    ├─ [1] AST obfuscation   — name mangling, string hex-encoding,
    │                          integer XOR expressions, dead-code injection,
    │                          docstring removal
    │
    ├─ [2] Bytecode compile  — source → CPython marshal'd code object
    │                          (no source text survives past this point)
    │
    ├─ [3] Compression       — zlib / lzma / bz2, best/smallest result is used
    │
    ├─ [4] Encryption        — AES-256-GCM with PBKDF2-HMAC-SHA256
    │                          (600,000 iterations, random salt+IV per file)
    │
    ├─ [5] Custom encoding   — per-file seeded alphabet (unique for every run)
    │                          + XOR spread layer
    │
    └─ [6] Stub generation   — fully obfuscated loader script
              │
              └─ your_script.gnolly.py   ← distribute this
```

The output file is a standalone `.py` that asks for a key before running. No source, no readable bytecode, no embedded key. The compiled C extension (`_gnolly_core.so`) performs all crypto and VM execution in native machine code.

---

<br>

## Quickstart

### Install

```bash
pip install pycryptodome
git clone https://github.com/therealOri/Gnolly
cd gnolly
pip install -e .
python setup_core.py build_ext --inplace   # builds _gnolly_core.so
```

### Protect a file

```bash
gnolly protect your_script.py your_script.gnolly.py
```

Gnolly prints the hex key and saves it to a `.key` file. **Back this up, you can NOT run the code without the key.**

### Run the protected file

```bash
# Option 1: environment variable (recommended for servers and CI)
export GNOLLY_KEY=<hex key>
python your_script.gnolly.py

# Option 2: interactive prompt
python your_script.gnolly.py
# Gnolly key: ▌<paste_key>
```

---

<br>

## The .so file, what it is and where it goes

The file `_gnolly_core.cpython-314-x86_64-linux-gnu.so` (name varies by platform and Python version) is a compiled C extension built from `gnolly/_gnolly_core.pyx`. It contains:

- The AES-256-GCM decryption and PBKDF2 key derivation
- The opcode unshuffle logic
- The VM protection layer (trace blackout, monitoring suppression, isolated namespace)
- A second round of anti-debug checks in native code

Without this file the protected script prints an error and exits. It is **not optional**.

### Building the .so

```bash
cd gnolly
python setup_core.py build_ext --inplace
```

This creates `gnolly/_gnolly_core.<platform-suffix>.so`. The suffix encodes the Python version and architecture (e.g. `.cpython-314-x86_64-linux-gnu.so`). **You must rebuild it for each target platform and Python version you want to support.**

### Where to place the .so when distributing

Gnolly searches for the `.so` in four locations, tried in this order:

| Priority | Location | Typical use case |
|---|---|---|
| 1 | **Same directory as the `.gnolly.py` file** | Simplest deployment, you just drop both files together |
| 2 | `./gnolly/` relative to the current working directory | Running from a project root that has gnolly installed locally |
| 3 | The `gnolly` package directory (via `sys.modules`) | gnolly is installed in the Python environment |
| 4 | `sys.path` scan for any `gnolly/` subdirectory | Non-standard layouts, virtualenvs, zip imports |

**The simplest deployment** -> put everything in one folder:

```
my_app/
├── my_script.gnolly.py
└── _gnolly_core.cpython-314-x86_64-linux-gnu.so
```

Then run from anywhere:
```bash
python /any/path/to/my_app/my_script.gnolly.py
```

<br>

**Alternative -> gnolly subdirectory:**

```
my_app/
├── my_script.gnolly.py
└── gnolly/
    └── _gnolly_core.cpython-314-x86_64-linux-gnu.so
```

<br>

**Alternative -> gnolly installed in the environment:**

```bash
pip install gnolly          # installs with pre-built .so
python my_script.gnolly.py  # finds .so via sys.modules
```

<br>

### What happens if the .so is not found

```
Gnolly runtime not found.
Place _gnolly_core*.so next to this script, or in ./gnolly/, or install gnolly.
```

The process exits with code 1. No decryption is attempted.

---

<br>

## CLI reference

```
gnolly protect <input.py> [output.py] [options]

  -K, --keyfile FILE    Use an existing keyfile instead of generating a new one
  --no-mangle           Skip name mangling
  --no-strings          Skip string literal obfuscation
  --no-dead             Skip dead-code injection
  --no-numbers          Skip integer obfuscation
  --seed INT            Fix the RNG seed (makes output reproducible)
  -v, --verbose         Show pipeline progress

gnolly keygen [keyfile] [options]

  --hint TEXT           Description stored in the keyfile
  --for-file TEXT       Which script this key belongs to (informational)

gnolly fingerprint      Print a machine fingerprint (for --bind)
```

---

<br>

## Python API

```python
from gnolly import protect, protect_file
from gnolly.keymanager import generate_key, save_keyfile, key_to_hex

key = generate_key()
save_keyfile(key, "myapp.key", protected_file="myapp.py")

stub_source = protect(source_code, key, verbose=True)
with open("myapp.gnolly.py", "w") as f:
    f.write(stub_source)

# Or directly from a file path
protect_file("myapp.py", "myapp.gnolly.py", key)
```

---

<br>

## Security design

| Property | How Gnolly achieves it |
|---|---|
| No source in output | Source is compiled to bytecode before encryption; never written to disk |
| No key in output | Key is always external -> env var or interactive prompt |
| Tamper detection | AES-GCM authentication tag; SHA-256 hash of `.so` baked into stub |
| Unique per-file encoding | Alphabet seeded from `key + seed`; same source produces different output each run |
| No `exec(string)` | Stub executes a marshalled code object, not a string |
| Strong KDF | PBKDF2-HMAC-SHA256, 600,000 iterations (OWASP 2024 recommendation) |
| No `__import__` in stub | All imports routed through an obfuscated `__builtins__` alias; `__import__` does not appear as a string anywhere in the generated file |
| No external network calls | Protected file is fully self-contained |
| Machine binding | `--bind` folds a machine fingerprint into the KDF -> wrong machine, wrong key, GCM auth fails silently |
| Obfuscated `.so` loading | The C extension is loaded by file path under a random fake module name; `gnolly` and `_gnolly_core` are not visible in the stub |
| Anti-debug (Python layer) | Trace/profile hooks, known debugger modules, and timing gates checked before any crypto work begins |
| Anti-debug (C layer) | A second independent sweep runs inside the compiled `.so` after the stub's checks, catching any hooks installed in between |
| VM protection | Code executes inside `gnolly_exec_vm()` in the C extension: `sys.settrace` is suspended, `sys.monitoring` events are suppressed, and user code runs in an isolated namespace -> Python-level debuggers cannot single-step into protected code |

### What Gnolly does NOT do

- **Gnolly is not DRM.** A determined adversary with enough time and if they have your key, can reconstruct the original logic by instrumenting the Python runtime at the C level. Code protection raises the cost and effort of reverse engineering; it does not make it theoretically impossible.
- Gnolly does not protect against someone who has both the key and a C-level debugger (e.g. gdb attached to the Python process). Yet..
- Gnolly does not prevent inspection of process memory at runtime. Yet..

For maximum protection, combine Gnolly with Cython compilation or Nuitka for the most sensitive modules.

---

<br>

## Comparison: Gnolly vs. alternatives

| | **Gnolly** | **PyArmor** | **Cython** | **Nuitka** | **PyInstaller** |
|---|---|---|---|---|---|
| **Price** | Free, open-source | Free tier limited; Pro ~$100 | Free | Free (Community) / €299 Commercial | Free |
| **Encryption** | AES-256-GCM | XOR-based (older); AES in some modes | None | None | None |
| **KDF** | PBKDF2-HMAC-SHA256, 600k rounds | Varies by version | — | — | — |
| **VM protection** | ✅ (trace/monitoring blackout, isolated namespace) | ✅ Pro only (`--advanced 2`) | ❌ | ❌ | ❌ |
| **Anti-debug** | ✅ Python + C layer | ✅ | ❌ | ❌ | ❌ |
| **Requires .so at runtime** | ✅ | ✅ | ✅ | ❌ (standalone binary) | ❌ (bundles runtime) |
| **Source hidden** | ✅ | ✅ | Partial (C source visible) | ✅ | ❌ (`.pyc` recoverable) |
| **No `__import__` in output** | ✅ | ❌ | — | — | — |
| **Per-file licensing** | ❌ None | ⚠️ Newer versions: yes | ❌ None | ❌ None | ❌ None |
| **License server / phone-home** | ❌ Never | ⚠️ Activation required | ❌ | ❌ | ❌ |
| **Open source** | ✅ AGPLv3 | ❌ | ✅ Apache 2 | ✅ Apache 2 | ✅ MIT |
| **Output is a .py file** | ✅ | ✅ | ❌ (.so) | ❌ (.exe or .so) | ❌ (bundle) |
| **Machine binding** | ✅ | ✅ Pro | ❌ | ❌ | ❌ |
| **Tamper detection** | ✅ GCM tag + SHA-256 .so hash | ✅ | ❌ | ❌ | ❌ |

### Key differences

**vs. PyArmor** -> PyArmor is the industry standard for Python obfuscation. Its VM mode (`--advanced 2`) is strong but requires a paid Pro license. Newer versions enforce per-machine and per-file activation via a license server. Gnolly matches its protection level for free, with no activation, no phone-home, and AES-256-GCM instead of PyArmor's older XOR-based schemes.

**vs. Cython** -> Cython compiles Python to a C extension but the `.so` is fairly reversible with tools like `pycdc`. It provides no encryption and no runtime key requirement. Gnolly provides much stronger protection for scripts that don't need to be compiled to C.

**vs. Nuitka** -> Nuitka produces a standalone native binary (no Python required to run), which is excellent against casual reversal. However it is not designed for IP protection specifically, the compiled binary can be disassembled. The Commercial edition adds some obfuscation. Nuitka is the right choice when you want a self-contained executable; Gnolly is the right choice when you want a `.py` file that runs on any Python installation with a key.

**vs. PyInstaller** -> PyInstaller bundles your script and the Python runtime into a single archive. It provides essentially no protection, the original `.pyc` files are trivially extractable. It is a packaging tool, not a protection tool.

---

<br>

## Running the tests

```bash
pip install pytest | If not installed
python -m pytest tests/ -v
```

---

<br>

## Project structure

```
gnolly/
├── gnolly/
│   ├── __init__.py           — public API
│   ├── cli.py                — command-line interface
│   ├── pipeline.py           — orchestrates all protection stages
│   ├── obfuscate.py          — AST transformer
│   ├── bytecode.py           — compile → marshal
│   ├── compress.py           — zlib/lzma/bz2 with auto-select
│   ├── crypto.py             — AES-256-GCM + PBKDF2
│   ├── encoding.py           — custom seeded-alphabet codec
│   ├── stub.py               — generates the obfuscated loader script
│   ├── import_hook.py        — generates .so search and load code
│   ├── antidebug.py          — generates anti-debug check code
│   ├── keymanager.py         — key generation, save, load
│   ├── _gnolly_core.pyx      — Cython source: crypto, unshuffle, VM layer
│   └── _gnolly_core.*.so     — compiled C extension (build with setup_core.py)
├── examples/
│   └── sample.py
├── tests/
│   └── test_gnolly.py
├── setup.py
├── setup_core.py             — builds the .so
└── README.md
```

---

