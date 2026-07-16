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

[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://python.org)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-success)](#platform-support)
[![Version](https://img.shields.io/badge/Version-1.0-blueviolet)](#changelog)

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
./make.sh
```
> Assuming you are in a 3.12 pyenv virtualenv.
> If `./make.sh` doesn't run, running `chmod+x make.sh` then trying again should work.

The provided build/make script, builds the needed .so files and then pip installs gnolly as a package into your site-packages dir, and then cleans up the local `build/`, egg-info, and in-place `.c`/`.so` artifacts (they're already copied into site-packages by `pip install .` at that point):

<br>

### Protect a file

```bash
gnolly protect your_script.py
```
> Gnolly prints the hex key and saves it to `your_script.gnly.key`. **Back this up, without it, the protected file cannot run.**

```bash
# Specify an output path explicitly
gnolly protect your_script.py your_output_file.gnly.py

# Use an existing keyfile
gnolly protect your_script.py -K my.key
```

<br>

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

### Where to place the .so files when distributing
> Gnolly searches for each `.so` in four locations, tried in order:

| Priority | Location | Typical use |
|---|---|---|
| 1 | Same directory as the `.gnly.py` file | Simplest, just drop both files together |
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
./make.sh          # pip installs with pre-built .so files
python my_script.gnly.py  # finds both .so files via sys.modules
```

<br>

### What happens if a .so file is not found

```
Gnolly runtime (_gnolly_vm) not found.
Place _gnolly_vm*.so next to this script, or in ./gnolly/, or install gnolly.
  pip install gnolly
```
> The process exits immediately with code 1. No decryption is attempted and no information about the code is exposed.

<br>

### Versioning & Deployment
The `.so` pair is part of the protected artifact, not a separate dependency, so every protected file cryptographically binds itself to the *exact* `_gnolly_core`/`_gnolly_vm` bytes present at protect time (see [Security & Design](#security--design)). This means `{your_script.gnly.py, _gnolly_core.so, _gnolly_vm.so}` is really **one versioned unit**, not a script plus a swappable runtime dependency.


- **Always ship the matching `.so` pair alongside each protected file.** Search location #1 (same directory as the script) is checked first specifically so a bundled pair always wins over anything else on the machine. This is the deployment model to use.

- **Don't rely on a separately-updatable, system-wide `gnolly` install for already-shipped files** (search locations #3/#4). If end users or your own infrastructure can `pip install --upgrade gnolly` independently of redeploying the protected files, the next `.so` upgrade will silently break every file that was protected using the old libs, because decryption keys, not just a version check, depend on the exact `.so` bytes. Expect older protected files to stop working the moment the shared install underneath them changes; this is not a bug, it is the point of the integrity binding. Old proected files use old libs, etc.

- **When we make a new release**: rebuild the `.so` files, then re-run `protect()`/`gnolly protect` on your sources using the latest build, and ship the new `.so` pair together with the newly protected output. This is normal build-artifact hygiene, not extra burden and it is the same model PyArmor and other bytecode-VM protectors use.

- **Avoid independent rebuilds of "the same" `.so` at different pipeline stages.** Cython/C compiles are not guaranteed byte-for-byte identical across separate builds of an identical source (build timestamps, absolute paths in debug info, compiler version, etc. can all vary). If your CI builds the `.so` once for the protect step and then rebuilds it again separately for the distributed bundle, the two can differ and a false-positive or an integrity failure with zero actual tampering could result in the code not running. Build once, then copy that exact file to every place it needs to be.
__ __

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
    verbose: bool = False,
    silent: bool = True,
) -> str
```

> Every call to `protect()` (and every underlying obfuscation/encoding step) is fully non-deterministic by design -- there is no seed, fixed or otherwise, anywhere in the pipeline, internal or CLI-exposed. Two calls with identical `source`/`password` always produce different output.

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

This composes with the `.so` integrity binding described [above](#versioning-the-so-pair-is-part-of-the-protected-artifact-not-a-separate-dependency): both foldings apply in sequence, so a wrong machine *or* a tampered/mismatched `.so` pair each independently break the key.

---

<br>

## Security & Design

| Property | How Gnolly achieves it |
|---|---|
| No source in output | Source is compiled to GIR before encryption; plaintext never written to disk |
| No key in output | Key is always external -> env var or interactive prompt |
| Tamper detection (blob) | AES-256-GCM authentication tag -> any modification of the encrypted code fails decryption outright |
| Tamper detection (`.so` files) | Both `.so` hashes are folded into the PBKDF2 key derivation (see `gnolly/integrity.py`); a modified `.so` silently derives a different key and fails GCM authentication. A separate, obfuscated hash pre-check gives a cleaner early exit for mismatches, but is not itself the security boundary, the key fold is what actually can't be bypassed by patching a comparison. |
| Unique per-file encoding | GIR opcode shuffle keyed per file; same source -> different binary blob every run |
| No CPython eval loop | Protected code runs in `_gnolly_vm`'s own Cython stack machine, never via `ceval.c` |
| No `marshal` | GIR is a custom binary format; `marshal.loads` is never called |
| `sys.settrace` blocked | VM execution produces zero trace events -> Python-level debuggers cannot single-step |
| `sys.monitoring` suppressed | 3.12+ monitoring events suppressed around decrypt and dispatch |
| Strong KDF | PBKDF2-HMAC-SHA256, 600,000 iterations (OWASP 2024 recommendation for SHA-256) |
| No `__import__` in stub | All imports routed through an obfuscated `__builtins__` alias |
| No external network calls | Protected file is fully self-contained; no phone-home, no activation |
| Machine binding | `--bind` folds a hardware fingerprint into the KDF: wrong machine -> wrong key -> GCM auth fails |
| Obfuscated `.so` loading | Extensions are loaded by file path under a random fake module name; `gnolly` and `_gnolly_core` do not appear as strings in the stub |
| Anti-debug (Python layer) | Trace/profile hooks, known debugger modules, and timing gates checked before any crypto work |
| Anti-debug (C layer) | A second independent sweep runs inside the compiled `.so` after the stub's checks |

### What Gnolly does NOT do

- **Gnolly is not DRM.** A determined adversary with your key and a C-level debugger (e.g. gdb attached to the Python process) can reconstruct logic by instrumenting the runtime at the C level. Code protection raises the cost and effort of reverse engineering; it does not make it theoretically impossible. 
- Gnolly does not prevent inspection of process memory at runtime. (yet)
- Gnolly does not enforce expiry dates, seat counts, or call home.
> I plan on improving anti-debug and anti-tamper as well as general security hardening eventually. At this point, I can only make things harder :).
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
