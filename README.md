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

**Python code protection that's free, open-source, and with no paywalls.**

[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://python.org)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPLv3-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-success)](#platform-support)
[![Version](https://img.shields.io/badge/Version-1.0-blueviolet)](#changelog)

</div>

__ __

> This readme and documentation is a WIP, more will be added as updates happen.

<br>

Gnolly encrypts, compresses, and obfuscates your python source so that only someone holding your key can run it. It is a direct free alternative to PyArmor and similar tools, just without the paywalls, license servers, or activation requirements.
__ __

> [!IMPORTANT]
> The gnolly VM protection is built and tested against Python 3.12. I will work on supporting 3.13+ at a later time. (or you can help too by making a pull request)
>
> I also have not tested anything out on windows systems yet, so be aware that idk if it works well on windows or not.

> [!WARNING]
> The protection here has not been "battle tested" yet and is incomplete, it is still in early development but it's at a stage where I am okay with it being public now.
> If you have any issues or feedback, feel free to make an issue or make a PR.


<br>

## What Gnolly does

When you protect a file, Gnolly runs your code through seven stages:

```
your_script.py
    │
    ├─ [1] AST obfuscation      —   name mangling, keyed string/bytes/float encoding
    │                               (multiple independently-rolled encoding dialects),
    │                               multi-family integer encoding (XOR / additive /
    │                               mul-div / shift identities), dead-code and decoy-
    │                               structure injection, bogus class hierarchies,
    │                               expression aliasing, docstring removal
    │
    ├─ [2] GIR VM translation   —   source -> Gnolly Intermediate Representation
    │                               (custom bytecode format; CPython opcodes
    │                               never exist at runtime)
    │
    ├─ [3] VM opcode shuffle    —   per-file permutation over the full 65536-entry
    │                               (16-bit) GIR opcode space
    │
    ├─ [4] Compression          —   zlib / lzma / bz2, best result is used
    │
    ├─ [5] Encryption           —   AES-256-GCM + Argon2id
    │                               (t=3, m=64MiB, p=4, random salt+IV per file)
    │
    ├─ [6] Custom encoding      —   per-file alphabet keyed from password + random
    │                               salt, unique every run
    │
    └─ [7] Stub generation      —   control-flow-flattened, minified, packed,
              │                     self-hash-verified, obfuscated loader script
              │
              └─ your_script.gnolly.py   <-  distribute this
```

The output is a standalone `.py` that asks for a key before running. No source text, no readable bytecode, no embedded key. Two compiled C extensions (`_gnolly_core.so` for decryption & core functionality, `_gnolly_vm.so` for execution) perform all of the work in native machine code. **Both are required at runtime.**

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
| `_gnolly_core.<suffix>.so` | AES-256-GCM decryption, Argon2id key derivation, anti-debug |
| `_gnolly_vm.<suffix>.so` | GIR interpreter: executes protected code without CPython's eval loop |

> Both must be present at runtime. If either is missing, the protected script just exits silently.

The suffix encodes the python version and platform, e.g. `.cpython-312-x86_64-linux-gnu.so`. **You must rebuild for each target platform and Python version.**

<br>

### Where to place the .so files when distributing
> Gnolly searches for each `.so` in four locations, tried in order:

| Priority | Location | Typical use |
|---|---|---|
| 1 | Same directory as the `.gnly.py` file | Simplest, just drop both files together |
| 2 | `./gnolly/` relative to current working directory | Running from a project root with gnolly installed locally |
| 3 | The `gnolly` package directory (via `sys.modules`) | gnolly installed in the python environment |
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
  --no-strings            Skip string/bytes/float encoding
  --no-dead               Skip dead-code and decoy-structure injection
  --no-numbers            Skip integer encoding
  --no-flatten            Skip control-flow flattening of the generated stub
  --no-hierarchy          Skip bogus inherited class hierarchy / opaque-token diversification
  --no-alias              Skip AST-level expression aliasing
  --no-minify             Skip stub minification
  --no-pack               Skip the final compression pass (ship the readable stub instead)
  --bind                  Bind output to THIS machine (uses current fingerprint)
  --bind-fp HEX           Bind to a specific machine fingerprint (from 'gnolly fingerprint')
  --ptrace                Linux-only: self-attach via ptrace so no debugger should be able to attach. Opt-in.
  --ptrace-no-heartbeat   Disable the default re-verification heartbeat. No effect without --ptrace
  -v, --verbose           Show pipeline progress
  --verbose-errors        Emit error messages from the stub on failure (dev only)
```

### `gnolly protect-dir`

Protect an entire directory of files, recursively.

```
gnolly protect-dir <input_dir> [output_dir] [options]

  --exclude GLOB [...]    Glob patterns to skip (e.g. "tests/*" "*.pyi")
  (all protect options above also apply)
```

### `gnolly protect-wheel`

Protect a package and build a real, installable `.whl`.

```
gnolly protect-wheel <input_dir> [output_dir] --name NAME --version VERSION [options]

  --name NAME               Distribution name (e.g. mypkg)
  --version VERSION         PEP 440 version, e.g. 1.0.0
  --description TEXT        Short summary for METADATA
  --author TEXT              Author name for METADATA
  --requires PKG [...]       Runtime dependencies to declare
  --python-requires SPEC    Requires-Python constraint (default: >=3.12)
  --bundle-runtime          Embed the matching .so pair in the wheel itself
  --exclude GLOB [...]      Glob patterns to skip
  (all protect options above also apply)
```
> The protected package is importable like any normal package; protected modules execute into their own `__dict__` rather than a `__main__` namespace.

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
    inject_junk: bool = True,
    machine_fingerprint: bytes | None = None,
    verbose: bool = False,
    silent: bool = True,
    flatten: bool = True,
    minify: bool = True,
    pack: bool = True,
    self_hash: bool = True,
    module_mode: bool = False,
    bogus_hierarchy: bool = True,
    alias_exprs: bool = True,
    decorrelate_checks: bool = True,
    poison_watchdog: bool = False,
    ptrace_guard: bool = False,
    ptrace_guard_strict: bool = True,
    ptrace_guard_heartbeat: bool = True,
    ptrace_guard_heartbeat_min_delay: float = 0.0005,
    ptrace_guard_heartbeat_max_delay: float = 0.002,
) -> str
```
> Every call to `protect()` (and every underlying obfuscation/encoding step) is fully non-deterministic by design. There is no seed, fixed or otherwise, anywhere in the pipeline, internal or CLI-exposed. Two calls with identical `source`/`password` should produce different output.

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

The machine fingerprint is folded into the Argon2id key derivation. On the wrong machine, AES-GCM authentication fails silently, the protected file exits with code 1 and no information is disclosed.

This composes with the `.so` integrity binding described [above](#versioning-the-so-pair-is-part-of-the-protected-artifact-not-a-separate-dependency): both foldings apply in sequence, so a wrong machine *or* a tampered/mismatched `.so` pair each independently break the key.

---

<br>

## Security & Design

| Property | How Gnolly achieves it |
|---|---|
| No source in output | Source is compiled to GIR before encryption; plaintext never written to disk |
| No key in output | Key is always external -> env var or interactive prompt |
| Tamper detection (blob) | AES-256-GCM authentication tag -> any modification of the encrypted code fails decryption outright |
| Tamper detection (`.so` files) | Both `.so` hashes are folded into the Argon2id key derivation (see `gnolly/integrity.py`); a modified `.so` silently derives a different key and fails GCM authentication. A separate, obfuscated hash pre-check gives a cleaner early exit for mismatches, but is not itself the security boundary, the key fold is what actually can't be bypassed by patching a comparison. |
| Unique per-file encoding | GIR opcode shuffle keyed per file; same source -> different binary blob every run |
| No CPython eval loop | Protected code runs in `_gnolly_vm`'s own Cython stack machine, never via `ceval.c` |
| No `marshal` | GIR is a custom binary format; `marshal.loads` is never called |
| `sys.settrace` blocked | VM execution produces zero trace events -> Python-level debuggers cannot single-step |
| `sys.monitoring` suppressed | 3.12+ monitoring events suppressed around decrypt and dispatch |
| Strong KDF | Argon2id, t=3 / m=64MiB / p=4 (RFC 9106 memory-constrained recommendation) |
| No `__import__` in stub | All imports routed through an obfuscated `__builtins__` alias |
| No external network calls | Protected file is fully self-contained; no phone-home, no activation |
| Machine binding | `--bind` folds a hardware fingerprint into the KDF: wrong machine -> wrong key -> GCM auth fails |
| Obfuscated `.so` loading | Extensions are loaded by file path under a random fake module name; `gnolly` and `_gnolly_core` do not appear as strings in the stub |
| Anti-debug (Python layer) | Trace/profile hooks, known debugger modules, and timing gates checked before any crypto work |
| Anti-debug (C layer) | A second independent sweep runs inside the compiled `.so` after the stub's checks |
| Anti-debug (ptrace self-attach, Linux, opt-in) | `--ptrace` self-attaches via a raw `ptrace(PTRACE_TRACEME,...)` syscall compiled into `_gnolly_core.so`, blocking any later debugger attach outright rather than detecting one after the fact; fails the run by default if that can't be established, and includes a sub-millisecond re-verification heartbeat by default. |
| Slow-execution debugger detection | Two independent bounded-loop timing checks flag single-stepping/heavy tracing overhead (complements the existing too-fast/replay timing gate); see `gnolly/antidebug.py` |
| Stub self-hash | The shipped stub verifies its own exact source text against an embedded digest via several independently-placed, differently-shaped checks at startup -> reformatting, patching, or beautifying the file for easier reading breaks it. See `gnolly/selfhash.py`. Always on when protecting via the CLI. Library callers can pass `self_hash=False` to `gnolly.pipeline.protect()` (e.g. alongside `pack=False`) if they need to inspect the readable stub source. |
| Control-flow flattening | The generated stub is rewritten into an opaque dispatch-loop state machine with multiple dispatch mechanisms, rather than its natural top-to-bottom control flow. See `gnolly/flatten.py`. |
| Bogus class hierarchy | AST-level fake inherited class hierarchies, plus diversified opaque-"True" tokens reused across the obfuscation passes so no single token is a reliable tell. On by default. |
| Expression aliasing | Call results are randomly routed through one of several indirection shapes (lambda wrapper, dict/tuple lookup, conditional expression, fake-class alias) before use, so the same call doesn't always look the same. |
| Multi-dialect string/number encoding | String, bytes, and float literals are rendered via one of several independently-applicable encoding dialects, re-rolled per literal; integers are rendered via one of several exact arithmetic identities (XOR, additive, mul-div, bit-shift), also re-rolled per literal. A decoder written against one instance won't match the next. See `gnolly/strcodec.py` and `gnolly/obfuscate.py`. |
| Decoy-structure injection | Dead code is injected in multiple structurally distinct shapes (unreachable branches, unused bindings, dead lambdas, never-iterated loops, raise/catch pairs) rather than one repeated pattern, so the decoys themselves don't become a fingerprint. |
| Minification + packing | The flattened stub is minified (`gnolly/minify.py`) and the final output is replaced with a tiny bootstrap plus one opaque compressed blob (`gnolly/pack.py`), collapsing the visible, readable surface of the shipped file. |
| Importable package / wheel protection | `gnolly protect-dir` and `gnolly protect-wheel` protect an entire package recursively and can emit a real, installable `.whl`; protected modules execute into their own module `__dict__` via `module_mode`, so normal `import` semantics keep working. |
| Import-hook-based hiding | Select internal helper logic is hidden behind a synthetic `sys.meta_path` Finder/Loader instead of an inline `exec()`'d blob, so it looks like an ordinary import rather than code being unpacked and run at the call site. See `gnolly/modhide.py`. |

### Ptrace self-attach (`--ptrace`)

Linux only, off by default. A process can call `ptrace(PTRACE_TRACEME, 0, NULL, NULL)` on itself; the kernel then records its real parent as the tracer, and Linux allows only one tracer per process. Once that succeeds, a later `PTRACE_ATTACH`/`PTRACE_SEIZE` from a debugger (gdb, `strace -p`, etc.) against that PID fails outright with `EPERM` -> the debugger never gets to attach at all, rather than attaching and being caught after the fact. `/proc/<pid>/mem` reads from another process that goes through the same kernel check, so those are blocked too.

```bash
gnolly protect app.py --ptrace                  # self-attach, strict + heartbeat, both on by default
gnolly protect app.py --ptrace --ptrace-no-heartbeat  # self-attach only, skip re-verifications
```

**Limitations:** this blocks *future* attachment; it can't retroactively catch an attacker already attached before this code runs. It does not defend against a root-level attacker reading memory through a channel that never goes through the kernel's `ptrace_may_access()` check at all -> a malicious kernel module, a hypervisor the attacker controls, or similar.

### What Gnolly does NOT do

- **Gnolly is not DRM.** A determined adversary with your key and a C-level debugger (e.g. gdb attached to the python process) can reconstruct logic by instrumenting the runtime at the C level. Code protection raises the cost and effort of reverse engineering; it does not make it theoretically impossible. 
- Gnolly does not prevent advanced inspection of process memory at runtime by default. `--ptrace` (Linux only, opt-in) blocks the most common attach-based inspection paths but not root-level/non-ptrace channels.
- Gnolly does not enforce expiry dates, seat counts, or call home. This was explored and deliberately dropped: no software-only scheme on untrusted hardware can be made truly unbypassable, and PyArmor's own expiry is just a locally clock-checked file.
> Python-source obfuscation (flatten, self-hash, modhide, antidebug) raises the cost of casual/automated attacks a lot, but a patient, skilled attacker gets through it eventually, the interpreter has to be able to run the real logic somewhere. See [What's next](#whats-next) for where more work is planned.
__ __

<br>

## Comparison: Gnolly vs. alternatives

| | **Gnolly** | **PyArmor** | **Cython** | **Nuitka** | **PyInstaller** |
|---|---|---|---|---|---|
| **Price** | Free, open-source | Free tier limited; Pro ~$100 | Free | Free / €299 Commercial | Free |
| **Encryption** | AES-256-GCM | Varies by version | None | None | None |
| **KDF** | Argon2id, t=3/m=64MiB/p=4 | Varies | — | — | — |
| **True VM (not CPython eval)** | ✅ | ✅ Pro only | ❌ | ❌ | ❌ |
| **Anti-debug** | ✅ Python + C layer (+ optional ptrace self-attach on Linux) | ✅ | ❌ | ❌ | ❌ |
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
| **Package / wheel protection** | ✅ `protect-dir` + real `.whl` output | ✅ | Partial (compiles, doesn't encrypt) | ✅ (standalone binary) | ❌ (no protection) |
| **Control-flow flattening** | ✅ (stub-level, multiple dispatch mechanisms) | ✅ | ❌ | ❌ | ❌ |

### Key differences

**vs. PyArmor** -> PyArmor is an industry standard for python obfuscation. Its VM mode (`--advanced 2`) is strong but requires a paid Pro license, per-machine activation, and a connection to PyArmor's license server. Newer versions enforce seat limits and can remotely revoke licenses. Gnolly matches PyArmor's protection level for free, with no activation, no phone-home, and AES-256-GCM (authenticated encryption) rather than PyArmor's older schemes. 
> (Because it is close source idk if what I have is actually better or not, but it does work.)

<br>

**vs. Cython** -> Cython compiles Python to a C extension but the `.so` is fairly reversible with tools like `pycdc`. It provides no encryption and no runtime key requirement. Gnolly provides much stronger protection for scripts that don't need to be compiled to native C.

**vs. Nuitka** -> Nuitka produces a standalone native binary (no python required to run). The compiled binary can be disassembled; it is a packaging and performance tool rather than an IP-protection tool. The right choice when you want a self-contained executable; Gnolly is the right choice when you want a `.py` file that runs on any python installation with a key. 
> (Use both for a best of both worlds option.)

<br>

**vs. PyInstaller** -> PyInstaller bundles your script and runtime into a single archive. It provides essentially no protection and the original `.pyc` files are trivially extractable. It is a packaging tool, not a protection tool.
__ __

<br>

## What's next

A hardening roadmap for defending against a serious and a more patient kind of attacker (not just casual/automated reverse engineering).

Python-source obfuscation -> everything currently in `flatten.py`, `selfhash.py`, `modhide.py`, `antidebug.py` raises the cost of casual and automated attacks a lot, but a patient, and skilled attacker will get through all of it eventually, since the interpreter has to be able to run the real logic somewhere. The techniques that actually matter against this tier of attacker live mostly at the `.so` / runtime-memory layer.

| Progress | Technique | Layer | Effort | Value vs. serious attacker |
|---|---|---|---|---|
| ✅ | Delayed / decorrelated failure reaction | Python | Low | High |
| ✅ | ptrace self-attach (`--ptrace`, opt-in) | `.so` (Linux) | Low | High |
| ✅ | Argon2id key derivation | `.so` / crypto | Low-Med | Medium |
| ⏳ | Extra python trigger primitives (`weakref`, `atexit`, `__del__`, frame inspection) | Python | Low | Medium |
| ⏳ | Continuous (not just startup) integrity checks | Python + `.so` | Medium | High |
| ⏳ | Cross-checking checks | Python | Medium | Medium-High |
| ⏳ | Explicit buffer wiping after decrypt | `.so` | Medium | High |
| ⏳ | aeskeyfind-class mitigation | `.so` | High | High |
| ⏳ | Decoy-blob payload scattering ("lattice") | Python / stub layout | High | Medium |
| ⏳ | In-VM opcode table re-verification | `.so` | High | Medium-High |

> After some hardening, I want to work on antitamper, antidebug, and improving that side of the project. Both .so and in python.

<br>
