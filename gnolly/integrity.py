"""
gnolly.integrity
~~~~~~~~~~~~~~~~
Runtime binary integrity binding.
------------
This is the exact same trick binding.py uses for machine fingerprints,
applied to the compiled extensions instead:

    core_hash = sha256(_gnolly_core.so bytes)
    vm_hash   = sha256(_gnolly_vm.so bytes)
    effective_password = HMAC(DOMAIN || core_hash || vm_hash, password)
    derived_key = PBKDF2(effective_password, salt)

There is no explicit "does the hash match" branch anywhere in this chain,
and nothing an attacker can patch to bypass it. A tampered .so silently
folds a different hash into the password, which derives a different AES
key, which makes AES-GCM authentication fail on decrypt. The failure is
the same "wrong key, corrupted file, or nothing" outcome the person seeing
it can't distinguish from any other decryption failure -> there's no
separate pass/fail checkpoint to find and disable.

This security boundary for .so tampering composes with
machine binding (binding.py): when --bind is used, both foldings apply in
sequence. So tampering with either the machine or the runtime binaries
breaks the key.

Relationship to the stub's hash pre-checks
-------------------------------------------
gnolly/import_hook.py also computes and compares each .so's SHA-256 against
an (obfuscated) expected value, exiting cleanly before ever reaching the
crypto layer. That check is NOT a replacement for this module -> it's a
cosmetic fast-fail layer that gives a clean exit for a version/deployment mismatch.
A determined attacker can still find and patch the comparison; if they do,
they still can't get anything useful out of it, because this module's fold
is what the correct key actually depends on, and it runs independently of
that check.

Neither layer can make .so tampering literally impossible to attempt.
No protection scheme can, once the attacker fully controls the machine
running the code. What this buys you is: tampering with either .so, by
any means, silently and unconditionally breaks decryption. There is no
way to patch around that short of also recovering the original .so bytes.
"""
from __future__ import annotations
import hashlib
import hmac
from pathlib import Path

# Domain separation from binding.py's _BIND_DOMAIN -> the two folds must
# never be confusable with each other even though both are "HMAC a hash
# of something into the password".
_INTEGRITY_DOMAIN = b'gnolly-integrity-bind-v1:'


def collect_runtime_hashes(core_so_path: Path | None = None,
                            vm_so_path: Path | None = None) -> bytes:
    """
    Return sha256(core.so) || sha256(vm.so) -> 64 bytes of key material
    representing the exact compiled extensions this file will be paired
    with when protect() is called.

    Raises RuntimeError if either .so hasn't been built yet -> protect()
    should not silently produce a file that can never decrypt correctly.
    """
    from .import_hook import get_core_so_path, get_vm_so_path

    core_path = core_so_path or get_core_so_path()
    vm_path   = vm_so_path   or get_vm_so_path()
    if core_path is None or vm_path is None:
        raise RuntimeError(
            "Cannot compute runtime integrity hashes: compiled extensions "
            "not found. Run `python setup.py build_ext --inplace` first."
        )
    core_hash = hashlib.sha256(core_path.read_bytes()).digest()
    vm_hash   = hashlib.sha256(vm_path.read_bytes()).digest()
    return core_hash + vm_hash


def fold_integrity(password: bytes, runtime_hashes: bytes) -> bytes:
    """
    Fold the compiled-extension hashes into password via HMAC-SHA256,
    mirroring binding.py's machine-fingerprint fold exactly (same shape,
    different domain-separated key material).

    Parameters
    ----------
    password        : the current effective password (already folded with
                       a machine fingerprint first, if binding is active)
    runtime_hashes  : 64 bytes from collect_runtime_hashes() -> the two
                       .so hashes concatenated

    Returns
    -------
    32-byte effective password that only reproduces correctly when paired
    with the exact .so bytes runtime_hashes was computed from.
    """
    return hmac.new(_INTEGRITY_DOMAIN + runtime_hashes, password, hashlib.sha256).digest()
