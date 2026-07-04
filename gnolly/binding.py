"""
gnolly.binding
~~~~~~~~~~~~~~
Machine/platform binding.

How it works
------------
The machine fingerprint is silently folded into the PBKDF2 salt before
key derivation.  The encrypted payload can only be decrypted on a machine
whose fingerprint produces the same derived key.

At protect time:
    fp = collect_fingerprint()               # developer supplies target fp
    effective_salt = HMAC(salt, fp)          # fold fp into salt
    derived_key = PBKDF2(password, effective_salt)
    encrypt(payload, derived_key)

At runtime:
    fp = collect_fingerprint()               # this machine's fp
    effective_salt = HMAC(salt, fp)
    derived_key = PBKDF2(password, effective_salt)
    decrypt(payload, derived_key)            # GCM auth fails if fp wrong

There is no explicit "machine check". The wrong fingerprint silently produces
the wrong key, which fails AES-GCM authentication.  The user sees only
"Wrong key, corrupted file, or nothing."

Developer workflow
------------------
    gnolly fingerprint                  # print this machine's fp hex
    gnolly protect --bind script.py     # bind to THIS machine (uses own fp)
    gnolly protect --bind-fp HEX script.py  # bind to specific machine by fp

Tolerance / graceful degradation
---------------------------------
Some VM hypervisors rotate MAC addresses on reboot.  Binding uses
ALL available sources hashed together, so if one source is unstable
the overall fingerprint shifts.  For maximum stability, I prefer
/etc/machine-id (Linux) or IOPlatformUUID (macOS) which are written
once at OS install and never change.
"""
from __future__ import annotations
import hashlib
import hmac
import socket
import sys
import uuid

# Protocol version byte, bump if the fingerprint algorithm changes
# so old bound files can detect the mismatch cleanly.
_BIND_VERSION = b'\x01'

# Separator used when combining key material
_BIND_DOMAIN = b'gnolly-machine-bind-v1:'


def collect_fingerprint(*, require: bool = False) -> bytes | None:
    """
    Collect a stable 32-byte machine fingerprint.

    Parameters
    ----------
    require : if True, raise RuntimeError when no stable sources found.
              if False (default), return None.

    Returns
    -------
    32 bytes or None
    """
    components: list[tuple[str, str]] = []

    # ── Source 1: /etc/machine-id (Linux/systemd) ─────────────────────────
    for path in ('/etc/machine-id', '/var/lib/dbus/machine-id'):
        try:
            mid = open(path).read().strip()
            if mid and len(mid) >= 16:
                components.append(('machine-id', mid))
                break
        except OSError:
            pass

    # ── Source 2: macOS IOPlatformUUID ────────────────────────────────────
    if sys.platform == 'darwin':
        try:
            import subprocess
            out = subprocess.check_output(
                ['ioreg', '-rd1', '-c', 'IOPlatformExpertDevice'],
                timeout=5, stderr=subprocess.DEVNULL
            ).decode(errors='replace')
            for line in out.splitlines():
                if 'IOPlatformUUID' in line:
                    parts = line.split('"')
                    if len(parts) >= 2:
                        components.append(('ioplatform-uuid', parts[-2]))
                        break
        except Exception:
            pass

    # ── Source 3: Windows MachineGuid ────────────────────────────────────
    if sys.platform == 'win32':
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r'SOFTWARE\Microsoft\Cryptography'
            )
            guid, _ = winreg.QueryValueEx(key, 'MachineGuid')
            components.append(('windows-machineguid', str(guid)))
        except Exception:
            pass

    # ── Source 4: MAC address ─────────────────────────────────────────────
    # Only use if not random/multicast (bit 40 of the 48-bit address).
    # Random MACs are assigned by VMs and change on reboot. (useless for binding.)
    mac = uuid.getnode()
    if not ((mac >> 40) & 1):
        components.append(('mac', f'{mac:012x}'))

    # ── Source 5: Hostname ────────────────────────────────────────────────
    try:
        hn = socket.gethostname()
        if hn and hn not in ('localhost', 'localhost.localdomain'):
            components.append(('hostname', hn))
    except Exception:
        pass

    if not components:
        if require:
            raise RuntimeError(
                "No stable machine identifiers found on this platform. "
                "Platform binding is not supported here."
            )
        return None

    # Combine with SHA-256: sorted for determinism regardless of discovery order
    h = hashlib.sha256()
    h.update(_BIND_DOMAIN)
    for k, v in sorted(components):
        h.update(f'{k}={v}\n'.encode())
    return h.digest()   # 32 bytes


def bind_salt(salt: bytes, fingerprint: bytes) -> bytes:
    """
    Derive a machine-bound salt by folding the fingerprint into the
    original PBKDF2 salt via HMAC-SHA256.

    Parameters
    ----------
    salt        : original random salt (32 bytes)
    fingerprint : 32-byte machine fingerprint from collect_fingerprint()

    Returns
    -------
    32-byte effective salt that embeds the machine identity
    """
    return hmac.new(fingerprint, salt, hashlib.sha256).digest()


def fingerprint_hex() -> str:
    """Return the current machine's fingerprint as a hex string, or '' if unavailable."""
    fp = collect_fingerprint()
    return fp.hex() if fp is not None else ''


def fingerprint_from_hex(hex_str: str) -> bytes:
    """Parse a hex fingerprint string back to bytes."""
    return bytes.fromhex(hex_str.strip())
