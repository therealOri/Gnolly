"""
gnolly.binding_stub
~~~~~~~~~~~~~~~~~~~
Generates the obfuscated machine fingerprint collection code
that is embedded into protected stubs when platform binding is active.

The emitted code is fully self-contained and it imports nothing from gnolly,
uses only stdlib modules (all via obfuscated __import__ calls), and
produces the same fingerprint as binding.collect_fingerprint() on the
same machine.
"""
from __future__ import annotations
import random
import secrets
from .namegen import random_confusable_name


def generate_binding_lines(
    s_fn: str,       # stub's str-decoder function name
    b_fn: str,       # stub's bytes-decoder function name  
    h_sys: str,      # sys module handle
    h_os: str,       # os module handle
    sm_key: str,     # the key variable to fold fingerprint into
    str_key: bytes,  # stub's string encoding key
    byt_key: bytes,  # stub's bytes encoding key
    obn,             # obf_int callable
    N: list,         # name pool (we use N[60:80] for local vars)
    rng: random.Random | None = None,  # for single-char comprehension names
    imp_fn: str = "__import__",  # obfuscated __import__ handle from the stub
) -> list[str]:
    """
    Return lines of Python source that:
    1. Collect a stable machine fingerprint
    2. Fold it into sm_key via HMAC-SHA256
    
    These lines go BEFORE the KDF call in the stub.
    The HMAC fold modifies sm_key in place:
        sm_key = HMAC(fingerprint, sm_key)
    """
    lines = []
    a = lines.append

    def enc(s: str) -> str:
        """Encode string s as s_fn([...]) call."""
        encoded = [ord(c) ^ str_key[i % len(str_key)] for i, c in enumerate(s)]
        return f"{s_fn}({encoded})"

    def em(obj: str, method: str, *args: str) -> str:
        """Generate getattr(obj, s_fn(encoded_method))(args) -> hides method names."""
        encoded = [ord(c) ^ str_key[i % len(str_key)] for i, c in enumerate(method)]
        arg_str = ', '.join(args)
        return f"getattr({obj}, {s_fn}({encoded}))({arg_str})"

    def encb(b: bytes) -> str:
        """Encode bytes as b_fn([...]) call."""
        encoded = [v ^ byt_key[i % len(byt_key)] for i, v in enumerate(b)]
        return f"{b_fn}({encoded})"

    # Local variable names from the pool (slots 60-79)
    vfp_parts  = N[60]   # list of fingerprint component strings
    vfp_hash   = N[61]   # hashlib.sha256 object
    vfp_result = N[62]   # final fingerprint bytes
    vfp_tmp    = N[63]   # temp var for each source
    vfp_line   = N[64]   # line from file iteration
    vfp_mac    = N[65]   # MAC address
    vfp_hn     = N[66]   # hostname
    vfp_hmac   = N[67]   # hmac module handle
    vfp_sub    = N[68]   # subprocess handle
    vfp_out    = N[69]   # subprocess output
    vfp_key    = N[70]   # winreg key handle
    vfp_h      = N[71]   # hashlib module
    vfp_uuid   = N[72]   # uuid module
    vfp_sock   = N[73]   # socket module
    vfp_proc   = N[74]   # platform module

    # Binding domain constant (encoded)
    domain_enc = encb(b'gnolly-machine-bind-v1:')  # must match binding._BIND_DOMAIN exactly

    a(f"# ── Machine binding: collect fingerprint + fold into key ─────────────")
    a(f"{vfp_parts} = []")
    a(f"{vfp_h}    = {imp_fn}({enc('hashlib')})")
    a(f"{vfp_uuid} = {imp_fn}({enc('uuid')})")
    a(f"{vfp_sock} = {imp_fn}({enc('socket')})")

    # Source 1: /etc/machine-id (Linux)
    a(f"for {vfp_tmp} in [{enc('/etc/machine-id')}, {enc('/var/lib/dbus/machine-id')}]:")
    a(f"    try:")
    a("        " + vfp_line + " = " + em(em("open(" + vfp_tmp + ")", "read"), "strip"))
    a(f"        if {vfp_line} and len({vfp_line}) >= {obn(16)}:")
    a("            " + em(vfp_parts, "append", enc("machine-id=") + " + " + vfp_line))
    a(f"            break")
    a(f"    except Exception: pass")

    # Source 2: macOS IOPlatformUUID
    a(f"if getattr({imp_fn}({enc('sys')}), {enc('platform')}) == {enc('darwin')}:")
    a(f"    try:")
    a(f"        {vfp_sub} = {imp_fn}({enc('subprocess')})")
    a(f"        {vfp_out} = getattr({vfp_sub}, {enc(chr(99)+chr(104)+chr(101)+chr(99)+chr(107)+chr(95)+chr(111)+chr(117)+chr(116)+chr(112)+chr(117)+chr(116))})(")
    a(f"            [{enc(chr(105)+chr(111)+chr(114)+chr(101)+chr(103))}, {enc(chr(45)+chr(114)+chr(100)+chr(49))}, {enc(chr(45)+chr(99))}, {enc(chr(73)+chr(79)+chr(80)+chr(108)+chr(97)+chr(116)+chr(102)+chr(111)+chr(114)+chr(109)+chr(69)+chr(120)+chr(112)+chr(101)+chr(114)+chr(116)+chr(68)+chr(101)+chr(118)+chr(105)+chr(99)+chr(101))}],")


    a(f"            timeout={obn(5)})")
    a("        " + vfp_out + " = " + em(vfp_out, "decode", enc(chr(117)+chr(116)+chr(102)+chr(45)+chr(56)), enc(chr(114)+chr(101)+chr(112)+chr(108)+chr(97)+chr(99)+chr(101))))

    a("        for " + vfp_line + " in " + em(vfp_out, "splitlines") + ":")
    a(f"            if {enc('IOPlatformUUID')} in {vfp_line}:")
    a(f"                {vfp_tmp} = {vfp_line}.split({enc(chr(34))})")
    a(f"                if len({vfp_tmp}) >= {obn(2)}:")
    a("                    " + em(vfp_parts, "append", enc("ioplatform-uuid=") + " + " + vfp_tmp + "[-" + obn(2) + "]"))
    a(f"                break")
    a(f"    except Exception: pass")

    # Source 3: Windows MachineGuid
    a(f"if getattr({imp_fn}({enc('sys')}), {enc('platform')}) == {enc('win32')}:")
    a(f"    try:")
    a(f"        {vfp_key} = {imp_fn}({enc('winreg')})")
    a(f"        {vfp_tmp} = getattr({vfp_key}, {enc('OpenKey')})(")
    a(f"            getattr({vfp_key}, {enc('HKEY_LOCAL_MACHINE')}),")
    a(f"            {enc(r'SOFTWARE\Microsoft\Cryptography')})")
    a(f"        {vfp_line}, _ = getattr({vfp_key}, {enc('QueryValueEx')})({vfp_tmp}, {enc('MachineGuid')})")
    a("        " + em(vfp_parts, "append", enc("windows-machineguid=") + " + str(" + vfp_line + ")"))
    a(f"    except Exception: pass")

    # Source 4: MAC address (only if not random/multicast)
    a(f"{vfp_mac} = getattr({vfp_uuid}, {enc('getnode')})()")
    a(f"if not (({vfp_mac} >> {obn(40)}) & {obn(1)}):")
    a("    " + em(vfp_parts, "append", enc("mac=") + " + format(" + vfp_mac + ", " + enc("012x") + ")"))

    # Source 5: Hostname
    a(f"try:")
    a(f"    {vfp_hn} = getattr({vfp_sock}, {enc('gethostname')})()")
    a(f"    if {vfp_hn} and {vfp_hn} not in [{enc('localhost')}, {enc('localhost.localdomain')}]:")
    a("        " + em(vfp_parts, "append", enc("hostname=") + " + " + vfp_hn))
    a(f"except Exception: pass")

    # Hash all components. The update-per-component loop becomes a
    # side-effecting comprehension (result discarded) -> a well-known
    # "abuse a comprehension for its effects, not its value" idiom that
    # reads as data-construction rather than an obvious step-by-step
    # hash-update loop. The discard target is a random confusable
    # character rather than the conventional bare "_", which would
    # otherwise telegraph "this assignment doesn't matter" to a reader.
    _rng = rng or random.Random()
    _hu_used: set = set()
    _cdisc = random_confusable_name(_rng, _hu_used, 1)
    a(f"if {vfp_parts}:")
    a(f"    {vfp_hash} = getattr({vfp_h}, {enc('sha256')})()")
    a(f"    getattr({vfp_hash}, {enc('update')})({domain_enc})")
    a(f"    {_cdisc} = [{em(vfp_hash, 'update', em('(' + vfp_tmp + ' + ' + enc(chr(10)) + ')', 'encode'))} for {vfp_tmp} in sorted({vfp_parts})]")
    a(f"    {vfp_result} = getattr({vfp_hash}, {enc('digest')})()")
    # Fold fingerprint into sm_key via HMAC
    a(f"    {vfp_hmac} = {imp_fn}({enc('hmac')})")
    a(f"    {sm_key} = getattr({vfp_hmac}, {enc('new')})({vfp_result}, {sm_key}, getattr({vfp_h}, {enc('sha256')})).digest()")

    # Cleanup binding locals
    try_del = ', '.join([vfp_hash, vfp_result, vfp_tmp, vfp_hmac])
    a("")

    return lines
