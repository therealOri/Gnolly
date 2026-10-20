"""
gnolly.memwipe_stub
~~~~~~~~~~~~~~~~~~~
Generates an obfuscated "best-effort secure zero" helper that's embedded into
protected stubs. And the swap-then-wipe snippet used at every point where the
stub discards one bytes key-material value in favour of the raw password/key bytes from the environment or getpass,
and each intermediate value produced by the machine-binding/integrity/poison
HMAC folds before sm_key is reassigned again.


Same caveats as the compiled version apply here: CPython-specific,
relies on the bytes object being a genuine unique heap allocation
(never call this on a literal or anything that could be a
cached/interned object), and it does nothing for `str` objects. There is no
equivalent-safety trick for type str: its internal representation varies
by content. So the hex string GNOLLY_KEY arrives as, or the string getpass()
returns, is NOT wiped by any of this. Only the bytes values derived
from them are. The whole setup is wrapped in try/except so a restricted
environment without (a working) ctypes for now will degrade into to a silent no-op
rather than breaking the protected program.
"""
from __future__ import annotations
import random
from .namegen import random_confusable_name
from .strcodec import _enc_str


def generate_wipe_setup_lines(
    s_fn: str,       # stub's str-decoder function name
    str_key: bytes,  # stub's string encoding key
    imp_fn: str,      # obfuscated __import__ handle
    h_ctypes: str,    # var to bind the ctypes module to
    pbs_var: str,     # var to bind ctypes.pythonapi.PyBytes_AsString to
    memset_var: str,  # var to bind ctypes.memset to
    wv_fn: str,       # var to bind the resulting wipe lambda to
    rng: random.Random | None = None,
) -> list[str]:
    """
    Emits, once, early in the stub (before any key material exists):
    """
    lines = []
    a = lines.append

    def enc(s: str) -> str:
        return _enc_str(s, str_key)

    def s(text: str) -> str:
        return f"{s_fn}({enc(text)})"

    _rng = rng or random.Random()
    p = random_confusable_name(_rng, set(), length=1)

    a("try:")
    a(f"    {h_ctypes} = {imp_fn}({s('ctypes')})")
    a(f"    {pbs_var} = getattr(getattr({h_ctypes}, {s('pythonapi')}), {s('PyBytes_AsString')})")
    a(f"    {pbs_var}.restype  = getattr({h_ctypes}, {s('c_void_p')})")
    a(f"    {pbs_var}.argtypes = [getattr({h_ctypes}, {s('py_object')})]")
    a(f"    {memset_var} = getattr({h_ctypes}, {s('memset')})")
    a(f"    {wv_fn} = lambda {p}: ({memset_var}({pbs_var}({p}), 0, len({p})) "
      f"if isinstance({p}, bytes) and len({p}) > 1 else " + "None)")
    a("except Exception:")
    a(f"    {wv_fn} = lambda {p}: None")
    return lines


def wipe_call(wv_fn: str, target: str) -> str:
    # best-effort zeroing of a target's backing bytes storage.
    return f"{wv_fn}({target})"
