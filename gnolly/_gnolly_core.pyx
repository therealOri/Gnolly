# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: cdivision=True
# cython: embedsignature=False
# cython: emit_code_comments=False
"""
gnolly/_gnolly_core.pyx  ->  Compiled C runtime core
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Decrypt -> decompress -> dispatch to GIR VM.
All security-critical crypto logic lives here as native machine code.

Execution model
----------------
After AES-256-GCM decrypt + decompress, the resulting payload/code is a GIR
(Gnolly Intermediate Representation) blob -> a custom bytecode format produced by gnolly.vm_translate at protect-time.
That blob is handed to _gnolly_vm.vm_exec_module(), a separate Cython extension implementing a
full bytecode interpreter (its own stack machine, frame objects, and
dispatch loop). CPython's eval loop (ceval.c) is never invoked on
protected code, and the original CPython opcodes never exist anywhere
at runtime -> they were translated to GIR once, at protect-time, and
the translation is one-way.

Both _gnolly_core.so (this module) and _gnolly_vm.so are required at
runtime. There is no fallback execution path; if _gnolly_vm cannot be
imported, this module exits immediately rather than degrading to a
less-protected mode.

Payload layout (after decrypt + decompress)
--------------------------------------------
  b'\\x01'              VM-mode flag (1 byte)
  u32_BE(gir_len)       GIR blob length
  <gir_blob>            shuffled GIR bytecode (per-file opcode permutation,
                         see vm_translate.py / vm_serialize.py)
  u32_BE(table_len)     reverse opcode table length (always 131072)
  <table_blob>          131072-byte (2*65536, big-endian u16 pairs) reverse
                         opcode table for the GIR shuffle
"""

import struct
import sys
import os
import hashlib
import zlib
import lzma
import bz2

from Crypto.Cipher import AES
from argon2.low_level import hash_secret_raw as _argon2_hash_secret_raw, Type as _Argon2Type


# ── Constants ─────────────────────────────────────────────────────────────────

cdef bytes _MAGIC_AAD  = b'GNLY\x01\x00'
cdef int   _HEADER_LEN = 6 + 32 + 12 + 16   # magic+ver + salt + iv + tag

# Must mirror gnolly/crypto.py's Argon2id parameters exactly -> any drift
# between protect-time (crypto.py) and run-time (here) silently derives a
# different key, which AES-GCM then reports as "wrong key" on every file.
cdef int _ARGON2_TIME_COST   = 3
cdef int _ARGON2_MEMORY_COST = 65536   # KiB (64 MiB)
cdef int _ARGON2_PARALLELISM = 4


# ── Key derivation ────────────────────────────────────────────────────────────

cdef bytes _argon2_key(bytes password, bytes salt):
    """Argon2id, time_cost=3 / memory_cost=64MiB / parallelism=4 → 32-byte key."""
    return _argon2_hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=_ARGON2_TIME_COST,
        memory_cost=_ARGON2_MEMORY_COST,
        parallelism=_ARGON2_PARALLELISM,
        hash_len=32,
        type=_Argon2Type.ID,
    )


# ── Decompression ─────────────────────────────────────────────────────────────

cdef bytes _decompress(bytes data):
    cdef bytes tag_b = data[:1]
    cdef bytes body  = data[1:]
    if tag_b == b'\x00':
        return body
    elif tag_b == b'\x01':
        return zlib.decompress(body)
    elif tag_b == b'\x02':
        return lzma.decompress(body)
    elif tag_b == b'\x03':
        return bz2.decompress(body)
    else:
        raise ValueError("Unknown compression tag")


# ── Anti-debug ────────────────────────────────────────────────────────────────

cdef void _anti_debug_c():
    """
    C-level anti-debug sweep -> runs after the stub's Python checks so it
    catches any hooks installed between stub execution and here.
    """
    if getattr(sys, 'gettrace', lambda: None)() is not None:
        sys.exit(1)
    if getattr(sys, 'getprofile', lambda: None)() is not None:
        sys.exit(1)

    cdef object _mods = sys.modules
    for _dbg in ('pydevd', 'debugpy', 'pydevd_tracing', '_pydevd_bundle',
                 'rpdb', 'wingdbstub', 'pywin32trace', 'birdseye',
                 '_pydev_bundle', 'pydev_ipython'):
        if _dbg in _mods:
            sys.exit(1)

    cdef object _mon = getattr(sys, 'monitoring', None)
    if _mon is not None:
        try:
            for _tid in (1, 2, 3):
                if getattr(_mon, 'get_tool', lambda _: None)(_tid) is not None:
                    sys.exit(1)
        except Exception:
            pass


# ── ptrace self-attach guard (Linux-only) ───────────────────────────────────
# Deliberately implemented here as compiled C, not as (even obfuscated)
# Python in the stub: an attacker who deobfuscates/rewrites the stub
# source to delete anti-debug lines never touches this, and the actual
# self-attach call goes through the raw syscall(2) entry point rather
# than glibc's ptrace() *symbol*, so it isn't caught by the common
# LD_PRELOAD trick of stubbing out ptrace() to silently report success
# without ever calling the kernel.
#
# A process can call ptrace(PTRACE_TRACEME, 0, NULL, NULL) on itself.
# The kernel then records its real parent as the tracer, and Linux
# allows only one tracer per process -> any later PTRACE_ATTACH /
# PTRACE_SEIZE from a debugger against this PID fails outright with
# EPERM, rather than succeeding and being detected after the fact.
# /proc/<pid>/mem reads from another process go through the same
# kernel ptrace_may_access() check, so those are blocked too.
#
# Caveats: containers/sandboxes commonly deny the ptrace syscall via
# seccomp, which also surfaces as a failure here -> indistinguishable
# from "already traced" at this layer, so the caller (stub.py, via
# gnolly.ptrace_guard) decides how to react to a failure rather than
# this function deciding for it. This blocks *future* attachment; it
# cannot retroactively detect an attacker already attached before this
# code ran, and it does not defend against a root-level attacker
# reading memory through a channel that never goes through
# ptrace_may_access() at all (a malicious kernel module, a hypervisor
# the attacker controls, etc.)
cdef extern from *:
    """
    #include <stddef.h>

    #if defined(__linux__)
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/syscall.h>
    #include <sys/ptrace.h>
    #include <pthread.h>
    #include <time.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>

    static volatile int gnolly_pt_ok_flag  = 0;
    static volatile int gnolly_pt_hb_alive = 0;
    static pid_t        gnolly_pt_traced_pid = 0;

    static long gnolly_pt_traceme(void) {
        /* Raw syscall(2), not the libc ptrace() wrapper. */
        return syscall(SYS_ptrace, PTRACE_TRACEME, 0, NULL, NULL);
    }

    static int gnolly_pt_guard_init_c(void) {
        /* PTRACE_TRACEME marks the CALLING THREAD as traced, not the
           process as a whole -> record which tid actually did this
           so the heartbeat thread below (a different thread/tid) knows which one to go on checking.
           A second TRACEME issued from a different thread would simply trace
           that thread instead and trivially "succeed", which is not
           the signal we want. */
        long ret = gnolly_pt_traceme();
        gnolly_pt_ok_flag = (ret == 0) ? 1 : 0;
        if (gnolly_pt_ok_flag) {
            gnolly_pt_traced_pid = getpid();
        }
        return gnolly_pt_ok_flag;
    }

    /* Reads /proc/<pid>/status and returns the TracerPid value, or -1
       on any read failure. Used by the heartbeat instead of a second
       TRACEME call, since TRACEME's "traced" state is per-thread and
       the heartbeat intentionally runs on a different thread than the
       one that originally self-attached. */
    static long gnolly_pt_read_tracer_pid(pid_t pid) {
        char path[64];
        char line[256];
        long tracer = -1;
        int n = snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
        if (n <= 0 || (size_t)n >= sizeof(path)) return -1;
        FILE *f = fopen(path, "r");
        if (!f) return -1;
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                tracer = strtol(line + 10, NULL, 10);
                break;
            }
        }
        fclose(f);
        return tracer;
    }

    /* Simple time/pid-seeded xorshift -> good enough for a randomized
       heartbeat interval, deliberately not used for anything
       cryptographic. */
    static double gnolly_pt_rand_delay(double lo, double hi) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        unsigned int seed = (unsigned int)ts.tv_nsec ^ (unsigned int)ts.tv_sec
                             ^ (unsigned int)getpid();
        seed ^= seed << 13; seed ^= seed >> 17; seed ^= seed << 5;
        double frac = (double)(seed % 1000000u) / 1000000.0;
        return lo + frac * (hi - lo);
    }

    typedef struct { double lo; double hi; } gnolly_pt_hb_cfg_t;
    /* Unused fallback (gnolly_pt_start_heartbeat_c always overwrites
       this from its lo/hi arguments before the thread reads it) ->
       kept in sync with _gnolly_ptrace_guard's own Python-level
       defaults below purely so the two don't silently drift apart. */
    static gnolly_pt_hb_cfg_t gnolly_pt_hb_cfg = {0.0005, 0.002};

    static void *gnolly_pt_hb_thread(void *arg) {
        (void)arg;
        for (;;) {
            double d = gnolly_pt_rand_delay(gnolly_pt_hb_cfg.lo, gnolly_pt_hb_cfg.hi);
            struct timespec req;
            req.tv_sec  = (time_t)d;
            req.tv_nsec = (long)((d - (double)req.tv_sec) * 1e9);
            nanosleep(&req, NULL);
            /* Once self-attached, /proc/<pid>/status's TracerPid for
               the thread that traced itself is expected to stay
               nonzero (our real parent) for the life of the process.
               If it ever reads back as 0, the trace relationship we
               established is gone (real parent detached/exited) and
               nothing has taken its place. A transient read failure
               (-1, e.g. /proc momentarily unreadable) is not treated
               as that signal -> only a confirmed 0 is. */
            if (gnolly_pt_read_tracer_pid(gnolly_pt_traced_pid) == 0) {
                _exit(1);
            }
        }
        return NULL;
    }

    static int gnolly_pt_start_heartbeat_c(double lo, double hi) {
        if (!gnolly_pt_ok_flag) return 0;
        if (gnolly_pt_hb_alive) return 1;
        gnolly_pt_hb_cfg.lo = lo;
        gnolly_pt_hb_cfg.hi = hi;
        pthread_t tid;
        pthread_attr_t attr;
        if (pthread_attr_init(&attr) != 0) return 0;
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        int rc = pthread_create(&tid, &attr, gnolly_pt_hb_thread, NULL);
        pthread_attr_destroy(&attr);
        if (rc != 0) return 0;
        gnolly_pt_hb_alive = 1;
        return 1;
    }
    #else
    static int gnolly_pt_guard_init_c(void) { return -1; }
    static int gnolly_pt_start_heartbeat_c(double lo, double hi) {
        (void)lo; (void)hi; return 0;
    }
    #endif
    """
    int gnolly_pt_guard_init_c()
    int gnolly_pt_start_heartbeat_c(double lo, double hi)


def _gnolly_ptrace_guard(bint start_heartbeat=True, double min_delay=0.0005, double max_delay=0.002):
    """
    Called by the stub immediately after it loads and hash-verifies
    this .so (see gnolly.import_hook) -> self-attach happens as early
    as the stub's own integrity model finishes and allows any of this module's code
    to run at all, not before.

    start_heartbeat : when True (default) and the initial self-attach
        succeeds, starts a detached pthread that
        periodically repeats the TRACEME call.

    min_delay, max_delay : randomized re-check interval in seconds.
        Default 0.0005-0.002s (0.5-2ms) -> deliberately tight: measured
        at ~6us of actual CPU work per check.
        A SIGSTOP freezes this entire process (heartbeat thread included),
        so this interval does NOT bound how long an attacker who is
        already the tracer can inspect frozen memory while we're
        stopped (they already have /proc/pid/mem access as the
        legitimate tracer at that point, with no time pressure at all).
        What is DOES bound is how long an attacker gets to act against the process
        once it's running again after a detach -> either left
        unmonitored, or now watched by their own swapped-in tracer ->
        before this notices and the process self-destructs. A few
        milliseconds of live interaction.

    Returns
    -------
     1  self-attach succeeded this run.
     0  self-attach failed -> already traced, or the syscall itself was
        denied (e.g. a seccomp profile without CAP_SYS_PTRACE).
    -1  not running on Linux; no-op.
    """
    cdef int rc = gnolly_pt_guard_init_c()
    if rc == 1 and start_heartbeat:
        gnolly_pt_start_heartbeat_c(min_delay, max_delay)
    return rc


# ── Secret-memory hardening (wiping, locking, core-dump prevention) ────────────
# decrypted plaintext and derived key material are kept in buffers THIS module
# owns (bytearray, not bytes) and are explicitly zeroed the moment they are no
# longer needed, instead of relying on normal refcounting/GC to eventually free
# memory that was never actually cleared. Paired with mlock (keep the secret
# out of swap) and MADV_DONTDUMP/RLIMIT_CORE=0 (keep it out of a crash core
# file), this closes the three main ways secret memory ends up somewhere an
# attacker with read access to disk/swap can find it later, after the process
# is no longer even running.
#
# Caveat....pycryptodome's AES keeps the expanded round-key schedule in its own opaque C/FFI state,
# which is never exposed to Python/Cython callers, so it cannot be
# explicitly zeroed from here. What we do instead is minimise its lifetime.
# the cipher object is dereferenced (`cipher = None`) the instant decryption finishes, so CPython's refcounting
# frees pycryptodome's C state (and whatever cleanup pycryptodome itself
# performs on free) as early as the interpreter allows.
cdef extern from *:
    """
    #include <string.h>
    #include <stddef.h>

    #if defined(_WIN32)
    #include <windows.h>
    #elif defined(__linux__)
    #include <unistd.h>
    #include <sys/syscall.h>
    #include <sys/mman.h>
    #include <sys/resource.h>
    #include <sys/prctl.h>
    #else
    /* macOS/BSD: not a current target platform for this project, kept
       on the plain libc path (mlock/madvise/setrlimit) for portability
       rather than hand-rolling syscalls for a platform not currently or planned to be supported. */
    #include <sys/mman.h>
    #include <sys/resource.h>
    #endif

    static void gnolly_secure_zero(void *ptr, size_t len) {
        if (!ptr || len == 0) return;
    #if defined(_WIN32)
        SecureZeroMemory(ptr, len);
    #elif defined(__APPLE__)
        memset_s(ptr, len, 0, len);
    #elif (defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 25))) \\
          || defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__)
        explicit_bzero(ptr, len);
    #else
        volatile unsigned char *p = (volatile unsigned char *)ptr;
        size_t i;
        for (i = 0; i < len; i++) p[i] = 0;
    #if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" ::: "memory");
    #endif
    #endif
    }

    /* Linux: raw syscall(2), not the libc mlock()/munlock() wrapper
       symbols -> same LD_PRELOAD-can't-silently-neuter reasoning as
       gnolly_pt_traceme() above, now applied consistently to every
       hardening primitive in this file, not just ptrace. */
    static int gnolly_lock_mem(void *ptr, size_t len) {
        if (!ptr || len == 0) return 0;
    #if defined(_WIN32)
        return VirtualLock(ptr, len) ? 1 : 0;
    #elif defined(__linux__)
        return (syscall(SYS_mlock, ptr, len) == 0) ? 1 : 0;
    #else
        return (mlock(ptr, len) == 0) ? 1 : 0;
    #endif
    }

    static int gnolly_unlock_mem(void *ptr, size_t len) {
        if (!ptr || len == 0) return 0;
    #if defined(_WIN32)
        return VirtualUnlock(ptr, len) ? 1 : 0;
    #elif defined(__linux__)
        return (syscall(SYS_munlock, ptr, len) == 0) ? 1 : 0;
    #else
        return (munlock(ptr, len) == 0) ? 1 : 0;
    #endif
    }

    /* Exclude this one buffer's pages from any crash dump this process
       ever produces (Linux-only primitive on top
       of gnolly_disable_core_dumps() below, since gdb's "gcore" and
       similar external dump tools also honour MADV_DONTDUMP). */
    static void gnolly_mark_undumpable(void *ptr, size_t len) {
    #if defined(__linux__) && defined(MADV_DONTDUMP)
        if (ptr && len) syscall(SYS_madvise, ptr, len, MADV_DONTDUMP);
    #else
        (void)ptr; (void)len;
    #endif
    }

    /* ── aeskeyfind-style memory-forensics mitigation:

       gnolly_aes256_key_schedule() below performs the full standard
       expansion (SubWord/RotWord/Rcon over 8 key words -> 60 round-key
       words) so that gnolly_deploy_chaff() can mint any number of
       structurally real AES-256 schedules from throwaway random seeds.
       Each one is indistinguishable from the genuine schedule by
       structure alone. aeskeyfind's structural test cannot tell real
       from decoy, and only trial-decrypting the actual ciphertext against
       each candidate can. One confirmed hit becomes 1-in-(N+1) guesswork.
    */
       
    static const unsigned char gnolly_sbox[256] = {
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
    };

    /* FIPS-197 AES-256 key expansion: Nk=8, Nr=14, Nb=4 -> 60 round-key
       words (240 bytes). key32 and out240 must be distinct, non-NULL,
       exactly 32 and 240 bytes respectively. */
    static void gnolly_aes256_key_schedule(const unsigned char *key32, unsigned char *out240) {
        static const unsigned char rcon[8] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40};
        unsigned char w[60][4];
        int i;
        for (i = 0; i < 8; i++) {
            w[i][0] = key32[4*i + 0];
            w[i][1] = key32[4*i + 1];
            w[i][2] = key32[4*i + 2];
            w[i][3] = key32[4*i + 3];
        }
        for (i = 8; i < 60; i++) {
            unsigned char t0 = w[i-1][0], t1 = w[i-1][1], t2 = w[i-1][2], t3 = w[i-1][3];
            if (i % 8 == 0) {
                unsigned char tmp = t0;
                t0 = gnolly_sbox[t1]; t1 = gnolly_sbox[t2]; t2 = gnolly_sbox[t3]; t3 = gnolly_sbox[tmp];
                t0 ^= rcon[i/8];
            } else if (i % 8 == 4) {
                t0 = gnolly_sbox[t0]; t1 = gnolly_sbox[t1]; t2 = gnolly_sbox[t2]; t3 = gnolly_sbox[t3];
            }
            w[i][0] = w[i-8][0] ^ t0;
            w[i][1] = w[i-8][1] ^ t1;
            w[i][2] = w[i-8][2] ^ t2;
            w[i][3] = w[i-8][3] ^ t3;
        }
        memcpy(out240, w, 240);
    }

    #if defined(_WIN32)
    /* Installed by gnolly_disable_core_dumps() below. Runs ahead of
       Windows Error Reporting's own handler -> terminate immediately
       instead of letting WER stage a minidump of this process. */
    static LONG WINAPI gnolly_crash_filter(EXCEPTION_POINTERS *info) {
        (void)info;
        TerminateProcess(GetCurrentProcess(), 1);
        return EXCEPTION_EXECUTE_HANDLER; /* unreachable; keeps MSVC quiet */
    }
    #endif

    /* Process-wide: refuse to ever leave a crash dump behind. (a core
       file on Linux or a WER minidump on Windows) and (on Linux) make the
       process non-ptrace-attachable by anything other than our own
       earlier self-attach. */
    static void gnolly_disable_core_dumps(void) {
    #if defined(_WIN32)
        SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);
        SetUnhandledExceptionFilter(gnolly_crash_filter);
    #elif defined(__linux__)
        struct rlimit rl;
        rl.rlim_cur = 0;
        rl.rlim_max = 0;
        syscall(SYS_setrlimit, RLIMIT_CORE, &rl);
        syscall(SYS_prctl, PR_SET_DUMPABLE, 0, 0, 0, 0);
    #else
        struct rlimit rl;
        rl.rlim_cur = 0;
        rl.rlim_max = 0;
        setrlimit(RLIMIT_CORE, &rl);
    #endif
    }
    """
    void gnolly_secure_zero(void *ptr, size_t length)
    int  gnolly_lock_mem(void *ptr, size_t length)
    int  gnolly_unlock_mem(void *ptr, size_t length)
    void gnolly_mark_undumpable(void *ptr, size_t length)
    void gnolly_disable_core_dumps()
    void gnolly_aes256_key_schedule(const unsigned char *key32, unsigned char *out240)


from cpython.buffer cimport Py_buffer, PyObject_GetBuffer, PyBuffer_Release, PyBUF_WRITABLE
from cpython.bytes  cimport PyBytes_AS_STRING, PyBytes_GET_SIZE
from cpython.exc    cimport PyErr_Clear


cdef void _wipe(object buf):
    """
    Securely zero a mutable buffer in place (bytearray, or a
    memoryview over one). No-op if buf doesn't expose a writable
    buffer.
    """
    if buf is None:
        return
    cdef Py_buffer view
    if PyObject_GetBuffer(buf, &view, PyBUF_WRITABLE) != 0:
        PyErr_Clear()
        return
    try:
        gnolly_secure_zero(view.buf, <size_t>view.len)
    finally:
        PyBuffer_Release(&view)


cdef void _wipe_bytes_unsafe(bytes data):
    """
    Best-effort zero of an otherwise-immutable bytes object's backing
    storage, in place.

    CPython's PyBytes_AS_STRING deliberately returns a non-const char*
    precisely so C extensions can do this kind of post-creation
    in-place mutation. It's undefined behaviour with other Python
    implementations and relies on said object being a genuine unique
    heap allocation, which is why this is only ever called on bytes we
    just received fresh from the argon2/zlib/etc stuff and never on a literal or
    anything that could be a cached/interned object.
    (CPython caches b'' and every single-byte bytes value,
    0-255, as shared singletons -> those must never be mutated).
    """
    cdef Py_ssize_t n = PyBytes_GET_SIZE(data)
    if n <= 1:
        return
    gnolly_secure_zero(<void*>PyBytes_AS_STRING(data), <size_t>n)


cdef void _lock(object buf):
    """Best-effort mlock + exclude-from-core-dump for a writable buffer."""
    if buf is None:
        return
    cdef Py_buffer view
    if PyObject_GetBuffer(buf, &view, PyBUF_WRITABLE) != 0:
        PyErr_Clear()
        return
    try:
        gnolly_lock_mem(view.buf, <size_t>view.len)
        gnolly_mark_undumpable(view.buf, <size_t>view.len)
    finally:
        PyBuffer_Release(&view)


cdef void _unlock(object buf):
    if buf is None:
        return
    cdef Py_buffer view
    if PyObject_GetBuffer(buf, &view, PyBUF_WRITABLE) != 0:
        PyErr_Clear()
        return
    try:
        gnolly_unlock_mem(view.buf, <size_t>view.len)
    finally:
        PyBuffer_Release(&view)


# ── aeskeyfind mitigation: key-schedule chaff ──────────────────────────────────
# Makes a passive memory-image scan for AES-256
# round-key schedules return several structurally valid
# candidates instead of one, with the real one and the decoys sharing an
# identical alloc/mlock/undumpable/wipe lifetime.
cdef int _CHAFF_COUNT = 20  # cost: ~20 * (240B alloc + one schedule expansion) per run

cdef bytearray _make_decoy_schedule():
    """One throwaway-seed AES-256 schedule, structurally real, key unknown to
    anything (seed is never retained)."""
    cdef bytearray seed = bytearray(os.urandom(32))
    cdef bytearray out  = bytearray(240)
    cdef Py_buffer seed_view, out_view
    if PyObject_GetBuffer(seed, &seed_view, PyBUF_WRITABLE) != 0:
        PyErr_Clear()
        return out
    if PyObject_GetBuffer(out, &out_view, PyBUF_WRITABLE) != 0:
        PyErr_Clear()
        PyBuffer_Release(&seed_view)
        return out
    try:
        gnolly_aes256_key_schedule(<const unsigned char*>seed_view.buf, <unsigned char*>out_view.buf)
    finally:
        PyBuffer_Release(&seed_view)
        PyBuffer_Release(&out_view)
    _wipe(seed)
    return out


cdef list _deploy_chaff(int n=-1):
    """
    Mint n decoy AES-256 schedules, each mlock'd + excluded from core dumps.
    We call this before the real key/schedule exists and wipe the result (`_wipe_chaff`)
    at the exact same point the real derived key is wiped, so both share one lifetime window.
    """
    if n < 0:
        n = _CHAFF_COUNT
    cdef list bufs = []
    cdef int i
    cdef bytearray buf
    for i in range(n):
        buf = _make_decoy_schedule()
        _lock(buf)
        bufs.append(buf)
    return bufs


cdef void _wipe_chaff(list bufs):
    cdef bytearray b
    if not bufs:
        return
    for b in bufs:
        _wipe(b)
        _unlock(b)
    bufs.clear()


# ── sys.monitoring blackout ───────────────────────────────────────────────────

cdef object _monitoring_blackout_enter():
    cdef object _mon = getattr(sys, 'monitoring', None)
    if _mon is None:
        return None
    cdef int _TOOL = 5
    try:
        getattr(_mon, 'use_tool_id')(_TOOL, 'gnolly_runtime')
        getattr(_mon, 'set_events')(_TOOL, 0)
        return _TOOL
    except Exception:
        return None


cdef void _monitoring_blackout_exit(object state):
    if state is None:
        return
    cdef object _mon = getattr(sys, 'monitoring', None)
    if _mon is None:
        return
    try:
        getattr(_mon, 'free_tool_id')(state)
    except Exception:
        pass

# ── Load _gnolly_vm -> required, no fallback ───────────────────────────────────
# Both .so files must be present. If _gnolly_vm is missing, we exit immediately.
cdef object _gvm_exec_module = None
cdef bint _VM_LOADED = False

def _gnolly_load_vm_module(object vm_module):
    """
    Called by the stub immediately after loading _gnolly_vm.so, before any
    call to gnolly_run(). Registers the VM's exec function for use below.
    This is the ONLY way gnolly_run can access the VM.
    """
    global _gvm_exec_module, _VM_LOADED
    try:
        _gvm_exec_module = vm_module.vm_exec_module
        _VM_LOADED = True
    except AttributeError:
        _VM_LOADED = False
        sys.exit(1)


# ── Public: gnolly_run ────────────────────────────────────────────────────────

def gnolly_run(
    bytes blob_raw,
    object key_input,
    bytes salt,
    bytes iv,
    bytes tag,
    int header_skip,
    bytes alpha_bytes,
    bytes xor_key,
    object caller_globals=None,
):
    """
    Full Gnolly runtime pipeline -> compiled to C.

    decrypt -> decompress -> GIR VM execute

    Payload/code format (after AES-GCM decrypt + decompress):
        b'\\x01'              VM-mode flag
        u32_BE(gir_len)      GIR blob length
        <gir_blob>           shuffled GIR bytecode
        u32_BE(table_len)    reverse table length (131072)
        <table_blob>         131072-byte reverse opcode table (u16 pairs)

    caller_globals : when provided (module_mode stubs, e.g. protected
        package/wheel submodules), the decoded output executes directly into
        a dict instead of throwaway namespace.

    Memory hygiene: every buffer that would hold the password, the derived
    key, or decrypted plaintext is a bytearray this function owns outright.
    Each one is mlock()'d + excluded from core dumps while live, and
    explicitly zeroed the moment it is no longer needed on both success
    and exception.
    """
    _anti_debug_c()
    gnolly_disable_core_dumps()
    if not _VM_LOADED:
        # _gnolly_vm.so was never registered via _gnolly_load_vm_module().
        # No fallback execution path exists -> refuse to run.
        sys.exit(1)
    cdef object _blackout_state = _monitoring_blackout_enter()

    # aeskeyfind mitigation: decoy schedules go live before any real key
    # material exists, and come down with the real derived key below -> any
    # memory image taken anywhere in that window sees both.
    cdef list _chaff = _deploy_chaff()

    # ── 1. Normalise key into a buffer we own and can wipe ──────────────────
    cdef bytearray key_buf
    if isinstance(key_input, (bytes, bytearray)):
        key_buf = bytearray(key_input)
    else:
        key_buf = bytearray(key_input.encode('utf-8'))
    _lock(key_buf)

    # ── 2. KDF ────────────────────────────────────────────────────────────────
    cdef bytes _derived_raw = _argon2_key(bytes(key_buf), salt)  # argon2 needs `bytes` in
    _wipe(key_buf)
    _unlock(key_buf)
    key_buf = None

    cdef bytearray derived_buf = bytearray(_derived_raw)
    _wipe_bytes_unsafe(_derived_raw)   # best-effort clear of argon2's own copy
    _derived_raw = None
    _lock(derived_buf)

    # ── 3. AES-256-GCM decrypt, straight into a buffer we already own ───────
    # output= writes the plaintext directly into plaintext_buf instead of
    # pycryptodome handing back fresh and immutable bytes that we'd then have to
    # copy out of and leave behind. (one fewer uncollectable copy of the
    # decrypted source floating in the heap.)
    cdef bytes ciphertext = blob_raw[header_skip:]
    cdef bytearray plaintext_buf = bytearray(len(ciphertext))
    _lock(plaintext_buf)
    cipher = None
    try:
        # pycryptodome's key= happens to accept bytes/bytearray/memoryview directly,
        # so we can pass the bytearray itself and have no extra immutable bytes copy of the key.
        cipher = AES.new(derived_buf, AES.MODE_GCM, nonce=iv, mac_len=16)
        cipher.update(_MAGIC_AAD)
        cipher.decrypt_and_verify(ciphertext, tag, output=plaintext_buf)
    except ValueError:
        _wipe(derived_buf); _unlock(derived_buf)
        _wipe(plaintext_buf); _unlock(plaintext_buf)
        _wipe_chaff(_chaff)
        sys.exit(1)
    finally:
        # Drop pycryptodome's cipher object (and whatever internal key-
        # schedule state it holds) the instant we're done with it, rather
        # than letting it live until the end of the function.
        cipher = None
        _wipe(derived_buf)
        _unlock(derived_buf)
        derived_buf = None
        _wipe_chaff(_chaff)

    # ── 4. Decompress ─────────────────────────────────────────────────────────
    # zlib/lzma/bz2 gives us an immutable bytes with no way to decompress
    # straight into a buffer we control, so we'll copy out to a bytearray immediately
    # and do a best-effort clear for the stdlib's own copy, then wipe+unlock the
    # ciphertext-shaped buffer we just finished reading from.
    cdef bytes _decompressed_raw = _decompress(bytes(plaintext_buf))
    _wipe(plaintext_buf)
    _unlock(plaintext_buf)
    plaintext_buf = None

    cdef bytearray decompressed = bytearray(_decompressed_raw)
    _wipe_bytes_unsafe(_decompressed_raw)
    _decompressed_raw = None
    _lock(decompressed)

    # ── 5. Unpack VM-mode payload ─────────────────────────────────────────────
    # Layout: VM_FLAG(1) | u32(gir_len) | gir_blob | u32(table_len) | table_blob
    if len(decompressed) < 1 or decompressed[0:1] != b'\x01':
        # Not a VM-mode payload/code -> refuse to execute
        _wipe(decompressed); _unlock(decompressed)
        sys.exit(1)

    cdef unsigned int gir_len, table_len
    gir_len,   = struct.unpack_from('>I', decompressed, 1)
    cdef bytearray gir_blob_buf   = decompressed[5 : 5 + gir_len]
    table_len, = struct.unpack_from('>I', decompressed, 5 + gir_len)
    cdef bytearray table_blob_buf = decompressed[9 + gir_len : 9 + gir_len + table_len]
    _wipe(decompressed)
    _unlock(decompressed)
    decompressed = None

    # ── 6. Dispatch to GIR VM interpreter ─────────────────────────────────────
    # CPython's eval loop never runs on this code.
    # _gnolly_vm.vm_exec_module deserialises the GIR blob and runs it
    # through its own Cython stack machine.
    cdef dict globs
    if caller_globals is not None:
        globs = caller_globals
        if '__builtins__' not in globs:
            globs['__builtins__'] = __builtins__
    else:
        globs = {
            '__name__':     '__main__',
            '__builtins__': __builtins__,
            '__doc__':      None,
            '__package__':  None,
            '__spec__':     None,
        }

    try:
        _gvm_exec_module(gir_blob_buf, table_blob_buf, globs)
    finally:
        _wipe(gir_blob_buf);   _unlock(gir_blob_buf);   gir_blob_buf = None
        _wipe(table_blob_buf); _unlock(table_blob_buf); table_blob_buf = None
    _monitoring_blackout_exit(_blackout_state)
