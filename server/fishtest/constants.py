"""Shared constants used by schemas, utilities, and views."""

PASSWORD_MAX_LENGTH = 72
VALID_USERNAME_PATTERN = "[A-Za-z0-9]{2,}"

# Worker sessions. A worker exchanges its password for a random session token
# once per run, so the password KDF does not run on every API call. Sessions
# end on logout, after this much inactivity, at this age, or on a password
# change.
WORKER_SESSION_IDLE_SECONDS = 24 * 3600
WORKER_SESSION_MAX_AGE_SECONDS = 30 * 24 * 3600
# /api/request_version, called before every task, refuses sessions this close
# to their maximum age, so the worker logs in again before a task can hit it.
WORKER_SESSION_RENEW_SECONDS = 24 * 3600
# Refresh a session's last_seen at most this often to limit database writes.
WORKER_SESSION_TOUCH_SECONDS = 600
# Per-user session cap is max(2 * machine_limit, WORKER_SESSION_MIN_CAP).
WORKER_SESSION_MIN_CAP = 32

supported_compilers = ["clang++", "g++"]

supported_arches = [
    "apple-silicon",
    "armv7",
    "armv7-neon",
    "armv8",
    "armv8-dotprod",
    "e2k",
    "general-32",
    "general-64",
    "loongarch64",
    "loongarch64-lasx",
    "loongarch64-lsx",
    "ppc-32",
    "ppc-64",
    "ppc-64-altivec",
    "ppc-64-vsx",
    "riscv64",
    "x86-32",
    "x86-32-sse2",
    "x86-32-sse41-popcnt",
    "x86-64",
    "x86-64-avx2",
    "x86-64-avx512",
    "x86-64-avxvnni",
    "x86-64-bmi2",
    "x86-64-sse3-popcnt",
    "x86-64-sse41-popcnt",
    "x86-64-ssse3",
    "x86-64-vnni512",
    "x86-64-avx512icl",
]
