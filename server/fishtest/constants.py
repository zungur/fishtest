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

# scrypt parameters for password hashing (logins, signup, password changes).
# N=2^16, r=8, p=2 is one of the OWASP minimum configurations (equivalent to
# N=2^17, r=8, p=1 with half the memory). Hashes with other parameters are
# upgraded at the next successful login.
# See https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
SCRYPT_N = 2**16
SCRYPT_R = 8
SCRYPT_P = 2
SCRYPT_DKLEN = 32
SCRYPT_SALT_BYTES = 16
# hashlib.scrypt enforces maxmem >= 128 * r * (N + p + 1) bytes; add margin.
SCRYPT_MAXMEM = 128 * SCRYPT_R * (SCRYPT_N + SCRYPT_P + 2)
# Each derivation holds ~SCRYPT_MAXMEM (64 MiB) for its duration, so cap how
# many run at once; at most SCRYPT_MAX_WAITERS further callers wait for a free
# slot, each at most SCRYPT_SLOT_WAIT_SECONDS, and the others are answered
# "server busy" at once. Waiters hold server threads (THREADPOOL_TOKENS = 200),
# so this keeps a burst of logins from stalling every other request.
SCRYPT_MAX_CONCURRENCY = 4
SCRYPT_MAX_WAITERS = 16
SCRYPT_SLOT_WAIT_SECONDS = 5.0

# Password logins (worker API, web login, profile changes). Failed checks are
# counted per (username, client), per client, per username and in total, in
# fixed windows starting at the first failure. A client is an IPv4 address or
# an IPv6 /64 network. A client over its (username, client) or client limit is
# rejected without running the KDF. A username over its limit, or the total
# over its limit, never causes a rejection by itself: password checks from
# clients not known for that username wait in a paced queue instead. These
# counts are kept in memory, per process.
PASSWORD_FAILURE_WINDOW_SECONDS = 60
PASSWORD_PAIR_FAILURE_LIMIT = 10
PASSWORD_IP_FAILURE_LIMIT = 30
PASSWORD_USER_FAILURE_LIMIT = 10
PASSWORD_GLOBAL_FAILURE_LIMIT = 100
PASSWORD_IPV6_PREFIX = 64
# Queued checks start at most this often, at most this many requests wait
# (each holds a server thread), and a request waits at most this long (with
# SCRYPT_SLOT_WAIT_SECONDS, well below the worker's 30 s HTTP timeout).
PASSWORD_QUEUE_INTERVAL_SECONDS = 1.0
PASSWORD_QUEUE_MAX_WAITERS = 8
PASSWORD_QUEUE_MAX_WAIT_SECONDS = 15.0
# Failed checks per username are also counted in MongoDB, shared by all
# processes, in fixed windows starting at the first failure. Over the limit,
# only clients known for that username get a password check, until the window
# ends or the password is changed.
PASSWORD_USER_DAILY_FAILURE_LIMIT = 100
PASSWORD_DAILY_FAILURE_WINDOW_SECONDS = 24 * 3600
# A client stays known for a user this long after a successful password
# login from it; the record is refreshed at most this often.
KNOWN_LOGIN_IP_DAYS = 30
KNOWN_LOGIN_IP_REFRESH_SECONDS = 3600

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
