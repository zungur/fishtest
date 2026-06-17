"""Shared constants used by schemas, utilities, and views."""

PASSWORD_MAX_LENGTH = 72
VALID_USERNAME_PATTERN = "[A-Za-z0-9]{2,}"

# Worker API tokens. High-entropy random secrets that authenticate workers
# without paying the cost of a password KDF on every API call.
API_KEY_PREFIX = "ft_"
# secrets.token_urlsafe(32) yields ~43 url-safe base64 chars.
API_KEY_PATTERN = r"ft_[A-Za-z0-9_-]{43}"

# scrypt parameters for interactive password hashing (web login, signup,
# password change). These run only on rare interactive flows now that workers
# authenticate with API tokens, so OWASP-grade cost is affordable.
# See https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
SCRYPT_N = 2**16
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SCRYPT_SALT_BYTES = 16
# hashlib.scrypt enforces maxmem >= 128 * r * (N + p + 1) bytes; add margin.
SCRYPT_MAXMEM = 128 * SCRYPT_R * (SCRYPT_N + SCRYPT_P + 2)

# Password reset tokens: short-lived, single-use, delivered by email and
# stored only as a sha256 digest.
PASSWORD_RESET_EXPIRY_HOURS = 1
# Minimum interval between forgot-password submissions per IP or email.
FORGOT_PASSWORD_RATE_LIMIT_SECONDS = 60

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
