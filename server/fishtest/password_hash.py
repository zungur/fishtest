"""Password hashing for interactive logins using stdlib ``hashlib.scrypt``.

Hashes are stored in a self-describing string so the cost parameters travel
with the hash and can be upgraded transparently:

    $scrypt$n=65536,r=8,p=1$<salt_b64>$<hash_b64>

Worker authentication does NOT use this module: workers present a
high-entropy API token that is checked with a cheap constant-time compare
(see ``UserDb.authenticate_worker``). Only rare interactive flows (web login,
signup, password change, password reset) pay the scrypt cost.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

from fishtest.constants import (
    SCRYPT_DKLEN,
    SCRYPT_MAXMEM,
    SCRYPT_N,
    SCRYPT_P,
    SCRYPT_R,
    SCRYPT_SALT_BYTES,
)

_PREFIX = "$scrypt$"


def _b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64decode(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _derive(password: str, *, n: int, r: int, p: int, dklen: int, salt: bytes) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=dklen,
        maxmem=SCRYPT_MAXMEM,
    )


def is_hashed(stored: str) -> bool:
    """Return True if ``stored`` is a scrypt hash produced by this module."""
    return isinstance(stored, str) and stored.startswith(_PREFIX)


def hash_password(password: str) -> str:
    """Hash ``password`` with the current scrypt parameters."""
    salt = secrets.token_bytes(SCRYPT_SALT_BYTES)
    digest = _derive(
        password, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN, salt=salt
    )
    params = f"n={SCRYPT_N},r={SCRYPT_R},p={SCRYPT_P}"
    return f"{_PREFIX}{params}${_b64encode(salt)}${_b64encode(digest)}"


def _parse(stored: str) -> tuple[int, int, int, bytes, bytes]:
    # Raises ValueError / KeyError on malformed input; callers handle it.
    _, scheme, params, salt_b64, hash_b64 = stored.split("$")
    if scheme != "scrypt":
        raise ValueError("not a scrypt hash")
    parsed = dict(item.split("=", 1) for item in params.split(","))
    n = int(parsed["n"])
    r = int(parsed["r"])
    p = int(parsed["p"])
    return n, r, p, _b64decode(salt_b64), _b64decode(hash_b64)


def verify_password(stored: str, password: str) -> bool:
    """Return True if ``password`` matches the scrypt ``stored`` hash."""
    try:
        n, r, p, salt, expected = _parse(stored)
    except (ValueError, KeyError) as e:
        print(f"Malformed password hash: {e}", flush=True)
        return False
    computed = _derive(password, n=n, r=r, p=p, dklen=len(expected), salt=salt)
    return hmac.compare_digest(computed, expected)


def needs_rehash(stored: str) -> bool:
    """Return True if ``stored`` should be re-hashed with current parameters.

    Legacy plaintext passwords and parameter changes both trigger a rehash.
    """
    try:
        n, r, p, _, expected = _parse(stored)
    except ValueError, KeyError:
        return True
    return (n, r, p, len(expected)) != (SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_DKLEN)
