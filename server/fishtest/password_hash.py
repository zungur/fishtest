"""Password hashing for interactive logins using stdlib ``hashlib.scrypt``.

Hashes are stored in a self-describing string so the cost parameters travel
with the hash and can be upgraded transparently:

    $scrypt$n=65536,r=8,p=2$<salt_b64>$<hash_b64>

Workers pay the scrypt cost only when they log in for a session; afterwards
they present a random session token that is checked with a cheap lookup (see
``fishtest.worker_sessions``). Otherwise only interactive flows (web login,
signup, password change) pay the scrypt cost.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import threading

from fishtest.constants import (
    SCRYPT_DKLEN,
    SCRYPT_MAX_CONCURRENCY,
    SCRYPT_MAX_WAITERS,
    SCRYPT_MAXMEM,
    SCRYPT_N,
    SCRYPT_P,
    SCRYPT_R,
    SCRYPT_SALT_BYTES,
    SCRYPT_SLOT_WAIT_SECONDS,
)

_PREFIX = "$scrypt$"
_kdf_slots = threading.BoundedSemaphore(SCRYPT_MAX_CONCURRENCY)
_kdf_waiters_lock = threading.Lock()
_kdf_waiters = 0


class PasswordHashBusy(Exception):  # noqa: N818
    """No KDF slot became free in time; the caller should answer "busy"."""


def _b64encode(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64decode(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _acquire_kdf_slot() -> bool:
    # Waiting without a bound, in time or in number, would let a flood of
    # password checks pile up every server thread behind the KDF slots.
    global _kdf_waiters  # noqa: PLW0603
    if _kdf_slots.acquire(blocking=False):
        return True
    with _kdf_waiters_lock:
        if _kdf_waiters >= SCRYPT_MAX_WAITERS:
            return False
        _kdf_waiters += 1
    try:
        return _kdf_slots.acquire(timeout=SCRYPT_SLOT_WAIT_SECONDS)
    finally:
        with _kdf_waiters_lock:
            _kdf_waiters -= 1


def _derive(password: str, *, n: int, r: int, p: int, dklen: int, salt: bytes) -> bytes:
    if not _acquire_kdf_slot():
        print("Password KDF busy, rejecting request", flush=True)
        raise PasswordHashBusy
    try:
        return hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=n,
            r=r,
            p=p,
            dklen=dklen,
            maxmem=SCRYPT_MAXMEM,
        )
    finally:
        _kdf_slots.release()


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
