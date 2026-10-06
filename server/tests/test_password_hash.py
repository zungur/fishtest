# ruff: noqa: ANN201, D100, D101, D102, INP001, PT009, S105, S106
"""Unit tests for the stdlib scrypt password hashing helpers."""

import threading
import time
import unittest
from unittest.mock import patch

from fishtest.constants import (
    SCRYPT_DKLEN,
    SCRYPT_MAX_CONCURRENCY,
    SCRYPT_N,
    SCRYPT_P,
    SCRYPT_R,
)
from fishtest.password_hash import (
    PasswordHashBusy,
    hash_password,
    is_hashed,
    needs_rehash,
    verify_password,
)


class TestPasswordHash(unittest.TestCase):
    def test_hash_is_self_describing(self):
        stored = hash_password("correct horse battery staple")
        self.assertTrue(is_hashed(stored))
        self.assertTrue(stored.startswith("$scrypt$"))
        self.assertIn(f"n={SCRYPT_N},r={SCRYPT_R},p={SCRYPT_P}", stored)

    def test_hash_is_salted(self):
        a = hash_password("same-password")
        b = hash_password("same-password")
        self.assertNotEqual(a, b)

    def test_verify_roundtrip(self):
        stored = hash_password("hunter2")
        self.assertTrue(verify_password(stored, "hunter2"))
        self.assertFalse(verify_password(stored, "hunter3"))

    def test_verify_rejects_malformed(self):
        self.assertFalse(verify_password("not-a-hash", "x"))
        self.assertFalse(verify_password("$scrypt$bogus", "x"))
        self.assertFalse(verify_password("", "x"))

    def test_needs_rehash(self):
        stored = hash_password("abc")
        self.assertFalse(needs_rehash(stored))
        # Legacy plaintext (or anything not produced by this module) must rehash.
        self.assertTrue(needs_rehash("legacy-plaintext"))
        # Weaker parameters must rehash.
        weaker = stored.replace(f"n={SCRYPT_N}", "n=1024")
        self.assertTrue(needs_rehash(weaker))

    def test_is_hashed(self):
        self.assertFalse(is_hashed("plaintext"))
        self.assertTrue(is_hashed(hash_password("x")))

    def test_concurrent_derivations_are_bounded(self):
        stored = hash_password("abc")
        lock = threading.Lock()
        active = 0
        peak = 0

        def slow_scrypt(*args, **kwargs):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            time.sleep(0.05)
            with lock:
                active -= 1
            return b"\0" * SCRYPT_DKLEN

        threads = [
            threading.Thread(target=verify_password, args=(stored, "abc"))
            for _ in range(SCRYPT_MAX_CONCURRENCY * 3)
        ]
        with patch("fishtest.password_hash.hashlib.scrypt", slow_scrypt):
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
        self.assertEqual(peak, SCRYPT_MAX_CONCURRENCY)

    def test_busy_when_no_slot_frees_up(self):
        stored = hash_password("abc")
        slots = threading.BoundedSemaphore(1)
        slots.acquire()
        with (
            patch("fishtest.password_hash._kdf_slots", slots),
            patch("fishtest.password_hash.SCRYPT_SLOT_WAIT_SECONDS", 0.01),
            self.assertRaises(PasswordHashBusy),
        ):
            verify_password(stored, "abc")
        slots.release()
        with patch("fishtest.password_hash._kdf_slots", slots):
            self.assertTrue(verify_password(stored, "abc"))

    def test_busy_at_once_when_too_many_wait(self):
        stored = hash_password("abc")
        slots = threading.BoundedSemaphore(1)
        slots.acquire()
        self.addCleanup(slots.release)
        with (
            patch("fishtest.password_hash._kdf_slots", slots),
            patch("fishtest.password_hash.SCRYPT_MAX_WAITERS", 0),
            patch("fishtest.password_hash.SCRYPT_SLOT_WAIT_SECONDS", 30.0),
            self.assertRaises(PasswordHashBusy),
        ):
            started = time.monotonic()
            try:
                verify_password(stored, "abc")
            finally:
                self.assertLess(time.monotonic() - started, 1.0)


if __name__ == "__main__":
    unittest.main()
