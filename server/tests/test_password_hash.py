# ruff: noqa: ANN201, D100, D101, D102, INP001, PT009, S105, S106
"""Unit tests for the stdlib scrypt password hashing helpers."""

import unittest

from fishtest.constants import SCRYPT_N, SCRYPT_P, SCRYPT_R
from fishtest.password_hash import (
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


if __name__ == "__main__":
    unittest.main()
