# ruff: noqa: ANN201, D100, D101, D102, INP001, PT009, S105, S106
"""Tests for the plaintext-password migration script."""

import importlib.util
import unittest
from pathlib import Path

import test_support

from fishtest.password_hash import is_hashed, verify_password

UTILS_DIR = Path(__file__).resolve().parents[1] / "utils"


def _load_util(name):
    spec = importlib.util.spec_from_file_location(name, UTILS_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestHashPasswords(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rundb = test_support.get_rundb()
        cls.script = _load_util("hash_passwords")
        cls.usernames = [f"TestPlaintextUser{i}" for i in range(6)]

    def setUp(self):
        self._delete_users()
        self.addCleanup(self._delete_users)
        for i, username in enumerate(self.usernames):
            self.rundb.userdb.users.insert_one(
                {"username": username, "password": f"plain-pw-{i}"}
            )

    def _delete_users(self):
        self.rundb.userdb.users.delete_many({"username": {"$in": self.usernames}})
        self.rundb.userdb.clear_cache()

    def _stored(self, username):
        return self.rundb.userdb.users.find_one({"username": username})["password"]

    def test_hashes_plaintext_passwords_once(self):
        with self.assertLogs(self.script.logger, level="INFO"):
            updated = self.script.hash_passwords(self.rundb, threads=3)
        self.assertGreaterEqual(updated, len(self.usernames))
        for i, username in enumerate(self.usernames):
            stored = self._stored(username)
            self.assertTrue(is_hashed(stored))
            self.assertTrue(verify_password(stored, f"plain-pw-{i}"))
        with self.assertLogs(self.script.logger, level="INFO"):
            self.assertEqual(self.script.hash_passwords(self.rundb), 0)

    def test_password_changed_meanwhile_is_kept(self):
        users = self.rundb.userdb.users
        user = users.find_one({"username": self.usernames[0]})
        users.update_one({"_id": user["_id"]}, {"$set": {"password": "changed"}})
        self.assertFalse(self.script._hash_user(users, user))
        self.assertEqual(self._stored(self.usernames[0]), "changed")


if __name__ == "__main__":
    unittest.main()
