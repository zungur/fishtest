# ruff: noqa: ANN201, D100, D101, D102, INP001, PT009
"""Tests for the unique email index and the duplicate-email report."""

import contextlib
import importlib.util
import io
import unittest
from pathlib import Path

import test_support
from pymongo.errors import DuplicateKeyError

UTILS_DIR = Path(__file__).resolve().parents[1] / "utils"


def _load_util(name):
    spec = importlib.util.spec_from_file_location(name, UTILS_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestEmailIndex(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rundb = test_support.get_rundb()
        cls.scratch = cls.rundb.conn["fishtest_tests_email_index"]
        cls.create_indexes = _load_util("create_indexes")
        cls.addClassCleanup(cls.create_indexes.conn.close)
        cls.find_duplicate_emails = _load_util("find_duplicate_emails")

    def setUp(self):
        self.rundb.conn.drop_database(self.scratch.name)
        self.addCleanup(self.rundb.conn.drop_database, self.scratch.name)
        self.create_indexes.db = self.scratch

    def _insert(self, username, email):
        self.scratch["users"].insert_one({"username": username, "email": email})

    def test_report_groups_addresses_ignoring_case(self):
        self._insert("alice", "Shared@Example.org")
        self._insert("bob", "shared@example.org")
        self._insert("carol", "carol@example.org")
        duplicates = self.find_duplicate_emails.find_duplicate_emails(
            self.scratch["users"]
        )
        self.assertEqual(len(duplicates), 1)
        self.assertEqual(
            sorted(a["username"] for a in duplicates[0]["accounts"]),
            ["alice", "bob"],
        )

    def test_index_creation_reports_duplicates_without_failing(self):
        self._insert("alice", "Shared@Example.org")
        self._insert("bob", "shared@example.org")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.create_indexes.create_users_indexes()
        self.assertIn("find_duplicate_emails.py", output.getvalue())
        self.assertNotIn(
            "users_email_unique", self.scratch["users"].index_information()
        )
        self.assertIn("password_reset_token", self.scratch["users"].index_information())

    def test_unique_index_rejects_case_variants(self):
        self._insert("alice", "Shared@Example.org")
        self.create_indexes.create_users_indexes()
        self.assertIn("users_email_unique", self.scratch["users"].index_information())
        with self.assertRaises(DuplicateKeyError):
            self._insert("bob", "shared@example.ORG")


if __name__ == "__main__":
    unittest.main()
