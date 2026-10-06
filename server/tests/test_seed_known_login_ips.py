# ruff: noqa: ANN201, D100, D101, D102, INP001, PT009
"""Tests for the known-client seeding script."""

import importlib.util
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

import test_support

from fishtest.constants import KNOWN_LOGIN_IP_DAYS

UTILS_DIR = Path(__file__).resolve().parents[1] / "utils"


def _load_util(name):
    spec = importlib.util.spec_from_file_location(name, UTILS_DIR / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _task(username, remote_addr, last_updated):
    return {
        "last_updated": last_updated,
        "worker_info": {"username": username, "remote_addr": remote_addr},
    }


class TestSeedKnownLoginIps(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rundb = test_support.get_rundb()
        cls.script = _load_util("seed_known_login_ips")
        cls.usernames = ["TestSeedUserA", "TestSeedUserB"]

    def setUp(self):
        self._clear()
        self.addCleanup(self._clear)

    def _clear(self):
        self.rundb.runs.delete_many({"_seed_test": True})
        for username in self.usernames:
            self.rundb.known_login_ips.forget_user(username)
        self.rundb.known_login_ips._cache.clear()

    def _insert_run(self, *, finished, last_updated, tasks):
        self.rundb.runs.insert_one(
            {
                "_seed_test": True,
                "finished": finished,
                "last_updated": last_updated,
                "tasks": tasks,
            }
        )

    def test_records_recent_task_clients(self):
        now = datetime.now(UTC)
        old = now - timedelta(days=KNOWN_LOGIN_IP_DAYS + 1)
        user_a, user_b = self.usernames
        self._insert_run(
            finished=False,
            last_updated=now,
            tasks=[
                _task(user_a, "192.0.2.1", now - timedelta(hours=1)),
                _task(user_a, "192.0.2.1", now - timedelta(hours=2)),
                _task(user_b, "2001:db8:1:2::7", now),
                _task(user_b, "192.0.2.9", old),
            ],
        )
        self._insert_run(
            finished=True,
            last_updated=now - timedelta(days=1),
            tasks=[_task(user_b, "192.0.2.3", now - timedelta(days=1))],
        )
        self._insert_run(
            finished=True,
            last_updated=old,
            tasks=[_task(user_a, "192.0.2.4", old)],
        )

        self.assertGreaterEqual(self.script.seed_known_login_ips(self.rundb), 3)
        known_ips = self.rundb.known_login_ips
        self.assertTrue(known_ips.is_known(user_a, "192.0.2.1"))
        self.assertTrue(known_ips.is_known(user_b, "2001:db8:1:2::/64"))
        self.assertTrue(known_ips.is_known(user_b, "192.0.2.3"))
        self.assertFalse(known_ips.is_known(user_b, "192.0.2.9"))
        self.assertFalse(known_ips.is_known(user_a, "192.0.2.4"))
        self.assertFalse(known_ips.is_known(user_b, "192.0.2.1"))

    def test_keeps_a_later_login(self):
        now = datetime.now(UTC)
        user_a = self.usernames[0]
        self.rundb.known_login_ips.remember(user_a, "192.0.2.1")
        self._insert_run(
            finished=False,
            last_updated=now,
            tasks=[_task(user_a, "192.0.2.1", now - timedelta(days=3))],
        )
        self.script.seed_known_login_ips(self.rundb)
        stored = self.rundb.known_login_ips.ips.find_one({"username": user_a})
        self.assertGreater(stored["last_success"], now - timedelta(minutes=1))


if __name__ == "__main__":
    unittest.main()
