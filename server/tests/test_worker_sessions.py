import unittest
from datetime import UTC, datetime, timedelta

import test_support

from fishtest.constants import (
    KNOWN_LOGIN_IP_DAYS,
    PASSWORD_DAILY_FAILURE_WINDOW_SECONDS,
    WORKER_SESSION_IDLE_SECONDS,
    WORKER_SESSION_MAX_AGE_SECONDS,
    WORKER_SESSION_MIN_CAP,
    WORKER_SESSION_TOUCH_SECONDS,
)
from fishtest.worker_sessions import hash_session_token


class TestWorkerSessions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rundb = test_support.get_rundb()
        cls.sessions = cls.rundb.worker_sessions
        cls.username = "TestWorkerSessionUser"
        cls.other_username = "TestWorkerSessionOther"

    def setUp(self):
        for username in (self.username, self.other_username):
            self.sessions.delete_for_user(username)
        self.sessions._cache.clear()

    def tearDown(self):
        for username in (self.username, self.other_username):
            self.sessions.delete_for_user(username)

    def _set_last_seen(self, token, last_seen):
        self.sessions.sessions.update_one(
            {"token_hash": hash_session_token(token)},
            {"$set": {"last_seen": last_seen}},
        )
        self.sessions._cache.clear()

    def _count(self, username=None):
        return self.sessions.sessions.count_documents(
            {"username": username or self.username}
        )

    def test_create_and_validate(self):
        token = self.sessions.create(self.username, 0, 16)
        self.assertTrue(self.sessions.validate(self.username, token, 0))
        stored = self.sessions.sessions.find_one({"username": self.username})
        self.assertEqual(stored["token_hash"], hash_session_token(token))
        self.assertNotIn(token, str(stored))

    def test_tokens_are_unique(self):
        first = self.sessions.create(self.username, 0, 16)
        second = self.sessions.create(self.username, 0, 16)
        self.assertNotEqual(first, second)
        self.assertEqual(self._count(), 2)

    def test_rejects_empty_or_unknown_token(self):
        self.sessions.create(self.username, 0, 16)
        self.assertFalse(self.sessions.validate(self.username, "", 0))
        self.assertFalse(self.sessions.validate(self.username, "unknown", 0))

    def test_rejects_other_username(self):
        token = self.sessions.create(self.username, 0, 16)
        self.assertFalse(self.sessions.validate(self.other_username, token, 0))

    def test_rejects_stale_credentials_version(self):
        token = self.sessions.create(self.username, 3, 16)
        self.assertTrue(self.sessions.validate(self.username, token, 3))
        self.assertFalse(self.sessions.validate(self.username, token, 4))

    def test_rejects_idle_session(self):
        token = self.sessions.create(self.username, 0, 16)
        idle = timedelta(seconds=WORKER_SESSION_IDLE_SECONDS + 60)
        self._set_last_seen(token, datetime.now(UTC) - idle)
        self.assertFalse(self.sessions.validate(self.username, token, 0))

    def _set_created(self, token, created):
        self.sessions.sessions.update_one(
            {"token_hash": hash_session_token(token)},
            {"$set": {"created": created}},
        )
        self.sessions._cache.clear()

    def test_rejects_and_removes_session_past_max_age(self):
        token = self.sessions.create(self.username, 0, 16)
        age = timedelta(seconds=WORKER_SESSION_MAX_AGE_SECONDS + 60)
        self._set_created(token, datetime.now(UTC) - age)
        self.assertFalse(self.sessions.validate(self.username, token, 0))
        self.assertEqual(self._count(), 0)

    def test_shorter_max_age_refuses_without_removing(self):
        token = self.sessions.create(self.username, 0, 16)
        self._set_created(token, datetime.now(UTC) - timedelta(days=2))
        self.assertFalse(
            self.sessions.validate(self.username, token, 0, max_age_seconds=24 * 3600)
        )
        self.assertTrue(self.sessions.validate(self.username, token, 0))

    def test_use_refreshes_last_seen(self):
        token = self.sessions.create(self.username, 0, 16)
        old = datetime.now(UTC) - timedelta(seconds=WORKER_SESSION_TOUCH_SECONDS + 60)
        self._set_last_seen(token, old)
        self.assertTrue(self.sessions.validate(self.username, token, 0))
        stored = self.sessions.sessions.find_one(
            {"token_hash": hash_session_token(token)}
        )
        self.assertGreater(stored["last_seen"], old + timedelta(seconds=60))

    def test_recent_use_does_not_write(self):
        token = self.sessions.create(self.username, 0, 16)
        recent = datetime.now(UTC) - timedelta(seconds=5)
        self._set_last_seen(token, recent)
        self.assertTrue(self.sessions.validate(self.username, token, 0))
        stored = self.sessions.sessions.find_one(
            {"token_hash": hash_session_token(token)}
        )
        self.assertLess(abs(stored["last_seen"] - recent), timedelta(seconds=1))

    def test_refresh_detects_session_removed_elsewhere(self):
        token = self.sessions.create(self.username, 0, 16)
        old = datetime.now(UTC) - timedelta(seconds=WORKER_SESSION_TOUCH_SECONDS + 60)
        self._set_last_seen(token, old)
        # Load the stale document into the cache, then remove it behind the
        # cache's back (as another server instance would).
        self.sessions._cache[hash_session_token(token)] = (
            self.sessions.sessions.find_one({"token_hash": hash_session_token(token)})
        )
        self.sessions.sessions.delete_many({"username": self.username})
        self.assertFalse(self.sessions.validate(self.username, token, 0))
        self.assertFalse(self.sessions.validate(self.username, token, 0))

    def test_delete(self):
        token = self.sessions.create(self.username, 0, 16)
        self.assertTrue(self.sessions.validate(self.username, token, 0))
        self.assertTrue(self.sessions.delete(token))
        self.assertFalse(self.sessions.validate(self.username, token, 0))
        self.assertFalse(self.sessions.delete(token))

    def test_delete_for_user(self):
        tokens = [self.sessions.create(self.username, 0, 16) for _ in range(3)]
        other = self.sessions.create(self.other_username, 0, 16)
        for token in tokens:
            self.assertTrue(self.sessions.validate(self.username, token, 0))
        self.assertEqual(self.sessions.delete_for_user(self.username), 3)
        for token in tokens:
            self.assertFalse(self.sessions.validate(self.username, token, 0))
        self.assertTrue(self.sessions.validate(self.other_username, other, 0))

    def test_cap_evicts_least_recently_used(self):
        old = datetime.now(UTC) - timedelta(hours=1)
        oldest = [self.sessions.create(self.username, 0, 0) for _ in range(2)]
        for token in oldest:
            self._set_last_seen(token, old)
        newest = [
            self.sessions.create(self.username, 0, 0)
            for _ in range(WORKER_SESSION_MIN_CAP)
        ]
        self.assertEqual(self._count(), WORKER_SESSION_MIN_CAP)
        for token in oldest:
            self.assertFalse(self.sessions.validate(self.username, token, 0))
        for token in newest:
            self.assertTrue(self.sessions.validate(self.username, token, 0))

    def test_cap_scales_with_machine_limit(self):
        machine_limit = WORKER_SESSION_MIN_CAP
        for _ in range(2 * machine_limit + 1):
            self.sessions.create(self.username, 0, machine_limit)
        self.assertEqual(self._count(), 2 * machine_limit)

    def test_cap_is_per_user(self):
        for _ in range(WORKER_SESSION_MIN_CAP):
            self.sessions.create(self.username, 0, 0)
        self.sessions.create(self.other_username, 0, 0)
        self.assertEqual(self._count(), WORKER_SESSION_MIN_CAP)
        self.assertEqual(self._count(self.other_username), 1)


class TestKnownLoginIps(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rundb = test_support.get_rundb()
        cls.known_ips = cls.rundb.known_login_ips
        cls.username = "TestKnownIpUser"

    def setUp(self):
        self._clear()
        self.addCleanup(self._clear)

    def _clear(self):
        self.known_ips.ips.delete_many({"username": self.username})
        self.known_ips.failures.delete_many({"username": self.username})
        self.known_ips._cache.clear()

    def test_failures_are_counted_per_user(self):
        self.addCleanup(
            self.known_ips.failures.delete_many, {"username": "SomeoneElse"}
        )
        self.assertEqual(self.known_ips.recent_failures(self.username), 0)
        for _ in range(3):
            self.known_ips.count_failure(self.username)
        self.known_ips.count_failure("SomeoneElse")
        self.assertEqual(self.known_ips.recent_failures(self.username), 3)
        self.assertEqual(self.known_ips.recent_failures("SomeoneElse"), 1)

    def test_failure_window_starts_again_after_it_ends(self):
        for _ in range(3):
            self.known_ips.count_failure(self.username)
        expired = datetime.now(UTC) - timedelta(
            seconds=PASSWORD_DAILY_FAILURE_WINDOW_SECONDS + 60
        )
        self.known_ips.failures.update_one(
            {"username": self.username}, {"$set": {"since": expired}}
        )
        self.assertEqual(self.known_ips.recent_failures(self.username), 0)
        self.known_ips.count_failure(self.username)
        self.assertEqual(self.known_ips.recent_failures(self.username), 1)

    def test_forget_user_clears_failures(self):
        self.known_ips.count_failure(self.username)
        self.known_ips.forget_user(self.username)
        self.assertEqual(self.known_ips.recent_failures(self.username), 0)

    def test_remembered_ip_is_known_for_that_user_only(self):
        self.assertFalse(self.known_ips.is_known(self.username, "192.0.2.1"))
        self.known_ips.remember(self.username, "192.0.2.1")
        self.assertTrue(self.known_ips.is_known(self.username, "192.0.2.1"))
        self.assertFalse(self.known_ips.is_known(self.username, "192.0.2.2"))
        self.assertFalse(self.known_ips.is_known("SomeoneElse", "192.0.2.1"))
        self.known_ips._cache.clear()
        self.assertTrue(self.known_ips.is_known(self.username, "192.0.2.1"))

    def test_forget_user(self):
        self.addCleanup(self.known_ips.ips.delete_many, {"username": "SomeoneElse"})
        self.known_ips.remember(self.username, "192.0.2.1")
        self.known_ips.remember(self.username, "192.0.2.2")
        self.known_ips.remember("SomeoneElse", "192.0.2.1")
        self.assertEqual(self.known_ips.forget_user(self.username), 2)
        self.assertFalse(self.known_ips.is_known(self.username, "192.0.2.1"))
        self.assertFalse(self.known_ips.is_known(self.username, "192.0.2.2"))
        self.assertTrue(self.known_ips.is_known("SomeoneElse", "192.0.2.1"))

    def test_missing_ip_is_never_known(self):
        self.known_ips.remember(self.username, None)
        self.assertFalse(self.known_ips.is_known(self.username, None))
        self.assertEqual(
            self.known_ips.ips.count_documents({"username": self.username}), 0
        )

    def test_old_login_expires(self):
        self.known_ips.ips.insert_one(
            {
                "username": self.username,
                "ip": "192.0.2.1",
                "last_success": datetime.now(UTC)
                - timedelta(days=KNOWN_LOGIN_IP_DAYS + 1),
            }
        )
        self.assertFalse(self.known_ips.is_known(self.username, "192.0.2.1"))

    def test_remember_writes_once_per_refresh_interval(self):
        self.known_ips.remember(self.username, "192.0.2.1")
        first = self.known_ips.ips.find_one({"username": self.username})
        self.known_ips.remember(self.username, "192.0.2.1")
        second = self.known_ips.ips.find_one({"username": self.username})
        self.assertEqual(first["last_success"], second["last_success"])
        self.assertEqual(
            self.known_ips.ips.count_documents({"username": self.username}), 1
        )


if __name__ == "__main__":
    unittest.main()
