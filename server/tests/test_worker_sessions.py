import unittest
from datetime import UTC, datetime, timedelta

import test_support

from fishtest.constants import (
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
