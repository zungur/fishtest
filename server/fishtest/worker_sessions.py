"""Worker sessions: random tokens a worker obtains with its password once per run.

Only the sha256 digest of a token is stored. A session is valid while it is
younger than the idle window (refreshed by use) and the maximum age, belongs
to the presented username, and carries the user's current
``credentials_version`` (bumped on password change). Idle records are
removed by a TTL index on ``last_seen`` (see ``utils/create_indexes.py``).
"""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from pymongo import DESCENDING
from vtjson import validate

from fishtest.constants import (
    WORKER_SESSION_IDLE_SECONDS,
    WORKER_SESSION_MAX_AGE_SECONDS,
    WORKER_SESSION_MIN_CAP,
    WORKER_SESSION_TOUCH_SECONDS,
)
from fishtest.lru_cache import LRUCache
from fishtest.schemas import worker_session_schema


def hash_session_token(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class WorkerSessionDb:
    def __init__(self, db):
        self.sessions = db["worker_sessions"]
        # token_hash -> session document. Another instance may see a logout up
        # to the expiration below late.
        self._cache = LRUCache(maxsize=20_000, expiration=30, refresh=False)

    def create(self, username, credentials_version, machine_limit):
        """Store a new session and return its raw token."""
        token = secrets.token_urlsafe(32)
        now = datetime.now(UTC)
        session = {
            "token_hash": hash_session_token(token),
            "username": username,
            "credentials_version": credentials_version,
            "created": now,
            "last_seen": now,
        }
        validate(worker_session_schema, session, "worker_session")
        self.sessions.insert_one(session)
        self._enforce_cap(username, max(2 * machine_limit, WORKER_SESSION_MIN_CAP))
        return token

    def _enforce_cap(self, username, cap):
        stale = self.sessions.find(
            {"username": username},
            {"token_hash": 1},
            sort=[("last_seen", DESCENDING)],
            skip=cap,
        )
        stale_hashes = [s["token_hash"] for s in stale]
        if stale_hashes:
            self.sessions.delete_many({"token_hash": {"$in": stale_hashes}})
            for token_hash in stale_hashes:
                self._cache.pop(token_hash, None)

    def validate(
        self,
        username,
        token,
        credentials_version,
        max_age_seconds=WORKER_SESSION_MAX_AGE_SECONDS,
    ):
        """Return True if ``token`` is a live session for ``username``.

        A session older than ``max_age_seconds`` is refused; one older than
        ``WORKER_SESSION_MAX_AGE_SECONDS`` is also removed.
        """
        if not token:
            return False
        token_hash = hash_session_token(token)
        session = self._cache.get(token_hash, refresh=False)
        if session is None:
            session = self.sessions.find_one({"token_hash": token_hash})
            if session is None:
                return False
            self._cache[token_hash] = session
        if session["username"] != username:
            return False
        if session["credentials_version"] != credentials_version:
            return False
        now = datetime.now(UTC)
        age = now - session["created"]
        if age > timedelta(seconds=WORKER_SESSION_MAX_AGE_SECONDS):
            self.delete(token)
            return False
        if age > timedelta(seconds=max_age_seconds):
            return False
        idle = now - session["last_seen"]
        if idle > timedelta(seconds=WORKER_SESSION_IDLE_SECONDS):
            return False
        if idle > timedelta(seconds=WORKER_SESSION_TOUCH_SECONDS):
            result = self.sessions.update_one(
                {"token_hash": token_hash}, {"$set": {"last_seen": now}}
            )
            if not result.matched_count:
                self._cache.pop(token_hash, None)
                return False
            self._cache[token_hash] = {**session, "last_seen": now}
        return True

    def delete(self, token):
        """End the session identified by ``token``; return True if it existed."""
        token_hash = hash_session_token(token)
        self._cache.pop(token_hash, None)
        return self.sessions.delete_one({"token_hash": token_hash}).deleted_count > 0

    def delete_for_user(self, username):
        """End every session of ``username``; return how many were removed."""
        for token_hash, session in list(self._cache.items()):
            if session["username"] == username:
                self._cache.pop(token_hash, None)
        return self.sessions.delete_many({"username": username}).deleted_count
