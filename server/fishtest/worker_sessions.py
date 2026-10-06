"""Worker sessions: random tokens a worker obtains with its password once per run.

Only the sha256 digest of a token is stored. A session is valid while it is
younger than the idle window (refreshed by use) and the maximum age, belongs
to the presented username, and carries the user's current
``credentials_version`` (bumped on password change or reset). Idle records are
removed by a TTL index on ``last_seen`` (see ``utils/create_indexes.py``).

``KnownLoginIpDb`` remembers which clients (see
``fishtest.password_throttle.client_key``) logged in successfully with a
user's password, on the worker API or the website, so a password-guessing
attack on that username does not slow down or stop the user's own machines.
It also counts the failed password checks of each user over a day, for all
server processes.
"""

import hashlib
import secrets
import time
from datetime import UTC, datetime, timedelta

from pymongo import DESCENDING
from pymongo.errors import DuplicateKeyError
from vtjson import validate

from fishtest.constants import (
    KNOWN_LOGIN_IP_DAYS,
    KNOWN_LOGIN_IP_REFRESH_SECONDS,
    PASSWORD_DAILY_FAILURE_WINDOW_SECONDS,
    WORKER_SESSION_IDLE_SECONDS,
    WORKER_SESSION_MAX_AGE_SECONDS,
    WORKER_SESSION_MIN_CAP,
    WORKER_SESSION_TOUCH_SECONDS,
)
from fishtest.lru_cache import LRUCache
from fishtest.schemas import (
    known_login_ip_schema,
    password_failure_schema,
    worker_session_schema,
)

# How long "this IP is not known for this user" is cached. Another instance
# that records the IP is seen at most this late.
_UNKNOWN_IP_CACHE_SECONDS = 60


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


class KnownLoginIpDb:
    def __init__(self, db):
        self.ips = db["known_login_ips"]
        self.failures = db["password_failures"]
        # (username, ip) -> (last_success or None, monotonic time of lookup).
        self._cache = LRUCache(
            maxsize=50_000, expiration=KNOWN_LOGIN_IP_REFRESH_SECONDS, refresh=False
        )

    def is_known(self, username, ip):
        """Return True if ``ip`` logged in as ``username`` recently."""
        if not ip:
            return False
        key = (username, ip)
        entry = self._cache.get(key, refresh=False)
        if entry is None or (
            entry[0] is None and time.monotonic() - entry[1] > _UNKNOWN_IP_CACHE_SECONDS
        ):
            doc = self.ips.find_one(
                {"username": username, "ip": ip}, {"last_success": 1}
            )
            entry = (doc["last_success"] if doc else None, time.monotonic())
            self._cache[key] = entry
        last_success = entry[0]
        return last_success is not None and datetime.now(
            UTC
        ) - last_success < timedelta(days=KNOWN_LOGIN_IP_DAYS)

    def remember(self, username, ip):
        """Record a successful password login of ``username`` from ``ip``."""
        if not ip:
            return
        key = (username, ip)
        now = datetime.now(UTC)
        entry = self._cache.get(key, refresh=False)
        if (
            entry is not None
            and entry[0] is not None
            and now - entry[0] < timedelta(seconds=KNOWN_LOGIN_IP_REFRESH_SECONDS)
        ):
            return
        record = {"username": username, "ip": ip, "last_success": now}
        validate(known_login_ip_schema, record, "known_login_ip")
        self.ips.update_one(
            {"username": username, "ip": ip},
            {"$set": {"last_success": now}},
            upsert=True,
        )
        self._cache[key] = (now, time.monotonic())

    def forget_user(self, username):
        """Forget every client and the failure count of ``username``.

        Returns how many clients were removed. Other instances may still treat
        a forgotten client as known for up to KNOWN_LOGIN_IP_REFRESH_SECONDS.
        """
        for key, _ in list(self._cache.items()):
            if key[0] == username:
                self._cache.pop(key, None)
        self.failures.delete_many({"username": username})
        return self.ips.delete_many({"username": username}).deleted_count

    def recent_failures(self, username):
        """Return the failed password checks of ``username`` in the current window."""
        start = datetime.now(UTC) - timedelta(
            seconds=PASSWORD_DAILY_FAILURE_WINDOW_SECONDS
        )
        doc = self.failures.find_one(
            {"username": username, "since": {"$gt": start}}, {"count": 1}
        )
        return doc["count"] if doc else 0

    def count_failure(self, username):
        """Count a failed password check of ``username``."""
        now = datetime.now(UTC)
        start = now - timedelta(seconds=PASSWORD_DAILY_FAILURE_WINDOW_SECONDS)
        current = {"username": username, "since": {"$gt": start}}
        if self.failures.update_one(current, {"$inc": {"count": 1}}).matched_count:
            return
        record = {"username": username, "count": 1, "since": now}
        validate(password_failure_schema, record, "password_failure")
        try:
            # Starts a new window, replacing an expired one.
            self.failures.update_one(
                {"username": username}, {"$set": record}, upsert=True
            )
        except DuplicateKeyError:
            # Another process started the window at the same time.
            self.failures.update_one(current, {"$inc": {"count": 1}})
