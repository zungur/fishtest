"""Limit password guessing without letting anyone lock out another user's machines.

Every password check (worker API, web login, profile changes) goes through
``check``. Failures are counted per (username, client), per client, per
username and in total (see the ``PASSWORD_*`` constants). Too many failures
from one client reject that client. Too many failures for a username, or in
total, only make checks from clients not known for that username wait in a
paced queue, so the KDF work an attacker can cause stays bounded while the
user's own machines keep logging in. Too many failures for a username in a
day reject clients not known for that username.

The short-window counts are kept in memory, per process; the daily counts are
kept by ``known_ips`` (in MongoDB).
"""

import collections
import contextlib
import ipaddress
import threading
import time

from fishtest.constants import (
    PASSWORD_FAILURE_WINDOW_SECONDS,
    PASSWORD_GLOBAL_FAILURE_LIMIT,
    PASSWORD_IP_FAILURE_LIMIT,
    PASSWORD_IPV6_PREFIX,
    PASSWORD_PAIR_FAILURE_LIMIT,
    PASSWORD_QUEUE_INTERVAL_SECONDS,
    PASSWORD_QUEUE_MAX_WAIT_SECONDS,
    PASSWORD_QUEUE_MAX_WAITERS,
    PASSWORD_USER_DAILY_FAILURE_LIMIT,
    PASSWORD_USER_FAILURE_LIMIT,
)
from fishtest.lru_cache import LRUCache


class PasswordThrottled(Exception):  # noqa: N818
    """The password was not checked because of too many recent failures."""


class _PasswordQueue:
    """Run password checks one at a time, in arrival order, paced apart.

    A check starts at most once per ``interval``. At most ``max_waiters``
    requests (including the one being checked) are in the queue, since each
    holds a server thread; a request that would exceed that, or that waits
    longer than ``max_wait``, raises ``PasswordThrottled``.
    """

    def __init__(self, interval, max_waiters, max_wait):
        self._interval = interval
        self._max_waiters = max_waiters
        self._max_wait = max_wait
        self._cond = threading.Condition()
        self._tickets = collections.deque()
        self._next_start = 0.0

    @contextlib.contextmanager
    def turn(self):
        ticket = object()
        with self._cond:
            if len(self._tickets) >= self._max_waiters:
                raise PasswordThrottled
            self._tickets.append(ticket)
            deadline = time.monotonic() + self._max_wait
            while True:
                now = time.monotonic()
                first = self._tickets[0] is ticket
                if first and now >= self._next_start:
                    break
                if now >= deadline:
                    self._tickets.remove(ticket)
                    self._cond.notify_all()
                    raise PasswordThrottled
                wake = min(deadline, self._next_start) if first else deadline
                self._cond.wait(wake - now)
            self._next_start = now + self._interval
        try:
            yield
        finally:
            with self._cond:
                self._tickets.popleft()
                self._cond.notify_all()


# Failure counters: key -> (count, monotonic time of the window's first
# failure). Keys are "global", "user:<name>", "ip:<client>" and
# "user_ip:<name>:<client>" (usernames cannot contain ":").
_failures = LRUCache(
    maxsize=50_000,
    expiration=PASSWORD_FAILURE_WINDOW_SECONDS,
    refresh=False,
)
_queue = _PasswordQueue(
    PASSWORD_QUEUE_INTERVAL_SECONDS,
    PASSWORD_QUEUE_MAX_WAITERS,
    PASSWORD_QUEUE_MAX_WAIT_SECONDS,
)
_GLOBAL_KEY = "global"


def client_key(remote_addr):
    """Return the client that ``remote_addr`` counts as.

    IPv6 addresses count per /64 network, since one host can usually pick
    any address in it. Anything that does not parse as an IP is used as is.
    """
    if not remote_addr:
        return remote_addr
    try:
        ip = ipaddress.ip_address(remote_addr)
    except ValueError:
        return remote_addr
    if ip.version == 6:
        if ip.ipv4_mapped is not None:
            return str(ip.ipv4_mapped)
        return str(ipaddress.IPv6Network((ip, PASSWORD_IPV6_PREFIX), strict=False))
    return str(ip)


def _failure_count(key):
    entry = _failures.get(key, None, refresh=False)
    if entry is None:
        return 0
    count, started = entry
    if time.monotonic() - started >= PASSWORD_FAILURE_WINDOW_SECONDS:
        return 0
    return count


def _count_failure(key):
    now = time.monotonic()
    entry = _failures.get(key, None, refresh=False)
    if entry is None or now - entry[1] >= PASSWORD_FAILURE_WINDOW_SECONDS:
        _failures[key] = (1, now)
    else:
        _failures[key] = (entry[0] + 1, entry[1])


def check(username, remote_addr, known_ips, attempt):
    """Run ``attempt()`` (a password check returning a bool) under the limits.

    Raises ``PasswordThrottled`` instead of running ``attempt`` when the
    client has failed too often, when the username has failed too often today
    and the client is not known for it, or when it has to wait in the queue
    and the queue is full or the wait runs out. ``known_ips`` (or None)
    provides ``is_known(username, client)``, ``remember(username, client)``,
    ``recent_failures(username)`` and ``count_failure(username)``.
    """
    client = client_key(remote_addr)
    source_limits = []
    if client:
        source_limits = [
            (f"ip:{client}", PASSWORD_IP_FAILURE_LIMIT),
            (f"user_ip:{username}:{client}", PASSWORD_PAIR_FAILURE_LIMIT),
        ]
    for key, limit in source_limits:
        if _failure_count(key) >= limit:
            print(f"Password check rejected ({key})", flush=True)
            raise PasswordThrottled

    known = known_ips is not None and known_ips.is_known(username, client)
    if (
        not known
        and known_ips is not None
        and known_ips.recent_failures(username) >= PASSWORD_USER_DAILY_FAILURE_LIMIT
    ):
        print(f"Password check rejected (daily:{username}, {client})", flush=True)
        raise PasswordThrottled

    user_key = f"user:{username}"
    under_attack = (
        _failure_count(user_key) >= PASSWORD_USER_FAILURE_LIMIT
        or _failure_count(_GLOBAL_KEY) >= PASSWORD_GLOBAL_FAILURE_LIMIT
    )
    if under_attack and not known:
        print(f"Password check queued ({user_key}, {client})", flush=True)
        with _queue.turn():
            ok = attempt()
    else:
        ok = attempt()

    if ok:
        if known_ips is not None:
            known_ips.remember(username, client)
    else:
        with _failures.lock:
            for key in [_GLOBAL_KEY, user_key] + [k for k, _ in source_limits]:
                _count_failure(key)
        if known_ips is not None:
            known_ips.count_failure(username)
    return ok


def reset():
    """Forget all failure counts (for tests)."""
    _failures.clear()
