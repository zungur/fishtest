# ruff: noqa: ANN201, D100, D101, D102, INP001, PT009, S105, S106
"""Unit tests for fishtest.password_throttle."""

import threading
import time
import unittest
from unittest.mock import patch

from fishtest import password_throttle
from fishtest.constants import (
    PASSWORD_FAILURE_WINDOW_SECONDS,
    PASSWORD_GLOBAL_FAILURE_LIMIT,
    PASSWORD_IP_FAILURE_LIMIT,
    PASSWORD_PAIR_FAILURE_LIMIT,
    PASSWORD_USER_DAILY_FAILURE_LIMIT,
    PASSWORD_USER_FAILURE_LIMIT,
)
from fishtest.password_throttle import PasswordThrottled, _PasswordQueue, client_key


class _StubKnownIps:
    def __init__(self, known=()):
        self.known = set(known)
        self.remembered = []
        self.failures = {}

    def is_known(self, username, ip):
        return (username, ip) in self.known

    def remember(self, username, ip):
        self.remembered.append((username, ip))

    def recent_failures(self, username):
        return self.failures.get(username, 0)

    def count_failure(self, username):
        self.failures[username] = self.failures.get(username, 0) + 1


class _RecordingQueue:
    def __init__(self, queue):
        self.queue = queue
        self.turns = 0

    def turn(self):
        self.turns += 1
        return self.queue.turn()


class TestPasswordThrottle(unittest.TestCase):
    def setUp(self):
        password_throttle.reset()
        self.addCleanup(password_throttle.reset)
        self.calls = []
        self.known_ips = _StubKnownIps()
        self.queue = _RecordingQueue(_PasswordQueue(0, 8, 1))
        patcher = patch.object(password_throttle, "_queue", self.queue)
        patcher.start()
        self.addCleanup(patcher.stop)

    def check(self, username, password, ip):
        def attempt():
            self.calls.append((username, password))
            return password == "right"

        return password_throttle.check(username, ip, self.known_ips, attempt)

    def fail_many(self, count, username=None, ip=None):
        for attempt in range(count):
            self.assertFalse(
                self.check(
                    username or f"user{attempt}",
                    f"wrong-{attempt}",
                    ip or f"10.{attempt // 250}.{attempt % 250}.1",
                )
            )

    def test_pair_limit_rejects_only_the_failing_client(self):
        self.fail_many(PASSWORD_PAIR_FAILURE_LIMIT, "alice", "10.0.0.1")
        calls = len(self.calls)
        with self.assertRaises(PasswordThrottled):
            self.check("alice", "right", "10.0.0.1")
        self.assertEqual(len(self.calls), calls)
        self.assertTrue(self.check("alice", "right", "10.0.0.2"))
        self.assertTrue(self.check("bob", "right", "10.0.0.1"))

    def test_ip_limit_rejects_client_for_every_username(self):
        self.fail_many(PASSWORD_IP_FAILURE_LIMIT, ip="10.0.0.1")
        with self.assertRaises(PasswordThrottled):
            self.check("carol", "right", "10.0.0.1")
        self.assertTrue(self.check("carol", "right", "10.0.0.2"))

    def test_ipv6_addresses_count_per_network(self):
        self.fail_many(PASSWORD_PAIR_FAILURE_LIMIT, "alice", "2001:db8:1:2::1")
        with self.assertRaises(PasswordThrottled):
            self.check("alice", "right", "2001:db8:1:2:ffff::9")
        self.assertTrue(self.check("alice", "right", "2001:db8:1:3::1"))

    def test_client_key(self):
        self.assertEqual(client_key("192.0.2.7"), "192.0.2.7")
        self.assertEqual(client_key("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::/64")
        self.assertEqual(client_key("::ffff:192.0.2.7"), "192.0.2.7")
        self.assertEqual(client_key("testclient"), "testclient")
        self.assertIsNone(client_key(None))

    def test_username_under_attack_queues_unknown_clients_only(self):
        self.known_ips.known.add(("alice", "10.0.0.99"))
        self.fail_many(PASSWORD_USER_FAILURE_LIMIT, "alice")
        self.assertEqual(self.queue.turns, 0)
        self.assertTrue(self.check("alice", "right", "10.0.0.99"))
        self.assertEqual(self.queue.turns, 0)
        self.assertTrue(self.check("alice", "right", "10.0.0.50"))
        self.assertEqual(self.queue.turns, 1)
        self.assertTrue(self.check("bob", "right", "10.0.0.51"))
        self.assertEqual(self.queue.turns, 1)

    def test_global_budget_queues_unknown_clients_for_every_username(self):
        self.known_ips.known.add(("bob", "10.200.0.1"))
        self.fail_many(PASSWORD_GLOBAL_FAILURE_LIMIT)
        self.assertEqual(self.queue.turns, 0)
        self.assertTrue(self.check("bob", "right", "10.200.0.1"))
        self.assertEqual(self.queue.turns, 0)
        self.assertTrue(self.check("dave", "right", "10.200.0.2"))
        self.assertEqual(self.queue.turns, 1)

    def test_full_queue_rejects_instead_of_checking(self):
        self.fail_many(PASSWORD_USER_FAILURE_LIMIT, "alice")
        calls = len(self.calls)
        with (
            patch.object(self.queue, "turn", side_effect=PasswordThrottled),
            self.assertRaises(PasswordThrottled),
        ):
            self.check("alice", "right", "10.0.0.50")
        self.assertEqual(len(self.calls), calls)

    def test_daily_limit_rejects_unknown_clients_only(self):
        self.known_ips.known.add(("alice", "10.0.0.99"))
        self.known_ips.failures["alice"] = PASSWORD_USER_DAILY_FAILURE_LIMIT
        calls = len(self.calls)
        with self.assertRaises(PasswordThrottled):
            self.check("alice", "right", "10.0.0.50")
        self.assertEqual(len(self.calls), calls)
        self.assertTrue(self.check("alice", "right", "10.0.0.99"))
        self.assertTrue(self.check("bob", "right", "10.0.0.50"))

    def test_failures_count_towards_the_daily_limit(self):
        self.fail_many(3, "alice", "10.0.0.1")
        self.assertTrue(self.check("alice", "right", "10.0.0.1"))
        self.assertEqual(self.known_ips.failures, {"alice": 3})

    def test_success_remembers_client_and_failure_does_not(self):
        self.assertFalse(self.check("alice", "wrong", "2001:db8::1"))
        self.assertEqual(self.known_ips.remembered, [])
        self.assertTrue(self.check("alice", "right", "2001:db8::1"))
        self.assertEqual(self.known_ips.remembered, [("alice", "2001:db8::/64")])

    def test_window_starts_at_first_failure(self):
        now = [1000.0]
        with patch.object(password_throttle.time, "monotonic", lambda: now[0]):
            for offset in (0, 30, PASSWORD_FAILURE_WINDOW_SECONDS - 1):
                now[0] = 1000.0 + offset
                password_throttle._count_failure("global")
            self.assertEqual(password_throttle._failure_count("global"), 3)
            now[0] = 1000.0 + PASSWORD_FAILURE_WINDOW_SECONDS
            self.assertEqual(password_throttle._failure_count("global"), 0)
            password_throttle._count_failure("global")
            self.assertEqual(password_throttle._failure_count("global"), 1)


class TestPasswordQueue(unittest.TestCase):
    def _wait_for_tickets(self, queue, count):
        deadline = time.monotonic() + 5
        while len(queue._tickets) < count:
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.001)

    def test_runs_in_arrival_order_paced_apart(self):
        interval = 0.05
        queue = _PasswordQueue(interval, 8, 5)
        starts = []

        def worker(name):
            with queue.turn():
                starts.append((name, time.monotonic()))

        threads = []
        with queue.turn():
            starts.append(("first", time.monotonic()))
            for count, name in enumerate(("second", "third"), start=2):
                thread = threading.Thread(target=worker, args=(name,))
                thread.start()
                threads.append(thread)
                self._wait_for_tickets(queue, count)
        for thread in threads:
            thread.join(5)
        self.assertEqual([name for name, _ in starts], ["first", "second", "third"])
        for (_, earlier), (_, later) in zip(starts, starts[1:], strict=False):
            self.assertGreaterEqual(later - earlier, interval * 0.9)

    def test_rejects_when_full(self):
        queue = _PasswordQueue(0, 2, 5)
        release = threading.Event()

        def worker():
            with queue.turn():
                release.wait(5)

        thread = threading.Thread(target=worker)
        with queue.turn():
            thread.start()
            self._wait_for_tickets(queue, 2)
            with self.assertRaises(PasswordThrottled), queue.turn():
                pass
            release.set()
        thread.join(5)
        self.assertEqual(len(queue._tickets), 0)

    def test_gives_up_after_max_wait(self):
        queue = _PasswordQueue(0, 8, 0.05)
        outcome = []

        def worker():
            try:
                with queue.turn():
                    outcome.append("ran")
            except PasswordThrottled:
                outcome.append("throttled")

        with queue.turn():
            thread = threading.Thread(target=worker)
            thread.start()
            thread.join(5)
            self.assertEqual(outcome, ["throttled"])
            self.assertEqual(len(queue._tickets), 1)
        self.assertEqual(len(queue._tickets), 0)
        with queue.turn():
            pass


if __name__ == "__main__":
    unittest.main()
