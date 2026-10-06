# ruff: noqa: ANN201, D100, D101, D102, INP001, PT009
"""Unit tests for background delivery in fishtest.emailer."""

import threading
import unittest

from fishtest import emailer
from fishtest.emailer import EmailSender


class _CapturingSender(EmailSender):
    def __init__(self):
        super().__init__(host="smtp.example.org", from_email="noreply@example.org")
        self.sent = []

    def send(self, to_email, subject, body):
        self.sent.append((to_email, subject, body))


class BackgroundEmailTests(unittest.TestCase):
    def setUp(self):
        self.sender = _CapturingSender()
        self.addCleanup(self.sender.close, 5)

    def test_sends_composed_message(self):
        self.assertTrue(
            self.sender.send_in_background(lambda: [("a@example.org", "subj", "body")])
        )
        self.assertTrue(self.sender.wait_idle(timeout=5))
        self.assertEqual(self.sender.sent, [("a@example.org", "subj", "body")])

    def test_compose_returning_no_messages_sends_nothing(self):
        self.assertTrue(self.sender.send_in_background(list))
        self.assertTrue(self.sender.wait_idle(timeout=5))
        self.assertEqual(self.sender.sent, [])

    def test_failing_job_does_not_stop_the_thread(self):
        def broken():
            raise RuntimeError("smtp down")

        with self.assertLogs("fishtest.emailer", level="ERROR"):
            self.sender.send_in_background(broken)
            self.assertTrue(self.sender.wait_idle(timeout=5))
        self.sender.send_in_background(lambda: [("b@example.org", "s", "b")])
        self.assertTrue(self.sender.wait_idle(timeout=5))
        self.assertEqual(len(self.sender.sent), 1)

    def test_failed_delivery_does_not_skip_other_messages(self):
        sent = self.sender.sent

        def send(to_email, subject, body):
            if to_email == "bad@example.org":
                raise OSError("rejected")
            sent.append(to_email)

        self.sender.send = send
        with self.assertLogs("fishtest.emailer", level="ERROR"):
            self.sender.send_in_background(
                lambda: [("bad@example.org", "s", "b"), ("good@example.org", "s", "b")]
            )
            self.assertTrue(self.sender.wait_idle(timeout=5))
        self.assertEqual(sent, ["good@example.org"])

    def test_full_queue_rejects_new_jobs(self):
        release = threading.Event()
        self.addCleanup(release.set)

        def blocking():
            release.wait(5)
            return []

        self.sender.send_in_background(blocking)
        accepted = [
            self.sender.send_in_background(list)
            for _ in range(emailer.BACKGROUND_QUEUE_SIZE + 1)
        ]
        self.assertIn(False, accepted)
        release.set()
        self.assertTrue(self.sender.wait_idle(timeout=5))

    def test_close_drains_queue_and_rejects_later_jobs(self):
        self.sender.send_in_background(lambda: [("c@example.org", "s", "b")])
        self.sender.close(timeout=5)
        self.assertEqual(len(self.sender.sent), 1)
        self.assertFalse(self.sender.send_in_background(list))


if __name__ == "__main__":
    unittest.main()
