"""Test worker setup, downloads, and command-line behavior."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from configparser import ConfigParser
from pathlib import Path

import games
import updater
import worker


class WorkerTest(unittest.TestCase):
    def setUp(self):
        self.worker_dir = Path(__file__).resolve().parents[1]
        self.tempdir_obj = tempfile.TemporaryDirectory()
        self.tempdir = Path(self.tempdir_obj.name)
        (self.tempdir / "testing").mkdir()

    def tearDown(self):
        try:
            self.tempdir_obj.cleanup()
        except PermissionError as e:
            if os.name == "nt":
                shutil.rmtree(self.tempdir, ignore_errors=True)
            else:
                raise e

    def test_item_download(self):
        blob = None
        try:
            blob = games.download_from_github("README.md")
        except Exception:
            pass
        self.assertIsNotNone(blob)

    def test_get_worker_arch(self):
        arch = worker.get_worker_arch(self.worker_dir)
        self.assertNotEqual(arch, "unknown")

    def test_config_setup(self):
        sys.argv = [sys.argv[0], "user", "pass", "--no_validation"]
        worker.CONFIGFILE = str(self.tempdir / "foo.txt")
        worker.setup_parameters(self.tempdir)
        config = ConfigParser(inline_comment_prefixes=";", interpolation=None)
        config.read(worker.CONFIGFILE)
        self.assertTrue(config.has_section("login"))
        self.assertTrue(config.has_section("parameters"))
        self.assertTrue(config.has_option("login", "username"))
        self.assertTrue(config.has_option("login", "password"))
        self.assertFalse(config.has_option("login", "session_token"))
        self.assertTrue(config.has_option("parameters", "host"))
        self.assertTrue(config.has_option("parameters", "port"))
        self.assertTrue(config.has_option("parameters", "concurrency"))

    def test_config_setup_ignores_session_token_option(self):
        worker.CONFIGFILE = str(self.tempdir / "foo.txt")
        Path(worker.CONFIGFILE).write_text(
            "[login]\nusername = user\npassword = pass\nsession_token = stale\n"
        )
        sys.argv = [sys.argv[0], "--no_validation"]
        options = worker.setup_parameters(self.tempdir)
        self.assertEqual(
            options.auth,
            {"username": "user", "password": "pass", "session_token": ""},
        )
        config = ConfigParser(inline_comment_prefixes=";", interpolation=None)
        config.read(worker.CONFIGFILE)
        self.assertEqual(config.get("login", "password"), "pass")
        self.assertFalse(config.has_option("login", "session_token"))

    def _verify_credentials(self, replies):
        calls = []
        sleeps = []

        def fake_request(url, payload, quiet=False):  # noqa: ARG001
            calls.append((url, dict(payload)))
            return replies[len(calls) - 1]

        with unittest.mock.patch(
            "worker.send_api_post_request", side_effect=fake_request
        ), unittest.mock.patch("worker.time.sleep", side_effect=sleeps.append):
            ret = worker.verify_credentials("https://example.com", "user", "pw", True)
        return ret, calls, sleeps

    def test_verify_credentials_logs_in_for_a_session(self):
        ret, calls, _ = self._verify_credentials(
            [{"version": worker.WORKER_VERSION, "session_token": "tok"}]
        )
        self.assertEqual(ret, "tok")
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][0].endswith("/api/request_version"))
        self.assertEqual(calls[0][1]["password"], "pw")
        self.assertIs(calls[0][1]["new_session"], True)

    def test_verify_credentials_retries_when_busy(self):
        busy = {"error": "/api/request_version: Server busy, try again later."}
        ret, calls, sleeps = self._verify_credentials(
            [busy, busy, {"version": worker.WORKER_VERSION, "session_token": "tok"}]
        )
        self.assertEqual(ret, "tok")
        self.assertEqual(len(calls), 3)
        self.assertEqual(
            sleeps, [worker.INITIAL_RETRY_TIME, 2 * worker.INITIAL_RETRY_TIME]
        )

    def test_verify_credentials_rejects_bad_password(self):
        ret, calls, sleeps = self._verify_credentials(
            [{"error": "/api/request_version: Invalid username or password."}]
        )
        self.assertIs(ret, False)
        self.assertEqual(len(calls), 1)
        self.assertEqual(sleeps, [])

    def test_verify_credentials_network_error(self):
        with unittest.mock.patch(
            "worker.send_api_post_request",
            side_effect=games.WorkerException("down"),
        ):
            ret = worker.verify_credentials("https://example.com", "user", "pw", True)
        self.assertIsNone(ret)

    def test_add_auth_sends_only_the_session_token(self):
        payload = {}
        games.add_auth(payload, {"session_token": "old", "password": "secret"})
        games.add_auth(payload, {"session_token": "tok", "password": "secret"})
        self.assertEqual(payload, {"session_token": "tok"})

    def test_heartbeat_uses_current_credentials(self):
        auth = {"session_token": "old", "password": "secret"}
        current_state = {
            "alive": True,
            "last_updated": worker.datetime(2000, 1, 1, tzinfo=worker.timezone.utc),
            "run": {"_id": "64e74776a170cad5f5d7ac84"},
            "task_id": 0,
        }
        sent = []

        def rotate_token(_seconds):
            auth["session_token"] = "new"

        def fake_request(_url, payload, quiet=False):  # noqa: ARG001
            sent.append(dict(payload))
            current_state["alive"] = False
            return {"task_alive": True}

        with unittest.mock.patch("worker.time.sleep", side_effect=rotate_token):
            with unittest.mock.patch(
                "worker.send_api_post_request", side_effect=fake_request
            ):
                worker.heartbeat(
                    {"unique_key": "k"}, auth, "https://example.com", current_state
                )
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["session_token"], "new")

    def _verify_worker_version(self, auth, replies, worker_lock=None):
        calls = []

        def fake_request(url, payload, quiet=False):  # noqa: ARG001
            calls.append((url, dict(payload)))
            return replies[len(calls) - 1]

        with unittest.mock.patch(
            "worker.send_api_post_request",
            side_effect=fake_request,
        ):
            ret = worker.verify_worker_version(
                "https://example.com",
                "user",
                auth,
                worker_lock=worker_lock,
            )
        return ret, calls

    def test_verify_worker_version_logs_in_for_session(self):
        auth = {"username": "user", "password": "secret", "session_token": ""}
        ret, calls = self._verify_worker_version(
            auth, [{"version": worker.WORKER_VERSION, "session_token": "tok"}]
        )
        self.assertTrue(ret)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1]["password"], "secret")
        self.assertIs(calls[0][1]["new_session"], True)
        self.assertEqual(auth["session_token"], "tok")

    def test_verify_worker_version_reuses_session(self):
        auth = {"username": "user", "password": "secret", "session_token": "tok"}
        ret, calls = self._verify_worker_version(
            auth, [{"version": worker.WORKER_VERSION}]
        )
        self.assertTrue(ret)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][1]["session_token"], "tok")
        self.assertNotIn("password", calls[0][1])
        self.assertNotIn("new_session", calls[0][1])
        self.assertEqual(auth["session_token"], "tok")

    def test_verify_worker_version_logs_in_again_after_expired_session(self):
        auth = {"username": "user", "password": "secret", "session_token": "old"}
        ret, calls = self._verify_worker_version(
            auth,
            [
                {"error": "/api/request_version: Invalid or expired session."},
                {"version": worker.WORKER_VERSION, "session_token": "new"},
            ],
        )
        self.assertTrue(ret)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][1]["session_token"], "old")
        self.assertEqual(calls[1][1]["password"], "secret")
        self.assertNotIn("session_token", calls[1][1])
        self.assertIs(calls[1][1]["new_session"], True)
        self.assertEqual(auth["session_token"], "new")

    def test_verify_worker_version_bad_password(self):
        auth = {"username": "user", "password": "wrong", "session_token": "old"}
        ret, calls = self._verify_worker_version(
            auth,
            [
                {"error": "/api/request_version: Invalid or expired session."},
                {"error": "/api/request_version: Invalid username or password."},
            ],
        )
        self.assertIs(ret, False)
        self.assertEqual(len(calls), 2)
        self.assertEqual(auth["session_token"], "")

    def test_verify_worker_version_retries_when_throttled(self):
        auth = {"username": "user", "password": "secret", "session_token": ""}
        ret, calls = self._verify_worker_version(
            auth,
            [
                {
                    "error": "/api/request_version: Too many failed password "
                    "attempts, try again later."
                },
            ],
        )
        self.assertIsNone(ret)
        self.assertEqual(len(calls), 1)
        self.assertEqual(auth["session_token"], "")

    def test_verify_worker_version_ends_session_before_update(self):
        auth = {"username": "user", "password": "secret", "session_token": ""}
        worker_lock = unittest.mock.Mock()
        with unittest.mock.patch("worker.update") as update, unittest.mock.patch(
            "worker.backup_log"
        ):
            ret, calls = self._verify_worker_version(
                auth,
                [
                    {"version": worker.WORKER_VERSION + 1, "session_token": "tok"},
                    {},
                ],
                worker_lock=worker_lock,
            )
        self.assertIs(ret, False)
        update.assert_called_once()
        worker_lock.release.assert_called_once()
        self.assertEqual(len(calls), 2)
        self.assertTrue(calls[1][0].endswith("/api/worker_logout"))
        self.assertEqual(calls[1][1]["session_token"], "tok")
        self.assertEqual(auth["session_token"], "")

    def test_end_session(self):
        auth = {"username": "user", "password": "secret", "session_token": "tok"}
        calls = []

        def fake_request(url, payload, quiet=False):  # noqa: ARG001
            calls.append((url, dict(payload)))
            return {}

        with unittest.mock.patch(
            "worker.send_api_post_request", side_effect=fake_request
        ):
            worker.end_session("https://example.com", auth)
            worker.end_session("https://example.com", auth)
        self.assertEqual(len(calls), 1)
        url, payload = calls[0]
        self.assertEqual(url, "https://example.com/api/worker_logout")
        self.assertEqual(payload["session_token"], "tok")
        self.assertEqual(payload["worker_info"], {"username": "user"})
        self.assertNotIn("password", payload)
        self.assertEqual(auth["session_token"], "")

    def test_end_session_ignores_network_errors(self):
        auth = {"username": "user", "password": "secret", "session_token": "tok"}
        with unittest.mock.patch(
            "worker.send_api_post_request",
            side_effect=games.WorkerException("down"),
        ):
            worker.end_session("https://example.com", auth)
        self.assertEqual(auth["session_token"], "")

    def test_worker_script_with_bad_args(self):
        self.assertFalse((self.worker_dir / "fishtest.cfg").exists())
        p = subprocess.run([sys.executable, "worker.py", "--no-validation"])
        self.assertEqual(p.returncode, 1)

    def test_setup_exception(self):
        cwd = self.tempdir
        with self.assertRaises(Exception):
            games.setup_engine("foo", cwd, cwd, "https://foo", "foo", "https://foo", 1)

    def test_updater(self):
        file_list = updater.update(restart=False, test=True)
        self.assertIn("worker.py", file_list)

    def test_sri(self):
        self.assertTrue(worker.verify_sri(self.worker_dir))

    def test_toolchain_verification(self):
        self.assertTrue(worker.verify_toolchain())

    def test_setup_fastchess(self):
        self.assertTrue(
            worker.setup_fastchess(
                self.tempdir,
                list(worker.detect_compilers())[0],
                4,
                "",
            )
        )

    def test_memory_expression(self):
        mem = worker._memory(MAX=1024)
        expr, ret = mem("MAX/2")
        self.assertEqual(expr, "MAX/2")
        self.assertEqual(ret, 512)

        # Clamped to [0, MAX]
        _, ret2 = mem("-10")
        self.assertEqual(ret2, 0)
        _, ret3 = mem("MAX*2")
        self.assertEqual(ret3, 1024)

    def test_concurrency_expression(self):
        conc = worker._concurrency(MAX=8)
        expr, ret = conc("max(1,min(3,MAX-1))")
        self.assertEqual(expr, "max(1,min(3,MAX-1))")
        self.assertEqual(ret, 3)

        # Invalid: <= 0
        with self.assertRaises(ValueError):
            conc("0")

        # Invalid: over MAX without explicit MAX variable in expression
        with self.assertRaises(ValueError):
            conc("999")


if __name__ == "__main__":
    unittest.main()
