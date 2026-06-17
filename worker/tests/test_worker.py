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
        self.assertTrue(config.has_option("login", "api_key"))
        self.assertTrue(config.has_option("parameters", "host"))
        self.assertTrue(config.has_option("parameters", "port"))
        self.assertTrue(config.has_option("parameters", "concurrency"))

    def test_api_key_flag_is_persisted(self):
        api_key = "ft_" + "A" * 43
        sys.argv = [
            sys.argv[0],
            "user",
            "pass",
            "--api_key",
            api_key,
            "--no_validation",
        ]
        worker.CONFIGFILE = str(self.tempdir / "foo.txt")
        worker.setup_parameters(self.tempdir)
        config = ConfigParser(inline_comment_prefixes=";", interpolation=None)
        config.read(worker.CONFIGFILE)
        self.assertEqual(config.get("login", "api_key"), api_key)

    def test_add_auth_prefers_api_key(self):
        payload = {}
        games.add_auth(payload, {"api_key": "ft_token", "password": "secret"})
        self.assertEqual(payload.get("api_key"), "ft_token")
        self.assertNotIn("password", payload)

    def test_add_auth_falls_back_to_password(self):
        payload = {}
        games.add_auth(payload, {"api_key": "", "password": "secret"})
        self.assertEqual(payload.get("password"), "secret")
        self.assertNotIn("api_key", payload)

    def test_verify_worker_version_falls_back_to_password(self):
        auth = {
            "api_key": "ft_revoked",
            "password": "secret",
        }
        calls = []

        def fake_request(_url, payload, quiet=False):  # noqa: ARG001
            calls.append(payload)
            if len(calls) == 1:
                return {"error": "/api/request_version: Invalid credentials."}
            return {
                "version": worker.WORKER_VERSION,
                "api_key": "ft_new_token",
            }

        with unittest.mock.patch(
            "worker.send_api_post_request",
            side_effect=fake_request,
        ):
            self.assertTrue(
                worker.verify_worker_version(
                    "https://example.com",
                    "user",
                    auth,
                    worker_lock=None,
                )
            )
        self.assertEqual(len(calls), 2)
        self.assertIn("api_key", calls[0])
        self.assertNotIn("password", calls[0])
        self.assertIn("password", calls[1])
        self.assertNotIn("api_key", calls[1])
        self.assertEqual(auth["api_key"], "ft_new_token")

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
