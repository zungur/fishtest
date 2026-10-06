# ruff: noqa: ANN201, ANN206, B904, D100, D101, D102, E501, EM102, INP001, PLC0415, PT009, S105, TRY003
"""Test auth, session, and shared user-facing smoke routes."""

from unittest.mock import patch
from urllib.parse import urlencode

import test_support
from ui_user_test_case import UiUserTestCase
from vtjson import ValidationError

from fishtest.http.settings import (
    SESSION_REMEMBER_ME_MAX_AGE_SECONDS,
    UI_STATE_COOKIE_MAX_AGE_SECONDS,
)
from fishtest.util import PASSWORD_MAX_LENGTH


class TestUsers(UiUserTestCase):
    username = "TestAuthUser"

    def setUp(self):
        from fishtest import password_throttle

        super().setUp()
        password_throttle.reset()
        self.addCleanup(password_throttle.reset)
        self.rundb.known_login_ips.forget_user(self.username)
        self.rundb.known_login_ips._cache.clear()

    def _post_login(self, password, username=None):
        response = self.client.get("/login")
        csrf = test_support.extract_csrf_token(response.text)
        return self.client.post(
            "/login",
            data={
                "username": username or self.username,
                "password": password,
                "csrf_token": csrf,
            },
            follow_redirects=True,
        )

    def _is_logged_in(self):
        response = self.client.get("/user", follow_redirects=False)
        return response.status_code == 200

    def test_web_login_failures_are_throttled(self):
        from fishtest.constants import PASSWORD_PAIR_FAILURE_LIMIT

        for attempt in range(PASSWORD_PAIR_FAILURE_LIMIT):
            response = self._post_login(f"wrong-{attempt}")
            self.assertIn("Invalid username or password", response.text)
        with patch("fishtest.userdb.verify_password") as verify:
            response = self._post_login(self.password)
        verify.assert_not_called()
        self.assertIn("Too many failed login attempts", response.text)
        self.assertFalse(self._is_logged_in())

    def test_web_login_unknown_usernames_are_not_counted(self):
        from fishtest.constants import PASSWORD_IP_FAILURE_LIMIT

        for attempt in range(PASSWORD_IP_FAILURE_LIMIT + 5):
            self._post_login("whatever", username=f"NoSuchUser{attempt}")
        self._post_login(self.password)
        self.assertTrue(self._is_logged_in())

    def test_web_login_remembers_client(self):
        self._login_user()
        self.assertTrue(
            self.rundb.known_login_ips.is_known(self.username, "testclient")
        )

    def test_web_login_busy_kdf_answers_503(self):
        from fishtest.password_hash import PasswordHashBusy

        with patch("fishtest.userdb.verify_password", side_effect=PasswordHashBusy):
            response = self.client.get("/login")
            csrf = test_support.extract_csrf_token(response.text)
            response = self.client.post(
                "/login",
                data={
                    "username": self.username,
                    "password": self.password,
                    "csrf_token": csrf,
                },
                follow_redirects=False,
            )
        self.assertEqual(response.status_code, 503)
        self.assertIn("Server busy", response.text)

    def test_profile_password_check_is_throttled(self):
        from fishtest.constants import PASSWORD_PAIR_FAILURE_LIMIT

        self._login_user()
        user = self.rundb.userdb.get_user(self.username)

        def post_profile(old_password):
            response = self.client.get("/user")
            csrf = test_support.extract_csrf_token(response.text)
            return self.client.post(
                "/user",
                data={
                    "user": self.username,
                    "old_password": old_password,
                    "password": "",
                    "password2": "",
                    "email": "",
                    "tests_repo": user["tests_repo"],
                    "csrf_token": csrf,
                },
                follow_redirects=True,
            )

        for attempt in range(PASSWORD_PAIR_FAILURE_LIMIT):
            self.assertIn("Invalid password!", post_profile(f"wrong-{attempt}").text)
        response = post_profile(self.password)
        self.assertIn("Too many failed login attempts", response.text)

    def _assert_no_store_headers(self, response):
        self.assertEqual(response.headers.get("Cache-Control"), "no-store")
        self.assertEqual(response.headers.get("Expires"), "0")

    def _response_cookie(self, response, name):
        for cookie in response.headers.get_list("set-cookie"):
            if cookie.startswith(f"{name}="):
                return cookie
        return ""

    def _check_auth_with_flag(self, field, expected_error, expected_code):
        user = self.rundb.userdb.get_user(self.username)
        original = user.get(field)
        user[field] = True
        self.rundb.userdb.save_user(user)
        try:
            token = self.rundb.userdb.authenticate(self.username, self.password)
            self.assertEqual(token["error"], expected_error)
            self.assertEqual(token["error_code"], expected_code)
        finally:
            user = self.rundb.userdb.get_user(self.username)
            user[field] = original
            self.rundb.userdb.save_user(user)

    def test_login_requires_csrf(self):
        response = self.client.post(
            "/login",
            data={"username": self.username, "password": "wrong-test-password"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn("Please login", response.text)

    def test_login_invalid_password_renders_flash(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        csrf = test_support.extract_csrf_token(response.text)

        response = self.client.post(
            "/login",
            data={
                "username": self.username,
                "password": "wrong-test-password",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Invalid username or password.", response.text)

    def test_login_pending_then_success_redirects(self):
        user = self.rundb.userdb.get_user(self.username)
        user["pending"] = True
        self.rundb.userdb.save_user(user)

        response = self.client.get("/login")
        csrf = test_support.extract_csrf_token(response.text)

        response = self.client.post(
            "/login",
            data={
                "username": self.username,
                "password": self.password,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("pending approval", response.text)
        self.assertIn("manually approve your new account", response.text)

        user = self.rundb.userdb.get_user(self.username)
        user["pending"] = False
        self.rundb.userdb.save_user(user)

        response = self.client.get("/login")
        csrf = test_support.extract_csrf_token(response.text)

        response = self.client.post(
            "/login",
            data={
                "username": self.username,
                "password": self.password,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("location", {k.lower() for k in response.headers})

    def test_signup_creates_user_and_redirects(self):
        response = self.client.get("/signup")
        self.assertEqual(response.status_code, 200)
        self._assert_no_store_headers(response)
        csrf = test_support.extract_csrf_token(response.text)
        with (
            patch.dict(
                "os.environ",
                {"FISHTEST_CAPTCHA_SECRET": "test-secret"},
                clear=False,
            ),
            patch(
                "fishtest.views.requests.post",
                return_value=type(
                    "_CaptchaResponse",
                    (),
                    {"json": staticmethod(lambda: {"success": True})},
                )(),
            ),
        ):
            response = self.client.post(
                "/signup",
                data={
                    "username": self.signup_username,
                    "password": self.signup_password,
                    "password2": self.signup_password,
                    "email": "signup-test@user.net",
                    "tests_repo": self.tests_repo,
                    "g-recaptcha-response": "captcha-ok",
                    "csrf_token": csrf,
                },
                follow_redirects=False,
            )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers.get("location", "").endswith("/login"))
        self._assert_no_store_headers(response)

    def test_signup_canonicalizes_tests_repo(self):
        signup_username = "TestCanonicalSignupUser"
        self.rundb.userdb.users.delete_many({"username": signup_username})
        self.rundb.userdb.clear_cache()
        self.addCleanup(
            self.rundb.userdb.users.delete_many,
            {"username": signup_username},
        )
        self.addCleanup(self.rundb.userdb.clear_cache)

        response = self.client.get("/signup")
        self.assertEqual(response.status_code, 200)
        csrf = test_support.extract_csrf_token(response.text)

        with (
            patch.dict(
                "os.environ",
                {"FISHTEST_CAPTCHA_SECRET": "test-secret"},
                clear=False,
            ),
            patch(
                "fishtest.views.requests.post",
                return_value=type(
                    "_CaptchaResponse",
                    (),
                    {"json": staticmethod(lambda: {"success": True})},
                )(),
            ),
        ):
            response = self.client.post(
                "/signup",
                data={
                    "username": signup_username,
                    "password": self.signup_password,
                    "password2": self.signup_password,
                    "email": "canonical-signup-test@user.net",
                    "tests_repo": self.tests_repo + "/",
                    "g-recaptcha-response": "captcha-ok",
                    "csrf_token": csrf,
                },
                follow_redirects=False,
            )

        self.assertEqual(response.status_code, 302)
        created_user = self.rundb.userdb.get_user(signup_username)
        self.assertIsNotNone(created_user)
        self.assertEqual(created_user["tests_repo"], self.tests_repo)

    def test_signup_rejects_too_long_password(self):
        long_password = "A1!a" * 20
        self.assertGreater(len(long_password), PASSWORD_MAX_LENGTH)
        response = self.client.get("/signup")
        self.assertEqual(response.status_code, 200)
        csrf = test_support.extract_csrf_token(response.text)
        response = self.client.post(
            "/signup",
            data={
                "username": "TestLongPasswordUser",
                "password": long_password,
                "password2": long_password,
                "email": "long-password-test@user.net",
                "tests_repo": self.tests_repo,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            f"Error! Password too long (max {PASSWORD_MAX_LENGTH} characters)",
            response.text,
        )

    def test_login_page_has_csrf_meta(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self._assert_no_store_headers(response)
        csrf = test_support.extract_csrf_token(response.text)
        self.assertTrue(csrf)

    def test_login_page_defaults_remember_me_checked(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn('name="stay_logged_in" value="0"', response.text)
        self.assertIn('name="stay_logged_in"', response.text)
        self.assertIn('id="staylogged"', response.text)
        self.assertIn(
            'data-remember-me-cookie-name="login_remember_me"',
            response.text,
        )
        self.assertIn(
            f'data-remember-me-cookie-max-age="{UI_STATE_COOKIE_MAX_AGE_SECONDS}"',
            response.text,
        )
        self.assertRegex(
            response.text,
            r'(?s)<input[^>]*id="staylogged"[^>]*checked[^>]*>',
        )

    def test_login_page_remember_me_cookie_can_uncheck_box(self):
        response = self.client.get(
            "/login",
            headers={"cookie": "login_remember_me=0"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotRegex(
            response.text,
            r'(?s)<input[^>]*id="staylogged"[^>]*checked[^>]*>',
        )

    def test_login_default_sets_persistent_cookie(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self._assert_no_store_headers(response)
        csrf = test_support.extract_csrf_token(response.text)

        response = self.client.post(
            "/login",
            data={
                "username": self.username,
                "password": self.password,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self._assert_no_store_headers(response)
        session_cookie = self._response_cookie(response, "fishtest_session")
        remember_cookie = self._response_cookie(response, "login_remember_me")
        self.assertIn("fishtest_session=", session_cookie)
        self.assertIn(
            f"Max-Age={SESSION_REMEMBER_ME_MAX_AGE_SECONDS}",
            session_cookie,
        )
        self.assertIn("login_remember_me=1", remember_cookie)
        self.assertIn(f"max-age={UI_STATE_COOKIE_MAX_AGE_SECONDS}", remember_cookie)

    def test_login_duplicate_remember_fields_keep_persistent_cookie(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        csrf = test_support.extract_csrf_token(response.text)

        response = self.client.post(
            "/login",
            content=urlencode(
                [
                    ("username", self.username),
                    ("password", self.password),
                    ("stay_logged_in", "0"),
                    ("stay_logged_in", "1"),
                    ("csrf_token", csrf),
                ]
            ),
            headers={"content-type": "application/x-www-form-urlencoded"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        session_cookie = self._response_cookie(response, "fishtest_session")
        remember_cookie = self._response_cookie(response, "login_remember_me")
        self.assertIn("fishtest_session=", session_cookie)
        self.assertIn(
            f"Max-Age={SESSION_REMEMBER_ME_MAX_AGE_SECONDS}",
            session_cookie,
        )
        self.assertIn("login_remember_me=1", remember_cookie)
        self.assertIn(f"max-age={UI_STATE_COOKIE_MAX_AGE_SECONDS}", remember_cookie)

    def test_login_explicit_non_remember_sets_session_cookie(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        csrf = test_support.extract_csrf_token(response.text)

        response = self.client.post(
            "/login",
            data={
                "username": self.username,
                "password": self.password,
                "stay_logged_in": "0",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        session_cookie = self._response_cookie(response, "fishtest_session")
        remember_cookie = self._response_cookie(response, "login_remember_me")
        self.assertIn("fishtest_session=", session_cookie)
        self.assertNotIn("Max-Age=", session_cookie)
        self.assertIn("login_remember_me=0", remember_cookie)
        self.assertIn(f"max-age={UI_STATE_COOKIE_MAX_AGE_SECONDS}", remember_cookie)

    def test_login_invalid_password_keeps_explicit_non_remember_preference(self):
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        csrf = test_support.extract_csrf_token(response.text)

        response = self.client.post(
            "/login",
            data={
                "username": self.username,
                "password": "wrong-test-password",
                "stay_logged_in": "0",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("Invalid username or password.", response.text)
        remember_cookie = self._response_cookie(response, "login_remember_me")
        self.assertIn("login_remember_me=0", remember_cookie)
        self.assertIn(f"max-age={UI_STATE_COOKIE_MAX_AGE_SECONDS}", remember_cookie)

    def test_signup_page_has_csrf_meta(self):
        response = self.client.get("/signup")
        self.assertEqual(response.status_code, 200)
        self._assert_no_store_headers(response)
        csrf = test_support.extract_csrf_token(response.text)
        self.assertTrue(csrf)

    def test_signup_requires_csrf(self):
        response = self.client.post(
            "/signup",
            data={
                "username": "TestNoCsrfUser",
                "password": "invalid-test-password",
                "password2": "invalid-test-password",
                "email": "no-csrf-test@user.net",
                "tests_repo": self.tests_repo,
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 403)
        self.assertIn("Register", response.text)

    def test_logout_redirects_and_clears_cookie(self):
        response = self.client.get("/login")
        csrf = test_support.extract_csrf_token(response.text)
        response = self.client.post(
            "/login",
            data={
                "username": self.username,
                "password": self.password,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)

        response = self.client.post(
            "/logout",
            data={"csrf_token": csrf},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("location", {k.lower() for k in response.headers})
        self.assertIn("set-cookie", {k.lower() for k in response.headers})

    def test_user_profile_post_requires_csrf(self):
        original_user = self.rundb.userdb.get_user(self.username)
        original_email = original_user["email"]
        original_tests_repo = original_user["tests_repo"]

        self._login_user()

        response = self.client.post(
            "/user",
            data={
                "user": self.username,
                "old_password": self.password,
                "email": "updated-auth-user@example.com",
                "tests_repo": original_tests_repo,
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 403)

        updated_user = self.rundb.userdb.get_user(self.username)
        self.assertEqual(updated_user["email"], original_email)
        self.assertEqual(updated_user["tests_repo"], original_tests_repo)

    def test_user_profile_post_canonicalizes_tests_repo(self):
        self._login_user()
        user = self.rundb.userdb.get_user(self.username)

        response = self.client.get("/user")
        self.assertEqual(response.status_code, 200)
        csrf = test_support.extract_csrf_token(response.text)

        response = self.client.post(
            "/user",
            data={
                "user": self.username,
                "old_password": self.password,
                "email": user["email"],
                "tests_repo": self.tests_repo + "/",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 302)
        updated_user = self.rundb.userdb.get_user(self.username)
        self.assertEqual(updated_user["tests_repo"], self.tests_repo)

    def test_user_admin_post_requires_csrf(self):
        target_username = self.signup_username
        self.rundb.userdb.users.delete_many({"username": target_username})
        self.rundb.userdb.clear_cache()

        created = self.rundb.userdb.create_user(
            target_username,
            "target-user-password",
            "target-user@example.com",
            self.tests_repo,
        )
        self.assertTrue(created)

        target_user = self.rundb.userdb.get_user(target_username)
        target_user["pending"] = False
        self.rundb.userdb.save_user(target_user)

        original_pending, original_groups = self._set_approver_state()
        try:
            self._login_user()

            response = self.client.post(
                f"/user/{target_username}",
                data={"user": target_username, "blocked": "1"},
                follow_redirects=False,
            )
            self.assertEqual(response.status_code, 403)

            updated_target_user = self.rundb.userdb.get_user(target_username)
            self.assertFalse(updated_target_user["blocked"])
        finally:
            self._restore_approver_state(original_pending, original_groups)
            self.rundb.userdb.users.delete_many({"username": target_username})
            self.rundb.userdb.clear_cache()

    def test_notfound_returns_html(self):
        response = self.client.get("/no-such-route")
        self.assertEqual(response.status_code, 404)
        self.assertIn("Oops! Page not found.", response.text)

    def test_list_and_detail_pages_render(self):
        response = self.client.get("/contributors")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Contributors", response.text)

        run_id = self._create_run()
        response = self.client.get(f"/tests/view/{run_id}")
        self.assertEqual(response.status_code, 200)
        self.assertIn(str(run_id), response.text)

    def test_add_user_group_raises_on_duplicate(self):
        username = "TestGroupUser"
        self.rundb.userdb.create_user(
            username,
            "test-group-password",
            "test-group@example.com",
            "",
        )
        try:
            self.rundb.userdb.add_user_group(username, "approvers")
            self.rundb.userdb.add_user_group(username, "dummy")
            with self.assertRaises(ValidationError):
                self.rundb.userdb.add_user_group(username, "approvers")
        finally:
            self.rundb.userdb.users.delete_one({"username": username})
            self.rundb.userdb.user_cache.delete_one({"username": username})
            self.rundb.userdb.clear_cache()

    def test_created_user_password_is_scrypt_hashed(self):
        from fishtest.password_hash import is_hashed, verify_password

        user = self.rundb.userdb.get_user(self.username)
        self.assertTrue(is_hashed(user["password"]))
        self.assertNotEqual(user["password"], self.password)
        self.assertTrue(verify_password(user["password"], self.password))

    def test_authenticate_success(self):
        token = self.rundb.userdb.authenticate(self.username, self.password)
        self.assertNotIn("error", token)
        self.assertTrue(token["authenticated"])

    def test_authenticate_lazy_upgrades_legacy_plaintext(self):
        from fishtest.password_hash import is_hashed

        username = "TestLegacyPlaintextUser"
        legacy_password = "legacy-plaintext-pw"
        self.rundb.userdb.users.delete_many({"username": username})
        self.rundb.userdb.clear_cache()
        self.addCleanup(self.rundb.userdb.users.delete_many, {"username": username})
        self.addCleanup(self.rundb.userdb.clear_cache)

        self.rundb.userdb.create_user(
            username,
            "initial-password",
            "legacy-plaintext@example.com",
            "",
        )
        # Simulate a pre-migration record with a plaintext password.
        user = self.rundb.userdb.get_user(username)
        user["password"] = legacy_password
        user["pending"] = False
        self.rundb.userdb.save_user(user)

        token = self.rundb.userdb.authenticate(username, legacy_password)
        self.assertTrue(token["authenticated"])

        upgraded = self.rundb.userdb.get_user(username)
        self.assertTrue(is_hashed(upgraded["password"]))
        # The upgraded hash still verifies the same password.
        token = self.rundb.userdb.authenticate(username, legacy_password)
        self.assertTrue(token["authenticated"])

    def _create_legacy_plaintext_user(self, username, password):
        self.rundb.userdb.users.delete_many({"username": username})
        self.addCleanup(self.rundb.userdb.users.delete_many, {"username": username})
        self.addCleanup(self.rundb.userdb.clear_cache)
        self.rundb.userdb.create_user(
            username, "initial-password", f"{username.lower()}@example.com", ""
        )
        self.rundb.userdb.users.update_one(
            {"username": username},
            {"$set": {"password": password, "pending": False}},
        )
        self.rundb.userdb.clear_cache()

    def test_legacy_plaintext_non_ascii_password(self):
        username = "TestLegacyUnicodeUser"
        self._create_legacy_plaintext_user(username, "pässwörd-légacy")
        token = self.rundb.userdb.authenticate(username, "wrong-pässwörd")
        self.assertEqual(token.get("error_code"), "invalid_credentials")
        token = self.rundb.userdb.authenticate(username, "pässwörd-légacy")
        self.assertTrue(token["authenticated"])

    def test_lazy_rehash_writes_only_the_password(self):
        from fishtest.password_hash import is_hashed

        username = "TestLegacyRehashUser"
        self._create_legacy_plaintext_user(username, "legacy-rehash-pw")
        stale = self.rundb.userdb.get_user(username)
        self.rundb.userdb.users.update_one(
            {"username": username}, {"$set": {"tests_repo": "concurrent-edit"}}
        )
        self.assertTrue(
            self.rundb.userdb._password_matches(dict(stale), "legacy-rehash-pw")
        )
        stored = self.rundb.userdb.users.find_one({"username": username})
        self.assertEqual(stored["tests_repo"], "concurrent-edit")
        self.assertTrue(is_hashed(stored["password"]))

    def test_lazy_rehash_does_not_undo_a_concurrent_password_change(self):
        username = "TestLegacyRaceUser"
        self._create_legacy_plaintext_user(username, "legacy-race-pw")
        stale = self.rundb.userdb.get_user(username)
        self.rundb.userdb.users.update_one(
            {"username": username}, {"$set": {"password": "changed-meanwhile"}}
        )
        self.rundb.userdb._password_matches(dict(stale), "legacy-race-pw")
        stored = self.rundb.userdb.users.find_one({"username": username})
        self.assertEqual(stored["password"], "changed-meanwhile")

    def _create_worker_session(self):
        user = self.rundb.userdb.get_user(self.username)
        self.addCleanup(self.rundb.worker_sessions.delete_for_user, self.username)
        return self.rundb.worker_sessions.create(
            self.username, user.get("credentials_version", 0), 16
        )

    def _worker_session_count(self):
        return self.rundb.worker_sessions.sessions.count_documents(
            {"username": self.username}
        )

    def test_login_strips_password_whitespace(self):
        response = self.client.get("/login")
        csrf = test_support.extract_csrf_token(response.text)

        response = self.client.post(
            "/login",
            data={
                "username": self.username,
                "password": f"  {self.password}  ",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)

    def test_password_change_revokes_worker_sessions(self):
        from fishtest.password_hash import hash_password

        self._login_user()
        user = self.rundb.userdb.get_user(self.username)
        session_token = self._create_worker_session()
        self.rundb.known_login_ips.remember(self.username, "203.0.113.7")

        response = self.client.get("/user")
        csrf = test_support.extract_csrf_token(response.text)
        new_password = "WorkerSessionRevokingPassword7!"
        try:
            response = self.client.post(
                "/user",
                data={
                    "user": self.username,
                    "old_password": self.password,
                    "password": new_password,
                    "password2": new_password,
                    "email": "",
                    "tests_repo": user["tests_repo"],
                    "csrf_token": csrf,
                },
                follow_redirects=False,
            )
            self.assertEqual(response.status_code, 302)
            self.assertTrue(response.headers.get("location", "").startswith("/login"))
            self.assertEqual(self._worker_session_count(), 0)
            updated = self.rundb.userdb.get_user(self.username)
            self.assertFalse(
                self.rundb.known_login_ips.is_known(self.username, "203.0.113.7")
            )
            self.assertFalse(
                self.rundb.worker_sessions.validate(
                    self.username,
                    session_token,
                    updated.get("credentials_version", 0),
                )
            )
        finally:
            restored = self.rundb.userdb.get_user(self.username)
            restored["password"] = hash_password(self.password)
            restored.pop("credentials_version", None)
            self.rundb.userdb.save_user(restored)
            self.rundb.userdb.clear_cache()

    def test_create_user_lets_a_busy_kdf_through(self):
        from fishtest.password_hash import PasswordHashBusy

        self.addCleanup(
            self.rundb.userdb.users.delete_one, {"username": "TestBusySignup"}
        )
        with (
            patch("fishtest.userdb.hash_password", side_effect=PasswordHashBusy),
            self.assertRaises(PasswordHashBusy),
        ):
            self.rundb.userdb.create_user(
                "TestBusySignup",
                "BusySignupPassword1!",
                "busy-signup-test@user.net",
                "https://github.com/official-stockfish/Stockfish",
            )
        self.assertIsNone(self.rundb.userdb.get_user("TestBusySignup", fresh=True))

    def test_authenticate_unknown_user(self):
        token = self.rundb.userdb.authenticate("MissingTestUser", "x")
        self.assertEqual(token["error"], "Invalid username or password.")
        self.assertEqual(token["error_code"], "invalid_credentials")

    def test_authenticate_blocked_user(self):
        self._check_auth_with_flag("blocked", "Your account is blocked.", "blocked")

    def test_authenticate_pending_user(self):
        self._check_auth_with_flag(
            "pending", "Your account is pending approval.", "pending"
        )
