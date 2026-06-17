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

    def test_created_user_has_api_key(self):
        user = self.rundb.userdb.get_user(self.username)
        self.assertTrue(user.get("api_key", "").startswith("ft_"))

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

    def test_authenticate_worker_with_api_key(self):
        user = self.rundb.userdb.get_user(self.username)
        token = self.rundb.userdb.authenticate_worker(self.username, user["api_key"])
        self.assertTrue(token["authenticated"])

        bad = self.rundb.userdb.authenticate_worker(self.username, "ft_wrong")
        self.assertEqual(bad["error_code"], "invalid_credentials")

    def test_reset_api_key_changes_token(self):
        user = self.rundb.userdb.get_user(self.username)
        old_key = user["api_key"]
        try:
            new_key = self.rundb.userdb.reset_api_key(user)
            self.assertNotEqual(new_key, old_key)
            self.assertEqual(self.rundb.userdb.get_api_key(self.username), new_key)
        finally:
            restored = self.rundb.userdb.get_user(self.username)
            restored["api_key"] = old_key
            self.rundb.userdb.save_user(restored)

    def test_ensure_api_key_provisions_missing_token(self):
        username = "TestEnsureApiKeyUser"
        self.rundb.userdb.users.delete_many({"username": username})
        self.rundb.userdb.clear_cache()
        self.addCleanup(self.rundb.userdb.users.delete_many, {"username": username})
        self.addCleanup(self.rundb.userdb.clear_cache)

        self.rundb.userdb.create_user(
            username,
            "ensure-api-key-password",
            "ensure-api-key@example.com",
            "",
        )
        user = self.rundb.userdb.get_user(username)
        user["pending"] = False
        user.pop("api_key", None)
        self.rundb.userdb.save_user(user)

        api_key = self.rundb.userdb.ensure_api_key(username)
        self.assertTrue(api_key.startswith("ft_"))
        self.assertEqual(self.rundb.userdb.get_api_key(username), api_key)
        updated = self.rundb.userdb.get_user(username)
        self.assertNotIn("credentials_version", updated)

    def test_provision_api_key_does_not_bump_credentials_version(self):
        user = self.rundb.userdb.get_user(self.username)
        old_key = user["api_key"]
        version = user.get("credentials_version", 0)
        try:
            user.pop("api_key", None)
            self.rundb.userdb.save_user(user)
            self.rundb.userdb.provision_api_key(
                self.rundb.userdb.get_user(self.username)
            )
            updated = self.rundb.userdb.get_user(self.username)
            self.assertNotEqual(updated["api_key"], old_key)
            self.assertEqual(updated.get("credentials_version", 0), version)
        finally:
            restored = self.rundb.userdb.get_user(self.username)
            restored["api_key"] = old_key
            self.rundb.userdb.save_user(restored)

    def test_consume_reset_token(self):
        import hashlib
        from datetime import UTC, datetime, timedelta

        user = self.rundb.userdb.get_user(self.username)
        token_hash = hashlib.sha256(b"consume-me").hexdigest()
        expires_at = datetime.now(UTC) + timedelta(hours=1)
        try:
            self.rundb.userdb.set_password_reset(user, token_hash, expires_at)
            self.assertTrue(
                self.rundb.userdb.consume_reset_token(user["_id"], token_hash)
            )
            self.assertIsNone(self.rundb.userdb.find_by_reset_token(token_hash))
            self.assertFalse(
                self.rundb.userdb.consume_reset_token(user["_id"], token_hash)
            )
        finally:
            cleaned = self.rundb.userdb.get_user(self.username)
            cleaned.pop("password_reset", None)
            self.rundb.userdb.users.update_one(
                {"_id": cleaned["_id"]},
                {"$unset": {"password_reset": ""}},
            )
            self.rundb.userdb.clear_cache()

    def test_reset_link_invalid_on_second_open(self):
        import hashlib
        from datetime import UTC, datetime, timedelta

        user = self.rundb.userdb.get_user(self.username)
        raw_token = "second-open-token"
        token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        expires_at = datetime.now(UTC) + timedelta(hours=1)
        try:
            self.rundb.userdb.set_password_reset(user, token_hash, expires_at)

            response = self.client.get(f"/reset_password/{raw_token}")
            self.assertEqual(response.status_code, 200)

            other_client = test_support.make_test_client(
                rundb=self.rundb,
                include_api=False,
                include_views=True,
            )
            response = other_client.get(
                f"/reset_password/{raw_token}",
                follow_redirects=False,
            )
            self.assertEqual(response.status_code, 302)
            self.assertTrue(response.headers.get("location", "").startswith("/login"))
        finally:
            cleaned = self.rundb.userdb.get_user(self.username)
            cleaned.pop("password_reset", None)
            self.rundb.userdb.users.update_one(
                {"_id": cleaned["_id"]},
                {"$unset": {"password_reset": ""}},
            )
            self.rundb.userdb.clear_cache()

    def test_password_reset_token_set_consume_and_expire(self):
        import hashlib
        from datetime import UTC, datetime, timedelta

        from fishtest.password_hash import hash_password, verify_password

        user = self.rundb.userdb.get_user(self.username)
        old_key = user["api_key"]
        token_hash = hashlib.sha256(b"raw-reset-token").hexdigest()
        expires_at = datetime.now(UTC) + timedelta(hours=1)
        self.rundb.userdb.set_password_reset(user, token_hash, expires_at)

        found = self.rundb.userdb.find_by_reset_token(token_hash)
        self.assertIsNotNone(found)
        self.assertEqual(found["username"], self.username)

        new_hash = hash_password("brand-new-password")
        result = self.rundb.userdb.update_password_with_reset_token(
            found["_id"], token_hash, new_hash
        )
        self.assertEqual(result.modified_count, 1)

        # Token is single-use: it is gone after consumption.
        self.assertIsNone(self.rundb.userdb.find_by_reset_token(token_hash))
        updated = self.rundb.userdb.get_user(self.username)
        self.assertNotIn("password_reset", updated)
        self.assertTrue(verify_password(updated["password"], "brand-new-password"))
        self.assertNotEqual(updated["api_key"], old_key)
        self.assertEqual(updated.get("credentials_version", 0), 1)

        # Restore the original password for other tests.
        restored = self.rundb.userdb.get_user(self.username)
        restored["password"] = hash_password(self.password)
        restored["api_key"] = old_key
        restored.pop("credentials_version", None)
        self.rundb.userdb.save_user(restored)

    def test_password_reset_token_expired_not_found(self):
        import hashlib
        from datetime import UTC, datetime, timedelta

        user = self.rundb.userdb.get_user(self.username)
        token_hash = hashlib.sha256(b"expired-reset-token").hexdigest()
        expires_at = datetime.now(UTC) - timedelta(hours=1)
        try:
            self.rundb.userdb.set_password_reset(user, token_hash, expires_at)
            self.assertIsNone(self.rundb.userdb.find_by_reset_token(token_hash))
        finally:
            cleaned = self.rundb.userdb.get_user(self.username)
            cleaned.pop("password_reset", None)
            self.rundb.userdb.users.update_one(
                {"_id": cleaned["_id"]},
                {"$unset": {"password_reset": ""}},
            )
            self.rundb.userdb.clear_cache()

    def test_forgot_password_page_renders(self):
        response = self.client.get("/forgot_password")
        self.assertEqual(response.status_code, 200)
        self.assertIn("Reset password", response.text)

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

    def test_password_reset_invalidates_existing_web_session(self):
        import hashlib
        from datetime import UTC, datetime, timedelta

        from fishtest.password_hash import hash_password

        self._login_user()
        response = self.client.get("/user")
        self.assertEqual(response.status_code, 200)

        user = self.rundb.userdb.get_user(self.username)
        token_hash = hashlib.sha256(b"invalidate-session-token").hexdigest()
        expires_at = datetime.now(UTC) + timedelta(hours=1)
        self.rundb.userdb.set_password_reset(user, token_hash, expires_at)

        response = self.client.get("/reset_password/invalidate-session-token")
        self.assertEqual(response.status_code, 200)
        csrf = test_support.extract_csrf_token(response.text)

        new_password = "NewSessionInvalidatingPassword1!"
        response = self.client.post(
            "/reset_password/invalidate-session-token",
            data={
                "password": new_password,
                "password2": new_password,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)

        response = self.client.get("/user", follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers.get("location", "").startswith("/login"))

        try:
            restored = self.rundb.userdb.get_user(self.username)
            restored["password"] = hash_password(self.password)
            restored.pop("credentials_version", None)
            self.rundb.userdb.save_user(restored)
        finally:
            self.rundb.userdb.clear_cache()

    def test_reset_api_key_requires_password(self):
        self._login_user()
        user = self.rundb.userdb.get_user(self.username)
        old_key = user["api_key"]

        response = self.client.get("/user")
        csrf = test_support.extract_csrf_token(response.text)

        response = self.client.post(
            "/user",
            data={
                "reset_api_key": "1",
                "password": "wrong-password",
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.rundb.userdb.get_api_key(self.username), old_key)

        response = self.client.get("/user")
        csrf = test_support.extract_csrf_token(response.text)
        response = self.client.post(
            "/user",
            data={
                "reset_api_key": "1",
                "password": self.password,
                "csrf_token": csrf,
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertNotEqual(self.rundb.userdb.get_api_key(self.username), old_key)

        try:
            restored = self.rundb.userdb.get_user(self.username)
            restored["api_key"] = old_key
            restored.pop("credentials_version", None)
            self.rundb.userdb.save_user(restored)
        finally:
            self.rundb.userdb.clear_cache()

    def test_forgot_password_rate_limited(self):
        user = self.rundb.userdb.get_user(self.username)
        email = user["email"]

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
            response = self.client.get("/forgot_password")
            csrf = test_support.extract_csrf_token(response.text)
            data = {
                "email": email,
                "g-recaptcha-response": "captcha-ok",
                "csrf_token": csrf,
            }
            response = self.client.post(
                "/forgot_password",
                data=data,
                follow_redirects=False,
            )
            self.assertEqual(response.status_code, 302)

            response = self.client.get("/forgot_password")
            csrf = test_support.extract_csrf_token(response.text)
            data["csrf_token"] = csrf
            response = self.client.post(
                "/forgot_password",
                data=data,
                follow_redirects=False,
            )
            self.assertEqual(response.status_code, 302)

    def test_forgot_password_smtp_not_configured_dev_warning(self):
        user = self.rundb.userdb.get_user(self.username)
        email = user["email"]

        with (
            patch.dict(
                "os.environ",
                {
                    "FISHTEST_CAPTCHA_SECRET": "test-secret",
                    "FISHTEST_INSECURE_DEV": "1",
                },
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
            patch(
                "fishtest.views._forgot_password_is_rate_limited", return_value=False
            ),
            patch("fishtest.views.email_valid", return_value=(True, email)),
        ):
            response = self.client.get("/forgot_password")
            csrf = test_support.extract_csrf_token(response.text)
            response = self.client.post(
                "/forgot_password",
                data={
                    "email": email,
                    "g-recaptcha-response": "captcha-ok",
                    "csrf_token": csrf,
                },
                follow_redirects=True,
            )
        self.assertEqual(response.status_code, 200)
        self.assertIn("If that email is registered", response.text)
        self.assertIn("Dev notice: password reset email was not sent", response.text)

    def test_backfill_api_keys_empty_string(self):
        from utils.backfill_api_keys import backfill_api_keys

        username = "TestBackfillEmptyApiKey"
        self.rundb.userdb.users.delete_many({"username": username})
        self.rundb.userdb.clear_cache()
        self.addCleanup(self.rundb.userdb.users.delete_many, {"username": username})
        self.addCleanup(self.rundb.userdb.clear_cache)

        self.rundb.userdb.create_user(
            username,
            "backfill-test-password",
            "backfill-empty@example.com",
            "",
        )
        user = self.rundb.userdb.get_user(username)
        self.rundb.userdb.users.update_one(
            {"_id": user["_id"]},
            {"$set": {"pending": False, "api_key": ""}},
        )
        self.rundb.userdb.clear_cache()

        updated = backfill_api_keys(self.rundb)
        self.assertGreaterEqual(updated, 1)
        backfilled = self.rundb.userdb.get_user(username)
        self.assertTrue(backfilled["api_key"].startswith("ft_"))

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
