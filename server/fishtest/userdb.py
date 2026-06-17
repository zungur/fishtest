import hmac
import secrets
from datetime import UTC, datetime

from pymongo import ASCENDING
from vtjson import ValidationError, validate

import fishtest.github_api as gh
from fishtest.constants import API_KEY_PREFIX
from fishtest.lru_cache import lru_cache
from fishtest.password_hash import (
    hash_password,
    is_hashed,
    needs_rehash,
    verify_password,
)
from fishtest.schemas import user_schema

DEFAULT_MACHINE_LIMIT = 16


def generate_api_key():
    """Return a fresh high-entropy worker API token."""
    return f"{API_KEY_PREFIX}{secrets.token_urlsafe(32)}"


def validate_user(user):
    try:
        validate(user_schema, user, "user")
    except ValidationError as e:
        message = f"The user object does not validate: {str(e)}"
        print(message, flush=True)
        raise ValidationError(message) from None


class UserDb:
    def __init__(self, db):
        self.db = db
        self.users = self.db["users"]
        self.user_cache = self.db["user_cache"]
        self.top_month = self.db["top_month"]

    def clear_cache(self):
        self.get_pending.cache_clear()
        self.get_blocked.cache_clear()
        self.find_by_username.cache_clear()
        self.get_usernames.cache_clear()

    @lru_cache(
        expiration=120, refresh=False, filter=lambda f, args, kw, val: val is not None
    )
    def find_by_username(self, name):
        return self.users.find_one({"username": name})

    def find_by_email(self, email):
        return self.users.find_one({"email": email})

    @staticmethod
    def _fail(*, user_message: str, code: str, log_message: str | None = None):
        print(log_message or user_message, flush=True)
        return {"error": user_message, "error_code": code}

    def _account_status_error(self, user, username):
        """Return an error dict if the (otherwise authenticated) account is not usable."""
        if user.get("blocked"):
            return self._fail(
                user_message="Your account is blocked.",
                code="blocked",
                log_message=f"Login rejected (account blocked): '{username}'",
            )
        if user.get("pending"):
            return self._fail(
                user_message="Your account is pending approval.",
                code="pending",
                log_message=f"Login rejected (pending approval): '{username}'",
            )
        return None

    def _password_matches(self, user, password):
        """Verify a plaintext password against the stored value.

        Lazily upgrades legacy plaintext and outdated scrypt hashes on success.
        """
        stored = user.get("password")
        if not isinstance(stored, str):
            return False
        if is_hashed(stored):
            matched = verify_password(stored, password)
        else:
            # Legacy plaintext password (pre-hashing migration).
            matched = hmac.compare_digest(stored, password)
        if not matched:
            return False
        if needs_rehash(stored):
            try:
                user["password"] = hash_password(password)
                self.save_user(user)
            except Exception as e:
                print(f"Failed to upgrade password hash: {e}", flush=True)
        return True

    def password_is_correct(self, username, password):
        """Return True if ``password`` is valid for ``username``.

        Performs the expensive scrypt verification (and lazy rehash). Account
        status (blocked/pending) is intentionally not considered here so the
        caller can cache the result and re-check status cheaply on every call.
        """
        user = self.get_user(username)
        if user is None:
            return False
        return self._password_matches(user, password)

    def authenticate(self, username, password):
        user = self.get_user(username)
        if user is None:
            # Avoid username enumeration: user-facing message is identical to wrong-password.
            return self._fail(
                user_message="Invalid username or password.",
                code="invalid_credentials",
                log_message=f"Login failed (unknown user): '{username}'",
            )

        if not self._password_matches(user, password):
            return self._fail(
                user_message="Invalid username or password.",
                code="invalid_credentials",
                log_message=f"Login failed (wrong password): '{username}'",
            )

        status_error = self._account_status_error(user, username)
        if status_error is not None:
            return status_error

        return {"username": username, "authenticated": True}

    def authenticate_worker(self, username, api_key):
        """Authenticate a worker using its API token (no password KDF cost)."""
        user = self.get_user(username)
        if user is None:
            return self._fail(
                user_message="Invalid credentials.",
                code="invalid_credentials",
                log_message=f"Worker auth failed (unknown user): '{username}'",
            )

        stored = user.get("api_key")
        if not isinstance(stored, str) or not hmac.compare_digest(stored, api_key):
            return self._fail(
                user_message="Invalid credentials.",
                code="invalid_credentials",
                log_message=f"Worker auth failed (bad api_key): '{username}'",
            )

        status_error = self._account_status_error(user, username)
        if status_error is not None:
            return status_error

        return {"username": username, "authenticated": True}

    def get_api_key(self, username):
        user = self.get_user(username)
        if user is not None:
            return user.get("api_key")
        return None

    def provision_api_key(self, user):
        """Assign an API token when missing without invalidating web sessions."""
        api_key = user.get("api_key")
        if isinstance(api_key, str) and api_key:
            return api_key
        api_key = self.rotate_api_key(user)
        self.save_user(user)
        return api_key

    def ensure_api_key(self, username):
        """Return the user's worker API token, creating one if missing."""
        user = self.get_user(username)
        if user is None:
            return None
        return self.provision_api_key(user)

    def bump_credentials_version(self, user):
        """Increment the credentials version used to invalidate web sessions."""
        version = int(user.get("credentials_version", 0)) + 1
        user["credentials_version"] = version
        return version

    def rotate_api_key(self, user):
        """Assign a fresh API token to ``user`` (caller must persist)."""
        api_key = generate_api_key()
        user["api_key"] = api_key
        return api_key

    def reset_api_key(self, user):
        """Assign a fresh API token to ``user`` and persist it."""
        api_key = self.rotate_api_key(user)
        self.bump_credentials_version(user)
        self.save_user(user)
        return api_key

    def set_password_reset(self, user, token, expires_at):
        """Store a single-use password reset token (sha256 digest) with expiry."""
        user["password_reset"] = {"token": token, "expires_at": expires_at}
        self.save_user(user)

    def find_by_reset_token(self, token):
        now = datetime.now(UTC)
        return self.users.find_one(
            {
                "password_reset.token": token,
                "password_reset.expires_at": {"$gte": now},
            }
        )

    def consume_reset_token(self, user_id, token):
        """Remove ``password_reset`` when the reset link is first opened."""
        result = self.users.update_one(
            {"_id": user_id, "password_reset.token": token},
            {"$unset": {"password_reset": ""}},
        )
        if result.modified_count:
            self.clear_cache()
        return result.modified_count > 0

    def update_password_with_reset_token(self, user_id, token, hashed_password):
        """Atomically set a new password, rotate the API token, and consume the token."""
        result = self.users.update_one(
            {"_id": user_id, "password_reset.token": token},
            {
                "$set": {
                    "password": hashed_password,
                    "api_key": generate_api_key(),
                },
                "$inc": {"credentials_version": 1},
                "$unset": {"password_reset": ""},
            },
        )
        if result.modified_count:
            self.clear_cache()
        return result

    def update_password_after_reset(self, user_id, hashed_password):
        """Complete a password reset after the link was consumed on GET."""
        result = self.users.update_one(
            {"_id": user_id},
            {
                "$set": {
                    "password": hashed_password,
                    "api_key": generate_api_key(),
                },
                "$inc": {"credentials_version": 1},
            },
        )
        if result.modified_count:
            self.clear_cache()
        return result

    def get_users(self):
        return self.users.find(sort=[("_id", ASCENDING)])

    @lru_cache(maxsize=1, expiration=30, refresh=False)
    def get_usernames(self):
        usernames = self.users.distinct("username")
        return sorted(
            [
                username
                for username in usernames
                if isinstance(username, str) and username
            ],
            key=str.lower,
        )

    @lru_cache(expiration=1, refresh=False)
    def get_pending(self):
        return list(self.users.find({"pending": True}, sort=[("_id", ASCENDING)]))

    @lru_cache(expiration=1, refresh=False)
    def get_blocked(self):
        return list(self.users.find({"blocked": True}, sort=[("_id", ASCENDING)]))

    def get_user(self, username):
        return self.find_by_username(username)

    def get_user_groups(self, username):
        user = self.get_user(username)
        if user is not None:
            groups = user["groups"]
            return groups

    def add_user_group(self, username, group):
        user = self.get_user(username)
        user["groups"].append(group)
        validate_user(user)
        self.users.replace_one({"_id": user["_id"]}, user)
        self.clear_cache()

    def create_user(self, username, password, email, tests_repo):
        try:
            if self.find_by_username(username) or self.find_by_email(email):
                return False
            # insert the new user in the db
            user = {
                "username": username,
                "password": hash_password(password),
                "api_key": generate_api_key(),
                "registration_time": datetime.now(UTC),
                "pending": True,
                "blocked": False,
                "email": email,
                "groups": [],
                "tests_repo": gh.canonicalize_repo_url(tests_repo),
                "machine_limit": DEFAULT_MACHINE_LIMIT,
            }
            validate_user(user)
            self.users.insert_one(user)
            self.clear_cache()

            return True
        except Exception:
            return None

    def save_user(self, user):
        if "tests_repo" in user:
            user["tests_repo"] = gh.canonicalize_repo_url(user["tests_repo"])
        validate_user(user)
        self.users.replace_one({"_id": user["_id"]}, user)
        self.clear_cache()

    def remove_user(self, user, rejector):
        result = self.users.delete_one({"_id": user["_id"]})
        if result.deleted_count > 0:
            # User successfully deleted
            self.clear_cache()
            # logs rejected users to the server
            print(
                f"user: {user['username']} with email: {user['email']} was rejected by: {rejector}",
                flush=True,
            )
            return True
        else:
            # User not found
            return False

    def get_machine_limit(self, username):
        user = self.get_user(username)
        if user and "machine_limit" in user:
            return user["machine_limit"]
        return DEFAULT_MACHINE_LIMIT
