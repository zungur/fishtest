import hmac
from datetime import UTC, datetime, timedelta

from pymongo import ASCENDING
from vtjson import ValidationError, validate

import fishtest.github_api as gh
from fishtest.constants import PASSWORD_RESET_MAX_TOKENS, PASSWORD_RESET_RESEND_SECONDS
from fishtest.lru_cache import lru_cache
from fishtest.password_hash import (
    PasswordHashBusy,
    hash_password,
    is_hashed,
    needs_rehash,
    verify_password,
)
from fishtest.schemas import password_reset_schema, user_schema

DEFAULT_MACHINE_LIMIT = 16
# Email addresses are compared case-insensitively; the unique index on
# users.email uses the same collation (see utils/create_indexes.py).
EMAIL_COLLATION = {"locale": "en", "strength": 2}


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
        return self.users.find_one({"email": email}, collation=EMAIL_COLLATION)

    def find_all_by_email(self, email):
        """Return every account using ``email``.

        More than one only while duplicates that predate the unique index
        remain (see utils/find_duplicate_emails.py).
        """
        return list(self.users.find({"email": email}, collation=EMAIL_COLLATION))

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
            # Legacy plaintext password (pre-hashing migration). compare_digest
            # only accepts ASCII str, so compare the UTF-8 bytes.
            matched = hmac.compare_digest(
                stored.encode("utf-8"), password.encode("utf-8")
            )
        if not matched:
            return False
        if needs_rehash(stored):
            try:
                new_hash = hash_password(password)
                # Only the password field, and only if nobody changed it since
                # it was read, so a concurrent update is never overwritten.
                result = self.users.update_one(
                    {"_id": user["_id"], "password": stored},
                    {"$set": {"password": new_hash}},
                )
                if result.modified_count:
                    user["password"] = new_hash
                self.clear_cache()
            except Exception as e:
                print(f"Failed to upgrade password hash: {e}", flush=True)
        return True

    def password_is_correct(self, username, password):
        """Return True if ``password`` is valid for ``username``.

        Performs the expensive scrypt verification (and lazy rehash) against
        the record in MongoDB. Account status (blocked/pending) is not
        considered here; callers check it separately.
        """
        user = self.get_user(username, fresh=True)
        if user is None:
            return False
        return self._password_matches(user, password)

    def authenticate(self, username, password):
        user = self.get_user(username, fresh=True)
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

        return {
            "username": username,
            "authenticated": True,
            "credentials_version": user.get("credentials_version", 0),
        }

    def add_password_reset(self, user_id, token, expires_at):
        """Add a password reset token (sha256 digest) unless one is recent.

        Returns False, storing nothing, if the account got a token less than
        ``PASSWORD_RESET_RESEND_SECONDS`` ago. Earlier tokens stay valid until
        they expire or one of them is used; only the newest
        ``PASSWORD_RESET_MAX_TOKENS`` are kept.
        """
        now = datetime.now(UTC)
        entry = {"token": token, "expires_at": expires_at, "created": now}
        validate(password_reset_schema, entry, "password_reset")
        recent = now - timedelta(seconds=PASSWORD_RESET_RESEND_SECONDS)
        result = self.users.update_one(
            {
                "_id": user_id,
                "password_reset": {
                    "$not": {"$elemMatch": {"created": {"$gt": recent}}}
                },
            },
            {
                "$push": {
                    "password_reset": {
                        "$each": [entry],
                        "$slice": -PASSWORD_RESET_MAX_TOKENS,
                    }
                }
            },
        )
        if result.modified_count:
            self.clear_cache()
        return result.modified_count > 0

    @staticmethod
    def _live_reset_token_query(token):
        return {
            "password_reset": {
                "$elemMatch": {
                    "token": token,
                    "expires_at": {"$gte": datetime.now(UTC)},
                }
            }
        }

    def find_by_reset_token(self, token):
        return self.users.find_one(self._live_reset_token_query(token))

    def update_password_with_reset_token(self, user_id, token, hashed_password):
        """Atomically set a new password, bump credentials_version, and consume all reset tokens."""
        result = self.users.update_one(
            {"_id": user_id, **self._live_reset_token_query(token)},
            {
                "$set": {"password": hashed_password},
                "$inc": {"credentials_version": 1},
                "$unset": {"password_reset": ""},
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

    def get_user(self, username, *, fresh=False):
        """Return the user record; ``fresh`` reads it from MongoDB, not the cache.

        The cached record of another process can be up to 2 minutes old: read
        it fresh before checking a password or saving a change.
        """
        if fresh:
            return self.users.find_one({"username": username})
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
        except PasswordHashBusy:
            raise
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
