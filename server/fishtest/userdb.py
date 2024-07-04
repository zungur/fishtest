import hashlib
import os
import sys
import threading
import time
from datetime import datetime, timezone
from functools import lru_cache

from pymongo import ASCENDING
from vtjson import ValidationError, validate

from fishtest.schemas import user_schema

DEFAULT_MACHINE_LIMIT = 16


def validate_user(user):
    try:
        validate(user_schema, user, "user")
    except ValidationError as e:
        message = f"The user object does not validate: {str(e)}"
        print(message, flush=True)
        raise Exception(message)


class UserDb:
    def __init__(self, db):
        self.db = db
        self.users = self.db["users"]
        self.user_cache = self.db["user_cache"]
        self.top_month = self.db["top_month"]

    # Cache user lookups for 120s
    user_lock = threading.Lock()
    cache = {}

    def find_by_username(self, name):
        with self.user_lock:
            user = self.cache.get(name)
            if user and time.time() < user["time"] + 120:
                return user["user"]
            user = self.users.find_one({"username": name})
            if user is not None:
                self.cache[name] = {"user": user, "time": time.time()}
            return user

    def find_by_email(self, email):
        return self.users.find_one({"email": email})

    def clear_cache(self):
        with self.user_lock:
            self.cache.clear()

    @lru_cache(maxsize=128)
    def hash_password(
        self,
        plaintext_pwd: str,
        salt: bytes = None,
        n: int = 2 ** 17,
        r: int = 8,
        p: int = 1,
        dklen: int = 64,
    ) -> dict:
        """
        n (int): CPU/memory cost factor. Defaults to 2**17.
        r (int): Block size factor. Defaults to 8 (1024 bytes).
        p (int): Parallelization factor. Defaults to 1.
        dklen (int): Length of the derived key. Defaults to 64.
        """
        # Generate a new 16-byte salt if none is provided
        if salt is None:
            salt = os.urandom(16)

        hashed_pwd = hashlib.scrypt(
            plaintext_pwd.encode(), salt=salt, n=n, r=r, p=p, dklen=dklen
        )

        return {"salt": salt, "hashed_pwd": hashed_pwd}

    # stored_result = hash_with_scrypt(plaintext_pwd)

    def check_password(
        self,
        plaintext_pwd: str,
        stored_hash: bytes,
        salt: bytes,
        n: int = 2 ** 14,
        r: int = 8,
        p: int = 1,
        dklen: int = 64,
    ) -> bool:

        tmp_hash = hashlib.scrypt(
            plaintext_pwd.encode(), salt=salt, n=n, r=r, p=p, dklen=dklen
        )
        return tmp_hash == stored_hash

    def authenticate(self, username, password):
        user = self.get_user(username)
        if not user:
            sys.stderr.write("Invalid username: '{}'\n".format(username))
            return {"error": "Invalid username: {}".format(username)}
        if user["password"] != password:
            sys.stderr.write("Invalid login (plaintext): '{}'\n".format(username))
            if not self.check_password(password, user["password"], user["salt"]):
                sys.stderr.write("Invalid login (hashed): '{}'\n".format(username))
                return {"error": "Invalid password for user: {}".format(username)}
        if "blocked" in user and user["blocked"]:
            sys.stderr.write("Blocked account: '{}'\n".format(username))
            return {"error": "Account blocked for user: {}".format(username)}
        if "pending" in user and user["pending"]:
            sys.stderr.write("Pending account: '{}'\n".format(username))
            return {"error": "Account pending for user: {}".format(username)}

        # temp: remove after all the passwords in userdb are hashed
        if user["password"] == password:
            hash_result = self.hash_password(user["password"])
            user["password"] = hash_result["hashed_pwd"]
            user["salt"] = hash_result["salt"]
            self.save_user(user)
        return {"username": username, "authenticated": True}

    def get_users(self):
        return self.users.find(sort=[("_id", ASCENDING)])

    # Cache pending for 1s
    last_pending_time = 0
    last_blocked_time = 0
    last_pending = None
    pending_lock = threading.Lock()
    blocked_lock = threading.Lock()

    def get_pending(self):
        with self.pending_lock:
            if time.time() > self.last_pending_time + 1:
                self.last_pending = list(
                    self.users.find({"pending": True}, sort=[("_id", ASCENDING)])
                )
                self.last_pending_time = time.time()
            return self.last_pending

    def get_blocked(self):
        with self.blocked_lock:
            if time.time() > self.last_blocked_time + 1:
                self.last_blocked = list(
                    self.users.find({"blocked": True}, sort=[("_id", ASCENDING)])
                )
                self.last_blocked_time = time.time()
            return self.last_blocked

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

    def create_user(self, username, password, salt, email, tests_repo):
        try:
            if self.find_by_username(username) or self.find_by_email(email):
                return False
            # insert the new user in the db
            user = {
                "username": username,
                "password": password,
                "salt": salt,
                "registration_time": datetime.now(timezone.utc),
                "pending": True,
                "blocked": False,
                "email": email,
                "groups": [],
                "tests_repo": tests_repo,
                "machine_limit": DEFAULT_MACHINE_LIMIT,
            }
            validate_user(user)
            self.users.insert_one(user)
            self.last_pending_time = 0
            self.last_blocked_time = 0

            return True
        except:
            return None

    def save_user(self, user):
        validate_user(user)
        self.users.replace_one({"_id": user["_id"]}, user)
        self.last_pending_time = 0
        self.last_blocked_time = 0
        self.clear_cache()

    def remove_user(self, user, rejector):

        result = self.users.delete_one({"_id": user["_id"]})
        if result.deleted_count > 0:
            # User successfully deleted
            self.last_pending_time = 0
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
