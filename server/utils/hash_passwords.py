#!/usr/bin/env python3
"""Scrypt-hash every user still on a legacy plaintext password.

One-shot migration companion to lazy login-time upgrades in
``UserDb._password_matches``. Safe to run repeatedly: users whose
``password`` field already holds a scrypt hash are skipped. Plaintext
cannot be recovered from a hash, so this script only upgrades rows that
still store the raw password.
"""

import logging

from fishtest.password_hash import hash_password, is_hashed
from fishtest.rundb import RunDb

logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(message)s")
logger = logging.getLogger(__name__)


def _password_needs_hashing(user: dict) -> bool:
    stored = user.get("password")
    return isinstance(stored, str) and stored and not is_hashed(stored)


def hash_passwords(rundb: RunDb) -> int:
    """Hash plaintext passwords. Returns the number of users updated."""
    updated = 0
    for user in rundb.userdb.get_users():
        if not _password_needs_hashing(user):
            continue
        plaintext = user["password"]
        hashed = hash_password(plaintext)
        result = rundb.userdb.users.update_one(
            {"_id": user["_id"], "password": plaintext},
            {"$set": {"password": hashed}},
        )
        if result.modified_count:
            updated += 1
            logger.info("Hashed password for %s", user["username"])
    rundb.userdb.clear_cache()
    return updated


def main() -> None:
    rundb = RunDb(is_primary_instance=False)
    updated = hash_passwords(rundb)
    logger.info("Password hash migration complete: %s user(s) updated", updated)


if __name__ == "__main__":
    main()
