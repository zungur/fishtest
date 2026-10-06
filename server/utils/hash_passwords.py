#!/usr/bin/env python3
"""Scrypt-hash every user still on a legacy plaintext password.

One-shot migration companion to lazy login-time upgrades in
``UserDb._password_matches``. Safe to run repeatedly: users whose
``password`` field already holds a scrypt hash are skipped. Plaintext
cannot be recovered from a hash, so this script only upgrades rows that
still store the raw password. Never run it while a server older than the
scrypt release is running: that server compares passwords as plaintext.
"""

import logging
from concurrent.futures import ThreadPoolExecutor

from fishtest.constants import SCRYPT_MAX_CONCURRENCY
from fishtest.password_hash import hash_password, is_hashed
from fishtest.rundb import RunDb

logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(message)s")
logger = logging.getLogger(__name__)

PROGRESS_EVERY = 500


def _password_needs_hashing(user: dict) -> bool:
    stored = user.get("password")
    return isinstance(stored, str) and stored and not is_hashed(stored)


def _hash_user(users, user: dict) -> bool:
    plaintext = user["password"]
    result = users.update_one(
        {"_id": user["_id"], "password": plaintext},
        {"$set": {"password": hash_password(plaintext)}},
    )
    return result.modified_count > 0


def hash_passwords(rundb: RunDb, threads: int = SCRYPT_MAX_CONCURRENCY) -> int:
    """Hash plaintext passwords. Returns the number of users updated.

    Hashing releases the GIL, so ``threads`` hashes run in parallel; more
    than ``SCRYPT_MAX_CONCURRENCY`` would only wait for a KDF slot.
    """
    users = rundb.userdb.users
    pending = [
        user
        for user in users.find({}, {"password": 1})
        if _password_needs_hashing(user)
    ]
    logger.info("%s user(s) with a plaintext password", len(pending))
    updated = 0
    with ThreadPoolExecutor(max_workers=threads) as pool:
        results = pool.map(lambda user: _hash_user(users, user), pending)
        for done, changed in enumerate(results, 1):
            updated += changed
            if done % PROGRESS_EVERY == 0 or done == len(pending):
                logger.info("Hashed %s/%s", done, len(pending))
    rundb.userdb.clear_cache()
    return updated


def main() -> None:
    rundb = RunDb(is_primary_instance=False)
    updated = hash_passwords(rundb)
    logger.info("Password hash migration complete: %s user(s) updated", updated)


if __name__ == "__main__":
    main()
