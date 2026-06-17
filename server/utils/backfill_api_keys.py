#!/usr/bin/env python3
"""Assign a worker API token to every user that does not have one yet.

This is a one-shot migration to support API-token based worker authentication
(see fishtest.userdb.generate_api_key). It is safe to run repeatedly: users
that already have a non-empty ``api_key`` are left untouched. Passwords are not affected;
they are upgraded to scrypt lazily on the next successful login.
"""

import logging

from fishtest.rundb import RunDb
from fishtest.userdb import generate_api_key

logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(message)s")
logger = logging.getLogger(__name__)


def _api_key_needs_backfill(user: dict) -> bool:
    api_key = user.get("api_key")
    return not isinstance(api_key, str) or not api_key


def backfill_api_keys(rundb: RunDb) -> int:
    """Give an api_key to each user missing one. Returns the number updated."""
    updated = 0
    for user in rundb.userdb.get_users():
        if not _api_key_needs_backfill(user):
            continue
        result = rundb.userdb.users.update_one(
            {
                "_id": user["_id"],
                "$or": [{"api_key": {"$exists": False}}, {"api_key": ""}],
            },
            {"$set": {"api_key": generate_api_key()}},
        )
        if result.modified_count:
            updated += 1
            logger.info("Assigned api_key to %s", user["username"])
    rundb.userdb.clear_cache()
    return updated


def main() -> None:
    rundb = RunDb(is_primary_instance=False)
    updated = backfill_api_keys(rundb)
    logger.info("Backfill complete: %s user(s) updated", updated)


if __name__ == "__main__":
    main()
