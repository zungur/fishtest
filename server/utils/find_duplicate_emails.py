#!/usr/bin/env python3
"""List email addresses used by more than one account.

The unique index on ``users.email`` (``create_indexes.py users``) cannot be
created while such duplicates exist. Addresses are compared like the index
does, ignoring case. This script changes nothing; resolve each duplicate (for
example by asking the owners, or by changing the email of abandoned accounts)
and run it again until it reports none. Exits with status 1 while duplicates
remain.
"""

import sys

from fishtest.rundb import RunDb
from fishtest.userdb import EMAIL_COLLATION


def find_duplicate_emails(users) -> list[dict]:
    """Return one entry per shared address, with the accounts using it."""
    pipeline = [
        {"$match": {"email": {"$type": "string"}}},
        {
            "$group": {
                "_id": "$email",
                "count": {"$sum": 1},
                "accounts": {
                    "$push": {
                        "username": "$username",
                        "email": "$email",
                        "registration_time": "$registration_time",
                        "pending": "$pending",
                        "blocked": "$blocked",
                    }
                },
            }
        },
        {"$match": {"count": {"$gt": 1}}},
        {"$sort": {"_id": 1}},
    ]
    return list(users.aggregate(pipeline, collation=EMAIL_COLLATION))


def main() -> None:
    rundb = RunDb(is_primary_instance=False)
    duplicates = find_duplicate_emails(rundb.userdb.users)
    for duplicate in duplicates:
        print(f"{duplicate['_id']} is used by {duplicate['count']} accounts:")
        for account in duplicate["accounts"]:
            flags = [name for name in ("pending", "blocked") if account.get(name)]
            print(
                f"  {account['username']} <{account['email']}>, registered "
                f"{account.get('registration_time')}"
                + (f" ({', '.join(flags)})" if flags else "")
            )
    print(f"{len(duplicates)} shared email address(es).")
    sys.exit(1 if duplicates else 0)


if __name__ == "__main__":
    main()
