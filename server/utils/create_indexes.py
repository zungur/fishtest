#!/usr/bin/env python3

# create_indexes.py - (re-)create indexes
#
# Run this script manually to create the indexes, it could take a few
# seconds/minutes to run.

import pprint
import sys

from pymongo import ASCENDING, DESCENDING, MongoClient
from pymongo.errors import OperationFailure

from fishtest.constants import (
    KNOWN_LOGIN_IP_DAYS,
    PASSWORD_DAILY_FAILURE_WINDOW_SECONDS,
    WORKER_SESSION_IDLE_SECONDS,
)
from fishtest.rundb import RunDb
from fishtest.userdb import EMAIL_COLLATION

db_name = "fishtest_new"

# MongoDB server is assumed to be on the same machine, if not user should use
# ssh with port forwarding to access the remote host.
conn = MongoClient("localhost")
db = conn[db_name]


def create_runs_indexes():
    rundb = RunDb()
    print("Creating indexes on runs collection")
    db["runs"].create_index(
        [("finished", ASCENDING)],
        name="unfinished_runs",
        partialFilterExpression={"finished": False},
    )
    # Keep "deleted" out of the partial filter or queries omitting it cannot
    # use this index; as a trailing key it still answers {"deleted": False}.
    db["runs"].create_index(
        [
            ("finished", ASCENDING),
            ("last_updated", DESCENDING),
            ("deleted", ASCENDING),
        ],
        name="finished_runs",
        partialFilterExpression={"finished": True},
    )
    db["runs"].create_index(
        [
            ("finished", ASCENDING),
            ("is_green", DESCENDING),
            ("last_updated", DESCENDING),
        ],
        name="finished_green_runs",
        partialFilterExpression={"finished": True, "is_green": True, "deleted": False},
    )
    db["runs"].create_index(
        [
            ("finished", ASCENDING),
            ("is_yellow", DESCENDING),
            ("last_updated", DESCENDING),
        ],
        name="finished_yellow_runs",
        partialFilterExpression={"finished": True, "is_yellow": True, "deleted": False},
    )
    db["runs"].create_index(
        [
            ("finished", ASCENDING),
            ("last_updated", DESCENDING),
            ("tc_base", DESCENDING),
        ],
        name="finished_ltc_runs",
        partialFilterExpression={
            "finished": True,
            "tc_base": {"$gte": rundb.ltc_lower_bound},
            "deleted": False,
        },
    )
    db["runs"].create_index(
        [("args.username", DESCENDING), ("last_updated", DESCENDING)],
        name="user_runs",
    )

    db["runs"].create_index(
        [
            ("args.username", DESCENDING),
            ("finished", ASCENDING),
            ("last_updated", DESCENDING),
        ],
        name="finished_user_runs",
        partialFilterExpression={"finished": True, "deleted": False},
    )
    db["runs"].create_index(
        [("args.info", "text")],
        name="finished_runs_text",
        default_language="none",
        partialFilterExpression={"finished": True, "deleted": False},
    )


def create_pgns_indexes():
    print("Creating indexes on pgns collection")
    db["pgns"].create_index([("run_id", DESCENDING)])


def create_nns_indexes():
    print("Creating indexes on nns collection")
    db["nns"].create_index([("name", DESCENDING)])


def create_users_indexes():
    db["users"].create_index("username", unique=True)
    db["users"].create_index(
        "password_reset.token",
        name="password_reset_token",
        sparse=True,
    )
    try:
        db["users"].create_index(
            "email",
            name="users_email_unique",
            unique=True,
            collation=EMAIL_COLLATION,
        )
    except OperationFailure as e:
        print(
            "Could not create the unique email index, probably because several "
            f"accounts share an email address ({e}).\n"
            "Run utils/find_duplicate_emails.py, resolve the duplicates, and "
            "run this script for the users collection again."
        )


def create_workers_indexes():
    db["workers"].create_index("worker_name", unique=True)


def create_worker_sessions_indexes():
    db["worker_sessions"].create_index("token_hash", unique=True)
    db["worker_sessions"].create_index(
        [("username", ASCENDING), ("last_seen", DESCENDING)],
        name="worker_sessions_user_last_seen",
    )
    db["worker_sessions"].create_index(
        "last_seen",
        name="worker_sessions_idle_ttl",
        expireAfterSeconds=WORKER_SESSION_IDLE_SECONDS,
    )


def create_known_login_ips_indexes():
    db["known_login_ips"].create_index(
        [("username", ASCENDING), ("ip", ASCENDING)],
        name="known_login_ips_user_ip",
        unique=True,
    )
    db["known_login_ips"].create_index(
        "last_success",
        name="known_login_ips_ttl",
        expireAfterSeconds=KNOWN_LOGIN_IP_DAYS * 24 * 3600,
    )


def create_password_failures_indexes():
    db["password_failures"].create_index(
        "username", name="password_failures_username", unique=True
    )
    db["password_failures"].create_index(
        "since",
        name="password_failures_ttl",
        expireAfterSeconds=PASSWORD_DAILY_FAILURE_WINDOW_SECONDS,
    )


def create_actions_indexes():
    db["actions"].create_index(
        [("time", DESCENDING), ("_id", DESCENDING)],
        name="actions_time_id",
    )
    db["actions"].create_index(
        [("username", ASCENDING), ("time", DESCENDING), ("_id", DESCENDING)],
        name="actions_user_time_id",
    )
    db["actions"].create_index(
        [("action", ASCENDING), ("time", DESCENDING), ("_id", DESCENDING)],
        name="actions_action_time_id",
    )
    db["actions"].create_index(
        [("run_id", ASCENDING), ("time", DESCENDING), ("_id", DESCENDING)],
        name="actions_run_time_id",
    )
    db["actions"].create_index([("username", ASCENDING), ("_id", DESCENDING)])
    db["actions"].create_index([("action", ASCENDING), ("_id", DESCENDING)])
    db["actions"].create_index([("run_id", ASCENDING), ("_id", DESCENDING)])
    db["actions"].create_index(
        [
            ("action", "text"),
            ("username", "text"),
            ("worker", "text"),
            ("message", "text"),
            ("run", "text"),
            ("user", "text"),
            ("nn", "text"),
            ("_id", DESCENDING),
        ],
        default_language="none",
    )


def print_current_indexes():
    for collection_name in db.list_collection_names():
        c = db[collection_name]
        print("Current indexes on " + collection_name + ":")
        pprint.pprint(
            c.index_information(),
            stream=None,
            indent=2,
            width=110,
            depth=None,
        )
        print()


def drop_indexes(collection_name):
    # Drop all indexes on collection except _id_
    print(f"\nDropping indexes on {collection_name}")
    collection = db[collection_name]
    index_keys = list(collection.index_information().keys())
    print(f"Current indexes: {index_keys}")
    for idx in index_keys:
        if idx != "_id_":
            print("Dropping " + collection_name + " index " + idx + " ...")
            collection.drop_index(idx)


if __name__ == "__main__":
    # Takes a list of collection names as arguments.
    # For each collection name, this script drops indexes and re-creates them.
    # With no argument, indexes are printed, but no indexes are re-created.
    collection_names = sys.argv[1:]
    if collection_names:
        print("Re-creating indexes...")
        for collection_name in collection_names:
            if collection_name == "users":
                drop_indexes("users")
                create_users_indexes()
            if collection_name == "workers":
                drop_indexes("workers")
                create_workers_indexes()
            elif collection_name == "worker_sessions":
                drop_indexes("worker_sessions")
                create_worker_sessions_indexes()
            elif collection_name == "known_login_ips":
                drop_indexes("known_login_ips")
                create_known_login_ips_indexes()
            elif collection_name == "password_failures":
                drop_indexes("password_failures")
                create_password_failures_indexes()
            elif collection_name == "actions":
                drop_indexes("actions")
                create_actions_indexes()
            elif collection_name == "runs":
                drop_indexes("runs")
                create_runs_indexes()
            elif collection_name == "pgns":
                drop_indexes("pgns")
                create_pgns_indexes()
            elif collection_name == "nns":
                drop_indexes("nns")
                create_nns_indexes()
        print("Finished creating indexes!\n")
    print_current_indexes()
    if not collection_names:
        print(f"Collections in {db_name}: {db.list_collection_names()}")
        print(
            "Give a list of collection names as arguments to re-create indexes. For example:\n",
        )
        print(
            "  python3 create_indexes.py users runs - drops and creates indexes for runs and users\n",
        )
