#!/usr/bin/env python3
"""Mark the clients that ran tasks recently as known for their users.

One-shot migration step, run after stopping the old server. Without it no
client is known when the new server starts, so a burst of failed password
checks (see ``fishtest.password_throttle``) would queue or refuse every
reconnecting worker. Workers older than the session release sent the password
with every request, so a task proves a password login from its client. Safe to
run repeatedly.
"""

import logging
from datetime import UTC, datetime, timedelta

from pymongo import UpdateOne

from fishtest.constants import KNOWN_LOGIN_IP_DAYS
from fishtest.password_throttle import client_key
from fishtest.rundb import RunDb

logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(message)s")
logger = logging.getLogger(__name__)

_TASK_FIELDS = {
    "tasks.last_updated": 1,
    "tasks.worker_info.username": 1,
    "tasks.worker_info.remote_addr": 1,
}


def recent_clients(runs, since: datetime) -> dict[tuple[str, str], datetime]:
    """Return (username, client) -> last task update, for tasks since ``since``."""
    clients = {}
    # Two queries, so that each can use a runs index.
    for query in (
        {"finished": False},
        {"finished": True, "last_updated": {"$gte": since}},
    ):
        for run in runs.find(query, _TASK_FIELDS):
            for task in run.get("tasks", []):
                last_updated = task.get("last_updated")
                worker_info = task.get("worker_info", {})
                username = worker_info.get("username")
                client = client_key(worker_info.get("remote_addr"))
                if not (username and client and last_updated) or last_updated < since:
                    continue
                key = (username, client)
                if key not in clients or clients[key] < last_updated:
                    clients[key] = last_updated
    return clients


def seed_known_login_ips(rundb: RunDb) -> int:
    """Record the recent clients of each user; return how many were found."""
    since = datetime.now(UTC) - timedelta(days=KNOWN_LOGIN_IP_DAYS)
    clients = recent_clients(rundb.runs, since)
    if clients:
        rundb.known_login_ips.ips.bulk_write(
            [
                UpdateOne(
                    {"username": username, "ip": client},
                    {"$max": {"last_success": last_updated}},
                    upsert=True,
                )
                for (username, client), last_updated in clients.items()
            ],
            ordered=False,
        )
    return len(clients)


def main() -> None:
    rundb = RunDb(is_primary_instance=False)
    seeded = seed_known_login_ips(rundb)
    logger.info("Known clients recorded: %s (username, client) pair(s)", seeded)


if __name__ == "__main__":
    main()
