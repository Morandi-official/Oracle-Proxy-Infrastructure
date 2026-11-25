"""Read aggregate admission state without handling credentials or device identifiers."""

import json
import sqlite3
import time
from contextlib import closing
from pathlib import Path


REGISTRY = Path("/var/lib/oracle-proxy-control/tailscale-devices.sqlite3")
HEADSCALE = Path("/var/lib/oracle-proxy-tailnet-headscale/db.sqlite")


def observe(registry=REGISTRY, headscale=HEADSCALE, now=None):
    now = int(time.time()) if now is None else now
    with closing(sqlite3.connect(registry.as_uri() + "?mode=ro", uri=True, timeout=2)) as db:
        db.execute("ATTACH DATABASE ? AS headscale", (headscale.as_uri() + "?mode=ro",))
        db.execute("PRAGMA query_only=ON")
        base = db.execute(
            """SELECT count(*) FILTER (WHERE NOT revoked AND node IS NOT NULL),
                      count(*) FILTER (WHERE NOT revoked AND node IS NULL AND issued_at > :recent),
                      count(*) FILTER (WHERE NOT revoked AND node IS NULL AND
                                       issued_at BETWEEN :window AND :recent),
                      count(*) FILTER (WHERE revoked)
               FROM tailscale_admission""",
            {"recent": now - 300, "window": now - 1800},
        ).fetchone()
        result = dict(zip(
            ("registered", "pending_in_lease", "unconfirmed_last_30_minutes", "revoked"), base,
        ))
        fields = {row[1] for row in db.execute("PRAGMA headscale.table_info(nodes)")}
        if {"id", "auth_key_id", "user_id"} <= fields:
            result["unconfirmed_with_node_last_30_minutes"] = db.execute(
                """SELECT count(*) FROM tailscale_admission AS admission
                   WHERE NOT revoked AND node IS NULL AND issued_at >= ? AND EXISTS (
                       SELECT 1 FROM headscale.nodes
                       WHERE auth_key_id = admission.ticket AND user_id = admission.coordinator_id
                   )""",
                (now - 1800,),
            ).fetchone()[0]
        return {"status": "OBSERVED", **result}


if __name__ == "__main__":
    try:
        result = observe()
    except (OSError, sqlite3.Error):
        result = {"status": "UNAVAILABLE"}
    print(json.dumps(result))
