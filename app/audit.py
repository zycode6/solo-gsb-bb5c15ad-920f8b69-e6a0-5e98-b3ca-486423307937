"""Tamper-evident audit chain for lease lifecycle events.

Each successful lease state transition -- allocation, renewal, release and
expiry reclamation -- appends one event **in the same** ``BEGIN IMMEDIATE``
transaction that performs the change. A failed operation raises before
COMMIT, so its event (if any) is rolled back together with the operation.

Hash chain
----------
Events carry a monotonically increasing ``seq``. The first event uses 64
ASCII zeroes as ``prev_hash``; every later event links to the previous
event's ``hash``. ``hash`` is SHA-256 over the concatenation of the
``prev_hash`` text and the compact, key-sorted UTF-8 JSON of all fields
except ``prev_hash`` and ``hash``.
"""

import hashlib
import json
import sqlite3

GENESIS_PREV_HASH = "0" * 64


def _canonical_json(payload: dict) -> str:
    """Compact JSON with keys sorted recursively, encoded as the spec mandates."""
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )


def _compute_hash(prev_hash: str, payload: dict) -> str:
    digest_input = prev_hash + _canonical_json(payload)
    return hashlib.sha256(digest_input.encode("utf-8")).hexdigest()


def append_event(
    conn: sqlite3.Connection,
    *,
    action: str,
    lease_id: int,
    pool_id: int,
    cidr: str,
    timestamp: int,
    details: dict | None = None,
) -> dict:
    """Append an audit event. Caller must hold the write transaction.

    The next ``seq``/``prev_hash`` are read inside that transaction, which
    (being ``BEGIN IMMEDIATE``) serializes all writers.
    """
    last = conn.execute(
        "SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1"
    ).fetchone()
    if last is None:
        seq = 1
        prev_hash = GENESIS_PREV_HASH
    else:
        seq = last["seq"] + 1
        prev_hash = last["hash"]

    payload = {
        "seq": seq,
        "action": action,
        "lease_id": lease_id,
        "pool_id": pool_id,
        "cidr": cidr,
        "timestamp": timestamp,
        "details": details if details is not None else {},
    }
    event_hash = _compute_hash(prev_hash, payload)

    conn.execute(
        "INSERT INTO audit_events (seq, action, lease_id, pool_id, cidr, "
        "timestamp, details, prev_hash, hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            seq,
            action,
            lease_id,
            pool_id,
            cidr,
            timestamp,
            _canonical_json(payload["details"]),
            prev_hash,
            event_hash,
        ),
    )

    payload["prev_hash"] = prev_hash
    payload["hash"] = event_hash
    return payload


def _row_to_dict(row: sqlite3.Row) -> dict:
    return {
        "seq": row["seq"],
        "action": row["action"],
        "lease_id": row["lease_id"],
        "pool_id": row["pool_id"],
        "cidr": row["cidr"],
        "timestamp": row["timestamp"],
        "details": json.loads(row["details"]),
        "prev_hash": row["prev_hash"],
        "hash": row["hash"],
    }


def list_events(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM audit_events ORDER BY seq ASC"
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def verify_chain(conn: sqlite3.Connection) -> dict:
    """Walk the chain in seq order and report the first broken event.

    A chain is valid when seqs are gapless 1..N, every ``prev_hash`` links
    to the preceding event's ``hash`` (or the genesis value), and every
    stored ``hash`` matches a fresh SHA-256 over the event fields.
    """
    rows = conn.execute(
        "SELECT * FROM audit_events ORDER BY seq ASC"
    ).fetchall()

    prev_hash = GENESIS_PREV_HASH
    expected_seq = 1
    for row in rows:
        payload = {
            "seq": row["seq"],
            "action": row["action"],
            "lease_id": row["lease_id"],
            "pool_id": row["pool_id"],
            "cidr": row["cidr"],
            "timestamp": row["timestamp"],
            "details": json.loads(row["details"]),
        }
        if (
            row["seq"] != expected_seq
            or row["prev_hash"] != prev_hash
            or _compute_hash(row["prev_hash"], payload) != row["hash"]
        ):
            return {"valid": False, "invalid_seq": row["seq"]}
        prev_hash = row["hash"]
        expected_seq += 1

    return {"valid": True, "invalid_seq": None}
