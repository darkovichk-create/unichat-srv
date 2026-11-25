#!/usr/bin/env python3
"""Read-only report for UniChatServerd SQLite audit metadata."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_DB = "/var/lib/unichatd/audit.db"
COLUMNS = (
    "id", "timestamp_utc", "event_type", "session_id", "client_id",
    "remote_ip", "target_id", "duration_ms", "packet_bytes", "result", "details",
)


def utc_text(value: int | None) -> str | None:
    if value is None:
        return None
    return datetime.fromtimestamp(value / 1000, tz=timezone.utc).isoformat(timespec="milliseconds")


def connect_read_only(path: Path) -> sqlite3.Connection:
    # SQLite URI mode=ro prevents accidental writes, even when run as root.
    return sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only viewer for UniChatServerd audit metadata (never modifies the database)."
    )
    parser.add_argument("--db", default=DEFAULT_DB, help=f"SQLite database path (default: {DEFAULT_DB})")
    parser.add_argument("--since-hours", type=float, default=24.0, help="show events from the last N hours (default: 24)")
    parser.add_argument("--all", action="store_true", help="show all retained events; overrides --since-hours")
    parser.add_argument("--client", help="filter by exact ClientId")
    parser.add_argument("--event", help="filter by exact event_type")
    parser.add_argument("--limit", type=int, default=50, help="maximum rows to show (1..500, default: 50)")
    parser.add_argument("--summary", action="store_true", help="show counts grouped by event type instead of event rows")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.since_hours < 0:
        parser.error("--since-hours must be non-negative")
    if not 1 <= args.limit <= 500:
        parser.error("--limit must be between 1 and 500")

    db_path = Path(args.db)
    if not db_path.is_file():
        print(f"Database not found: {db_path}", file=sys.stderr)
        return 2

    clauses: list[str] = []
    parameters: list[Any] = []
    if not args.all:
        clauses.append("timestamp_utc >= ?")
        parameters.append(int(datetime.now(timezone.utc).timestamp() * 1000 - args.since_hours * 3_600_000))
    if args.client:
        clauses.append("client_id = ?")
        parameters.append(args.client)
    if args.event:
        clauses.append("event_type = ?")
        parameters.append(args.event)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""

    try:
        with connect_read_only(db_path) as connection:
            connection.row_factory = sqlite3.Row
            if args.summary:
                rows = connection.execute(
                    "SELECT event_type, COUNT(*) AS event_count, "
                    "COUNT(DISTINCT client_id) AS clients "
                    f"FROM audit_events{where} GROUP BY event_type ORDER BY event_count DESC, event_type",
                    parameters,
                ).fetchall()
                result = {
                    "database": str(db_path), "mode": "read-only",
                    "summary": [
                        {"event_type": row["event_type"], "count": row["event_count"],
                         "distinct_clients": row["clients"]} for row in rows
                    ],
                }
            else:
                selected = ", ".join(COLUMNS)
                rows = connection.execute(
                    f"SELECT {selected} FROM audit_events{where} "
                    "ORDER BY timestamp_utc DESC, id DESC LIMIT ?",
                    [*parameters, args.limit],
                ).fetchall()
                result = {
                    "database": str(db_path), "mode": "read-only",
                    "events": [
                        {**dict(row), "timestamp_utc_iso": utc_text(row["timestamp_utc"])}
                        for row in rows
                    ],
                }

        if args.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        elif args.summary:
            print(f"Database: {db_path} (read-only)")
            if not result["summary"]:
                print("No matching events.")
            for row in result["summary"]:
                print(f'{row["event_type"]:<28} {row["count"]:>8} events  {row["distinct_clients"]:>5} clients')
        else:
            print(f"Database: {db_path} (read-only)")
            if not result["events"]:
                print("No matching events.")
            for row in result["events"]:
                print(
                    f'{row["timestamp_utc_iso"] or "-"} | {row["event_type"]:<22} | '
                    f'client={row["client_id"] or "-"} | ip={row["remote_ip"] or "-"} | '
                    f'target={row["target_id"] or "-"} | result={row["result"] or "-"} | '
                    f'{row["details"] or "-"}'
                )
        return 0
    except sqlite3.Error as exc:
        print(f"Could not read audit database: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
