"""Counts for dashboard tagging progress; no observation content is exposed."""

from __future__ import annotations

import sqlite3


def tagging_counts(conn: sqlite3.Connection, scan_id: str) -> tuple[int, int]:
    endpoint_columns = {row[1] for row in conn.execute("PRAGMA table_info(endpoints)")}
    actionable = " AND COALESCE(e.is_excluded,0)=0" if "is_excluded" in endpoint_columns else ""
    row = conn.execute(
        f"""SELECT COUNT(*), COALESCE(SUM(EXISTS(
            SELECT 1 FROM endpoint_annotations a WHERE a.observation_id=o.observation_id
        )),0)
        FROM endpoint_observations o
        JOIN endpoints e ON e.endpoint_id=o.endpoint_id
        JOIN origins g ON g.origin_id=e.origin_id
        JOIN assets s ON s.asset_id=g.asset_id
        WHERE s.scan_id=?{actionable}""",
        (scan_id,),
    ).fetchone()
    return int(row[0]), int(row[1])


def tagging_progress_params(total: int, processed: int) -> dict[str, int]:
    return {
        "observation_total": total,
        "processed": processed,
        "progress": 76 + (12 * processed // total if total else 0),
    }
