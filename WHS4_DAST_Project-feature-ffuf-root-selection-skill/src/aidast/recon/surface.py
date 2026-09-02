"""Exports the recon result for a scan as Surface.json."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path


def export_surface(conn: sqlite3.Connection, *, scan_id: str, output_path: Path) -> Path:
    origins = conn.execute(
        """SELECT o.origin_id, o.base_url, o.spa_detected, o.framework_signature
           FROM origins o JOIN assets a ON o.asset_id = a.asset_id
           WHERE a.scan_id = ?""",
        (scan_id,),
    ).fetchall()

    result: dict = {"scan_id": scan_id, "origins": []}
    for origin_id, base_url, spa_detected, framework in origins:
        endpoints = conn.execute(
            """SELECT method, normalized_path, content_type, source_tools
               FROM endpoints WHERE origin_id=? AND is_excluded=0""",
            (origin_id,),
        ).fetchall()
        signals = conn.execute(
            "SELECT signal_type, value FROM surface_signals WHERE origin_id=?",
            (origin_id,),
        ).fetchall()
        result["origins"].append(
            {
                "base_url": base_url,
                "spa_detected": bool(spa_detected),
                "framework": framework,
                "endpoints": [
                    {
                        "method": method,
                        "path": path,
                        "content_type": content_type,
                        "source_tools": (source_tools or "").split(","),
                    }
                    for method, path, content_type, source_tools in endpoints
                ],
                "surface_signals": {key: value for key, value in signals},
            }
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return output_path
