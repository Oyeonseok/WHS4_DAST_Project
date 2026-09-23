from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from aidast.attack.skill_selector import (
    MAX_RELEVANT_HUNT_SKILLS,
    available_attack_skill_names,
    select_relevant_attack_skills,
)
from aidast.recon import db


def selector_database(root: Path, *, completed: bool = True) -> Path:
    path = root / "Pipeline.db"
    conn = db.init_db(path)
    db.insert_scan(conn, scan_id="scan", scope_type="approved", scope_value="scope")
    asset = db.insert_asset(conn, scan_id="scan", identifier="example.test", asset_type="DOMAIN")
    origin = db.upsert_origin(
        conn, asset_id=asset, scheme="https", host="example.test", port=443,
        base_url="https://example.test", framework_signature="Next.js Express",
        spa_detected=True,
    )
    endpoint = db.upsert_endpoint(
        conn, origin_id=origin, method="POST",
        path="/api/oauth/upload/webhook/search/callback",
        normalized_path="/api/oauth/upload/webhook/search/callback",
        content_type="application/json", auth_required=True, source_tool="fixture",
    )
    conn.execute(
        """INSERT INTO parameters
           (parameter_id,endpoint_id,name,location,data_type,is_identifier)
           VALUES ('p',?,'object_id','query','string',1)""",
        (endpoint,),
    )
    conn.execute(
        "INSERT INTO observations VALUES ('o',?,'response_header','vary','Origin','fixture',CURRENT_TIMESTAMP)",
        (origin,),
    )
    if completed:
        conn.execute(
            "UPDATE scans SET status='completed',finished_at=CURRENT_TIMESTAMP WHERE scan_id='scan'"
        )
    conn.commit()
    conn.close()
    return path


class AttackSkillSelectorTests(unittest.TestCase):
    def test_structured_recon_signals_select_only_bounded_relevant_skills(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = selector_database(Path(temporary))
            selected, reasons = select_relevant_attack_skills(
                path, "scan", available_attack_skill_names()
            )
        self.assertLessEqual(len(selected), MAX_RELEVANT_HUNT_SKILLS)
        self.assertIn("hunt-idor", selected)
        self.assertIn("hunt-cors", selected)
        self.assertIn("hunt-nextjs", selected)
        self.assertIn("hunt-oauth", selected)
        self.assertNotIn("hunt-xxe", selected)
        self.assertNotIn("chain", selected)
        self.assertIn("identifier parameter", reasons["hunt-idor"])

    def test_empty_surface_falls_back_to_misc(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "Pipeline.db"
            conn = db.init_db(path)
            db.insert_scan(conn, scan_id="scan", scope_type="approved", scope_value="scope")
            conn.execute(
                "UPDATE scans SET status='completed',finished_at=CURRENT_TIMESTAMP WHERE scan_id='scan'"
            )
            conn.commit()
            conn.close()
            selected, _ = select_relevant_attack_skills(
                path, "scan", available_attack_skill_names()
            )
        self.assertEqual(selected, ("hunt-misc",))

    def test_incomplete_recon_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = selector_database(Path(temporary), completed=False)
            with self.assertRaisesRegex(ValueError, "completed Recon"):
                select_relevant_attack_skills(
                    path, "scan", available_attack_skill_names()
                )

    def test_recon_parameter_role_selects_matching_attack_skill(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "Pipeline.db"
            conn = db.init_db(path)
            db.insert_scan(conn, scan_id="scan", scope_type="approved", scope_value="scope")
            asset = db.insert_asset(conn, scan_id="scan", identifier="example.test", asset_type="DOMAIN")
            origin = db.upsert_origin(conn, asset_id=asset, scheme="https", host="example.test",
                                      port=443, base_url="https://example.test")
            endpoint = db.upsert_endpoint(conn, origin_id=origin, method="GET", path="/view",
                                          normalized_path="/view", source_tool="fixture")
            db.upsert_parameter(conn, endpoint_id=endpoint, name="destination", location="query",
                                data_type="string", role="url")
            conn.execute("UPDATE scans SET status='completed',finished_at=CURRENT_TIMESTAMP WHERE scan_id='scan'")
            conn.commit()
            conn.close()
            selected, reasons = select_relevant_attack_skills(
                path, "scan", available_attack_skill_names()
            )
        self.assertIn("hunt-ssrf", selected)
        self.assertIn("URL parameter", reasons["hunt-ssrf"])

    def test_packaged_enumeration_excludes_chaining_skill(self) -> None:
        names = available_attack_skill_names()
        self.assertIn("hunt-dispatch", names)
        self.assertNotIn("chain", names)


if __name__ == "__main__":
    unittest.main()
