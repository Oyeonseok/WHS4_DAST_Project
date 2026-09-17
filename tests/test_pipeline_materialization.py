from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from aidast.pipeline.live_schema import migrate_live_pipeline_schema
from aidast.pipeline.materialize import materialize_pipeline
from aidast.pipeline.models import HandoffManifest, hash_artifact
from aidast.recon import db


class PipelineMaterializationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.recon_path = self.root / "Recon.db"
        with db.connect(self.recon_path) as connection:
            db.insert_scan(
                connection,
                scan_id="scan",
                scope_type="test",
                scope_value="scope",
            )
        artifact = hash_artifact(
            self.recon_path,
            root=self.root,
            role="database",
            media_type="application/vnd.sqlite3",
        )
        self.handoff_path = self.root / "Handoff.json"
        self.handoff_path.write_text(
            HandoffManifest(
                scan_id="scan",
                db_path="Recon.db",
                artifacts=[artifact],
            ).model_dump_json(indent=2),
            encoding="utf-8",
        )

    def test_materialization_preserves_recon_and_records_source(self) -> None:
        source_before = self.recon_path.read_bytes()
        source_digest = hashlib.sha256(source_before).hexdigest()
        pipeline_path = self.root / "Pipeline.db"

        result = materialize_pipeline(self.handoff_path, pipeline_path)

        self.assertEqual(result.pipeline_path, pipeline_path)
        self.assertEqual(result.scan_id, "scan")
        self.assertEqual(result.recon_database_sha256, source_digest)
        self.assertEqual(self.recon_path.read_bytes(), source_before)
        with sqlite3.connect(self.recon_path) as source:
            self.assertEqual(source.execute("PRAGMA user_version").fetchone()[0], 4)
            source_schema = source.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
        with sqlite3.connect(pipeline_path) as pipeline:
            self.assertEqual(pipeline.execute("PRAGMA user_version").fetchone()[0], 10)
            self.assertEqual(
                pipeline.execute(
                    """SELECT scan_id,source_database_sha256
                    FROM pipeline_sources"""
                ).fetchone(),
                ("scan", source_digest),
            )
            self.assertEqual(
                pipeline.execute(
                    "SELECT scope_value FROM scans WHERE scan_id='scan'"
                ).fetchone(),
                ("scope",),
            )
            with self.assertRaises(sqlite3.IntegrityError):
                pipeline.execute(
                    "UPDATE pipeline_sources SET source_database_sha256=?",
                    ("0" * 64,),
                )
        with sqlite3.connect(self.recon_path) as source:
            self.assertEqual(
                source.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                ).fetchall(),
                source_schema,
            )

    def test_live_migration_is_idempotent_on_v4_copy(self) -> None:
        pipeline_path = self.root / "Pipeline.db"
        materialize_pipeline(self.handoff_path, pipeline_path)

        with sqlite3.connect(pipeline_path) as connection:
            migrate_live_pipeline_schema(connection)
            migrate_live_pipeline_schema(connection)
            connection.commit()

            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 10)
            self.assertEqual(
                connection.execute(
                    "SELECT scan_id FROM pipeline_sources"
                ).fetchall(),
                [("scan",)],
            )

    def test_tampered_recon_is_rejected_before_copy(self) -> None:
        with self.recon_path.open("ab") as stream:
            stream.write(b"tampered")

        with self.assertRaisesRegex(ValueError, "integrity mismatch"):
            materialize_pipeline(
                self.handoff_path,
                self.root / "Pipeline.db",
            )


if __name__ == "__main__":
    unittest.main()
