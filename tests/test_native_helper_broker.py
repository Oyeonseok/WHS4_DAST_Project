from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from aidast.agents.helper_broker import (
    PIPELINE_DATABASE_TOKEN,
    HelperCommandBroker,
    stage_helper_client,
)
from aidast.pipeline.live_schema import migrate_live_pipeline_schema
from aidast.recon import db


def test_broker_allows_packaged_helper_without_exposing_database_directory() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        work_dir = root / "sandbox"
        work_dir.mkdir()
        database = root / "private" / "Pipeline.db"
        database.parent.mkdir()
        connection = db.init_db(database)
        migrate_live_pipeline_schema(connection)
        db.insert_scan(
            connection,
            scan_id="scan",
            scope_type="test",
            scope_value="scope",
        )
        connection.commit()
        connection.close()

        with HelperCommandBroker(
            database=database,
            work_dir=work_dir,
            python_executable=Path(sys.executable),
        ) as broker:
            client = work_dir / "db_cli.py"
            stage_helper_client(client, broker=broker, helper="attack_db")
            completed = subprocess.run(
                [
                    sys.executable,
                    str(client),
                    "query",
                    "--db",
                    PIPELINE_DATABASE_TOKEN,
                    "--sql",
                    "SELECT scan_id FROM scans",
                ],
                cwd=work_dir,
                text=True,
                capture_output=True,
                check=False,
            )

        assert completed.returncode == 0
        assert '"scan_id": "scan"' in completed.stdout
        assert database.parent != work_dir


def test_broker_rejects_host_paths_before_running_helper() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        work_dir = root / "sandbox"
        work_dir.mkdir()
        database = root / "private" / "Pipeline.db"
        database.parent.mkdir()
        connection = db.init_db(database)
        connection.close()

        broker = HelperCommandBroker(
            database=database,
            work_dir=work_dir,
            python_executable=Path(sys.executable),
        )

        with pytest.raises(ValueError, match="outside the staged work directory"):
            broker.prepare_arguments(
                [
                    "commit-finding",
                    "--db",
                    PIPELINE_DATABASE_TOKEN,
                    "--scan-id",
                    "scan",
                    "--payload",
                    "/etc/passwd",
                ]
            )
        for arguments in (
            [
                "commit-finding",
                f"--db={PIPELINE_DATABASE_TOKEN}",
                "--scan-id=scan",
                "--payload=/etc/passwd",
            ],
            [
                "query",
                f"--db={PIPELINE_DATABASE_TOKEN}",
                "--sql-file=../../etc/passwd",
            ],
            [
                "query",
                "--db=/tmp/alternate.db",
                "--sql=SELECT 1",
            ],
        ):
            with pytest.raises(ValueError):
                broker.prepare_arguments(arguments)
        with pytest.raises(ValueError, match="outside the staged work directory"):
            broker.prepare_arguments(
                [
                    "commit-finding",
                    "--db",
                    PIPELINE_DATABASE_TOKEN,
                    "--scan-id",
                    "scan",
                    "--payload",
                    "../../etc/passwd",
                ]
            )
