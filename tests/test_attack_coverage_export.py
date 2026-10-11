from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from aidast.attack.coverage_export import export_coverage_results
from aidast.pipeline.live_schema import migrate_live_pipeline_schema
from aidast.recon import db


def test_export_records_all_three_stage_outcomes(tmp_path: Path) -> None:
    database = tmp_path / "Pipeline.db"
    db.init_db(database).close()
    with sqlite3.connect(database) as conn:
        migrate_live_pipeline_schema(conn)
        conn.execute(
            "INSERT INTO scans(scan_id,scope_type,scope_value,status,finished_at) "
            "VALUES ('scan_test','lab','fixture','completed',CURRENT_TIMESTAMP)"
        )
        conn.execute(
            """INSERT INTO benchmark_catalog_items
               (catalog_item_id,scan_id,ordinal,category,title,source_path,
                source_line,source_ref,source_sha256)
               VALUES ('catalog','scan_test',1,'Fixture','Declared issue',
                       'README.md',10,'fixture-ref',?)""",
            ("a" * 64,),
        )
        conn.execute(
            "INSERT INTO assets(asset_id,scan_id,identifier,asset_type) "
            "VALUES ('asset','scan_test','127.0.0.1','URL')"
        )
        conn.execute(
            "INSERT INTO origins(origin_id,asset_id,base_url) "
            "VALUES ('origin','asset','http://127.0.0.1:5001')"
        )
        conn.execute(
            "INSERT INTO endpoints(endpoint_id,origin_id,method,normalized_path) "
            "VALUES ('endpoint','origin','GET','/fixture')"
        )
        conn.execute(
            "INSERT INTO endpoint_observations"
            "(observation_id,endpoint_id,source_tool,discovery_kind,association_method,observed_at) "
            "VALUES ('observation','endpoint','source','tool_report','direct',CURRENT_TIMESTAMP)"
        )
        conn.execute(
            "INSERT INTO annotation_runs"
            "(annotation_run_id,scan_id,model,prompt_version,taxonomy_version,status) "
            "VALUES ('run','scan_test','source','1','1','completed')"
        )
        conn.execute(
            "INSERT INTO endpoint_annotations VALUES "
            "('annotation','observation','run','source_vulnerability','sqli',"
            "'source marker',1.0,CURRENT_TIMESTAMP)"
        )
        conn.execute(
            """INSERT INTO attack_coverage_items
               (coverage_id,coverage_key,scan_id,endpoint_id,annotation_id,
                vuln_class,skill_name,status,disposition_reason)
               VALUES ('coverage','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                       'scan_test','endpoint','annotation',
                       'sqli','hunt-sqli','tested_negative','no differential')"""
        )

    result = export_coverage_results(database, "scan_test", tmp_path / "result")
    payload = json.loads(Path(result["json"]).read_text(encoding="utf-8"))
    assert payload["total"] == 1
    assert payload["items"][0]["attack"]["status"] == "tested_negative"
    assert payload["items"][0]["validation"]["status"] == "NOT_APPLICABLE"
    assert payload["items"][0]["report"]["status"] == "WITHHELD"
    assert payload["benchmark_catalog"]["total"] == 1
    assert payload["benchmark_catalog"]["assessment_statuses"] == {
        "declared_unassessed": 1,
    }
    assert "coverage" in Path(result["markdown"]).read_text(encoding="utf-8")
