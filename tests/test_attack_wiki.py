from __future__ import annotations

import json
import sqlite3

import pytest

from aidast.attack.wiki import (
    AttackWikiError,
    compare_sources,
    database_snapshot,
    ingest_database,
    lint_wiki,
    prioritize_runtime_history,
)
from aidast.attack.wiki_cli import main
from aidast.pipeline.live_schema import migrate_live_pipeline_schema
from aidast.recon.db import init_db
from aidast.web.attack_wiki import AttackWikiCatalog


def database(path, *, scan="run", started="2026-01-02", source=False, status="completed", request=True,
             coverage_status="tested_negative", confirmed=False, method="GET", parameter="id", identity="unauthenticated"):
    conn = init_db(path)
    migrate_live_pipeline_schema(conn)
    conn.commit()
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("INSERT INTO scans(scan_id,scope_type,scope_value,status,started_at,finished_at) VALUES (?,?,?,?,?,?)",
                 (scan, "source_import" if source else "URL", "https://lab.test", "completed", started, started))
    conn.execute("INSERT INTO assets(asset_id,scan_id,identifier,asset_type) VALUES ('asset',?,'lab.test','URL')", (scan,))
    conn.execute("INSERT INTO origins(origin_id,asset_id,base_url) VALUES ('origin','asset','https://lab.test')")
    conn.execute("INSERT INTO endpoints(endpoint_id,origin_id,method,path,normalized_path,source_tools) "
                 "VALUES ('endpoint','origin',?,'/items/:id','/items/:id',?)", (method, "flask_source_import" if source else "katana"))
    conn.execute("INSERT INTO stage_runs(stage_run_id,scan_id,stage,status,started_at,finished_at) VALUES ('stage',?,'attack',?,?,?)",
                 (scan, status, started, started if status != "running" else None))
    conn.execute("""INSERT INTO attack_coverage_items(coverage_id,coverage_key,scan_id,endpoint_id,annotation_id,
                 vuln_class,skill_name,injection_location,parameter_name,required_identity_role,status,last_stage_run_id,
                 last_task_id,finding_id) VALUES ('coverage',?,?,'endpoint','annotation','idor','hunt-idor','path',?,?,?,'stage','task',?)""",
                 ("a"*64, scan, parameter, identity, coverage_status, "finding" if confirmed else None))
    if request:
        conn.execute("""INSERT INTO attack_http_requests(request_id,scan_id,stage_run_id,task_id,policy_id,method,url,
                 request_fingerprint,status,response_status,scheduled_at,finished_at,endpoint_reference_id)
                 VALUES ('request',?,'stage','task','policy',?,'https://lab.test/items/1?secret=redacted',?,'completed',200,0,1,'endpoint')""",
                 (scan, method, "b"*64))
    if confirmed:
        conn.execute("""INSERT INTO validation_cases(case_id,scan_id,target_kind,finding_id,latest_stage_run_id,
                 processing_phase,current_status,decision_json,decision_sha256)
                 VALUES ('case',?,'finding','finding','stage','completed','CONFIRMED','{}',?)""", (scan, "c"*64))
    conn.commit()
    conn.close()
    return path


def ingest(root, path, *, kind="runtime"):
    return ingest_database(root, path, kind=kind, target_id="lab")


def test_real_shared_schema_readonly_idempotent_and_no_replay_secrets(tmp_path):
    path = database(tmp_path / "Pipeline.db")
    original = path.read_bytes()
    first = ingest(tmp_path / "Wiki", path)
    second = ingest(tmp_path / "Wiki", path)
    assert first["source_id"] == second["source_id"]
    assert first["created"] and not second["created"]
    assert first["tested_count"] == 1 and first["confirmed_count"] == 0
    assert first["execution_mode"] == "black_box"
    assert path.read_bytes() == original
    raw = (tmp_path / "Wiki/raw" / (first["source_id"] + ".json")).read_text()
    assert "secret=redacted" not in raw and "payload" not in raw
    assert lint_wiki(tmp_path / "Wiki") == ()


@pytest.mark.parametrize("mutation", [
    "UPDATE attack_http_requests SET status='outcome_unknown',response_status=NULL",
    "UPDATE attack_http_requests SET task_id='foreign'",
    "UPDATE attack_http_requests SET method='POST'",
    "UPDATE attack_http_requests SET url='https://foreign.test/items/1'",
])
def test_unbound_or_unknown_requests_do_not_count_as_actual_tests(tmp_path, mutation):
    path = database(tmp_path / "Pipeline.db")
    with sqlite3.connect(path) as conn:
        conn.execute(mutation)
    assert ingest(tmp_path / "Wiki", path)["tested_count"] == 0


def test_runtime_requires_terminal_stage_but_source_is_evaluation_only(tmp_path):
    path = database(tmp_path / "Pipeline.db", status="running", source=True)
    with pytest.raises(AttackWikiError, match="terminal"):
        ingest(tmp_path / "Wiki", path)
    source = ingest(tmp_path / "Wiki", path, kind="source")
    assert source["execution_mode"] == "source_assisted" and source["tested_count"] == 0


def test_runtime_requires_terminal_scan_even_when_attack_stage_has_finished(tmp_path):
    path = database(tmp_path / "Pipeline.db")
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE scans SET status='running',finished_at=NULL")
    with pytest.raises(AttackWikiError, match="terminal"):
        database_snapshot(path, kind="runtime")


def test_post_run_benchmark_catalog_remains_evaluation_only(tmp_path):
    path = database(tmp_path / "Pipeline.db")
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("INSERT INTO annotation_runs(annotation_run_id,scan_id,model,prompt_version,"
                     "taxonomy_version,status) VALUES ('catalog-run','run','test','test','test','completed')")
        conn.execute("INSERT INTO endpoint_annotations(annotation_id,annotation_run_id,observation_id,"
                     "category,tag,confidence,rationale,created_at) VALUES "
                     "('catalog','catalog-run','observation','benchmark_catalog_vulnerability',"
                     "'idor',1,'claim','2026-01-02')")
    assert database_snapshot(path, kind="runtime")["execution_mode"] == "black_box"


def test_executed_catalog_coverage_marks_source_assisted_execution(tmp_path):
    path = database(tmp_path / "Pipeline.db")
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("INSERT INTO annotation_runs(annotation_run_id,scan_id,model,prompt_version,"
                     "taxonomy_version,status) VALUES ('catalog-run','run','test','test','test','completed')")
        conn.execute("INSERT INTO endpoint_annotations(annotation_id,annotation_run_id,observation_id,"
                     "category,tag,confidence,rationale,created_at) VALUES "
                     "('catalog','catalog-run','observation','benchmark_catalog_vulnerability',"
                     "'idor',1,'claim','2026-01-02')")
        conn.execute("UPDATE attack_coverage_items SET annotation_id='catalog'")
    assert database_snapshot(path, kind="runtime")["execution_mode"] == "source_assisted"


def test_missing_tests_keep_policy_auth_and_unsupported_dispositions_separate(tmp_path):
    root = tmp_path / "Wiki"
    baselines = [ingest(root, database(tmp_path / f"{parameter}.db", scan=parameter,
                                    source=True, parameter=parameter), kind="source")["source_id"]
                 for parameter in ("id", "policy", "auth", "budget", "unplanned")]
    path = database(tmp_path / "observed.db")
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA foreign_keys=OFF")
        for parameter, status in (("policy", "policy_excluded"), ("auth", "blocked_auth"),
                                  ("budget", "unsupported")):
            conn.execute("""INSERT INTO attack_coverage_items(coverage_id,coverage_key,scan_id,
                endpoint_id,annotation_id,vuln_class,skill_name,injection_location,parameter_name,
                required_identity_role,status) VALUES (?,?, 'run','endpoint',?,'idor',
                'hunt-idor','path',?,'unauthenticated',?)""",
                (parameter, parameter.ljust(64, "x"), parameter, parameter, status))
    observed = ingest(root, path)
    score = compare_sources(root, observed_source_id=observed["source_id"],
                            baseline_source_ids=baselines)
    assert score["baseline_count"] == 5 and score["tested_recall"] == 1 / 5
    assert score["missing_disposition_counts"] == {
        "policy_excluded": 1, "blocked_auth": 1, "unsupported": 1, "not_planned": 1}
    assert len(score["missing"]) == 4
    assert "not verified eligibility" in score["denominator_semantics"]


def test_confirmation_requires_completed_independent_validation(tmp_path):
    path = database(tmp_path / "Pipeline.db", confirmed=True, coverage_status="confirmed")
    assert ingest(tmp_path / "Wiki", path)["confirmed_count"] == 1
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE validation_cases SET current_status='DISPROVEN'")
    updated = ingest(tmp_path / "Wiki", path)
    assert updated["confirmed_count"] == 0 and updated["candidate_count"] == 1
    assert len(list((tmp_path / "Wiki/raw").glob("*.json"))) == 2
    history = next((tmp_path / "Wiki/wiki/targets").glob("*.md")).read_text()
    assert "CONFIRMED" in history and "DISPROVEN" in history


@pytest.mark.parametrize("changes", [{"method":"POST"}, {"parameter":"other"}, {"identity":"authenticated"}])
def test_exact_recall_preserves_method_input_and_identity_boundaries(tmp_path, changes):
    baseline = database(tmp_path / "baseline.db", scan="baseline", source=True)
    observed = database(tmp_path / "observed.db", **changes)
    root = tmp_path / "Wiki"
    first, second = ingest(root, baseline, kind="source"), ingest(root, observed)
    score = compare_sources(root, observed_source_id=second["source_id"], baseline_source_ids=[first["source_id"]])
    assert score["tested_recall"] == 0 and len(score["missing"]) == 1


def test_historical_union_deduplicates_and_negative_baseline_has_no_positive_recall(tmp_path):
    root = tmp_path / "Wiki"
    a = ingest(root, database(tmp_path / "a.db", scan="a", started="2026-01-01"))
    b = ingest(root, database(tmp_path / "b.db", scan="b", started="2026-01-02"))
    c = ingest(root, database(tmp_path / "c.db", scan="c", started="2026-01-03"))
    result = compare_sources(root, observed_source_id=c["source_id"], baseline_source_ids=[a["source_id"],b["source_id"]])
    assert result["baseline_count"] == 1 and result["tested_recall"] == 1
    assert result["baseline_positive_count"] == 0 and result["confirmed_recall"] is None
    with pytest.raises(AttackWikiError, match="precede"):
        compare_sources(root, observed_source_id=a["source_id"], baseline_source_ids=[c["source_id"]])


def test_raw_mutation_is_detected(tmp_path):
    root = tmp_path / "Wiki"
    source = ingest(root, database(tmp_path / "Pipeline.db"))
    path = root / "raw" / (source["source_id"] + ".json")
    value = json.loads(path.read_text())
    value["inventory"]["items"][0]["status"] = "confirmed"
    path.write_text(json.dumps(value))
    assert "integrity" in lint_wiki(root)[0]


def test_snapshot_includes_committed_wal_evidence(tmp_path):
    path = database(tmp_path / "Pipeline.db", request=False)
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA wal_autocheckpoint=0")
        conn.execute("""INSERT INTO attack_http_requests(request_id,scan_id,stage_run_id,task_id,policy_id,
            method,url,request_fingerprint,status,response_status,scheduled_at,finished_at,endpoint_reference_id)
            VALUES ('wal-request','run','stage','task','policy','GET','https://lab.test/items/1',?,
            'completed',200,0,1,'endpoint')""", ("d"*64,))
        conn.commit()
        snapshot = database_snapshot(path, kind="runtime")
        assert snapshot["items"][0]["tested"]
        assert snapshot["items"][0]["request_ids"] == ["wal-request"]


def test_independent_positive_recall_uses_confirmed_historical_denominator(tmp_path):
    root = tmp_path / "Wiki"
    baseline = ingest(root, database(tmp_path / "a.db", scan="a", started="2026-01-01",
                                    confirmed=True, coverage_status="confirmed"))
    observed = ingest(root, database(tmp_path / "b.db", scan="b", confirmed=True, coverage_status="candidate"))
    score = compare_sources(root, observed_source_id=observed["source_id"],
                            baseline_source_ids=[baseline["source_id"]])
    assert score["baseline_positive_count"] == 1
    assert score["candidate_recall"] == 1 and score["confirmed_recall"] == 1


def test_dashboard_opaque_ids_and_symlink_boundary(tmp_path):
    root = tmp_path / "result"
    database(root / "run/Pipeline.db")
    outside = database(tmp_path / "outside/Pipeline.db", scan="outside")
    (root / "escape").symlink_to(outside.parent, target_is_directory=True)
    catalog = AttackWikiCatalog(root)
    entries = catalog.public_entries()
    assert len(entries) == 1 and not any(key.startswith("_") for key in entries[0])
    result = catalog.accumulate("run", program_id="program")
    assert result["tested_count"] == 1 and result["lint"]["ok"]
    assert catalog.status("run", program_id="program")["source_id"] == result["source_id"]


def test_dashboard_rejects_disjoint_application_baseline(tmp_path):
    root = tmp_path / "result"
    database(root / "runtime/Pipeline.db")
    baseline_path = database(
        root / "different-app/Pipeline.db", scan="source", source=True
    )
    with sqlite3.connect(baseline_path) as conn:
        conn.execute(
            "UPDATE endpoints SET path='/foreign/:id',normalized_path='/foreign/:id'"
        )
    catalog = AttackWikiCatalog(root)
    baseline = next(item for item in catalog.entries() if item["scan_id"] == "source")
    assert "different-app" in baseline["label"]
    with pytest.raises(AttackWikiError, match="route inventory does not overlap"):
        catalog.accumulate(
            "run", program_id="program", baseline_id=baseline["database_id"],
            baseline_kind="source",
        )


def test_cli_ingests_and_lints(tmp_path, capsys):
    path = database(tmp_path / "Pipeline.db")
    root = tmp_path / "Wiki"
    assert main(["ingest", str(path), "--kind", "runtime", "--root", str(root)]) == 0
    assert json.loads(capsys.readouterr().out)["tested_count"] == 1
    assert main(["lint", "--root", str(root)]) == 0


def test_runtime_modules_do_not_consume_evaluation_wiki():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / "src/aidast"
    for name in ("attack/planner.py", "attack/recon_hypotheses.py", "attack/runtime.py",
                 "attack/agent.py", "orchestration/coverage_attack.py"):
        assert "attack.wiki" not in (root / name).read_text()
        assert "candidate_baseline" not in (root / name).read_text()
        assert "build_juice_shop_attack_baseline" not in (root / name).read_text()
    attack_coordinator = (root / "orchestration/attack.py").read_text()
    assert "prioritize_runtime_history" in attack_coordinator
    assert "candidate_baseline" not in attack_coordinator


def test_runtime_history_only_seeds_coordinate_priority_from_prior_blackbox(
    tmp_path,
) -> None:
    wiki_root = tmp_path / "AttackWiki"
    target_wiki = wiki_root / "juice-shop-history"
    historical = database(
        tmp_path / "historical.db", scan="historical", started="2026-01-01",
        confirmed=True, coverage_status="candidate",
    )
    source = database(
        tmp_path / "source.db", scan="source", started="2026-01-01",
        source=True, confirmed=True, coverage_status="candidate",
    )
    ingest_database(target_wiki, historical, kind="runtime", target_id="juice-shop")
    ingest_database(target_wiki, source, kind="source", target_id="juice-shop")
    current = database(
        tmp_path / "current.db", scan="current", started="2026-01-03",
        coverage_status="pending", request=False,
    )

    assert prioritize_runtime_history(
        wiki_root, current, scan_id="current", target_hint="juice-shop-current",
    ) == 1
    with sqlite3.connect(current) as conn:
        row = conn.execute(
            """SELECT fact_key,fact_value FROM attack_facts
               WHERE fact_type='historical_runtime_priority'"""
        ).fetchone()
    assert row[0] == "coverage"
    assert json.loads(row[1]) == {
        "historical_black_box_candidate": True,
        "matching_snapshot_count": 1,
    }


def test_api_requires_terminal_scan_and_same_origin(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from aidast.web.server import create_app
    root = tmp_path / "result"
    database(root / "run/Pipeline.db")
    app = create_app(result_root=root)
    state = {"scan_id": "run", "status": "running", "program_id": "program"}
    monkeypatch.setattr(app.state.projector, "snapshot", lambda scan_id: state)
    with TestClient(app) as client:
        assert len(client.get("/api/v1/attack-wiki/databases").json()["databases"]) == 1
        headers = {"Origin": "http://testserver"}
        assert client.post("/api/v1/scans/run/attack-wiki", json={}, headers=headers).status_code == 409
        state["status"] = "completed"
        assert client.post("/api/v1/scans/run/attack-wiki", json={}).status_code == 403
        result = client.post("/api/v1/scans/run/attack-wiki", json={}, headers=headers)
        assert result.status_code == 200 and result.json()["tested_count"] == 1
        assert client.get("/api/v1/scans/run/attack-wiki").json()["configured"]


@pytest.mark.parametrize("kind", ["source", "benchmark"])
def test_source_provenance_does_not_make_unadjudicated_coordinates_positive(tmp_path, kind):
    root = tmp_path / "Wiki"
    baseline = ingest(root, database(tmp_path / "source.db", scan="source", source=True), kind=kind)
    observed = ingest(root, database(tmp_path / "observed.db", confirmed=True, coverage_status="candidate"))
    result = compare_sources(root, observed_source_id=observed["source_id"],
                             baseline_source_ids=[baseline["source_id"]])
    assert result["baseline_count"] == 1 and result["tested_recall"] == 1
    assert result["baseline_positive_count"] == 0
    assert result["candidate_recall"] is None and result["confirmed_recall"] is None


def official_candidates():
    from pathlib import Path
    from scripts.build_validation_candidates import juice_candidates
    source = Path(__file__).resolve().parents[1] / "resources/lab/juice-shop-v20.2.0-challenges.yml"
    return juice_candidates(source)


def candidate_baseline(root, observed, *, manifest=None):
    from aidast.attack.candidate_baseline import ingest_candidate_baseline
    from scripts.build_validation_candidates import JUICE_VERSION, JUICE_SHA256
    return ingest_candidate_baseline(root, official_candidates(), project="juice-shop",
                                     observed_source_id=observed["source_id"],
                                     source_version=JUICE_VERSION, source_sha256=JUICE_SHA256,
                                     mapping_manifest=manifest)


def reviewed_manifest(entries):
    from scripts.build_validation_candidates import JUICE_VERSION, JUICE_SHA256
    return {"schema_version": 1, "project": "juice-shop", "source_version": JUICE_VERSION,
            "source_sha256": JUICE_SHA256, "entries": entries}


def reviewed_entry(candidate_id, *, verdict="UNASSESSED"):
    return {"candidate_id": candidate_id, "mapping_evidence_ref": "fixture:exact-coordinate-review",
            "adjudication_status": verdict,
            "adjudication_evidence_ref": "fixture:independent-review" if verdict != "UNASSESSED" else None,
            "coordinates": [{"origin": "https://lab.test", "method": "GET", "path": "/items/:id",
                             "vuln_class": "idor", "injection_location": "path", "parameter_name": "id",
                             "required_identity_role": "unauthenticated"}]}


def test_all_official_candidates_remain_unmapped_unassessed_without_a_review(tmp_path):
    root = tmp_path / "AttackWiki"
    path = database(tmp_path / "Pipeline.db")
    before = path.read_bytes()
    observed = ingest(root, path)
    first = candidate_baseline(root, observed)
    raw_path = root / "raw" / (first["source_id"] + ".json")
    raw = raw_path.read_bytes()
    second = candidate_baseline(root, observed)
    result = compare_sources(root, observed_source_id=observed["source_id"],
                             baseline_source_ids=[first["source_id"]])
    assert first["source_candidate_count"] == 116
    assert first["unmapped_candidate_count"] == first["unassessed_candidate_count"] == 116
    assert first["tested_count"] == first["candidate_count"] == first["confirmed_count"] == 0
    assert first["source_id"] == second["source_id"] and not second["created"]
    assert raw_path.read_bytes() == raw and path.read_bytes() == before
    assert result["baseline_count"] == result["baseline_positive_count"] == 0
    assert result["tested_recall"] is None and result["candidate_recall"] is None
    assert result["confirmed_recall"] is None and len(result["unmapped_source_candidates"]) == 116
    assert lint_wiki(root) == ()
    snapshot = json.loads(raw)["inventory"]
    assert snapshot["evaluation_only"] and snapshot["execution_mode"] == "evaluation_only"
    assert snapshot["bound_observed_source_id"] == observed["source_id"]
    assert {row["evaluation_status"] for row in snapshot["source_candidates"]} == {
        "UNASSESSED", "OUT_OF_TEST_SCOPE", "MANUAL_ONLY"}
    assert all("description" not in row for row in snapshot["source_candidates"])


@pytest.mark.parametrize("verdict,positive", [("UNASSESSED", 0), ("VULNERABLE", 1), ("NOT_VULNERABLE", 0)])
def test_mapping_and_positive_adjudication_are_independent(tmp_path, verdict, positive):
    root = tmp_path / "Wiki"
    observed = ingest(root, database(tmp_path / "observed.db", confirmed=True, coverage_status="candidate"))
    candidate_id = next(row["candidate_id"] for row in official_candidates() if row["evaluation_status"] == "UNASSESSED")
    baseline = candidate_baseline(root, observed, manifest=reviewed_manifest([reviewed_entry(candidate_id, verdict=verdict)]))
    result = compare_sources(root, observed_source_id=observed["source_id"],
                             baseline_source_ids=[baseline["source_id"]])
    assert result["baseline_count"] == 1 and result["tested_recall"] == 1
    assert result["baseline_positive_count"] == positive
    assert result["mapped_candidate_count"] == 1 and result["unmapped_candidate_count"] == 115
    assert result["candidate_recall"] == (1 if positive else None)
    assert result["confirmed_recall"] == (1 if positive else None)


def test_unmapped_positive_and_source_exclusions_never_enter_positive_denominator(tmp_path):
    root = tmp_path / "Wiki"
    observed = ingest(root, database(tmp_path / "observed.db"))
    rows = official_candidates()
    available = next(row["candidate_id"] for row in rows if row["evaluation_status"] == "UNASSESSED")
    excluded = next(row["candidate_id"] for row in rows if row["evaluation_status"] == "OUT_OF_TEST_SCOPE")
    unmapped = {**reviewed_entry(available, verdict="VULNERABLE"), "coordinates": []}
    baseline = candidate_baseline(root, observed, manifest=reviewed_manifest([
        unmapped, reviewed_entry(excluded, verdict="VULNERABLE")]))
    result = compare_sources(root, observed_source_id=observed["source_id"],
                             baseline_source_ids=[baseline["source_id"]])
    assert result["adjudicated_positive_candidate_count"] == 2
    assert result["baseline_positive_count"] == result["baseline_count"] == 0
    assert result["confirmed_recall"] is None


@pytest.mark.parametrize("mutation,error", [
    (lambda manifest: manifest.update(source_sha256="f" * 64), "provenance"),
    (lambda manifest: manifest["entries"][0]["coordinates"][0].pop("parameter_name"), "every exact"),
    (lambda manifest: manifest["entries"][0]["coordinates"][0].update(origin="https://foreign.test"), "origin"),
    (lambda manifest: manifest["entries"][0].pop("mapping_evidence_ref"), "mapping requires"),
    (lambda manifest: manifest["entries"][0].update(adjudication_status="VULNERABLE"), "adjudication requires"),
])
def test_candidate_manifest_requires_version_exact_mapping_and_adjudication_evidence(tmp_path, mutation, error):
    root = tmp_path / "Wiki"
    observed = ingest(root, database(tmp_path / "observed.db"))
    candidate_id = next(row["candidate_id"] for row in official_candidates() if row["evaluation_status"] == "UNASSESSED")
    manifest = reviewed_manifest([reviewed_entry(candidate_id)])
    mutation(manifest)
    with pytest.raises(AttackWikiError, match=error):
        candidate_baseline(root, observed, manifest=manifest)
    assert len(list((root / "raw").glob("*.json"))) == 1


def test_candidate_baseline_requires_post_run_observation(tmp_path):
    from aidast.attack.candidate_baseline import ingest_candidate_baseline
    from scripts.build_validation_candidates import JUICE_VERSION, JUICE_SHA256
    with pytest.raises(AttackWikiError, match="terminal runtime"):
        ingest_candidate_baseline(tmp_path / "Wiki", official_candidates(), project="juice-shop",
                                  observed_source_id="runtime-absent", source_version=JUICE_VERSION,
                                  source_sha256=JUICE_SHA256)
    root = tmp_path / "Wiki"
    running = database(tmp_path / "running.db", source=True, status="running")
    source = ingest(root, running, kind="source")
    with pytest.raises(AttackWikiError, match="terminal runtime"):
        candidate_baseline(root, source)


def test_candidate_union_retains_unassessed_history_and_conflicting_reviews(tmp_path):
    root = tmp_path / "Wiki"
    observed = ingest(root, database(tmp_path / "observed.db"))
    candidate_id = next(row["candidate_id"] for row in official_candidates() if row["evaluation_status"] == "UNASSESSED")
    snapshots = [candidate_baseline(root, observed)]
    for verdict in ("VULNERABLE", "NOT_VULNERABLE"):
        snapshots.append(candidate_baseline(root, observed, manifest=reviewed_manifest([
            reviewed_entry(candidate_id, verdict=verdict)])))
    result = compare_sources(root, observed_source_id=observed["source_id"],
                             baseline_source_ids=[snapshot["source_id"] for snapshot in snapshots])
    assert result["source_candidate_count"] == 116 and result["unassessed_candidate_count"] == 116
    assert result["baseline_adjudication_conflict_count"] == 1 and result["baseline_positive_count"] == 0
    assert {item["adjudication_status"] for item in result["source_candidate_histories"]
            if item["candidate_id"] == candidate_id} == {"UNASSESSED", "VULNERABLE", "NOT_VULNERABLE"}


def test_pinned_juice_builder_guards_application_and_optional_inventory(tmp_path):
    from pathlib import Path
    from scripts.build_juice_shop_attack_baseline import build_baseline
    from scripts.build_validation_candidates import build_inventory, VULN_BANK_COMMIT
    root = tmp_path / "Wiki"
    path = database(tmp_path / "Pipeline.db")
    foreign = ingest(root, path)
    with pytest.raises(AttackWikiError, match="Juice Shop application"):
        build_baseline(root, foreign["source_id"])
    with sqlite3.connect(path) as conn:
        conn.execute("UPDATE endpoints SET path='/rest/products/search',normalized_path='/rest/products/search'")
    observed = ingest(root, path)
    source = Path(__file__).resolve().parents[1] / "resources/lab/juice-shop-v20.2.0-challenges.yml"
    inventory = tmp_path / "CandidateInventory.db"
    build_inventory(inventory, source, {}, vuln_commit=VULN_BANK_COMMIT)
    with sqlite3.connect(inventory) as conn:
        conn.row_factory = sqlite3.Row
        sample = dict(conn.execute("SELECT * FROM attack_candidates LIMIT 1").fetchone())
        for number in range(4):
            control = {**sample, "candidate_id": f"juice-shop:control-{number}",
                       "external_id": f"control-{number}", "claim_basis": "source_code"}
            conn.execute(f"INSERT INTO attack_candidates VALUES ({','.join('?' for _ in control)})", tuple(control.values()))
        assert conn.execute("SELECT COUNT(*) FROM attack_candidates").fetchone()[0] == 120
    before = inventory.read_bytes()
    baseline = build_baseline(root, observed["source_id"], candidate_inventory=inventory)
    assert baseline["source_candidate_count"] == 116 and inventory.read_bytes() == before
    with sqlite3.connect(inventory) as conn:
        conn.execute("DELETE FROM attack_candidates WHERE candidate_id=(SELECT candidate_id FROM attack_candidates LIMIT 1)")
    with pytest.raises(AttackWikiError, match="pinned official Juice Shop set"):
        build_baseline(root, observed["source_id"], candidate_inventory=inventory)
