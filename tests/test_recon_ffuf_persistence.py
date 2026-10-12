"""Offline tool-output transport tests: subprocess and target traffic are mocked."""
import json
from pathlib import Path
from types import SimpleNamespace

from aidast.recon import db
from aidast.recon.annotations import ObservationRecorder
from aidast.recon.tools import endpoint_discovery as discovery


def test_generated_priority_words_first_root_reports_reach_recon_db(tmp_path, monkeypatch):
    base = "https://example.test/"
    operator_words = tmp_path / "words.txt"
    operator_words.write_text("zulu\nalpha\nhealthz\n", encoding="utf-8")
    commands = []
    ordered_words = []
    expected_words = list(discovery._FFUF_DISCOVERY_PRIORITY[:6])

    def fake_process(command, **_options):
        commands.append(command)
        words = Path(command[command.index("-w") + 1]).read_text(encoding="utf-8").splitlines()
        ordered_words.extend(words)
        assert words[:6] == expected_words
        assert len(words) == len(set(words))
        assert command[command.index("-u") + 1] == base + "FUZZ"
        # Synthetic pre-recorded tool results exercise transport only. No
        # process launches, target requests, or source-baseline input occur.
        Path(command[command.index("-o") + 1]).write_text(json.dumps({
            "results": [{"input": {"FUZZ": word}, "status": 200,
                         "content-type": "application/json", "length": 2}
                        for word in expected_words]
        }), encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(discovery.shutil, "which", lambda _tool: "/mock/ffuf")
    monkeypatch.setattr(discovery.subprocess, "run", fake_process)
    budget_calls = iter([True, False])
    rows = discovery.discover_with_ffuf(
        base, wordlist=str(operator_words), seed_endpoints=[{"method": "GET", "path": "/"}],
        auth_headers=None, root_selector=lambda _seeds: ["/", "/api"],
        budget_available=lambda: next(budget_calls),
    )
    assert len(commands) == 1
    assert ordered_words[:6] == expected_words
    assert len(rows) == len(expected_words)

    with db.connect(tmp_path / "Recon.db") as connection:
        db.insert_scan(connection, scan_id="scan", scope_type="url", scope_value=base)
        asset = db.insert_asset(connection, scan_id="scan", identifier="example.test", asset_type="URL")
        origin = db.upsert_origin(connection, asset_id=asset, scheme="https", host="example.test",
                                  port=443, base_url=base)
        ObservationRecorder(connection, origin_id=origin, scan_id="scan").record("ffuf", rows)

        persisted = connection.execute(
            "SELECT method,path,verification_status FROM endpoints").fetchall()
        assert set(persisted) == {("GET", "/" + word, "verified") for word in expected_words}
        observations = connection.execute(
            "SELECT source_tool,discovery_kind,evidence_json FROM endpoint_observations").fetchall()
        assert len(observations) == len(expected_words)
        for source, kind, evidence_json in observations:
            evidence = json.loads(evidence_json)
            assert (source, kind) == ("ffuf", "http_response")
            assert evidence["response_status"] == 200
            assert evidence["fuzz_root"] == "/"
            assert evidence["source"] == "ffuf"
