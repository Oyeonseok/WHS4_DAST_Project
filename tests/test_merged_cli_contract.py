from __future__ import annotations

from unittest.mock import patch

from aidast.cli import _parser, main


def test_shared_validation_cli_contract() -> None:
    parsed = _parser().parse_args(
        ["validate", "run", "Pipeline.db", "--scan-id", "scan"]
    )

    assert parsed.scan_id == "scan"
    assert parsed.database.name == "Pipeline.db"


def test_case_report_cli_contract() -> None:
    parsed = _parser().parse_args(
        [
            "report",
            "run",
            "Pipeline.db",
            "--case-id",
            "case",
            "--platform",
            "hackerone",
        ]
    )

    assert parsed.case_id == "case"
    assert parsed.validation_id is None


def test_integrated_run_requires_tagging_before_handoff() -> None:
    with patch("aidast.cli._run_recon", return_value=0) as run:
        result = main(["run", "https://program.example", "--all-targets"])

    assert result == 0
    assert run.call_args.kwargs["prepare_attack"] is True
    assert run.call_args.args[0].tag_after is True
