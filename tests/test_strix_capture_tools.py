from __future__ import annotations

import json
from types import SimpleNamespace

from aidast.recon.strix_engine.tools.proxy.aidast_capture_tools import _records


def test_native_mitm_records_are_visible_with_stable_derived_ids(tmp_path) -> None:
    capture = tmp_path / "mitm_capture.jsonl"
    allowed = {
        "url": "https://api.example.com/items",
        "method": "GET",
        "policy_blocked": False,
        "response_status": 200,
    }
    capture.write_text(
        "\n".join(
            [
                json.dumps({**allowed, "policy_blocked": True}),
                json.dumps(allowed),
                "incomplete JSON",
            ]
        ),
        encoding="utf-8",
    )
    context = SimpleNamespace(context={"aidast_capture_host_path": str(capture)})

    first = list(_records(context))
    second = list(_records(context))

    assert len(first) == 1
    assert first[0]["url"] == allowed["url"]
    assert first[0]["id"].startswith("capture_00000002_")
    assert second[0]["id"] == first[0]["id"]


def test_capture_reader_requires_explicit_fail_closed_admission(tmp_path) -> None:
    capture = tmp_path / "mitm_capture.jsonl"
    capture.write_text(
        json.dumps({"url": "https://example.com/", "method": "GET"}) + "\n",
        encoding="utf-8",
    )
    context = SimpleNamespace(context={"aidast_capture_host_path": str(capture)})

    assert list(_records(context)) == []
