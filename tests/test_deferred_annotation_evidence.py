from __future__ import annotations

import json
import tempfile
from pathlib import Path

from aidast.recon import db
from aidast.recon.annotations import (
    AnnotationBatch,
    ObservationRecorder,
    tag_pending_observations,
)


class RecordingAgent:
    def _run_structured(self, **kwargs):
        self.prompt = kwargs["prompt"]
        payload = json.loads(self.prompt.split("\n", 1)[1])
        return AnnotationBatch(
            annotations=[
                {
                    "observation_id": item["observation_id"],
                    "category": "function",
                    "tag": "unknown",
                    "rationale": "근거가 부족함",
                    "confidence": None,
                }
                for item in payload["observations"]
            ]
        )


def test_deferred_tagging_reuses_sanitized_observation_evidence() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        database = Path(temporary) / "Recon.db"
        with db.connect(database) as connection:
            db.insert_scan(
                connection,
                scan_id="scan",
                scope_type="test",
                scope_value="scope",
            )
            asset_id = db.insert_asset(
                connection,
                scan_id="scan",
                identifier="example.com",
                asset_type="DOMAIN",
            )
            origin_id = db.upsert_origin(
                connection,
                asset_id=asset_id,
                scheme="https",
                host="example.com",
                port=443,
                base_url="https://example.com",
            )
            ObservationRecorder(
                connection,
                origin_id=origin_id,
                scan_id="scan",
            ).record(
                "ffuf",
                [
                    {
                        "method": "GET",
                        "path": "/api",
                        "source": "ffuf",
                        "evidence": {
                            "response_status": 401,
                            "content_length": 42,
                        },
                    }
                ],
            )
            agent = RecordingAgent()

            completed, failed = tag_pending_observations(
                connection,
                scan_id="scan",
                agent=agent,
            )

    assert (completed, failed) == (1, 0)
    assert '"response_status": 401' in agent.prompt
    assert '"content_length": 42' in agent.prompt
