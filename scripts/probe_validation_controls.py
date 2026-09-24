"""Record response codes for the read-only local-lab answer-key probes.

The report contains no response bodies, credentials, or data returned by the apps.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

try:
    from scripts.build_validation_candidates import (
        JUICE_IMAGE_DIGEST, VULN_BANK_COMMIT, VULN_BANK_FILE_SHA256,
    )
except ModuleNotFoundError:  # Direct `python scripts/probe_validation_controls.py`.
    from build_validation_candidates import (
        JUICE_IMAGE_DIGEST, VULN_BANK_COMMIT, VULN_BANK_FILE_SHA256,
    )

ROOT = Path(__file__).resolve().parents[1]
BASE_URLS = {"juice-shop": "http://127.0.0.1:3001", "vuln-bank": "http://127.0.0.1:5001"}
EXPECTED_IMAGES = {
    "juice-shop": f"bkimminich/juice-shop@{JUICE_IMAGE_DIGEST}",
    "vuln-bank": "aidast-lab/vuln-bank:5e5ea5425fcf",
}


def _command(*arguments: str) -> str:
    return subprocess.run(arguments, capture_output=True, text=True,
                          check=True, timeout=20).stdout.strip()


def verify_runtime_identity() -> dict:
    """Bind local observations to the running Compose images and pinned source."""
    checkout = ROOT / "result/lab/vuln-bank"
    revision = _command("git", "-C", str(checkout), "rev-parse", "HEAD")
    if revision != VULN_BANK_COMMIT:
        raise ValueError("VulnBank checkout differs from pinned commit")
    for filename, expected in VULN_BANK_FILE_SHA256.items():
        if hashlib.sha256((checkout / filename).read_bytes()).hexdigest() != expected:
            raise ValueError(f"VulnBank source differs from pinned file: {filename}")
    raw = _command("docker", "compose", "-f", str(ROOT / "lab/compose.yaml"),
                   "ps", "--format", "json")
    containers = [json.loads(line) for line in raw.splitlines() if line.strip()]
    result = {"vuln_bank_commit": revision, "services": {}}
    for service, expected_image in EXPECTED_IMAGES.items():
        matches = [item for item in containers if item.get("Service") == service]
        if len(matches) != 1 or matches[0].get("State") != "running":
            raise ValueError(f"local lab service is not running exactly once: {service}")
        item = matches[0]
        port = int(BASE_URLS[service].rsplit(":", 1)[1])
        if item.get("Image") != expected_image or not any(
            published.get("URL") == "127.0.0.1" and published.get("PublishedPort") == port
            for published in item.get("Publishers") or []
        ):
            raise ValueError(f"local lab image or published port differs: {service}")
        running_id = _command("docker", "inspect", item["ID"], "--format", "{{.Image}}")
        expected_id = _command("docker", "image", "inspect", expected_image,
                               "--format", "{{.Id}}")
        if running_id != expected_id:
            raise ValueError(f"running local lab image differs from pinned reference: {service}")
        result["services"][service] = {"image_ref": expected_image, "image_id": running_id,
                                       "published_port": port}
    return result


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        return None


def fetch_status_and_digest(url: str) -> tuple[int, str, int]:
    """Read one bounded GET response from exactly the requested URL."""
    opener = build_opener(_NoRedirect)
    try:
        with opener.open(Request(url, method="GET", headers={"Accept": "application/json"}), timeout=5) as response:
            if response.geturl() != url:
                raise ValueError("local probe response URL changed")
            status = response.status
            body = response.read(1_048_577)
    except HTTPError as error:
        status = error.code
        body = error.read(1_048_577)
        error.close()
    if len(body) > 1_048_576:
        raise ValueError("local probe response exceeded bounded size")
    return status, hashlib.sha256(body).hexdigest(), len(body)


def request_path(candidate: dict) -> str:
    path = candidate["path"]
    probe = candidate["probe"]
    if ":id" in path:
        path = path.replace(":id", quote(str(probe["path_value"]), safe=""))
    if "<int:" in path:
        path = re.sub(r"<int:[^>]+>", quote(str(probe["path_value"]), safe=""), path)
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        default=ROOT / "result/test-runs/validation-candidates/LocalControlObservations.json")
    args = parser.parse_args()
    controls = json.loads((ROOT / "resources/lab/validation-control-candidates.json").read_text())
    answers = json.loads((ROOT / "resources/lab/validation-answer-key.json").read_text())
    identity = verify_runtime_identity()
    by_id = {item["candidate_id"]: item for item in controls}
    rows = []
    for answer in answers:
        if answer["evidence_level"] != "source_and_local_http":
            continue
        candidate = by_id.get(answer["candidate_id"])
        if candidate is None:
            # The positive /debug/users entry is sourced from the curated inventory.
            if answer["candidate_id"] != "vuln-bank:curated:GET:/debug/users:excessive_data_exposure":
                raise ValueError(f"unknown live-probe candidate: {answer['candidate_id']}")
            candidate = {"project": "vuln-bank", "method": "GET", "path": "/debug/users", "probe": {}}
        if candidate["method"] != "GET":
            raise ValueError("local control probes must be read-only GET requests")
        url = BASE_URLS[candidate["project"]] + request_path(candidate)
        observed, body_hash, body_length = fetch_status_and_digest(url)
        expected = answer["observed_http_status"]
        rows.append({"candidate_id": answer["candidate_id"], "method": "GET",
                     "url": url, "authorization": "none", "observed_http_status": observed,
                     "response_body_sha256": body_hash,
                     "response_bytes": body_length,
                     "answer_key_http_status": expected, "matches_answer_key": observed == expected})
    report = {"observed_at_utc": datetime.now(timezone.utc).isoformat(),
              "scope": "local educational lab, bounded GET response metadata only",
              "runtime_identity": identity, "observations": rows}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"{len(rows)} read-only probes; {sum(row['matches_answer_key'] for row in rows)} matched; report={args.output}")
    if not all(row["matches_answer_key"] for row in rows):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
