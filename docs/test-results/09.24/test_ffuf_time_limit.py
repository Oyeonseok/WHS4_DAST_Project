"""ffuf time limits stay configurable and visible in Recon diagnostics."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from aidast.cli import _parser
from aidast.recon.policy import TargetPolicy
from aidast.recon.tools.endpoint_discovery import discover_with_ffuf
from aidast.scope.models import AssetType


def test_recon_and_run_parse_ffuf_max_time() -> None:
    for command in ("recon", "run"):
        args = _parser().parse_args([
            command,
            "https://lab.aidast.invalid/juice-shop",
            "--target", "http://127.0.0.1:3001/",
            "--ffuf-max-time-seconds", "400",
        ])
        assert args.ffuf_max_time_seconds == 400


def test_ffuf_uses_configured_time_and_reports_wordlist_size() -> None:
    policy = TargetPolicy(
        scope_id="scope", policy_id="policy", asset_type=AssetType.URL,
        asset="https://example.test/", allowed_hosts=["example.test"],
        allowed_ports=[443], allowed_path_prefixes=["/"],
    )
    diagnostics: list[tuple[str, dict]] = []
    commands: list[tuple[list[str], dict]] = []

    def run(command: list[str], **kwargs: object) -> SimpleNamespace:
        commands.append((command, kwargs))
        Path(command[command.index("-o") + 1]).write_text(
            json.dumps({"results": []}), encoding="utf-8"
        )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    with TemporaryDirectory() as directory:
        wordlist = Path(directory) / "words.txt"
        wordlist.write_text("profile\nusers\n", encoding="utf-8")
        with (
            patch("aidast.recon.tools.endpoint_discovery.shutil.which", return_value="/bin/ffuf"),
            patch("aidast.recon.tools.endpoint_discovery.subprocess.run", side_effect=run),
        ):
            discover_with_ffuf(
                "https://example.test/", wordlist=str(wordlist),
                seed_endpoints=[], auth_headers=None,
                proxy_url="http://127.0.0.1:8080", target_policy=policy,
                max_time_seconds=400,
                root_selector=lambda _: ["/"],
                diagnostic_callback=lambda event, **details: diagnostics.append((event, details)),
            )

    command, kwargs = commands[0]
    assert command[command.index("-maxtime") + 1] == "400"
    assert kwargs["timeout"] == 430
    assert ("ffuf_roots", {
        "component": "endpoint_discovery", "root_count": 1, "roots": ["/"],
        "wordlist_lines": 2, "max_time_seconds": 400,
    }) in diagnostics
