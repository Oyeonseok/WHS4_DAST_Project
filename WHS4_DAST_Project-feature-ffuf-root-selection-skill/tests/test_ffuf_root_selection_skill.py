from __future__ import annotations

import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from aidast.agents.main import CodexMainAgent
from aidast.recon.tools.endpoint_discovery import discover_with_ffuf
from aidast.recon.tools.ffuf_root_selector import (
    FfufRootSelection,
    select_ffuf_roots_from_endpoints,
)


class FfufRootSelectionSkillTests(unittest.TestCase):
    def test_ffuf_root_selection_skill_uses_codex_standard_frontmatter(self) -> None:
        content = (
            files("aidast.skills.ffuf_root_selection")
            .joinpath("SKILL.md")
            .read_text(encoding="utf-8")
        )

        self.assertTrue(content.startswith("---\n"))
        self.assertIn("name: aidast-ffuf-root-selection", content)
        self.assertIn("description:", content)
        self.assertIn("# Safety Boundaries", content)
        self.assertIn("# Selection", content)
        self.assertIn("# Output", content)

    def test_ffuf_root_selection_skill_stages_in_codex_native_discovery_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            work_dir = Path(temporary_dir)
            CodexMainAgent._stage_native_skill(
                work_dir=work_dir,
                package="aidast.skills.ffuf_root_selection",
                skill_name="aidast-ffuf-root-selection",
            )

            staged = (
                work_dir
                / ".agents"
                / "skills"
                / "aidast-ffuf-root-selection"
                / "SKILL.md"
            )
            self.assertTrue(staged.is_file())
            self.assertIn(
                "name: aidast-ffuf-root-selection",
                staged.read_text(encoding="utf-8"),
            )

    def test_selector_uses_pydantic_schema_and_rejects_invented_roots(self) -> None:
        agent_result = FfufRootSelection(
            base_url="",
            roots=["/api/v1", "/invented", "/", "/api", "/api"],
            count=5,
            selection_reason="공통 API 경로를 우선했습니다.",
        )

        with mock.patch.object(
            CodexMainAgent,
            "_run_structured",
            return_value=agent_result,
        ) as run_structured:
            roots = select_ffuf_roots_from_endpoints(
                [
                    {
                        "path": "/api/v1/users/123",
                        "method": "GET",
                        "source": "katana",
                    }
                ],
                max_roots=3,
            )

        self.assertEqual(roots, ["/", "/api", "/api/v1"])
        self.assertIs(
            run_structured.call_args.kwargs["model_type"],
            FfufRootSelection,
        )
        self.assertEqual(
            run_structured.call_args.kwargs["native_skill"],
            (
                "aidast.skills.ffuf_root_selection",
                "aidast-ffuf-root-selection",
            ),
        )

    def test_ffuf_calls_root_selection_before_building_commands(self) -> None:
        with tempfile.NamedTemporaryFile() as wordlist:
            with (
                mock.patch(
                    "aidast.recon.tools.endpoint_discovery.shutil.which",
                    return_value="/usr/local/bin/ffuf",
                ),
                mock.patch(
                    "aidast.recon.tools.endpoint_discovery."
                    "select_ffuf_roots_from_endpoints",
                    return_value=["/api"],
                ) as selector,
                mock.patch(
                    "aidast.recon.tools.endpoint_discovery.subprocess.run",
                    return_value=SimpleNamespace(
                        returncode=0,
                        stdout="",
                        stderr="",
                    ),
                ) as run_ffuf,
            ):
                discover_with_ffuf(
                    "https://example.com",
                    wordlist=wordlist.name,
                    seed_endpoints=[
                        {
                            "path": "/api/v1/users",
                            "source": "katana",
                        }
                    ],
                    auth_headers=None,
                    proxy_url="http://127.0.0.1:8080",
                )

        selector.assert_called_once()
        command = run_ffuf.call_args.args[0]
        self.assertIn("https://example.com/api/FUZZ", command)
        self.assertEqual(command[command.index("-x") + 1], "http://127.0.0.1:8080")


if __name__ == "__main__":
    unittest.main()
