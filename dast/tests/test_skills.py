from __future__ import annotations

import tempfile
import unittest
from importlib.resources import files
from pathlib import Path

from aidast.agents.main import CodexMainAgent


class NativeSkillTests(unittest.TestCase):
    def test_scope_skill_uses_codex_standard_frontmatter(self) -> None:
        content = files("aidast.skills.scope").joinpath("SKILL.md").read_text(
            encoding="utf-8"
        )

        self.assertTrue(content.startswith("---\n"))
        self.assertIn("name: aidast-scope", content)
        self.assertIn("description:", content)
        self.assertIn("# Collection Rules", content)
        self.assertIn("# Interpretation Rules", content)

    def test_stages_scope_skill_in_codex_native_discovery_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            work_dir = Path(temporary_dir)
            CodexMainAgent._stage_native_skill(
                work_dir=work_dir,
                package="aidast.skills.scope",
                skill_name="aidast-scope",
            )

            staged = (
                work_dir
                / ".agents"
                / "skills"
                / "aidast-scope"
                / "SKILL.md"
            )
            self.assertTrue(staged.is_file())
            self.assertIn("name: aidast-scope", staged.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
