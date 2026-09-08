from __future__ import annotations

import io
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from aidast.auth.codex import CodexAuth, CodexAuthError
from aidast.cli import main


class CodexAuthTests(unittest.TestCase):
    def test_login_delegates_to_codex_and_verifies_status(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir)
            log_path = root / "calls.log"
            executable = root / "codex-test"
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "import os, pathlib, sys\n"
                "log = pathlib.Path(os.environ['AIDAST_TEST_CODEX_LOG'])\n"
                "with log.open('a') as handle: handle.write(' '.join(sys.argv[1:]) + '\\n')\n"
                "raise SystemExit(0)\n",
                encoding="utf-8",
            )
            executable.chmod(executable.stat().st_mode | 0o111)

            with patch.dict(
                os.environ,
                {"AIDAST_TEST_CODEX_LOG": str(log_path)},
            ):
                CodexAuth(executable=str(executable)).login()

            self.assertEqual(
                log_path.read_text(encoding="utf-8").splitlines(),
                ["login", "login status"],
            )

    def test_require_login_rejects_unauthenticated_codex(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            executable = Path(temporary_dir) / "codex-test"
            executable.write_text(
                "#!/usr/bin/env python3\nraise SystemExit(1)\n",
                encoding="utf-8",
            )
            executable.chmod(executable.stat().st_mode | 0o111)

            with self.assertRaisesRegex(CodexAuthError, "aidast login"):
                CodexAuth(executable=str(executable)).require_login()


class LoginCliTests(unittest.TestCase):
    def test_aidast_login_invokes_codex_auth(self) -> None:
        output = io.StringIO()
        with (
            patch("aidast.cli.CodexAuth") as auth_type,
            redirect_stdout(output),
        ):
            result = main(["login"])

        self.assertEqual(result, 0)
        auth_type.return_value.login.assert_called_once_with()
        self.assertIn("Codex login verified", output.getvalue())

    def test_aidast_login_reports_auth_failure(self) -> None:
        errors = io.StringIO()
        with (
            patch("aidast.cli.CodexAuth") as auth_type,
            redirect_stderr(errors),
        ):
            auth_type.return_value.login.side_effect = CodexAuthError("failed")
            result = main(["login"])

        self.assertEqual(result, 1)
        self.assertIn("aidast: failed", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
