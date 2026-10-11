from __future__ import annotations

import unittest
import subprocess
from unittest.mock import patch

from aidast.recon.tools.asset_dns_port import (
    ReconToolError,
    run_naabu,
    run_nmap,
    run_subfinder,
)


class PortPolicyTests(unittest.TestCase):
    def test_subfinder_missing_is_not_reported_as_successful_empty_result(self) -> None:
        with patch("aidast.recon.tools.asset_dns_port.shutil.which", return_value=None):
            with self.assertRaisesRegex(ReconToolError, "설치돼 있지"):
                run_subfinder("example.com")

    def test_subfinder_nonzero_exit_is_a_discovery_failure(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["subfinder"], returncode=1, stdout="", stderr="provider error",
        )
        with (
            patch("aidast.recon.tools.asset_dns_port.shutil.which", return_value="/bin/subfinder"),
            patch("aidast.recon.tools.asset_dns_port.subprocess.run", return_value=completed),
        ):
            with self.assertRaisesRegex(ReconToolError, "provider error"):
                run_subfinder("example.com")

    def test_subfinder_successful_empty_result_stays_distinct(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["subfinder"], returncode=0, stdout="", stderr="",
        )
        with (
            patch("aidast.recon.tools.asset_dns_port.shutil.which", return_value="/bin/subfinder"),
            patch("aidast.recon.tools.asset_dns_port.subprocess.run", return_value=completed),
        ):
            self.assertEqual(run_subfinder("example.com"), [])

    def test_empty_allowed_ports_skip_port_tools(self) -> None:
        with patch("aidast.recon.tools.asset_dns_port._run_tool") as run_tool:
            self.assertEqual(run_naabu(["example.com"], ports=[]), [])
        run_tool.assert_not_called()

        with patch("aidast.recon.tools.asset_dns_port.shutil.which") as which:
            self.assertEqual(run_nmap(["example.com"], ports=[]), [])
        which.assert_not_called()

    def test_naabu_receives_only_policy_allowed_ports(self) -> None:
        with patch(
            "aidast.recon.tools.asset_dns_port._run_tool", return_value=[]
        ) as run_tool:
            run_naabu(["example.com"], ports=[443, 8443])

        self.assertEqual(
            run_tool.call_args.args[0],
            ["naabu", "-silent", "-p", "443,8443"],
        )


if __name__ == "__main__":
    unittest.main()
