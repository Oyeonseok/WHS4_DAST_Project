from __future__ import annotations

import tempfile
import unittest
from importlib.resources import files
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from aidast.agents.main import CodexMainAgent
from aidast.recon.tools.endpoint_discovery import (
    _filter_results_by_policy,
    _normalize_route,
    _parse_katana_output,
    discover_with_ffuf,
)
from aidast.recon.tools.ffuf_root_selector import (
    FfufRootSelection,
    select_ffuf_roots_from_endpoints,
)
from aidast.recon.policy import TargetPolicy
from aidast.scope.models import AssetType
import pytest


class FfufRootSelectionSkillTests(unittest.TestCase):
    def test_normalizer_drops_escaped_or_html_entity_routes(self) -> None:
        base = "https://github.com/owner/repo"
        self.assertIsNone(_normalize_route("/owner/repo/activity%5C", base))
        self.assertIsNone(_normalize_route("/owner/repo/activity%255C", base))
        self.assertIsNone(_normalize_route("/owner/repo/activity\\", base))
        self.assertIsNone(_normalize_route("/owner/repo/activity&quot", base))
        self.assertIsNone(_normalize_route("/owner/repo/activity%", base))
        self.assertEqual(
            _normalize_route("/owner/repo/file%20name", base),
            "/owner/repo/file%20name",
        )

    def test_katana_results_are_filtered_by_policy_path(self) -> None:
        policy = TargetPolicy(
            scope_id="scope_test",
            policy_id="policy_test",
            asset_type=AssetType.DOMAIN,
            asset="github.com",
            allowed_hosts=["github.com"],
            allowed_ports=[443],
            allowed_path_prefixes=["/owner/repo"],
        )
        results = _parse_katana_output(
            "https://github.com/owner/repo/issues\nhttps://github.com/settings\n",
            base_url="https://github.com/owner/repo",
            source="katana",
            target_policy=policy,
        )
        self.assertEqual([item["path"] for item in results], ["/owner/repo/issues"])

    def test_playwright_results_are_filtered_by_policy_path(self) -> None:
        policy = TargetPolicy(
            scope_id="scope_test", policy_id="policy_test",
            asset_type=AssetType.DOMAIN, asset="github.com",
            allowed_hosts=["github.com"], allowed_ports=[443],
            allowed_path_prefixes=["/owner/repo"],
        )
        results = _filter_results_by_policy(
            [
                {"method": "GET", "path": "/owner/repo/issues"},
                {"method": "GET", "path": "/login"},
            ],
            base_url="https://github.com/owner/repo",
            target_policy=policy,
        )
        self.assertEqual([item["path"] for item in results], ["/owner/repo/issues"])

    def test_skill_is_packaged_and_staged(self) -> None:
        content = files("aidast.skills.ffuf_root_selection").joinpath("SKILL.md").read_text(encoding="utf-8")
        self.assertIn("name: aidast-ffuf-root-selection", content)
        with tempfile.TemporaryDirectory() as temporary_dir:
            work_dir = Path(temporary_dir)
            CodexMainAgent._stage_native_skill(
                work_dir=work_dir,
                package="aidast.skills.ffuf_root_selection",
                skill_name="aidast-ffuf-root-selection",
            )
            self.assertTrue((work_dir / ".agents/skills/aidast-ffuf-root-selection/SKILL.md").is_file())

    def test_selector_rejects_invented_roots(self) -> None:
        agent_result = FfufRootSelection(
            base_url="", roots=["/api/v1", "/invented", "/", "/api", "/api"],
            count=5, selection_reason="공통 API 경로를 우선했습니다.",
        )
        with mock.patch.object(CodexMainAgent, "_run_structured", return_value=agent_result):
            roots = select_ffuf_roots_from_endpoints(
                [{"path": "/api/v1/users/123", "method": "GET", "source": "katana"}],
                max_roots=3,
            )
        self.assertEqual(roots, ["/", "/api", "/api/v1"])

    def test_selector_uses_recon_model(self) -> None:
        agent_result = FfufRootSelection(
            base_url="", roots=["/api"], count=1,
            selection_reason="관측한 API prefix를 선택했습니다.",
        )
        with mock.patch("aidast.recon.tools.ffuf_root_selector.CodexMainAgent") as agent:
            agent.return_value._run_structured.return_value = agent_result
            roots = select_ffuf_roots_from_endpoints([
                {"path": "/api/users", "method": "GET", "source": "katana"},
            ])
        self.assertEqual(roots, ["/api"])
        self.assertEqual(agent.call_args.kwargs["main_model"], "gpt-6-luna")

    def test_ffuf_selects_roots_before_running(self) -> None:
        with tempfile.NamedTemporaryFile() as wordlist:
            with (
                mock.patch("aidast.recon.tools.endpoint_discovery.shutil.which", return_value="/usr/local/bin/ffuf"),
                mock.patch("aidast.recon.tools.endpoint_discovery.select_ffuf_roots_from_endpoints", return_value=["/api"]) as selector,
                mock.patch("aidast.recon.tools.endpoint_discovery.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout="", stderr="")) as run_ffuf,
            ):
                discover_with_ffuf(
                    "https://example.com", wordlist=wordlist.name,
                    seed_endpoints=[{"path": "/api/v1/users", "source": "katana"}],
                    auth_headers=None,
                    proxy_url="http://127.0.0.1:8080",
                )
        selector.assert_called_once()
        self.assertIn("https://example.com/api/FUZZ", run_ffuf.call_args.args[0])
        command = run_ffuf.call_args.args[0]
        self.assertEqual(command[command.index("-x") + 1], "http://127.0.0.1:8080")

    def test_ffuf_uses_origin_when_start_url_contains_a_path(self) -> None:
        policy = TargetPolicy(
            scope_id="scope_test",
            policy_id="policy_test",
            asset_type=AssetType.DOMAIN,
            asset="github.com",
            allowed_hosts=["github.com"],
            allowed_ports=[443],
            allowed_path_prefixes=["/owner/repo"],
        )
        with tempfile.NamedTemporaryFile() as wordlist:
            with (
                mock.patch("aidast.recon.tools.endpoint_discovery.shutil.which", return_value="/usr/local/bin/ffuf"),
                mock.patch("aidast.recon.tools.endpoint_discovery.select_ffuf_roots_from_endpoints", return_value=["/owner/repo"]),
                mock.patch("aidast.recon.tools.endpoint_discovery.subprocess.run", return_value=SimpleNamespace(returncode=0, stdout="", stderr="")) as run_ffuf,
            ):
                discover_with_ffuf(
                    "https://github.com/owner/repo",
                    wordlist=wordlist.name,
                    seed_endpoints=[{"path": "/owner/repo", "source": "playwright"}],
                    auth_headers=None,
                    target_policy=policy,
                    proxy_url="http://127.0.0.1:8080",
                )
        self.assertIn(
            "https://github.com/owner/repo/FUZZ",
            run_ffuf.call_args.args[0],
        )


if __name__ == "__main__":
    unittest.main()


def guided_policy():
    return TargetPolicy(scope_id='scope', policy_id='guided', asset_type='URL',
        asset='https://example.com/', allowed_hosts=['example.com'],
        policy_notes=['Agent-guided exclusion: Do not fuzz sensitive account resources.'])


def test_ffuf_root_agent_receives_precautions_before_baseline_selection(tmp_path):
    wordlist = tmp_path / 'words.txt'; wordlist.write_text('probe\n')
    result = FfufRootSelection(base_url='', roots=[], count=0, selection_reason='Skip questionable roots')
    with (mock.patch('aidast.recon.tools.endpoint_discovery.shutil.which', return_value='/fake/ffuf'),
          mock.patch.object(CodexMainAgent, '_run_structured', return_value=result) as agent,
          mock.patch('aidast.recon.tools.endpoint_discovery.subprocess.run') as run):
        discover_with_ffuf('https://example.com/', wordlist=str(wordlist),
            seed_endpoints=[dict(path='/sensitive/forms', method='GET', source='observed')],
            auth_headers=None, target_policy=guided_policy(), proxy_url='http://127.0.0.1:8080')
        prompt = agent.call_args.kwargs['prompt']
        assert guided_policy().policy_notes[0] in prompt
        assert 'before selecting fuzzing roots' in prompt
        assert 'baseline_prefix_candidate' in prompt
        run.assert_not_called()


@pytest.mark.parametrize('selected', [[], ['/safe'], 'failure'])
def test_guided_ffuf_never_reintroduces_agent_declined_baseline_roots(tmp_path, selected):
    wordlist = tmp_path / 'words.txt'; wordlist.write_text('probe\n')
    options = ({'side_effect': RuntimeError('Unavailable selection')}
               if selected == 'failure' else {'return_value': FfufRootSelection(
                   base_url='', roots=selected, count=len(selected), selection_reason='Reviewed roots')})
    with (mock.patch('aidast.recon.tools.endpoint_discovery.shutil.which', return_value='/fake/ffuf'),
          mock.patch.object(CodexMainAgent, '_run_structured', **options),
          mock.patch('aidast.recon.tools.endpoint_discovery.subprocess.run',
              return_value=SimpleNamespace(returncode=0, stdout='', stderr='')) as run):
        discover_with_ffuf('https://example.com/', wordlist=str(wordlist),
            seed_endpoints=[dict(path='/sensitive/forms'), dict(path='/safe/items')],
            auth_headers=None, target_policy=guided_policy(), proxy_url='http://127.0.0.1:8080')
        commands = [call.args[0] for call in run.call_args_list]
        assert len(commands) == int(selected == ['/safe'])
        if commands:
            assert 'https://example.com/safe/FUZZ' in commands[0]
