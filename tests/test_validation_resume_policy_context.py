"""Resume binds current precautions at the real comparison prompt boundary."""
import json

import pytest

import test_validation_coordinator as fixtures
from aidast.recon import db
from aidast.validation import CandidateIntegrityGate, ValidationCoordinator, ValidationCoordinatorError
from aidast.validation.orchestration.codex_runner import CodexBlindValidationRunner


@pytest.mark.parametrize('previous_case', [False, True])
def test_resumed_comparison_receives_only_current_policy_without_reassessing(previous_case):
    fixture = fixtures.ValidationCoordinatorTests()
    fixture.setUp()
    fixture.policy = fixture.policy.model_copy(update={'policy_notes': ['CURRENT_PRECAUTION: use owned data only']})
    runner = None
    try:
        with pytest.raises(ValidationCoordinatorError):
            ValidationCoordinator(db_path=fixture.path, agent=fixtures.CompareCrashedAgent(),
                reproduction=fixtures.FakePort(), policy_provider=lambda *args: fixture.policy).run('scan')
        with db.connect(fixture.path) as conn:
            stage = conn.execute("SELECT stage_run_id FROM stage_runs WHERE stage='validation'").fetchone()[0]
            frozen = conn.execute('SELECT case_id,blind_case_sha256,blind_assessment_sha256,attack_claim_sha256 FROM validation_cases').fetchone()
            candidate = CandidateIntegrityGate(conn).validate_finding(case_id=frozen[0], scan_id='scan', finding_id='finding')
            blind = candidate.staged.blind_view()
        prompts = []
        class Model:
            def _run_structured_session(self, **kwargs):
                prompts.append(kwargs['prompt'])
                assert kwargs['artifact_name'] == 'claim-comparison', 'frozen assessment must not rerun'
                context = json.loads(kwargs['prompt'].split('<unblinded_context_json>\n')[1].split('\n</unblinded_context_json>')[0])
                return fixtures.FakeAgent().compare(context['attack_claim'], context['blind_assessment']), 'offline-thread'
        runner = CodexBlindValidationRunner(Model())
        if previous_case:
            runner.prepare_comparison({**blind, 'case_id': 'previous-case'})
            runner.set_policy_context(fixture.policy.model_copy(update={'asset': 'previous.example', 'policy_notes': ['PREVIOUS_PRECAUTION']}))
            runner.compare({'blind_assessment_sha256': 'a'*64, 'attack_claim_sha256': 'b'*64, 'attack_evidence_ids': ['old']},
                           {'case_id': 'previous-case', 'evidence_ids': ['old']})
            assert 'PREVIOUS_PRECAUTION' in prompts.pop()
        current = fixture.policy.model_copy(update={'policy_notes': ['CURRENT_PRECAUTION: use owned data only']})
        port = fixtures.FakePort()
        result = ValidationCoordinator(db_path=fixture.path, agent=runner, reproduction=port,
            policy_provider=lambda *args: current).resume(stage)
        assert result.status == 'completed'
        assert port.calls == []
        assert len(prompts) == 1
        assert 'CURRENT_PRECAUTION' in prompts[0]
        assert 'PREVIOUS_PRECAUTION' not in prompts[0]
        assert 'previous.example' not in prompts[0]
        with db.connect(fixture.path) as conn:
            assert conn.execute('SELECT case_id,blind_case_sha256,blind_assessment_sha256,attack_claim_sha256 FROM validation_cases').fetchone() == frozen
    finally:
        if runner:
            runner.close()
        fixture.doCleanups()
