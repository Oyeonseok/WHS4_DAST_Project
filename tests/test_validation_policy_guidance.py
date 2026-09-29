"""Legacy evidence reviewers receive only applicable hash-bound policy warnings."""
import json
from unittest.mock import patch

import pytest

from aidast.attack.store import materialize_attack_database
from aidast.pipeline.models import HandoffManifest, hash_artifact
from aidast.recon import db
from aidast.recon.policy import TargetPolicy
from aidast.validation import ValidationAgent, ValidationError, prepare_validation
from aidast.validation.legacy.agent import EvidenceOnlyReviewer
from aidast.validation.persistence.source import digest


def policy(asset='https://example.test/', notes=()):
    from urllib.parse import urlsplit
    return TargetPolicy(scope_id='scope', policy_id=asset, asset_type='URL', asset=asset,
        allowed_hosts=[urlsplit(asset).hostname], allowed_path_prefixes=[urlsplit(asset).path],
        policy_notes=list(notes), required_identity_headers={'Researcher-ID': 'PRIVATE_IDENTITY'})


def legacy_source(root, document=None, role='target-policy'):
    bundle = root / 'handoff'
    bundle.mkdir()
    recon = bundle / 'Recon.db'
    conn = db.init_db(recon)
    conn.execute("INSERT INTO scans(scan_id,scope_type,scope_value,status,finished_at) VALUES ('scan','test','local','completed','2026-09-09T00:00:00Z')")
    conn.commit()
    conn.close()
    artifacts = [hash_artifact(recon, root=bundle, role='database')]
    if document is not None:
        source = bundle / 'BoundPolicy.json'
        source.write_text(json.dumps(document))
        artifacts.append(hash_artifact(source, root=bundle, role=role))
    handoff = bundle / 'Handoff.json'
    handoff.write_text(HandoffManifest(manifest_id='handoff', scan_id='scan', db_path='Recon.db', artifacts=artifacts).model_dump_json())
    with materialize_attack_database(handoff, root / 'attack', run_id='run') as store:
        store.conn.execute("INSERT INTO findings(finding_id,scan_id,vuln_type,severity,title,run_id) VALUES ('finding','scan','fixture','INFO','Fixture finding','run')")
        store.conn.execute("INSERT INTO attack_requests(request_id,finding_id,method,url,request_headers,response_body) VALUES ('request','finding','GET','https://example.test/path?token=RAW_QUERY','Authorization: Bearer RAW_HEADER','RAW_BODY')")
        store.conn.commit()
        attack = store.path
    return attack, bundle


@pytest.mark.parametrize('role', ['target-policy', 'target_policy', 'policy'])
def test_actual_legacy_reviewer_receives_only_bound_applicable_redacted_warnings(tmp_path, role):
    applicable = policy(notes=['Sensitive data: use owned data only.', 'Authorization: Bearer NOTE_SECRET'])
    unrelated = policy('https://other.test/', ['OTHER_TARGET_WARNING'])
    other_path = policy('https://example.test/other/', ['OTHER_PATH_WARNING'])
    attack, bundle = legacy_source(tmp_path, {'policies': [item.model_dump(mode='json') for item in [applicable, unrelated, other_path]]}, role)
    original = {p: p.read_bytes() for p in [attack, *bundle.iterdir()]}
    seen = []
    class Reviewer(EvidenceOnlyReviewer):
        def review(self, context, skill):
            seen.append(context)
            return super().review(context, skill)
    with patch('socket.create_connection', side_effect=AssertionError('offline only')):
        ValidationAgent(Reviewer()).run(attack, tmp_path / 'validation')
    context = seen[0]
    assert 'Sensitive data' in json.dumps(context.get('policy_guidance'))
    for secret in ['OTHER_TARGET_WARNING', 'OTHER_PATH_WARNING', 'NOTE_SECRET', 'RAW_QUERY', 'RAW_HEADER', 'RAW_BODY', 'PRIVATE_IDENTITY']:
        assert secret not in json.dumps(context)
    assert context['context_sha256'] == digest({k: v for k, v in context.items() if k != 'context_sha256'})
    for p, content in original.items():
        assert p.read_bytes() == content


@pytest.mark.parametrize('document', [None, {}, {'policies': []}, {'policies': [policy().model_dump(mode='json')]}])
def test_no_warning_keeps_old_context_and_ignores_unbound_sidecar(tmp_path, document):
    attack, bundle = legacy_source(tmp_path, document)
    first = prepare_validation(attack, tmp_path / 'validation')['contexts'][0]
    (bundle / 'TargetPolicy.json').write_text(json.dumps({'policies': [policy(notes=['UNBOUND_WARNING']).model_dump(mode='json')]}))
    second = prepare_validation(attack, tmp_path / 'validation')['contexts'][0]
    assert 'policy_guidance' not in first
    assert first == second
    assert first['context_sha256'] == digest({k: v for k, v in first.items() if k not in {'context_sha256', 'policy_guidance'}})


def test_changed_bound_policy_bytes_fail_before_reviewer(tmp_path):
    attack, bundle = legacy_source(tmp_path, {'policies': [policy(notes=['Sensitive data']).model_dump(mode='json')]})
    (bundle / 'BoundPolicy.json').write_text('{}')
    with pytest.raises(ValidationError, match='integrity mismatch'):
        prepare_validation(attack, tmp_path / 'validation')


def test_long_source_quote_does_not_hide_following_policy_guidance(tmp_path):
    note = 'Captured context: ' + 'x' * 9000 + ' Stop on sensitive data; use owned data only.'
    attack, _ = legacy_source(tmp_path, {'policies': [policy(notes=[note]).model_dump(mode='json')]})
    context = prepare_validation(attack, tmp_path / 'validation')['contexts'][0]
    assert 'Stop on sensitive data; use owned data only.' in json.dumps(context['policy_guidance'])
