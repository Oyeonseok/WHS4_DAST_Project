"""Separate valid endpoint plans from ungrounded model proposals."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import TYPE_CHECKING

from aidast.recon.annotations import safe_text

if TYPE_CHECKING:
    from aidast.attack.recon_hypotheses import EndpointHypotheses, ReconAttackPlan, ReconHypothesis


@dataclass(frozen=True)
class PlanningIssue:
    endpoint_id: str | None
    reason_code: str
    reason: str
    proposal: dict[str, str]

    def feedback(self) -> dict:
        return {'endpoint_id': self.endpoint_id, 'reason_code': self.reason_code,
                'reason': self.reason, 'proposal': self.proposal}


def hypothesis_fields(hypothesis: ReconHypothesis) -> dict[str, str]:
    return {name: getattr(hypothesis, name) for name in
            ('vuln_class', 'injection_location', 'parameter_name', 'required_identity_role')}


def partition_plan(
    plan: ReconAttackPlan, contexts: list[dict], skills: dict[str, str],
    *, rejected_proposals: list[PlanningIssue] | None = None,
    validated_endpoint_tests: set[tuple[str, str, str]] | None = None,
) -> tuple[list[EndpointHypotheses], list[PlanningIssue]]:
    """Retain only independently grounded hypotheses; never invent a replacement."""
    expected = {item['endpoint_id']: item for item in contexts}
    counts = Counter(item.endpoint_id for item in plan.endpoints)
    accepted, issues = [], []
    for endpoint_id in expected:
        if counts[endpoint_id] != 1:
            issues.append(PlanningIssue(endpoint_id,
                'missing_endpoint' if not counts[endpoint_id] else 'duplicate_endpoint',
                'Attack planning must account for every supplied endpoint exactly once', {}))
    for item in plan.endpoints:
        context = expected.get(item.endpoint_id)
        if context is None:
            issues.append(PlanningIssue(None, 'unknown_endpoint',
                'Attack planning references an endpoint absent from this batch',
                {'endpoint_id': safe_text(item.endpoint_id)}))
            continue
        if counts[item.endpoint_id] != 1:
            continue
        if bool(item.hypotheses) != (item.disposition == 'planned'):
            issues.append(PlanningIssue(item.endpoint_id, 'inconsistent_disposition',
                'planned endpoints require hypotheses; unplanned endpoints require a reason', {}))
            continue
        annotation_ids = {annotation['annotation_id'] for annotation in context['annotations']}
        parameters = {(parameter['location'], parameter['name']) for parameter in context['parameters']}
        valid = []
        for hypothesis in item.hypotheses:
            code, reason = '', ''
            if hypothesis.vuln_class not in skills:
                code, reason = 'unavailable_skill', 'Attack hypothesis references an unavailable vulnerability Skill'
            elif not set(hypothesis.annotation_ids) <= annotation_ids:
                code, reason = 'foreign_annotation', 'Attack hypothesis references foreign or invented annotations'
            elif ((hypothesis.injection_location, hypothesis.parameter_name) != ('endpoint', '')
                  and (hypothesis.injection_location, hypothesis.parameter_name) not in parameters):
                code = 'unobserved_parameter'
                observed = ', '.join(f'{location}.{name}' for location, name in sorted(parameters)[:8]) or '(none)'
                reason = ('Attack hypothesis parameter is absent from this endpoint evidence: '
                          f'proposed {hypothesis.injection_location}.{hypothesis.parameter_name}; observed {observed}')
            elif ((hypothesis.injection_location, hypothesis.parameter_name) == ('endpoint', '')
                  and (item.endpoint_id, hypothesis.vuln_class, hypothesis.required_identity_role) not in (validated_endpoint_tests or set())
                  and any(issue.endpoint_id == item.endpoint_id
                          and issue.reason_code in {'unobserved_parameter', 'ungrounded_endpoint_fallback'}
                          and issue.proposal.get('vuln_class') == hypothesis.vuln_class
                          and issue.proposal.get('required_identity_role') == hypothesis.required_identity_role
                          for issue in (rejected_proposals or []))):
                code = 'ungrounded_endpoint_fallback'
                reason = 'Correction cannot replace an unobserved input with an endpoint-wide test'
            elif not context['observations']:
                code, reason = 'missing_observation', 'Attack hypothesis requires an observed endpoint reference'
            if code:
                issues.append(PlanningIssue(item.endpoint_id, code, safe_text(reason),
                    {key: safe_text(value)[:200] for key, value in hypothesis_fields(hypothesis).items()}))
            else:
                valid.append(hypothesis)
        if valid or not item.hypotheses:
            accepted.append(item.model_copy(update={'hypotheses': valid}))
    return accepted, issues
