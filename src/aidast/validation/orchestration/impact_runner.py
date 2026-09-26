"""Isolated Codex planner for one profile-bounded impact hypothesis."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from uuid import uuid4

from aidast.agents.main import CodexMainAgent

from ..execution.impact_development import ImpactDevelopmentPlan, ImpactDevelopmentRequest
from ..core.profiles import SkillProfileResolver


class CodexImpactDevelopmentRunner:
    """Let Python dispatch one short-lived planner per impact hypothesis."""

    def __init__(self, *, attack_skill_name: str, agent: CodexMainAgent | None = None):
        resolved = SkillProfileResolver().resolve(attack_skill_name)
        self._attack_skill_name = attack_skill_name
        self._validation_skill_text = resolved.validation_skill_text
        self._agent = agent or CodexMainAgent()
        self.agent_id = "impact_development_agent_" + uuid4().hex
        self._temporary = tempfile.TemporaryDirectory(prefix="aidast-impact-development-")
        self._work_root = Path(self._temporary.name)

    def plan(self, request: ImpactDevelopmentRequest, *, evidence: tuple[dict, ...]) -> ImpactDevelopmentPlan:
        work_dir = self._work_root / ("hypothesis-" + uuid4().hex)
        work_dir.mkdir()
        context = json.dumps({
            "impact_development_request": request.model_dump(mode="json"),
            "evidence": evidence,
            "citation_contract": {
                "validation_evidence_ids": [
                    *request.supporting_evidence_ids,
                    *(observation["evidence_id"]
                      for item in evidence
                      if item.get("context_kind") == "verified_impact_precondition_observations"
                      for observation in item.get("observations", ())
                      if observation.get("evidence_id")),
                ],
                "source_request_ids": [
                    source["request_id"]
                    for item in evidence
                    if item.get("context_kind") == "verified_attack_source_requests"
                    for source in item.get("requests", ())
                ],
            },
        }, ensure_ascii=False, sort_keys=True)
        prompt = f"""Follow the selected Validation Skill only for precondition judgment.
                    Return only ImpactDevelopmentPlan. Choose execute only when every declared prerequisite
                    is supported by the supplied evidence. Never invent or modify an endpoint, method,
                    identity, credential, payload, assertion, signal, score, or final Validation status.
                    Verified Attack source requests and verified marker observations may support
                    planning preconditions. They do not establish final impact: only the fresh
                    bounded action and its response can support an increased impact score.
                    In ImpactDevelopmentPlan, evidence_ids may cite only current-stage Validation
                    evidence IDs from citation_contract.validation_evidence_ids. Cite verified
                    Attack provenance only in source_request_ids, using IDs from
                    citation_contract.source_request_ids. Never put an Attack request ID in
                    evidence_ids or invent a citation ID.

                    <selected_validation_skill name=\"{self._attack_skill_name}\">
                    {self._validation_skill_text}
                    </selected_validation_skill>
                    <impact_context_json>
                    {context}
                    </impact_context_json>
                    """
        session_method = getattr(type(self._agent), "_run_structured_session", None)
        if callable(session_method):
            result, _ = self._agent._run_structured_session(
                prompt=prompt, model_type=ImpactDevelopmentPlan,
                artifact_name="impact-development-plan",
                operation="impact development planning", work_dir=work_dir,
                session_id=None,
            )
            return result
        return self._agent._run_structured(
            prompt=prompt, model_type=ImpactDevelopmentPlan,
            artifact_name="impact-development-plan",
            operation="impact development planning",
        )

    def close(self) -> None:
        self._temporary.cleanup()
