"""Replay one transition scenario in two stages, recording the intermediate phase.

Fixture assessment mode fixes only the initial impact axes. Real HTTP replay,
the native Development port, and the Validation state machine still run.
Use real modes to evaluate agent judgments separately from the controlled run.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from typing import Callable

from aidast.validation import ClaimComparison, CodexImpactDevelopmentRunner
from aidast.validation.contracts.eligibility import EligibilityAssessment
from aidast.validation.orchestration.codex_runner import CodexBlindValidationRunner

try:
    from scripts.prepare_validation_lab import probe_impact_markers
    from scripts.run_validation_impact_lab import (
        build_impact_lab_coordinator, verify_impact_lab_preconditions,
    )
except ModuleNotFoundError:  # Direct CLI invocation.
    from prepare_validation_lab import probe_impact_markers
    from run_validation_impact_lab import (
        build_impact_lab_coordinator, verify_impact_lab_preconditions,
    )


class FixtureEligibilityAgent:
    agent_id = "transition_fixture_eligibility"

    def assess(self, request, correction=None):
        return EligibilityAssessment(
            case_id=request.case_id, scope_sha256=request.scope_sha256,
            phase=request.phase, eligibility="ELIGIBLE", matched_rule="Pinned local lab scope",
            scope_quote=request.scope_markdown, required_impact=(), replay_allowed=True,
            reason="The selected GET is covered by the pinned local lab scope.",
            evidence_refs=request.evidence_refs,
        )


class FixtureBlindAgent:
    agent_id = "transition_fixture_blind_assessment"

    def __init__(self, axes: dict[str, int]):
        self.axes = axes

    def assess(self, blind_case, observations, correction=None):
        targets = tuple(item for item in observations if item["attempt_kind"] == "target")
        controls = tuple(item for item in observations if item["attempt_kind"] != "target")
        if (len(targets) != 3 or len(controls) != 2
                or not all(item["signal_observed"] is True for item in targets)):
            raise ValueError("controlled transition requires three observed target GETs")
        evidence = tuple(item["evidence_id"] for item in observations)
        target_evidence = targets[0]["evidence_id"]
        negative_evidence = next(item["evidence_id"] for item in controls
                                 if item["attempt_kind"] == "negative_control")
        def axis(name: str):
            citations = ((target_evidence, negative_evidence)
                         if name == "boundary" else (target_evidence,))
            return {
                "score": self.axes[name], "evidence_ids": citations,
                "reason": f"Controlled baseline {name} axis for transition testing.",
            }
        return {
            "case_id": blind_case["case_id"],
            "blind_case_sha256": blind_case["blind_case_sha256"],
            "reproduced": True, "signal_types": tuple(blind_case["signal_types"]),
            "target_attempt_ids": tuple(item["attempt_id"] for item in targets),
            "control_attempt_ids": tuple(item["attempt_id"] for item in controls),
            "evidence_ids": evidence, "blocker_axis": None, "blocker_reason": None,
            "impact_boundary": axis("boundary"),
            "impact_sensitivity": axis("sensitivity"),
            "impact_actor_requirements": axis("actor_requirements"),
            "conclusion": "Controlled baseline from observed local GET responses.",
        }

    def compare(self, claim, assessment, correction=None):
        return ClaimComparison(
            case_id=assessment["case_id"],
            blind_assessment_sha256=claim["blind_assessment_sha256"],
            attack_claim_sha256=claim["attack_claim_sha256"],
            alignment="aligned", conflict_axes=(),
            validation_evidence_ids=(assessment["evidence_ids"][0],),
            attack_evidence_ids=(claim["attack_evidence_ids"][0],),
            reason="The controlled replay matches the synthetic Attack claim.",
        )


class RecordingBlindAgent:
    """Record the Agent's pre-Development axes without changing its output."""

    def __init__(self, delegate, records: list[dict]):
        self.delegate, self.records = delegate, records
        self.agent_id = delegate.agent_id

    def assess(self, blind_case, observations, correction=None):
        raw = self.delegate.assess(blind_case, observations, correction=correction)
        value = raw.model_dump(mode="json") if hasattr(raw, "model_dump") else raw
        if isinstance(value, dict):
            try:
                axes = [value[name]["score"] for name in (
                    "impact_boundary", "impact_sensitivity", "impact_actor_requirements",
                )]
                self.records.append({
                    "impact_axes": axes, "reproduced": value.get("reproduced"),
                    "evidence_ids": list(value.get("evidence_ids", [])),
                })
            except (KeyError, TypeError):
                self.records.append({"recording_error": "impact_axes_unavailable"})
        return raw

    def prepare_comparison(self, blind_case):
        prepare = getattr(self.delegate, "prepare_comparison", None)
        if callable(prepare):
            prepare(blind_case)

    def compare(self, claim, assessment, correction=None):
        return self.delegate.compare(claim, assessment, correction=correction)

    def close(self):
        close = getattr(self.delegate, "close", None)
        if callable(close):
            close()


class PhaseRecordingPlanner:
    def __init__(self, *, bundle: Path, finding_id: str, scenario_id: str,
                 skill_name: str, mode: str, observations: list[dict], plans: list[dict]):
        self.bundle, self.finding_id = bundle, finding_id
        self.scenario_id, self.observations, self.plans = scenario_id, observations, plans
        self.agent_id = "transition_fixture_impact_planner" if mode == "fixture" else "transition_real_impact_planner"
        self.delegate = (CodexImpactDevelopmentRunner(attack_skill_name=skill_name)
                         if mode == "real" else None)

    def plan(self, request, *, evidence):
        with sqlite3.connect(self.bundle / "Pipeline.db") as conn:
            row = conn.execute(
                "SELECT current_status,processing_phase FROM validation_cases WHERE finding_id=?",
                (self.finding_id,),
            ).fetchone()
        self.observations.append({
            "status": row[0], "processing_phase": row[1], "path_id": request.path_id,
        })
        if self.delegate is not None:
            plan = self.delegate.plan(request, evidence=evidence)
            self.plans.append(plan.model_dump(mode="json") if hasattr(plan, "model_dump") else dict(plan))
            return plan
        execute = self.scenario_id in {
            "verified_marker", "minimal_threshold", "false_marker", "partial_boundary",
        }
        receipt_ids = [observation["evidence_id"] for item in evidence
                       if item.get("context_kind") == "verified_impact_precondition_observations"
                       for observation in item.get("observations", ())]
        plan = {
            "path_id": request.path_id, "proposal_sha256": request.proposal_sha256,
            "disposition": "execute" if execute else "skip",
            "preconditions_satisfied": execute,
            "evidence_ids": [*request.supporting_evidence_ids, *receipt_ids],
            "reason": ("Pinned source and marker are available for the bounded GET."
                       if execute else "No unique verified marker is available."),
        }
        self.plans.append(dict(plan))
        return plan

    def close(self):
        if self.delegate is not None:
            self.delegate.close()


def _case_snapshot(bundle: Path, finding_id: str, stage_run_id: str) -> dict:
    with sqlite3.connect(bundle / "Pipeline.db") as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT case_id,current_status,processing_phase,impact_boundary,"
            "impact_sensitivity,impact_actor_requirements FROM validation_cases "
            "WHERE finding_id=? AND latest_stage_run_id=?",
            (finding_id, stage_run_id),
        ).fetchone()
    if row is None:
        raise ValueError("transition run did not create the selected Validation case")
    return {
        "stage_run_id": stage_run_id, "status": row["current_status"],
        "processing_phase": row["processing_phase"],
        "impact_axes": [row["impact_boundary"], row["impact_sensitivity"],
                        row["impact_actor_requirements"]],
    }


def run_transition_case(
    root: Path, scenario_id: str, *, assessment_mode: str = "fixture",
    planner_mode: str = "real", transport=None,
    impact_marker_probe: Callable[[str], tuple[set[str], str]] = probe_impact_markers,
) -> dict:
    """Run baseline UNDERPOWERED first, then revalidate with the Development port."""
    if assessment_mode not in {"fixture", "real"} or planner_mode not in {"fixture", "real"}:
        raise ValueError("transition mode must be fixture or real")
    root = Path(root)
    manifest = json.loads((root / "TransitionManifest.json").read_text())
    matches = [case for case in manifest["cases"] if case["scenario_id"] == scenario_id]
    if len(matches) != 1:
        raise ValueError("unknown transition scenario")
    selected = matches[0]
    if assessment_mode == "real" and selected.get("real_axis_trial_ready") is False:
        raise ValueError(
            "real Blind trial lacks distinct baseline evidence: "
            + str(selected.get("real_axis_trial_reason", "unknown"))
        )
    bundle = root / scenario_id
    trace_path = bundle / "TransitionTrace.json"
    if trace_path.exists():
        raise ValueError("transition scenario was already run")
    blind_assessments: list[dict] = []

    def coordinator():
        delegate = (FixtureBlindAgent(selected["fixture_baseline_axes"])
                    if assessment_mode == "fixture" else CodexBlindValidationRunner())
        blind_agent = RecordingBlindAgent(delegate, blind_assessments)
        value, mapped = build_impact_lab_coordinator(
            bundle, agent=blind_agent, transport=transport,
        )
        if mapped["finding_id"] != selected["finding_id"]:
            raise ValueError("transition finding selection changed")
        value.eligibility_agent = FixtureEligibilityAgent()
        value.impact_precondition_verifier = (
            (lambda candidate, request: None) if scenario_id == "weak_marker" else
            (lambda candidate, request: verify_impact_lab_preconditions(
                candidate, request, probe=impact_marker_probe,
            ))
        )
        return value, blind_agent

    baseline_coordinator, baseline_agent = coordinator()
    baseline_coordinator.impact_development_port = None
    try:
        baseline_result = baseline_coordinator.run(
            selected["scan_id"], finding_id=selected["finding_id"],
        )
    finally:
        baseline_agent.close()
    baseline = _case_snapshot(bundle, selected["finding_id"], baseline_result.stage_run_id)
    trace = {
        "scenario_id": scenario_id, "assessment_mode": assessment_mode,
        "eligibility_mode": "fixture",
        "planner_mode": planner_mode,
        "transport_mode": "native" if transport is None else "injected",
        "baseline": baseline, "blind_assessments": blind_assessments,
        "planner_observations": [], "planner_plans": [],
        "developed": None, "hypotheses": [],
    }
    if baseline["status"] == "UNDERPOWERED":
        developed_coordinator, developed_agent = coordinator()
        developed_coordinator.impact_agent_factory = lambda skill_name: PhaseRecordingPlanner(
            bundle=bundle, finding_id=selected["finding_id"], scenario_id=scenario_id,
            skill_name=skill_name, mode=planner_mode,
            observations=trace["planner_observations"],
            plans=trace["planner_plans"],
        )
        try:
            developed_result = developed_coordinator.run(
                selected["scan_id"], finding_id=selected["finding_id"],
            )
        except Exception as exc:
            cause = exc.__cause__ or exc
            with sqlite3.connect(bundle / "Pipeline.db") as conn:
                row = conn.execute(
                    "SELECT c.latest_stage_run_id,c.processing_phase,s.status "
                    "FROM validation_cases c JOIN stage_runs s "
                    "ON s.stage_run_id=c.latest_stage_run_id WHERE c.finding_id=?",
                    (selected["finding_id"],),
                ).fetchone()
            trace["execution_error"] = {
                "type": type(cause).__name__, "message": str(cause),
                "stage_run_id": row[0] if row else None,
                "processing_phase": row[1] if row else None,
                "stage_status": row[2] if row else None,
            }
            trace_path.write_text(json.dumps(trace, ensure_ascii=False, indent=2) + "\n")
            raise
        finally:
            developed_agent.close()
        trace["developed"] = _case_snapshot(
            bundle, selected["finding_id"], developed_result.stage_run_id,
        )
        with sqlite3.connect(bundle / "Pipeline.db") as conn:
            rows = conn.execute(
                "SELECT status,observation_json FROM validation_impact_hypotheses "
                "WHERE case_id=(SELECT case_id FROM validation_cases WHERE finding_id=?) "
                "AND stage_run_id=? ORDER BY ordinal",
                (selected["finding_id"], developed_result.stage_run_id),
            ).fetchall()
        trace["hypotheses"] = [{
            "status": status,
            "outcome": json.loads(observation)["outcome"] if observation else None,
        } for status, observation in rows]
    trace_path.write_text(json.dumps(trace, ensure_ascii=False, indent=2) + "\n")
    return trace


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    parser.add_argument("scenario_id")
    parser.add_argument("--assessment-mode", choices=("fixture", "real"), default="fixture")
    parser.add_argument("--planner-mode", choices=("fixture", "real"), default="real")
    args = parser.parse_args()
    trace = run_transition_case(
        args.root, args.scenario_id, assessment_mode=args.assessment_mode,
        planner_mode=args.planner_mode,
    )
    print(json.dumps({"scenario_id": trace["scenario_id"],
                      "baseline": trace["baseline"]["status"],
                      "developed": trace["developed"]["status"] if trace["developed"] else None},
                     ensure_ascii=False))


if __name__ == "__main__":
    main()
