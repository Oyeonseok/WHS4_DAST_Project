from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError

from aidast.agents.main import CodexMainAgent
from aidast.cli import main
from aidast.orchestration.recon import ReconCoordinator, ReconCoordinatorError
from aidast.orchestration.scope import ScopeCoordinator
from aidast.recon.models import (
    ReconPlan,
    ReconPlanProposal,
    ReconPlanTarget,
    ReconStep,
)
from aidast.scope.models import (
    AssetType,
    CaptureReason,
    CaptureStatus,
    ProgramPage,
    ScopeAnalysis,
    ScopeAsset,
    ScopeDocument,
    SourceEvidence,
)


PROGRAM_URL = "https://bugcrowd.com/engagements/example"


def scope_analysis() -> ScopeAnalysis:
    return ScopeAnalysis(
        program_name="Example",
        program_description="테스트 프로그램",
        in_scope_assets=[
            ScopeAsset(
                asset_type=AssetType.WILDCARD,
                asset="*.example.com",
                description="웹 자산",
                eligibility="보상 대상",
                maximum_severity="Critical",
            )
        ],
        out_of_scope_assets=[],
        allowed_activities=["비파괴적 테스트"],
        prohibited_activities=["서비스 거부 공격"],
        submission_requirements=["재현 절차 제공"],
        operational_constraints=["낮은 요청 속도 유지"],
        safe_harbor="정책 준수 활동은 허가됨",
        ambiguities=[],
        source_evidence=[
            SourceEvidence(section="Scope", quote="*.example.com is in scope")
        ],
    )


def program_page() -> ProgramPage:
    text = ("*.example.com is in scope. Public bug bounty program. " * 20).strip()
    return ProgramPage(
        requested_url=PROGRAM_URL,
        final_url=PROGRAM_URL,
        title="Example",
        captured_at=datetime.now(timezone.utc),
        capture_status=CaptureStatus.COMPLETE,
        capture_reason=CaptureReason.NONE,
        content_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        text=text,
    )


def plan(scope_id: str, *, asset: str = "*.example.com") -> ReconPlan:
    return ReconPlan(
        plan_id="plan_test",
        scope_id=scope_id,
        objective="승인된 웹 자산의 공격 표면을 수집한다.",
        mode="FULL_RECON",
        targets=[
            ReconPlanTarget(
                asset_type=AssetType.WILDCARD,
                asset=asset,
                steps=[
                    ReconStep.ASSET_DISCOVERY,
                    ReconStep.DNS_RESOLUTION,
                    ReconStep.HTTP_PROBE,
                ],
                constraints=["서비스에 영향을 주지 않는다."],
            )
        ],
        global_constraints=["승인된 Scope를 벗어나지 않는다."],
        completion_criteria=["각 단계의 결과가 반환된다."],
    )


class FakeReconMainAgent:
    def __init__(self) -> None:
        self.received_scope_markdown: str | None = None

    def collect_scope(self, program_url: str) -> tuple[ProgramPage, ScopeAnalysis]:
        return program_page(), scope_analysis()

    def interpret_captured_scope(self, page: ProgramPage) -> ScopeAnalysis:
        return scope_analysis()

    def create_recon_plan(self, *, scope_id: str, scope_markdown: str) -> ReconPlan:
        self.received_scope_markdown = scope_markdown
        return plan(scope_id)


class ReconCoordinatorTests(unittest.TestCase):
    def test_converts_each_target_step_into_a_dependency_chain(self) -> None:
        document = ScopeDocument(
            scope_id="scope_test",
            created_at=datetime.now(timezone.utc),
            source=program_page(),
            analysis=scope_analysis(),
        )
        tasks = ReconCoordinator().create_tasks(
            plan=plan(document.scope_id), scope=document
        )

        self.assertEqual([task.task_type for task in tasks], [
            ReconStep.ASSET_DISCOVERY,
            ReconStep.DNS_RESOLUTION,
            ReconStep.HTTP_PROBE,
        ])
        self.assertEqual(tasks[0].depends_on_task_ids, [])
        self.assertEqual(tasks[1].depends_on_task_ids, [tasks[0].task_id])
        self.assertEqual(tasks[2].depends_on_task_ids, [tasks[1].task_id])
        self.assertEqual(tasks[0].status.value, "PENDING")

    def test_task_conversion_is_deterministic_for_same_plan(self) -> None:
        document = ScopeDocument(
            scope_id="scope_test",
            created_at=datetime.now(timezone.utc),
            source=program_page(),
            analysis=scope_analysis(),
        )
        recon_plan = plan(document.scope_id)

        first = ReconCoordinator().create_tasks(plan=recon_plan, scope=document)
        second = ReconCoordinator().create_tasks(plan=recon_plan, scope=document)

        self.assertEqual(first, second)

    def test_rejects_target_not_present_in_approved_scope(self) -> None:
        document = ScopeDocument(
            scope_id="scope_test",
            created_at=datetime.now(timezone.utc),
            source=program_page(),
            analysis=scope_analysis(),
        )
        with self.assertRaisesRegex(ReconCoordinatorError, "unapproved target"):
            ReconCoordinator().create_tasks(
                plan=plan(document.scope_id, asset="evil.example"),
                scope=document,
            )

    def test_scope_target_authorization_is_case_sensitive(self) -> None:
        analysis = scope_analysis().model_copy(
            update={
                "in_scope_assets": [
                    ScopeAsset(
                        asset_type=AssetType.URL,
                        asset="https://example.com/Admin",
                        description="관리 경로",
                        eligibility="보상 대상",
                        maximum_severity="Critical",
                    )
                ]
            }
        )
        document = ScopeDocument(
            scope_id="scope_test",
            created_at=datetime.now(timezone.utc),
            source=program_page(),
            analysis=analysis,
        )
        recon_plan = ReconPlan(
            plan_id="plan_case",
            scope_id=document.scope_id,
            objective="승인된 경로를 정찰한다.",
            mode="FULL_RECON",
            targets=[
                ReconPlanTarget(
                    asset_type=AssetType.URL,
                    asset="https://example.com/admin",
                    steps=[ReconStep.HTTP_PROBE],
                    constraints=[],
                )
            ],
            global_constraints=[],
            completion_criteria=["응답 확인"],
        )
        with self.assertRaisesRegex(ReconCoordinatorError, "unapproved target"):
            ReconCoordinator().create_tasks(plan=recon_plan, scope=document)


class ReconModelTests(unittest.TestCase):
    def test_rejects_blank_plan_narrative(self) -> None:
        with self.assertRaises(ValidationError):
            ReconPlanProposal(
                objective=" ",
                mode="FULL_RECON",
                targets=[
                    ReconPlanTarget(
                        asset_type=AssetType.WILDCARD,
                        asset="*.example.com",
                        steps=[ReconStep.DNS_RESOLUTION],
                        constraints=[],
                    )
                ],
                global_constraints=[],
                completion_criteria=["완료"],
            )


class ReconMainAgentTests(unittest.TestCase):
    def test_codex_creates_structured_recon_plan_from_scope_markdown(self) -> None:
        proposal = ReconPlanProposal(
            objective="승인된 자산의 공격 표면을 수집한다.",
            mode="FULL_RECON",
            targets=[
                ReconPlanTarget(
                    asset_type=AssetType.WILDCARD,
                    asset="*.example.com",
                    steps=[ReconStep.ASSET_DISCOVERY, ReconStep.DNS_RESOLUTION],
                    constraints=["서비스 거부 공격 금지"],
                )
            ],
            global_constraints=["Scope 외부 요청 금지"],
            completion_criteria=["DNS 결과 확보"],
        )
        with tempfile.TemporaryDirectory() as temporary_dir:
            executable = Path(temporary_dir) / "codex-test"
            executable.write_text(
                "#!/usr/bin/env python3\n"
                "import pathlib, sys\n"
                "if sys.argv[1:3] == ['login', 'status']:\n"
                "    raise SystemExit(0)\n"
                "output = pathlib.Path(sys.argv[sys.argv.index('--output-last-message') + 1])\n"
                f"output.write_text({json.dumps(proposal.model_dump(mode='json'))!r})\n",
                encoding="utf-8",
            )
            executable.chmod(executable.stat().st_mode | 0o111)

            result = CodexMainAgent(
                executable=str(executable), timeout_seconds=10
            ).create_recon_plan(
                scope_id="scope_test",
                scope_markdown="## In-scope assets\n| WILDCARD | \\*.example.com |",
            )

        self.assertEqual(result.scope_id, "scope_test")
        self.assertEqual(result.plan_type, "RECON")
        self.assertEqual(result.targets[0].asset, "*.example.com")


class ReconCliTests(unittest.TestCase):
    def test_recon_collects_and_approves_scope_before_planning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir) / "Scope"
            fake_main = FakeReconMainAgent()
            output = io.StringIO()
            with (
                patch("aidast.cli.CodexMainAgent", return_value=fake_main),
                patch("builtins.input", return_value="y"),
                redirect_stdout(output),
            ):
                result = main(
                    ["recon", PROGRAM_URL, "--output-dir", str(root), "--by", "reviewer"]
                )

            program_dir = root / "bugcrowd" / "example"
            self.assertEqual(result, 0)
            self.assertTrue((program_dir / "Scope.md").is_file())
            self.assertIsNotNone(fake_main.received_scope_markdown)
            self.assertIn("Recon Plan created", output.getvalue())
            self.assertIn("3 tasks", output.getvalue())

    def test_recon_verifies_and_reuses_existing_approved_scope(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir) / "Scope"
            program_dir = root / "bugcrowd" / "example"
            ScopeCoordinator(program_dir).collect(
                PROGRAM_URL,
                main_agent=FakeReconMainAgent(),
                approved_by="reviewer",
                review=lambda _: True,
            )
            fake_main = FakeReconMainAgent()
            output = io.StringIO()
            with (
                patch("aidast.cli.CodexMainAgent", return_value=fake_main),
                redirect_stdout(output),
            ):
                result = main(["recon", PROGRAM_URL, "--output-dir", str(root)])

            self.assertEqual(result, 0)
            self.assertIn("Reusing approved Scope", output.getvalue())
            self.assertIsNotNone(fake_main.received_scope_markdown)

    def test_recon_rejects_tampered_existing_scope_before_planning(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_dir:
            root = Path(temporary_dir) / "Scope"
            program_dir = root / "bugcrowd" / "example"
            ScopeCoordinator(program_dir).collect(
                PROGRAM_URL,
                main_agent=FakeReconMainAgent(),
                approved_by="reviewer",
                review=lambda _: True,
            )
            with (program_dir / "Scope.md").open("a", encoding="utf-8") as handle:
                handle.write("tampered\n")
            fake_main = FakeReconMainAgent()
            errors = io.StringIO()
            with (
                patch("aidast.cli.CodexMainAgent", return_value=fake_main),
                redirect_stderr(errors),
            ):
                result = main(["recon", PROGRAM_URL, "--output-dir", str(root)])

            self.assertEqual(result, 1)
            self.assertIn("changed", errors.getvalue())
            self.assertIsNone(fake_main.received_scope_markdown)


if __name__ == "__main__":
    unittest.main()
