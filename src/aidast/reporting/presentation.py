"""Reader-facing summaries of already masked report fields and evidence."""
from __future__ import annotations

from importlib.resources import files
import html
import json
from pathlib import Path
import re


def report_language(report_db: Path, *, platform: str = "generic") -> str:
    """Locale is separate from immutable source-bound draft bytes."""
    from .runtime import ReportError, _path
    path = report_db.parent / "Report.language.json"
    if not path.exists() and not path.is_symlink():
        return "ko" if platform == "generic" else "en"
    path = _path(path, existing=True)
    if path.stat().st_size > 128:
        raise ReportError("invalid report language metadata")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {"language"} or value["language"] not in ("ko", "en"):
        raise ReportError("invalid report language metadata")
    return value["language"]


def _plain(value: str) -> str:
    # Entities protect captured syntax without visible backslashes in Markdown
    # viewers that do not implement backslash escaping for ordinary punctuation.
    value = html.escape(value, quote=False)
    value = re.sub(r"([\\`*_{}\[\]()#+!|~])", lambda match: f"&#{ord(match[0])};", value)
    value = re.sub(r"(?m)^(\s*\d+)\.\s", r"\1&#46; ", value)
    return re.sub(r"(?m)^(\s*)-(?=\s|--)", r"\1&#45;", value)


def writing_guidance(platform: str, language: str = "ko") -> str:
    title = (
        "Structure the title as affected feature -> verified cause -> weakness type "
        '(for example, "기능 A에서 원인 B로 인해 발생하는 취약점 C" in Korean). '
        "Do not invent a cause: when the root cause is not verified, use the observed "
        "condition instead and avoid asserting an internal mechanism. Keep the title concise "
        "and cite evidence for every factual element."
    )
    if platform != "generic":
        return title
    locale = "English" if language == "en" else "Korean"
    return (f"Write the title and all reader-facing report content in {locale}.\n\n"
            + title + "\n\n"
            + files("aidast.skills.reporting.generic").joinpath("references", "writing.md").read_text(encoding="utf-8"))


def evidence_display(item: dict, attempt_kind: str | None = None, *, language: str = "ko") -> dict[str, str]:
    kind = item["kind"]
    details = item["details"] if isinstance(item["details"], dict) else {}
    labels = {"positive_control": "정상 기준 요청", "negative_control": "비교 요청", "target": "재현 요청"}
    names = {"observation": "응답 관측", "blind_assessment": "재현 판정", "claim_comparison": "주장과 관측 결과 비교",
             "blind_profile_evidence_audit": "검증 근거 검토"}
    label = labels.get(attempt_kind, names.get(kind, "검증 기록"))
    response = []
    if type(details.get("response_status")) is int:
        response.append(f"HTTP {details['response_status']}")
    if type(details.get("response_bytes")) is int:
        response.append(f"{details['response_bytes']:,} bytes")
    evaluation = details.get("evaluation")
    assertions = evaluation.get("assertions", []) if isinstance(evaluation, dict) else []
    results = [a.get("passed") for a in assertions if isinstance(a, dict)] if isinstance(assertions, list) else []
    if results and all(value is True for value in results):
        result = "판별 조건 충족"
    elif any(value is False for value in results):
        result = "판별 조건 미충족"
    elif type(details.get("reproduced")) is bool:
        result = "재현 확인" if details["reproduced"] else "재현 미확인"
    elif isinstance(details.get("alignment"), str) and details["alignment"] in {"aligned", "conflicting"}:
        result = "주장과 관측 결과 일치" if details["alignment"] == "aligned" else "주장과 관측 결과 불일치"
    else:
        result = "상세 검증 기록에 포함"
    if language == "en":
        translated = {
            "정상 기준 요청": "Baseline request", "비교 요청": "Comparison request", "재현 요청": "Reproduction request",
            "응답 관측": "Observation", "재현 판정": "Reproduction assessment", "주장과 관측 결과 비교": "Claim and observation comparison",
            "검증 근거 검토": "Evidence review", "검증 기록": "Validation record",
            "판별 조건 충족": "Check condition met", "판별 조건 미충족": "Check condition not met",
            "재현 확인": "Reproduction confirmed", "재현 미확인": "Reproduction not confirmed",
            "주장과 관측 결과 일치": "Claim agrees with observations", "주장과 관측 결과 불일치": "Claim conflicts with observations",
            "상세 검증 기록에 포함": "Included in detailed validation records",
        }
        label, result = translated[label], translated[result]
    return {"label": label, "response": " · ".join(response), "result": result}


def generic_markdown(fields: dict[str, str], evidence: list[dict], body: str | None = None, *, language: str = "ko") -> str:
    headings = {"경영진 요약": "Executive summary", "기술 보고서": "Technical report",
                "진단 범위": "Assessment scope", "취약점 평가": "Vulnerability assessment",
                "취약점 재현 및 확인": "Exploitation and confirmation", "확인된 영향": "Demonstrated impact",
                "조치 권고": "Remediation recommendations", "핵심 요약": "Summary",
                "영향받는 대상": "Affected asset", "엔드포인트": "Endpoint", "취약점 분류": "Weakness",
                "심각도": "Severity", "재현 조건": "Prerequisites", "기대 결과": "Expected behavior",
                "실제 관측 결과": "Observed behavior", "개선 권고": "Recommended remediation"}
    tk = lambda ko, en: en if language == "en" else ko
    blocks = ["# " + _plain(fields["title"])]
    if body is None:
        blocks.append(tk("보고서 형식: PTES 기반 개별 취약점 보고서", "Format: PTES-style technical finding"))
    def heading(title: str, level: int = 2) -> None:
        blocks.append("#" * level + " " + (headings.get(title, title) if language == "en" else title))
    def section(title: str, key: str, level: int = 4) -> None:
        if fields.get(key):
            heading(title, level)
            blocks.append(_plain(fields[key]))
    if body is not None:
        blocks.append(body)
    else:
        heading("경영진 요약")
        section("핵심 요약", "summary", 3)
        heading("기술 보고서")
        heading("진단 범위", 3)
        section("영향받는 대상", "asset")
        section("엔드포인트", "endpoint")
        heading("취약점 평가", 3)
        section("취약점 분류", "weakness")
        section("심각도", "severity")
        section("CVSS", "cvss_vector")
        heading("취약점 재현 및 확인", 3)
        section("재현 조건", "prerequisites")
        if fields.get("steps_to_reproduce"):
            blocks.extend(["#### " + tk("재현 절차", "Reproduction steps"), "\n".join(
                # Retain Markdown numbering, while treating captured text as plain text.
                line.split(". ", 1)[0] + ". " + _plain(line.split(". ", 1)[1])
                if line.split(". ", 1)[0].isdigit() and ". " in line else _plain(line)
                for line in fields["steps_to_reproduce"].splitlines())])
        section("기대 결과", "expected_behavior")
        section("실제 관측 결과", "actual_behavior")
    if evidence:
        blocks.extend([("## " if body is not None else "#### ") + tk("검증 근거", "Validation evidence"), tk("| 확인 항목 | 응답 | 관측 결과 |", "| Check | Response | Observation |") + "\n| --- | --- | --- |"])
        rows = []
        for item in evidence:
            display = item.get("display") or evidence_display(item, language=language)
            rows.append("| " + " | ".join(_plain(display[key] or "—") for key in ("label", "response", "result")) + " |")
        blocks[-1] += "\n" + "\n".join(rows)
    if body is None:
        heading("확인된 영향", 3)
        section("영향", "impact")
        heading("조치 권고", 3)
        section("개선 권고", "remediation")
        known = {"title", "summary", "impact", "asset", "weakness", "severity", "cvss_vector", "prerequisites",
                 "steps_to_reproduce", "expected_behavior", "actual_behavior", "remediation", "endpoint"}
        extras = [(key, value) for key, value in fields.items() if key not in known and value]
        if extras:
            blocks.extend(["## " + tk("추가 정보", "Additional information"), "\n".join(_plain(key) + ": " + _plain(value) for key, value in extras)])
    blocks.extend(["## " + tk("상세 검증 자료", "Detailed validation records"), tk("마스킹된 상세 기록(metadata)과 근거 식별 정보는 ZIP의 별도 자료에 보관합니다. 원본 HTTP 본문이나 실제 화면 녹화는 포함하지 않습니다.", "Masked metadata and evidence identifiers are stored separately in the ZIP. Raw HTTP bodies and screen recordings are not included in the report evidence.")])
    return "\n\n".join(blocks) + "\n"
