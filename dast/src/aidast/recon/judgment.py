"""Normalize/Merge/Rule Engine and Deep Path judgment.

The design docs assign these to an LLM call. For the MVP, both are plain
rule-based Python so the pipeline runs end to end without any LLM
dependency. Swap the body of `assess_gap_ratio` for an LLM call later - the
executor only depends on the `GapRatioResult` shape, not on how it's
computed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

PARAM_PATTERN = re.compile(r"/\d+(?=/|$)|/[0-9a-fA-F]{8,}(?=/|$)")

STATIC_EXTENSIONS = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".map",
)


def normalize_path(raw_path: str) -> str:
    """`/api/users/123` -> `/api/users/:id` (rule-based, MVP)."""
    return PARAM_PATTERN.sub("/:id", raw_path) or "/"


def is_static_asset(path: str) -> bool:
    return path.lower().endswith(STATIC_EXTENSIONS)


def merge_and_normalize(raw_endpoints: list[dict]) -> list[dict]:
    """Merges raw findings from every tool into deduplicated endpoints.

    Static assets are kept but flagged `is_excluded` rather than dropped, so
    the exclusion decision stays auditable.
    """
    merged: dict[tuple[str, str], dict] = {}
    for item in raw_endpoints:
        norm_path = normalize_path(item["path"])
        key = (item["method"], norm_path)
        excluded = is_static_asset(item["path"])
        if key not in merged:
            merged[key] = {
                "method": item["method"],
                "path": item["path"],
                "normalized_path": norm_path,
                "content_type": item.get("content_type"),
                "source_tools": {item["source"]},
                "is_excluded": excluded,
                "exclude_reason": "static_asset" if excluded else None,
            }
        else:
            merged[key]["source_tools"].add(item["source"])
    return list(merged.values())


@dataclass
class GapRatioResult:
    ratio: float
    needs_deep_crawl: bool
    reasoning: str


def assess_gap_ratio(merged_endpoints: list[dict], *, threshold: float = 0.3) -> GapRatioResult:
    """katana_standard와 katana_headless를 둘 다 돌린 뒤, headless에서만
    나온(= JS 렌더링 없이는 못 찾는) 엔드포인트 비율을 잰다.

    두 모드를 이미 다 실행했으므로 `needs_deep_crawl=True`가 나와도 추가로
    재크롤링할 필요는 없다 - headless 결과는 이미 merged_endpoints 안에
    포함돼 있다. 이 값은 "이 origin이 실제로 SPA 성격이 강한가"를 보여주는
    감사(audit)용 신호일 뿐이다.
    """
    total = len(merged_endpoints)
    if total == 0:
        return GapRatioResult(ratio=0.0, needs_deep_crawl=False, reasoning="발견된 엔드포인트 없음")

    dynamic_only = sum(
        1 for e in merged_endpoints
        if "katana_headless" in e["source_tools"] and "katana_standard" not in e["source_tools"]
    )
    ratio = dynamic_only / total
    needs_deep = ratio >= threshold
    comparator = ">=" if needs_deep else "<"
    reasoning = (
        f"katana_headless 전용 발견 {dynamic_only}/{total} ({ratio:.0%}) "
        f"{comparator} 임계값 {threshold:.0%}"
    )
    return GapRatioResult(ratio=ratio, needs_deep_crawl=needs_deep, reasoning=reasoning)


def assess_observation_gap(merged_endpoints: list[dict], *, threshold: float = 0.3) -> GapRatioResult:
    """실제 트래픽(mitmproxy)과 메인 크롤러(katana) 비교판. 구조는
    assess_gap_ratio와 완전히 같고 비교 대상 태그만 다르다 - katana는
    "봇 두 종류끼리" 비교였다면, 이건 "진짜 트래픽 vs 봇" 비교라 더
    직접적인 신호다. mitmproxy 전용으로 발견된(= 자동 크롤러가 못 찾은)
    비율을 잰다.

    아직 실전 검증 안 됨 - mitm_ingest.py 상단 TODO 참고."""
    total = len(merged_endpoints)
    if total == 0:
        return GapRatioResult(ratio=0.0, needs_deep_crawl=False, reasoning="발견된 엔드포인트 없음")

    crawler_tags = {"katana_standard", "katana_headless"}
    observed_only = sum(
        1 for e in merged_endpoints
        if "mitmproxy" in e["source_tools"] and not (e["source_tools"] & crawler_tags)
    )
    ratio = observed_only / total
    needs_action = ratio >= threshold
    comparator = ">=" if needs_action else "<"
    reasoning = (
        f"mitmproxy 전용 발견 {observed_only}/{total} ({ratio:.0%}) "
        f"{comparator} 임계값 {threshold:.0%}"
    )
    return GapRatioResult(ratio=ratio, needs_deep_crawl=needs_action, reasoning=reasoning)
