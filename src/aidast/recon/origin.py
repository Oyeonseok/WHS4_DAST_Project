"""ORIGIN_DISCOVERY - confirms an Origin from an HTTP_PROBE result and
decides SPA vs server-rendered with simple rule-based signatures.

MVP note: this replaces the LLM judgment mentioned in the design docs with
plain if-statements. The function signature is deliberately small
(ProbeResult in, OriginResolution out) so swapping the body for an LLM call
later doesn't require touching the executor.
"""

from __future__ import annotations

from dataclasses import dataclass

from aidast.recon.tools.http_probe import ProbeResult

SPA_SIGNATURES = {
    "Angular": ["ng-version", "ng-app", "_nghost"],
    "React": ["__next_data__", 'id="root"', "data-reactroot"],
    "Vue": ['id="app"', "data-v-app", "__vue__"],
}


@dataclass
class OriginResolution:
    spa_detected: bool
    framework_signature: str | None
    main_crawler_mode: str


def resolve_origin(probe_result: ProbeResult) -> OriginResolution:
    body_lower = probe_result.body.lower()

    for framework, markers in SPA_SIGNATURES.items():
        if any(marker.lower() in body_lower for marker in markers):
            return OriginResolution(
                spa_detected=True,
                framework_signature=framework,
                main_crawler_mode="katana_headless",
            )

    # Short body with several <script> tags and little visible text is a
    # reasonable SPA heuristic even without a recognized framework marker.
    script_count = body_lower.count("<script")
    if len(probe_result.body) < 2000 and script_count >= 2:
        return OriginResolution(
            spa_detected=True,
            framework_signature=None,
            main_crawler_mode="katana_headless",
        )

    return OriginResolution(
        spa_detected=False,
        framework_signature=None,
        main_crawler_mode="katana_standard",
    )
