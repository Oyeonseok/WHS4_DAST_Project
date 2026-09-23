"""ORIGIN_DISCOVERY - confirms an Origin from an HTTP_PROBE result.

 Crawler selection is deliberately not based on SPA/framework heuristics.
Endpoint discovery runs standard and browser-backed collectors for every
origin. The signal is retained only as metadata for adaptive discovery and
Attack skill prioritization; it never suppresses a collector.
"""

from __future__ import annotations

from dataclasses import dataclass

from aidast.recon.tools.http_probe import ProbeResult

SPA_SIGNATURES = {
    "Angular": ["ng-version", "ng-app", "_nghost", "<app-root", "ng-component"],
    "React": ["__next_data__", 'id="root"', "data-reactroot"],
    "Vue": ['id="app"', "data-v-app", "__vue__"],
}

@dataclass
class OriginResolution:
    spa_detected: bool | None
    framework_signature: str | None
    main_crawler_mode: str


def resolve_origin(probe_result: ProbeResult) -> OriginResolution:
    # Detect only as a non-blocking signal. It must not select standard versus
    # headless: both collectors always run in endpoint_discovery.
    body_lower = probe_result.body.lower()
    framework = next(
        (name for name, markers in SPA_SIGNATURES.items()
         if any(marker in body_lower for marker in markers)),
        None,
    )
    if framework is None:
        script_count = body_lower.count("<script")
        module_count = body_lower.count('type="module"') + body_lower.count("type='module'")
        mount = any(marker in body_lower for marker in (
            "<app-root", 'id="root"', "id=\'root\'", 'id="app"', "id=\'app\'",
        ))
        if (len(body_lower) < 2000 and script_count >= 2) or module_count or mount:
            framework = None
            spa_detected = True
        else:
            spa_detected = False
    else:
        spa_detected = True
    return OriginResolution(
        spa_detected=spa_detected,
        framework_signature=framework,
        main_crawler_mode="katana_both",
    )
