"""Compare Recon HTTP evidence with a pinned GET route inventory."""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from urllib.parse import urlsplit


def _matches(template: str, observed: str) -> bool:
    expected_parts = (template.rstrip("/") or "/").split("/")
    actual_parts = (observed.rstrip("/") or "/").split("/")
    return len(expected_parts) == len(actual_parts) and all(
        expected.casefold() == actual.casefold()
        or (expected.startswith(":") and bool(actual))
        for expected, actual in zip(expected_parts, actual_parts)
    )


def _observed_gets(db_path: Path, origin: str) -> list[tuple[str, int]]:
    connection = sqlite3.connect(db_path.resolve().as_uri() + "?mode=ro", uri=True)
    try:
        scan_statuses = connection.execute("SELECT status FROM scans").fetchall()
        if scan_statuses != [("completed",)]:
            raise ValueError(f"scan not completed: {db_path} ({scan_statuses})")
        rows = connection.execute("""
            SELECT t.url, t.response_status
            FROM endpoints AS e
            JOIN origins AS o ON o.origin_id = e.origin_id
            JOIN http_transactions AS t
              ON t.endpoint_id = e.endpoint_id AND t.origin_id = e.origin_id
            WHERE o.base_url = ? AND e.method = 'GET'
              AND t.method = 'GET' AND e.is_excluded = 0
              AND t.response_status IS NOT NULL
        """, (origin,)).fetchall()
        expected = urlsplit(origin)
        return [
            (parsed.path or "/", status)
            for url, status in rows
            if url and (parsed := urlsplit(url)).scheme.casefold() == expected.scheme.casefold()
            and parsed.netloc.casefold() == expected.netloc.casefold()
        ]
    finally:
        connection.close()


def _render(truth: dict, runs: list[tuple[str, Path]]) -> str:
    routes = truth["routes"]
    if len(routes) != len(set(routes)) or any(not route.startswith("GET /") for route in routes):
        raise ValueError("ground truth must contain unique GET routes")
    observations = {name: _observed_gets(db, truth["origin"]) for name, db in runs}
    results: dict[str, dict[str, list[int]]] = {}
    for name, observed in observations.items():
        results[name] = {
            route: sorted({status for path, status in observed if _matches(route[4:], path)})
            for route in routes
        }

    lines = [
        "# Juice Shop Recon GET route O/X 평가",
        "",
        f"기준: `{truth['origin']}`의 명시적 application GET route {len(routes)}개. "
        "O는 Recon DB에 같은 origin의 비제외 GET HTTP 요청 URL과 응답이 일치하는 경로가 있다는 뜻이다. "
        "경로는 Express 기본 설정에 맞춰 대소문자를 구분하지 않는다. "
        "HTTP 500도 경로 관측 O로 표시하며 정상 동작을 뜻하지 않는다. "
        "정적 파일, generic middleware, SPA fallback URL은 정답지에 포함하지 않는다.",
        "",
        "| 실행 | 발견 | 누락 |",
        "| --- | ---: | ---: |",
    ]
    for name, _ in runs:
        found = sum(bool(statuses) for statuses in results[name].values())
        lines.append(f"| {name} | {found}/{len(routes)} | {len(routes) - found} |")
    lines += ["", "| 정답 경로 | " + " | ".join(
        f"{name} O/X | {name} HTTP" for name, _ in runs
    ) + " |", "| --- | " + " | ".join("--- | ---" for _ in runs) + " |"]
    for route in routes:
        cells = []
        for name, _ in runs:
            statuses = results[name][route]
            cells += ["O" if statuses else "X", ", ".join(map(str, statuses)) if statuses else "—"]
        lines.append(f"| {route} | " + " | ".join(cells) + " |")
    for name, _ in runs:
        lines += ["", f"### {name} 누락 경로", ""]
        lines += [f"- `{route}`" for route in routes if not results[name][route]] or ["없음"]
    return "\n".join(lines) + "\n"


def _render_surface(truth: dict, runs: list[tuple[str, Path]]) -> str:
    routes = truth["routes"]
    results: dict[str, dict[str, bool]] = {}
    for name, path in runs:
        surface = json.loads(path.read_text(encoding="utf-8"))
        observed = [
            endpoint["path"]
            for origin in surface["origins"]
            if origin["base_url"] == truth["origin"]
            for endpoint in origin["endpoints"]
            if endpoint["method"] == "GET"
        ]
        results[name] = {
            route: any(_matches(route[4:], path) for path in observed)
            for route in routes
        }

    lines = [
        "# Juice Shop Recon Surface GET route O/X 평가", "",
        "O는 최종 Surface.json에 같은 origin의 GET 경로가 정답 route로 명시되어 있음을 뜻한다. "
        "`/api/:param` 같은 일반화 경로는 서로 다른 정적 route의 발견으로 세지 않는다. "
        "이 표는 실제 HTTP 요청 관측과 별개로 최종 공격표면에 남은 경로를 평가한다.",
        "", "| 실행 | Surface 보존 | 누락 |", "| --- | ---: | ---: |",
    ]
    for name, _ in runs:
        found = sum(results[name].values())
        lines.append(f"| {name} | {found}/{len(routes)} | {len(routes) - found} |")
    lines += ["", "| 정답 경로 | " + " | ".join(f"{name} O/X" for name, _ in runs) + " |",
              "| --- | " + " | ".join("---" for _ in runs) + " |"]
    for route in routes:
        cells = ["O" if results[name][route] else "X" for name, _ in runs]
        lines.append(f"| {route} | " + " | ".join(cells) + " |")
    for name, _ in runs:
        lines += ["", f"### {name} Surface 누락 경로", ""]
        lines += [f"- `{route}`" for route in routes if not results[name][route]] or ["없음"]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ground-truth", required=True, type=Path)
    parser.add_argument("--run", required=True, action="append", metavar="LABEL=RECON_DB")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--surface-run", action="append", metavar="LABEL=SURFACE_JSON")
    parser.add_argument("--surface-output", type=Path)
    args = parser.parse_args(argv)
    if bool(args.surface_run) != bool(args.surface_output):
        parser.error("--surface-run and --surface-output must be used together")
    runs = []
    for run in args.run:
        name, separator, path = run.partition("=")
        if not separator or not name or not path:
            parser.error("--run must be LABEL=RECON_DB")
        runs.append((name, Path(path)))
    truth = json.loads(args.ground_truth.read_text(encoding="utf-8"))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(_render(truth, runs), encoding="utf-8")
    if args.surface_run:
        surface_runs = []
        for run in args.surface_run:
            name, separator, path = run.partition("=")
            if not separator or not name or not path:
                parser.error("--surface-run must be LABEL=SURFACE_JSON")
            surface_runs.append((name, Path(path)))
        args.surface_output.parent.mkdir(parents=True, exist_ok=True)
        args.surface_output.write_text(_render_surface(truth, surface_runs), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
