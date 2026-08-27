"""ASSET_DISCOVERY / DNS_RESOLUTION / HOST_PORT_DISCOVERY - Domain/Wildcard
scope only. A URL-scope target (e.g. Juice Shop) never reaches these.

Every wrapper skips gracefully (prints a warning, returns []) when the
underlying binary isn't installed, so the pipeline never hard-crashes just
because subfinder/dnsx/naabu aren't on PATH yet.
"""

from __future__ import annotations

import shutil
import subprocess


def _run_tool(command: list[str], *, tool_name: str, input_text: str | None = None, timeout: int = 120) -> list[str]:
    if shutil.which(command[0]) is None:
        print(f"  [건너뜀] {tool_name}이 설치돼 있지 않음")
        return []
    try:
        completed = subprocess.run(
            command, input=input_text, capture_output=True, text=True, timeout=timeout
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        print(f"  [경고] {tool_name} 실행 실패: {exc}")
        return []
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def run_subfinder(domain: str) -> list[str]:
    return _run_tool(["subfinder", "-d", domain, "-silent"], tool_name="subfinder")


def run_dnsx(hosts: list[str]) -> list[str]:
    if not hosts:
        return []
    return _run_tool(["dnsx", "-silent"], tool_name="dnsx", input_text="\n".join(hosts))


def run_naabu(hosts: list[str]) -> list[str]:
    if not hosts:
        return []
    return _run_tool(["naabu", "-silent"], tool_name="naabu", input_text="\n".join(hosts))
