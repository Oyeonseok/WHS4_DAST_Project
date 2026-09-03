"""Fail-closed recon tool runner backed by a policy-aware mitmproxy addon."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from playwright.sync_api import sync_playwright

from aidast.recon.policy import (
    INTERNAL_EXECUTION_HEADER,
    PolicyError,
    ProxyCoverage,
    ProxyMode,
    ReconPolicy,
    ScopeGuard,
    ToolPolicy,
    TrafficClass,
)
from aidast.recon.policy_store import PolicyRunStore


SUPPORTED_TARGET_HTTP_TOOLS = {
    "curl",
    "httpx",
    "katana",
    "playwright",
    "ffuf",
    "nuclei",
}


def supported_tool_ids() -> set[str]:
    """Return a copy of tool IDs backed by audited, fixed-argument adapters."""
    return set(SUPPORTED_TARGET_HTTP_TOOLS)


@dataclass(frozen=True)
class ExecutionResult:
    execution_id: str
    tool_id: str
    exit_code: int
    stdout: str
    stderr: str


def _header_arguments(tool_id: str, headers: dict[str, str]) -> list[str]:
    flag = "--header" if tool_id == "curl" else "-H"
    result: list[str] = []
    for name, value in headers.items():
        result.extend([flag, f"{name}: {value}"])
    return result


def _redact_arguments(arguments: list[str]) -> list[str]:
    redacted: list[str] = []
    hide_next = False
    for argument in arguments:
        if hide_next:
            header_name = argument.partition(":")[0]
            redacted.append(f"{header_name}: <redacted>")
            hide_next = False
            continue
        redacted.append(argument)
        if argument in {"-H", "--header"}:
            hide_next = True
    return redacted


class MitmProxyProcess:
    def __init__(
        self,
        *,
        policy: ReconPolicy,
        flow_log_path: Path,
        run_id: str,
        port: int,
    ):
        self.flow_log_path = flow_log_path
        self.run_id = run_id
        self.port = port
        self.process: subprocess.Popen[str] | None = None
        self._temporary_confdir = tempfile.TemporaryDirectory(prefix="aidast-mitm-")
        self._policy_snapshot = Path(self._temporary_confdir.name) / "recon-policy.json"
        self._stderr_path = Path(self._temporary_confdir.name) / "mitmdump.stderr.log"
        self._policy_snapshot.write_text(
            policy.model_dump_json(indent=2), encoding="utf-8"
        )

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def ca_cert_path(self) -> Path:
        return Path(self._temporary_confdir.name) / "mitmproxy-ca-cert.pem"

    def start(self) -> None:
        environment_executable = Path(sys.executable).with_name("mitmdump")
        executable = (
            str(environment_executable)
            if environment_executable.is_file()
            else shutil.which("mitmdump")
        )
        if executable is None:
            raise PolicyError("mitmdump is not installed or is not on PATH")
        addon_path = Path(__file__).parent / "tools" / "mitm_addon.py"
        command = [
            executable,
            "-q",
            "-s",
            str(addon_path),
            "--set",
            f"flow_log={self.flow_log_path}",
            "--set",
            f"policy_file={self._policy_snapshot}",
            "--set",
            f"run_id={self.run_id}",
            "--set",
            f"confdir={self._temporary_confdir.name}",
            "--listen-host",
            "127.0.0.1",
            "--listen-port",
            str(self.port),
        ]
        with self._stderr_path.open("w", encoding="utf-8") as stderr_file:
            self.process = subprocess.Popen(
                command,
                stdout=stderr_file,
                stderr=subprocess.STDOUT,
                text=True,
            )
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise PolicyError(
                    "mitmdump exited before accepting connections: "
                    + self._startup_error()
                )
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    if self.ca_cert_path.is_file():
                        time.sleep(0.1)
                        if self.process.poll() is None:
                            return
            except OSError:
                time.sleep(0.05)
        detail = self._startup_error()
        self.stop()
        raise PolicyError(
            f"mitmdump did not listen on 127.0.0.1:{self.port}: {detail}"
        )

    def _startup_error(self) -> str:
        try:
            message = self._stderr_path.read_text(encoding="utf-8").strip()
        except OSError:
            return "stderr unavailable"
        return message[-1000:] or "no stderr output"

    def exited_error(self) -> str | None:
        if self.process is None or self.process.poll() is None:
            return None
        return self._startup_error()

    def stop(self) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        self._temporary_confdir.cleanup()


class PolicyToolRunner:
    def __init__(
        self,
        *,
        policy: ReconPolicy,
        policy_path: Path,
        target: str,
        db_path: Path,
        flow_log_path: Path,
        proxy_port: int = 18080,
        headers: dict[str, str] | None = None,
        runtime_inputs: dict[str, str] | None = None,
        wordlist: Path | None = None,
    ):
        allowed, reason = ScopeGuard(policy).evaluate_url(target)
        if not allowed:
            raise PolicyError(f"target is outside policy: {reason}")
        self.policy = policy
        self.policy_path = policy_path
        self.target = target
        self.store = PolicyRunStore(db_path)
        self.flow_log_path = flow_log_path
        self.proxy_port = proxy_port
        self.headers = dict(headers or {})
        self.runtime_inputs = dict(runtime_inputs or {})
        self.wordlist = wordlist

    def close(self) -> None:
        self.store.close()

    def run(self, tool_ids: list[str]) -> list[ExecutionResult]:
        if not tool_ids:
            raise PolicyError("at least one tool must be requested")
        if len(tool_ids) != len(set(tool_ids)):
            raise PolicyError("duplicate tool IDs are not allowed")

        tool_policies = {
            tool_id: self._validate_tool(tool_id) for tool_id in tool_ids
        }
        self._validate_runtime_inputs(tool_ids)
        for tool_id in tool_ids:
            self._validate_prerequisites(tool_id)
        run_id = self.store.start_run(
            policy_path=self.policy_path, target=self.target
        )
        proxy = MitmProxyProcess(
            policy=self.policy,
            flow_log_path=self.flow_log_path,
            run_id=run_id,
            port=self.proxy_port,
        )
        results: list[ExecutionResult] = []
        try:
            proxy.start()
            for tool_id in tool_ids:
                results.append(
                    self._run_one(
                        tool_id,
                        tool_policies[tool_id],
                        proxy.url,
                        run_id,
                        ca_cert_path=proxy.ca_cert_path,
                    )
                )
        except BaseException as exc:
            proxy_error = proxy.exited_error()
            proxy.stop()
            self.store.ingest_flow_log(self.flow_log_path, run_id=run_id)
            self.store.finish_run(run_id, status="failed")
            if proxy_error is not None:
                raise PolicyError(
                    f"mitmdump exited during tool execution: {proxy_error}"
                ) from exc
            raise

        proxy.stop()
        self.store.ingest_flow_log(self.flow_log_path, run_id=run_id)
        missing_captures = [
            result.tool_id
            for result in results
            if self.store.count_execution_flows(result.execution_id) == 0
        ]
        if missing_captures:
            self.store.finish_run(run_id, status="failed")
            raise PolicyError(
                "proxy enforcement is unverified for tools with no captured flows: "
                + ", ".join(missing_captures)
            )
        self.store.finish_run(run_id, status="completed")
        return results

    def _validate_tool(self, tool_id: str) -> ToolPolicy:
        tool = self.policy.require_executable_tool(tool_id)
        if tool_id not in SUPPORTED_TARGET_HTTP_TOOLS:
            raise PolicyError(f"runner has no safe adapter for tool: {tool_id}")
        if tool.traffic_class is not TrafficClass.TARGET_HTTP:
            raise PolicyError(
                f"tool traffic cannot be safely constrained by target rules: {tool_id} "
                f"({tool.traffic_class.value})"
            )
        if self.policy.global_controls.proxy_required_for_http and (
            tool.proxy.mode is ProxyMode.UNSUPPORTED
            or tool.proxy.coverage in {ProxyCoverage.NONE, ProxyCoverage.UNKNOWN}
        ):
            raise PolicyError(f"policy requires proxy coverage for tool: {tool_id}")
        return tool

    def _validate_prerequisites(self, tool_id: str) -> None:
        if tool_id == "ffuf" and (
            self.wordlist is None or not self.wordlist.is_file()
        ):
            raise PolicyError("ffuf requires an existing wordlist")
        if tool_id != "playwright" and shutil.which(tool_id) is None:
            raise PolicyError(f"tool is not installed or is not on PATH: {tool_id}")

    def _validate_runtime_inputs(self, tool_ids: list[str]) -> None:
        missing = [
            item.id
            for item in self.policy.runtime_inputs
            if any(tool_id in item.required_by for tool_id in tool_ids)
            and item.id not in self.runtime_inputs
        ]
        if missing:
            raise PolicyError("missing runtime inputs: " + ", ".join(sorted(missing)))

        supplied_headers = {name.casefold() for name in self.headers}
        for requirement in self.policy.global_controls.required_headers:
            if requirement.required and requirement.value is None:
                if requirement.name.casefold() not in supplied_headers:
                    raise PolicyError(f"missing required header: {requirement.name}")

    def _resolved_headers(self, execution_id: str) -> dict[str, str]:
        headers = {
            name: value
            for name, value in self.headers.items()
            if name.casefold() != INTERNAL_EXECUTION_HEADER.casefold()
        }
        for requirement in self.policy.global_controls.required_headers:
            if requirement.value is not None:
                headers = {
                    name: value
                    for name, value in headers.items()
                    if name.casefold() != requirement.name.casefold()
                }
                headers[requirement.name] = requirement.value
        headers[INTERNAL_EXECUTION_HEADER] = execution_id
        return headers

    def _run_one(
        self,
        tool_id: str,
        tool: ToolPolicy,
        proxy_url: str,
        run_id: str,
        ca_cert_path: Path | None = None,
    ) -> ExecutionResult:
        execution_id = "tool_exec_" + uuid.uuid4().hex
        if tool_id == "playwright":
            return self._run_playwright(
                tool,
                proxy_url,
                run_id,
                execution_id=execution_id,
            )
        command, timeout = self._build_command(
            tool_id,
            tool,
            proxy_url,
            execution_id=execution_id,
            ca_cert_path=ca_cert_path,
        )
        execution_id = self.store.start_execution(
            run_id=run_id,
            tool_id=tool_id,
            redacted_arguments=_redact_arguments(command),
            execution_id=execution_id,
        )
        try:
            environment = os.environ.copy()
            if ca_cert_path is not None:
                environment["SSL_CERT_FILE"] = str(ca_cert_path)
                environment["REQUESTS_CA_BUNDLE"] = str(ca_cert_path)
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=environment,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            self.store.finish_execution(
                execution_id,
                status="timed_out",
                exit_code=None,
                stdout=stdout,
                stderr=stderr,
            )
            raise PolicyError(f"tool timed out: {tool_id}") from exc

        status = "completed" if completed.returncode == 0 else "failed"
        self.store.finish_execution(
            execution_id,
            status=status,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )
        if completed.returncode != 0:
            raise PolicyError(
                f"tool failed: {tool_id} (exit code {completed.returncode})"
            )
        return ExecutionResult(
            execution_id=execution_id,
            tool_id=tool_id,
            exit_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )

    def _run_playwright(
        self,
        tool: ToolPolicy,
        proxy_url: str,
        run_id: str,
        *,
        execution_id: str,
    ) -> ExecutionResult:
        timeout = (
            tool.enforced_controls.maximum_duration_seconds
            or self.policy.global_controls.maximum_duration_seconds
            or 120
        )
        command = ["playwright", "goto", self.target, "--proxy", proxy_url]
        self._validate_adapter_arguments("playwright", tool, command)
        execution_id = self.store.start_execution(
            run_id=run_id,
            tool_id="playwright",
            redacted_arguments=command,
            execution_id=execution_id,
        )
        browser = None
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(
                    headless=True,
                    proxy={"server": proxy_url},
                    timeout=timeout * 1000,
                )
                context = browser.new_context(
                    ignore_https_errors=True,
                    extra_http_headers=self._resolved_headers(execution_id),
                    service_workers="block",
                )
                page = context.new_page()
                response = page.goto(
                    self.target,
                    wait_until="domcontentloaded",
                    timeout=timeout * 1000,
                )
                output = {
                    "final_url": page.url,
                    "status": response.status if response is not None else None,
                    "title": page.title(),
                }
                stdout = json.dumps(output, ensure_ascii=False)
        except Exception as exc:  # Playwright exposes multiple runtime error classes.
            self.store.finish_execution(
                execution_id,
                status="failed",
                exit_code=1,
                stdout="",
                stderr=str(exc),
            )
            raise PolicyError(f"tool failed: playwright ({exc})") from exc
        finally:
            if browser is not None and browser.is_connected():
                browser.close()

        self.store.finish_execution(
            execution_id,
            status="completed",
            exit_code=0,
            stdout=stdout,
            stderr="",
        )
        return ExecutionResult(
            execution_id=execution_id,
            tool_id="playwright",
            exit_code=0,
            stdout=stdout,
            stderr="",
        )

    def _build_command(
        self,
        tool_id: str,
        tool: ToolPolicy,
        proxy_url: str,
        *,
        execution_id: str,
        ca_cert_path: Path | None = None,
    ) -> tuple[list[str], int]:
        controls = tool.enforced_controls
        global_controls = self.policy.global_controls
        rate = (
            controls.maximum_requests_per_second
            or global_controls.maximum_requests_per_second
            or 1
        )
        concurrency = (
            controls.maximum_concurrency
            or global_controls.maximum_concurrency
            or 1
        )
        timeout = (
            controls.maximum_duration_seconds
            or global_controls.maximum_duration_seconds
            or 120
        )
        headers = self._resolved_headers(execution_id)

        if tool_id == "curl":
            command = [
                "curl",
                "--silent",
                "--show-error",
                "--proxy",
                proxy_url,
                "--max-time",
                str(timeout),
            ]
            if ca_cert_path is not None:
                command.extend(["--cacert", str(ca_cert_path)])
            if global_controls.follow_off_scope_redirects:
                command.extend(["--location", "--max-redirs", "5"])
            command.extend(_header_arguments(tool_id, headers))
            command.append(self.target)
        elif tool_id == "httpx":
            command = [
                "httpx",
                "-u",
                self.target,
                "-silent",
                "-http-proxy",
                proxy_url,
                "-rl",
                str(rate),
                "-t",
                str(concurrency),
            ]
            command.extend(_header_arguments(tool_id, headers))
        elif tool_id == "katana":
            command = [
                "katana",
                "-u",
                self.target,
                "-silent",
                "-jc",
                "-proxy",
                proxy_url,
                "-rl",
                str(rate),
                "-c",
                str(concurrency),
                "-ct",
                f"{timeout}s",
            ]
            command.extend(_header_arguments(tool_id, headers))
        elif tool_id == "ffuf":
            if self.wordlist is None or not self.wordlist.is_file():
                raise PolicyError("ffuf requires an existing wordlist")
            command = [
                "ffuf",
                "-u",
                self.target.rstrip("/") + "/FUZZ",
                "-w",
                str(self.wordlist),
                "-x",
                proxy_url,
                "-s",
                "-rate",
                str(rate),
                "-t",
                str(concurrency),
                "-maxtime",
                str(timeout),
            ]
            command.extend(_header_arguments(tool_id, headers))
        elif tool_id == "nuclei":
            command = [
                "nuclei",
                "-u",
                self.target,
                "-silent",
                "-proxy",
                proxy_url,
                "-rl",
                str(rate),
                "-c",
                str(concurrency),
            ]
            command.extend(_header_arguments(tool_id, headers))
        else:
            raise PolicyError(f"runner has no adapter for tool: {tool_id}")

        self._validate_adapter_arguments(tool_id, tool, command)
        return command, timeout

    def _validate_adapter_arguments(
        self, tool_id: str, tool: ToolPolicy, command: list[str]
    ) -> None:
        missing_required = [
            argument
            for argument in tool.enforced_controls.required_arguments
            if argument not in command
        ]
        if missing_required:
            raise PolicyError(
                f"safe adapter does not implement required arguments for {tool_id}: "
                + ", ".join(missing_required)
            )
        if any(
            argument in command
            for argument in tool.enforced_controls.forbidden_arguments
        ):
            raise PolicyError(
                f"safe adapter contains a forbidden argument for {tool_id}"
            )
