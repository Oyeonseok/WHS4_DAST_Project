"""Atomic, barrier-released HTTP and multipart Validation transport."""

from __future__ import annotations

import hashlib
import queue
import sqlite3
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.error import HTTPError
from urllib.request import Request, build_opener
from uuid import uuid4

from aidast.core.request_broker import BrokerResponse
from aidast.recon.policy import TargetPolicy

from ..contracts.binary import BinaryArtifactResolver, BinaryArtifactUnavailable
from ..contracts.concurrent_contract import (
    ConcurrentAggregateAssertion, ConcurrentAttemptContract, ConcurrentRuntimeContract,
)
from ..contracts.models import BlindCase, ReproductionObservation
from ..contracts.multipart_contract import MultipartRequestTemplate, encode_multipart
from ..contracts.runtime_contract import (
    HttpRequestTemplate, evaluate_http_response, render_http_request,
)
from .credentials import PipelineCredentialResolver
from .multipart_adapter import MultipartReproductionPort, _NoRedirect
from .transport_broker import (
    TransportDispatchResult, TransportOperationSpec, ValidationTransportBroker,
    ValidationTransportError,
)


_MAX_RESPONSE_BYTES = 200_000


class ConcurrentExecutionError(ValidationTransportError):
    """A concurrent attempt could not establish a definite terminal observation."""


@dataclass(frozen=True)
class ConcurrentMemberResult:
    """Sanitized terminal fact for one pre-reserved group member."""

    ordinal: int
    operation_id: str
    response_status: int | None
    response_sha256: str | None
    response_bytes: int
    duration_ms: float | None
    evaluation: Mapping[str, Any] | None
    outcome_unknown: bool = False


@dataclass(frozen=True)
class _PreparedRequest:
    url: str
    headers: Mapping[str, str]
    body: bytes | None
    request_sha256: str


def evaluate_concurrent_results(
    results: tuple[ConcurrentMemberResult, ...],
    assertions: tuple[ConcurrentAggregateAssertion, ...], *, start_skew_ms: float,
    final_evaluation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate only bounded aggregate facts, never response contents."""
    completed = tuple(item for item in results if not item.outcome_unknown and item.evaluation is not None)
    success_count = sum(bool(item.evaluation["signal_observed"]) for item in completed)
    response_digests = {item.response_sha256 for item in completed if item.response_sha256 is not None}
    values: dict[str, Any] = {
        "success_count": success_count,
        "distinct_response_digests": len(response_digests),
        "start_skew_ms": start_skew_ms,
    }
    assertion_results = []
    for assertion in assertions:
        if assertion.kind == "success_count_equals":
            actual, passed = success_count, success_count == assertion.expected
        elif assertion.kind == "success_count_at_least":
            actual, passed = success_count, success_count >= assertion.expected
        elif assertion.kind == "distinct_response_digests_at_least":
            actual, passed = len(response_digests), len(response_digests) >= assertion.expected
        else:
            actual = None if final_evaluation is None else final_evaluation.get("signal_observed")
            passed = actual is not None and actual == assertion.expected
        assertion_results.append({
            "assertion_id": assertion.assertion_id, "kind": assertion.kind,
            "passed": passed, "actual": actual,
        })
    return values | {
        "signal_observed": (
            all(item["passed"] for item in assertion_results)
            if assertion_results else bool(completed) and all(
                bool(item.evaluation["signal_observed"]) for item in completed
            )
        ),
        "assertions": assertion_results,
    }


class ConcurrentReproductionPort:
    """Dispatch an already-authorized finite group through one release barrier."""

    requires_request_ledger = True

    def __init__(self, *, transport: Callable | None = None,
                 credential_resolver: Callable[[str], Mapping[str, str]] | None = None,
                 artifact_resolver: BinaryArtifactResolver | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 monotonic_ns: Callable[[], int] = time.monotonic_ns):
        self.transport = transport or build_opener(_NoRedirect()).open
        self.credential_resolver = credential_resolver
        self.artifact_resolver = artifact_resolver
        self.clock, self.monotonic_ns = clock, monotonic_ns

    def unsupported_reason(self, blind_case: BlindCase) -> str | None:
        if blind_case.target_kind != "finding":
            return "concurrent_adapter_does_not_support_chain"
        if (blind_case.runtime_contract or {}).get("runtime_kind") != "concurrent":
            return "concurrent_runtime_contract_missing"
        try:
            ConcurrentRuntimeContract.model_validate(blind_case.runtime_contract)
        except ValueError:
            return "concurrent_runtime_contract_invalid"
        if blind_case.credential_references and self.credential_resolver is None:
            return "credential_reference_unavailable"
        return None

    @staticmethod
    def _observation(blind_case: BlindCase, *, outcome: str, observed: bool | None,
                     details: Mapping[str, Any], blocker_axis: str | None = None,
                     policy_allowed: bool = True) -> ReproductionObservation:
        digest = hashlib.sha256(b"").hexdigest()
        values = {
            "outcome": outcome, "signal_type": blind_case.signal_types[0],
            "signal_observed": observed, "blocker_axis": blocker_axis,
            "details": dict(details), "content_sha256": digest, "content_length": 0,
            "policy_allowed": policy_allowed,
        }
        # The existing generic envelope predates durable concurrent attempts.
        # Preserve its wire compatibility while exposing the mandated unknown state.
        if outcome == "outcome_unknown":
            return ReproductionObservation.model_construct(**values)
        return ReproductionObservation(**values)

    def _resolved_headers(self, blind_case: BlindCase) -> dict[str, str] | None:
        headers: dict[str, str] = {}
        for reference in blind_case.credential_references:
            if self.credential_resolver is None:
                return None
            try:
                resolved = PipelineCredentialResolver._headers(self.credential_resolver(reference))
            except (ImportError, OSError, KeyError, ValueError, sqlite3.Error):
                return None
            if {name.casefold() for name in headers} & {name.casefold() for name in resolved}:
                return None
            headers.update(resolved)
        return headers

    def _prepare(self, attempt: ConcurrentAttemptContract, endpoint: str,
                 credential_headers: Mapping[str, str]) -> _PreparedRequest:
        if isinstance(attempt.request, MultipartRequestTemplate):
            from ..contracts.multipart_contract import MultipartAttemptContract
            multipart_attempt = MultipartAttemptContract(
                request=attempt.request, assertions=attempt.member_assertions,
            )
            url, headers, body = encode_multipart(multipart_attempt, endpoint, self.artifact_resolver)
        elif isinstance(attempt.request, HttpRequestTemplate):
            url, headers, body = render_http_request(endpoint, attempt.request)
        else:  # pragma: no cover - Pydantic union prevents this boundary bypass.
            raise ConcurrentExecutionError("concurrent child is not HTTP or multipart")
        if {name.casefold() for name in headers} & {name.casefold() for name in credential_headers}:
            raise ConcurrentExecutionError("credential header collision")
        headers = dict(headers) | dict(credential_headers)
        payload = body or b""
        return _PreparedRequest(url, headers, body, hashlib.sha256(payload).hexdigest())

    @staticmethod
    def _pre_dispatch_error(error: ValidationTransportError) -> bool:
        return str(error) == "transport operation is outside current TargetPolicy" or str(error).startswith((
            "TargetPolicy request budget exhausted", "TargetPolicy concurrency limit reached",
            "TargetPolicy validation byte budget exhausted",
        ))

    def execute(self, blind_case: BlindCase, *, attempt_kind: str, batch_no: int,
                ordinal: int, attempt_id: str, db_path: Path, scan_id: str,
                stage_run_id: str, case_id: str, policy: TargetPolicy) -> ReproductionObservation:
        unsupported = self.unsupported_reason(blind_case)
        if unsupported is not None:
            raise ConcurrentExecutionError(unsupported)
        runtime = ConcurrentRuntimeContract.model_validate(blind_case.runtime_contract)
        attempt = runtime.for_attempt(attempt_kind)
        if runtime.total_members > policy.limits.concurrency:
            return self._observation(
                blind_case, outcome="blocked", observed=False, blocker_axis="timing_concurrency",
                details={"reason": "current_policy_rejected"}, policy_allowed=False,
            )
        credential_headers = self._resolved_headers(blind_case)
        if credential_headers is None:
            return self._observation(
                blind_case, outcome="blocked", observed=False, blocker_axis="identity_auth",
                details={"reason": "credential_reference_unavailable"},
            )
        try:
            prepared = self._prepare(attempt, blind_case.endpoint, credential_headers)
        except BinaryArtifactUnavailable:
            return self._observation(
                blind_case, outcome="blocked", observed=False, blocker_axis="encoding_transport",
                details={"reason": "artifact_unavailable"},
            )
        except ValueError as exc:
            raise ConcurrentExecutionError("concurrent request preflight failed") from exc

        broker = ValidationTransportBroker(
            db_path=db_path, scan_id=scan_id, stage_run_id=stage_run_id, case_id=case_id,
            attempt_id=attempt_id, blind_case=blind_case, policy=policy,
        )
        request_bytes = len(prepared.body or b"")
        metadata = {
            "request_payload_sha256": prepared.request_sha256,
            "request_payload_length": request_bytes,
        }
        specs = tuple(
            TransportOperationSpec(
                runtime_kind="concurrent", operation_kind="member", destination=prepared.url,
                policy_url=prepared.url, method=blind_case.method, request_bytes=request_bytes,
                max_response_bytes=_MAX_RESPONSE_BYTES, concurrency_units=1, metadata=metadata,
            ) for _ in range(runtime.total_members)
        )
        try:
            reservations = broker.reserve_group(specs, "vgrp_" + uuid4().hex)
        except ValidationTransportError as exc:
            if self._pre_dispatch_error(exc):
                return self._observation(
                    blind_case, outcome="blocked", observed=False,
                    details={"reason": "current_policy_rejected"}, policy_allowed=False,
                )
            raise

        deadline = self.clock() + min(float(policy.limits.timeout_seconds), runtime.barrier_timeout_seconds)
        barrier = threading.Barrier(runtime.total_members + 1)
        ready: queue.Queue[int] = queue.Queue(maxsize=runtime.total_members)
        dispatch_times: list[int] = []
        dispatch_lock = threading.Lock()

        def remaining() -> float:
            value = deadline - self.clock()
            if value <= 0:
                raise ConcurrentExecutionError("concurrent attempt deadline exceeded")
            return value

        def send_member(member_ordinal: int, timeout: float) -> TransportDispatchResult[tuple[BrokerResponse, float, int]]:
            ready.put(member_ordinal)
            try:
                barrier.wait(timeout=min(runtime.barrier_timeout_seconds, remaining()))
            except threading.BrokenBarrierError as exc:
                raise ConcurrentExecutionError("concurrent release barrier failed") from exc
            started = self.clock()
            request = Request(prepared.url, data=prepared.body, headers=dict(prepared.headers), method=blind_case.method)
            try:
                # Keep the timestamp adjacent to the ordinary transport call.
                dispatch_ns = self.monotonic_ns()
                with dispatch_lock:
                    dispatch_times.append(dispatch_ns)
                response = self.transport(request, timeout=min(timeout, remaining()))
            except HTTPError as error:
                response = error
            try:
                body = MultipartReproductionPort._read_complete_response(response)
                headers = dict(getattr(response, "headers", {}) or {})
                response_url = response.geturl()
                status = int(getattr(response, "status", getattr(response, "code", 0)))
            finally:
                response.close()
            duration_ms = max(0.0, (self.clock() - started) * 1000)
            broker_response = BrokerResponse(status, response_url, headers, body)
            response_metadata = metadata | {
                "response_payload_sha256": hashlib.sha256(body).hexdigest(),
                "response_payload_length": len(body), "response_status": status,
            }
            return TransportDispatchResult((broker_response, duration_ms, dispatch_ns), len(body), response_metadata)

        def dispatch_member(member_ordinal: int) -> ConcurrentMemberResult:
            try:
                operation_id, (response, duration_ms, _) = broker.dispatch_reserved(
                    reservations[member_ordinal], lambda timeout: send_member(member_ordinal, timeout),
                )
                evaluation = evaluate_http_response(response, attempt.member_assertions, duration_ms=duration_ms)
                return ConcurrentMemberResult(
                    member_ordinal, operation_id, response.status_code,
                    hashlib.sha256(response.body).hexdigest(), len(response.body), duration_ms, evaluation,
                )
            except BaseException:
                return ConcurrentMemberResult(
                    member_ordinal, reservations[member_ordinal].operation_id, None, None, 0, None, None,
                    outcome_unknown=True,
                )

        futures: list[Future[ConcurrentMemberResult]] = []
        with ThreadPoolExecutor(max_workers=runtime.total_members) as executor:
            futures = [executor.submit(dispatch_member, member_ordinal)
                       for member_ordinal in range(runtime.total_members)]
            try:
                for _ in reservations:
                    ready.get(timeout=min(runtime.barrier_timeout_seconds, remaining()))
                barrier.wait(timeout=min(runtime.barrier_timeout_seconds, remaining()))
            except (queue.Empty, ConcurrentExecutionError, threading.BrokenBarrierError):
                barrier.abort()
            results = tuple(future.result() for future in futures)

        if any(item.outcome_unknown for item in results) or len(dispatch_times) != runtime.total_members:
            return self._observation(
                blind_case, outcome="outcome_unknown", observed=None,
                details={"operation_ids": [item.operation_id for item in results], "reason": "member_outcome_unknown"},
            )
        start_skew_ms = (max(dispatch_times) - min(dispatch_times)) / 1_000_000
        final_evaluation, final_operation_id = None, None
        if attempt.final_verification is not None:
            try:
                final_evaluation, final_operation_id = self._final_verification(
                    broker, attempt, blind_case, credential_headers, deadline,
                )
            except BaseException:
                return self._observation(
                    blind_case, outcome="outcome_unknown", observed=None,
                    details={"operation_ids": [item.operation_id for item in results],
                             "reason": "final_verification_outcome_unknown"},
                )
        aggregate = evaluate_concurrent_results(
            results, attempt.aggregate_assertions, start_skew_ms=start_skew_ms,
            final_evaluation=final_evaluation,
        )
        if attempt.start_skew_at_most_ms is not None:
            aggregate["assertions"].append({
                "assertion_id": "start_skew_at_most_ms", "kind": "start_skew_at_most_ms",
                "passed": start_skew_ms <= attempt.start_skew_at_most_ms,
                "actual": start_skew_ms,
            })
            aggregate["signal_observed"] = all(item["passed"] for item in aggregate["assertions"])
        observed = bool(aggregate["signal_observed"])
        details = {
            "operation_ids": [item.operation_id for item in results],
            "start_skew_ms": start_skew_ms, "aggregate": aggregate,
            "members": [{
                "ordinal": item.ordinal, "status": item.response_status,
                "response_sha256": item.response_sha256, "response_bytes": item.response_bytes,
                "duration_ms": item.duration_ms, "evaluation": item.evaluation,
            } for item in results],
        }
        if final_operation_id is not None:
            details["final_operation_id"] = final_operation_id
        return self._observation(
            blind_case, outcome="observed" if observed else "not_observed", observed=observed, details=details,
        )

    def _final_verification(self, broker: ValidationTransportBroker, attempt: ConcurrentAttemptContract,
                            blind_case: BlindCase, credential_headers: Mapping[str, str], deadline: float) -> tuple[dict[str, Any], str]:
        assert attempt.final_verification is not None
        url, headers, body = render_http_request(blind_case.endpoint, attempt.final_verification.request)
        if {name.casefold() for name in headers} & {name.casefold() for name in credential_headers}:
            raise ConcurrentExecutionError("credential header collision")
        headers = dict(headers) | dict(credential_headers)
        request_body = body or b""
        spec = TransportOperationSpec(
            runtime_kind="concurrent", operation_kind="final_verification", destination=url,
            policy_url=url, method=blind_case.method, request_bytes=len(request_body),
            max_response_bytes=_MAX_RESPONSE_BYTES, concurrency_units=1,
            metadata={"request_payload_sha256": hashlib.sha256(request_body).hexdigest(),
                      "request_payload_length": len(request_body)},
        )
        reservation = broker.reserve(spec)
        started = self.clock()

        def sender(timeout: float) -> TransportDispatchResult[BrokerResponse]:
            remaining = deadline - self.clock()
            if remaining <= 0:
                raise ConcurrentExecutionError("concurrent attempt deadline exceeded")
            request = Request(url, data=body, headers=headers, method=blind_case.method)
            try:
                response = self.transport(request, timeout=min(timeout, remaining))
            except HTTPError as error:
                response = error
            try:
                captured = MultipartReproductionPort._read_complete_response(response)
                result = BrokerResponse(
                    int(getattr(response, "status", getattr(response, "code", 0))), response.geturl(),
                    dict(getattr(response, "headers", {}) or {}), captured,
                )
            finally:
                response.close()
            return TransportDispatchResult(
                result, len(captured),
                {"response_payload_sha256": hashlib.sha256(captured).hexdigest(),
                 "response_payload_length": len(captured), "response_status": result.status_code},
            )

        operation_id, response = broker.dispatch_reserved(reservation, sender)
        return evaluate_http_response(
            response, attempt.final_verification.assertions,
            duration_ms=max(0.0, (self.clock() - started) * 1000),
        ), operation_id
