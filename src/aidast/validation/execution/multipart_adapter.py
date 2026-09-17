"""Policy-gated, bounded multipart Validation transport."""

from __future__ import annotations

import hashlib
import sqlite3
import time
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from aidast.core.request_broker import BrokerResponse
from aidast.recon.policy import TargetPolicy

from ..contracts.binary import BinaryArtifactResolver, BinaryArtifactUnavailable
from ..contracts.models import BlindCase, ReproductionObservation
from ..contracts.multipart_contract import MultipartRuntimeContract, encode_multipart
from ..contracts.runtime_contract import evaluate_http_response
from .credentials import PipelineCredentialResolver
from .transport_broker import (
    TransportDispatchResult, TransportOperationSpec, ValidationTransportBroker,
    ValidationTransportError,
)


_MAX_RESPONSE_BYTES = 200_000
_RESPONSE_READ_CHUNK_BYTES = 65_536
_ADAPTER_OWNED_HEADERS = frozenset({
    "content-type", "content-length", "content-disposition", "transfer-encoding",
    "trailer", "host", "connection", "keep-alive", "upgrade", "te", "expect",
    "proxy-connection",
})


class MultipartResponseIncompleteError(ValidationTransportError):
    """The response cannot establish bounded, complete assertion evidence."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class MultipartReproductionPort:
    """Serialize one declared multipart attempt after durable policy reservation."""

    requires_request_ledger = True

    def __init__(self, *, artifact_resolver: BinaryArtifactResolver | None = None,
                 credential_resolver: Callable | None = None,
                 transport: Callable | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self.artifact_resolver = artifact_resolver
        self.credential_resolver = credential_resolver
        self.transport = transport or build_opener(_NoRedirect()).open
        self.clock = clock

    def unsupported_reason(self, blind_case: BlindCase) -> str | None:
        if blind_case.target_kind != "finding":
            return "multipart_adapter_does_not_support_chain"
        if (blind_case.runtime_contract or {}).get("runtime_kind") != "multipart":
            return "multipart_runtime_contract_missing"
        try:
            MultipartRuntimeContract.model_validate(blind_case.runtime_contract)
        except ValueError:
            return "multipart_runtime_contract_invalid"
        return None

    @staticmethod
    def _artifact_blocked(blind_case: BlindCase) -> ReproductionObservation:
        return ReproductionObservation(
            outcome="blocked", signal_type=blind_case.signal_types[0], signal_observed=False,
            blocker_axis="encoding_transport", details={"reason": "artifact_unavailable"},
            content_sha256=hashlib.sha256(b"").hexdigest(), content_length=0,
        )

    @staticmethod
    def _blocked(blind_case: BlindCase, reason: str, *, policy_allowed: bool = True,
                 blocker_axis: str | None = None) -> ReproductionObservation:
        return ReproductionObservation(
            outcome="blocked", signal_type=blind_case.signal_types[0], signal_observed=False,
            blocker_axis=blocker_axis, details={"reason": reason},
            content_sha256=hashlib.sha256(b"").hexdigest(), content_length=0,
            policy_allowed=policy_allowed,
        )

    @staticmethod
    def _merge_credential_headers(headers: dict[str, str], raw: object) -> dict[str, str]:
        resolved = PipelineCredentialResolver._headers(raw)
        names = {name.casefold() for name in headers}
        resolved_names = [name.casefold() for name in resolved]
        caller_names = names - _ADAPTER_OWNED_HEADERS
        if (len(resolved_names) != len(set(resolved_names))
                or names.intersection(resolved_names)
                or any(name in _ADAPTER_OWNED_HEADERS for name in resolved_names)
                or len(caller_names | set(resolved_names)) > 32
                or any(any(not 32 <= ord(char) <= 126 for char in value)
                       for value in resolved.values())):
            raise ValueError("multipart credential headers invalid")
        return headers | resolved

    @staticmethod
    def _is_pre_dispatch_policy_or_budget_error(error: ValidationTransportError) -> bool:
        message = str(error)
        return (
            message == "transport operation is outside current TargetPolicy"
            or message.startswith("TargetPolicy request budget exhausted")
            or message.startswith("TargetPolicy concurrency limit reached")
            or message.startswith("TargetPolicy validation byte budget exhausted")
        )

    @staticmethod
    def _content_length_is_incomplete(response, received_bytes: int) -> bool:
        """Recognize declared-length EOF truncation, including HTTPError wrappers."""
        candidates = (response, getattr(response, "fp", None))
        for candidate in candidates:
            if candidate is None:
                continue
            remaining = getattr(candidate, "length", None)
            if type(remaining) is int and remaining >= 0:
                return remaining > 0
        headers = getattr(response, "headers", None)
        transfer_encoding = headers.get("Transfer-Encoding") if headers is not None else None
        content_length = headers.get("Content-Length") if headers is not None else None
        if transfer_encoding is not None or content_length is None:
            return False
        try:
            declared = int(content_length)
        except (TypeError, ValueError):
            return False
        return declared >= 0 and received_bytes < declared

    @staticmethod
    def _read_complete_response(response, *, deadline: float | None = None,
                                clock: Callable[[], float] = time.monotonic,
                                before_read: Callable[[], None] | None = None) -> bytes:
        """Read complete data below the capture limit, never a byte beyond it."""
        content = bytearray()
        # read1 returns buffered/available bytes without waiting to fill a whole
        # chunk. This leaves a deadline check between socket reads while the
        # caller's watchdog bounds HTTP framing/header reads inside read1.
        read_available = getattr(response, "read1", None) if deadline is not None else None
        reader = read_available or response.read
        maximum = _RESPONSE_READ_CHUNK_BYTES if deadline is None or read_available else 1
        while len(content) < _MAX_RESPONSE_BYTES:
            if deadline is not None and clock() >= deadline:
                raise MultipartResponseIncompleteError("multipart response exceeded its absolute deadline")
            if before_read is not None:
                before_read()
            chunk = reader(min(maximum, _MAX_RESPONSE_BYTES - len(content)))
            if deadline is not None and clock() >= deadline:
                raise MultipartResponseIncompleteError("multipart response exceeded its absolute deadline")
            if type(chunk) is not bytes:
                raise ValidationTransportError("multipart response reader returned invalid bytes")
            if not chunk:
                if MultipartReproductionPort._content_length_is_incomplete(response, len(content)):
                    raise MultipartResponseIncompleteError(
                        "multipart response ended before its declared content length"
                    )
                return bytes(content)
            content.extend(chunk)
        # Reading even one lookahead byte would exceed the durable response-byte reservation.
        raise MultipartResponseIncompleteError("multipart response completeness is unknown at capture limit")

    def execute(self, blind_case: BlindCase, *, attempt_kind: str, batch_no: int,
                ordinal: int, attempt_id: str, db_path: Path, scan_id: str,
                stage_run_id: str, case_id: str, policy: TargetPolicy) -> ReproductionObservation:
        unsupported = self.unsupported_reason(blind_case)
        if unsupported is not None:
            raise ValueError(unsupported)
        runtime = MultipartRuntimeContract.model_validate(blind_case.runtime_contract)
        attempt = runtime.for_attempt(attempt_kind)
        try:
            url, headers, body = encode_multipart(attempt, blind_case.endpoint, self.artifact_resolver)
        except BinaryArtifactUnavailable:
            return self._artifact_blocked(blind_case)
        if not policy.allows_validation_url(url, method=blind_case.method):
            return self._blocked(
                blind_case, "current_policy_rejected", policy_allowed=False,
            )
        for reference in blind_case.credential_references:
            if self.credential_resolver is None:
                return self._blocked(
                    blind_case, "credential_reference_unavailable", blocker_axis="identity_auth",
                )
            try:
                raw_headers = self.credential_resolver(reference)
                headers = self._merge_credential_headers(headers, raw_headers)
            except (ImportError, OSError, KeyError, ValueError, sqlite3.Error):
                return self._blocked(
                    blind_case, "credential_reference_unavailable", blocker_axis="identity_auth",
                )
            except Exception:
                raise ValidationTransportError("multipart credential resolution failed") from None
        broker = ValidationTransportBroker(
            db_path=db_path, scan_id=scan_id, stage_run_id=stage_run_id, case_id=case_id,
            attempt_id=attempt_id, blind_case=blind_case, policy=policy,
        )
        request_metadata = {
            "request_payload_sha256": hashlib.sha256(body).hexdigest(),
            "request_payload_length": len(body),
        }
        spec = TransportOperationSpec(
            runtime_kind="multipart", operation_kind="request", destination=url,
            policy_url=url, method=blind_case.method, request_bytes=len(body),
            max_response_bytes=_MAX_RESPONSE_BYTES,
            metadata=request_metadata,
        )

        def sender(timeout: float) -> TransportDispatchResult[BrokerResponse]:
            request = Request(url, data=body, headers=headers, method=blind_case.method)
            try:
                response = self.transport(request, timeout=timeout)
            except HTTPError as error:
                response = error
            try:
                response_body = self._read_complete_response(response)
                response_headers = dict(getattr(response, "headers", {}) or {})
                response_url = response.geturl()
                status = int(getattr(response, "status", getattr(response, "code", 0)))
            finally:
                response.close()
            broker_response = BrokerResponse(status, response_url, response_headers, response_body)
            return TransportDispatchResult(
                broker_response, len(response_body),
                request_metadata | {
                    "response_payload_sha256": hashlib.sha256(response_body).hexdigest(),
                    "response_payload_length": len(response_body),
                },
            )

        try:
            reservation = broker.reserve(spec)
        except ValidationTransportError as exc:
            if not self._is_pre_dispatch_policy_or_budget_error(exc):
                raise
            return self._blocked(
                blind_case, "current_policy_rejected", policy_allowed=False,
            )
        started = self.clock()
        operation_id, response = broker.dispatch_reserved(reservation, sender)
        duration_ms = max(0.0, (self.clock() - started) * 1000)
        evaluation = evaluate_http_response(response, attempt.assertions, duration_ms=duration_ms)
        observed = evaluation["signal_observed"]
        digest = hashlib.sha256(response.body).hexdigest()
        return ReproductionObservation(
            outcome="observed" if observed else "not_observed",
            signal_type=blind_case.signal_types[0], signal_observed=observed,
            details={"response_body_sha256": digest, "response_bytes": len(response.body),
                     "operation_ids": [operation_id]},
            content_sha256=digest, content_length=len(response.body),
        )
