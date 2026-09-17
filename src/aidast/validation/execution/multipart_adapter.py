"""Policy-gated, bounded multipart Validation transport."""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Callable
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from aidast.core.request_broker import BrokerResponse
from aidast.recon.policy import TargetPolicy

from ..contracts.binary import BinaryArtifactResolver
from ..contracts.models import BlindCase, ReproductionObservation
from ..contracts.multipart_contract import MultipartRuntimeContract, encode_multipart
from ..contracts.runtime_contract import evaluate_http_response
from .transport_broker import (
    TransportDispatchResult, TransportOperationSpec, ValidationTransportBroker,
    ValidationTransportError,
)


_MAX_RESPONSE_BYTES = 200_000


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class MultipartReproductionPort:
    """Serialize one declared multipart attempt after durable policy reservation."""

    requires_request_ledger = True

    def __init__(self, *, artifact_resolver: BinaryArtifactResolver | None = None,
                 transport: Callable | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self.artifact_resolver = artifact_resolver
        self.transport = transport or build_opener(_NoRedirect()).open
        self.clock = clock

    def unsupported_reason(self, blind_case: BlindCase) -> str | None:
        if blind_case.target_kind != "finding":
            return "multipart_adapter_does_not_support_chain"
        if (blind_case.runtime_contract or {}).get("runtime_kind") != "multipart":
            return "multipart_runtime_contract_missing"
        if blind_case.credential_references:
            return "multipart_runtime_does_not_support_credentials"
        try:
            runtime = MultipartRuntimeContract.model_validate(blind_case.runtime_contract)
        except ValueError:
            return "multipart_runtime_contract_invalid"
        if self.artifact_resolver is None and any(
            part.content.artifact_ref is not None
            for runtime_attempt in (runtime.target, runtime.positive_control, runtime.negative_control)
            for part in runtime_attempt.request.files
        ):
            return "artifact_resolver_missing"
        return None

    def execute(self, blind_case: BlindCase, *, attempt_kind: str, batch_no: int,
                ordinal: int, attempt_id: str, db_path: Path, scan_id: str,
                stage_run_id: str, case_id: str, policy: TargetPolicy) -> ReproductionObservation:
        unsupported = self.unsupported_reason(blind_case)
        if unsupported is not None:
            raise ValueError(unsupported)
        runtime = MultipartRuntimeContract.model_validate(blind_case.runtime_contract)
        attempt = runtime.for_attempt(attempt_kind)
        url, headers, body = encode_multipart(attempt, blind_case.endpoint, self.artifact_resolver)
        broker = ValidationTransportBroker(
            db_path=db_path, scan_id=scan_id, stage_run_id=stage_run_id, case_id=case_id,
            attempt_id=attempt_id, blind_case=blind_case, policy=policy,
        )
        spec = TransportOperationSpec(
            runtime_kind="multipart", operation_kind="request", destination=url,
            policy_url=url, method=blind_case.method, request_bytes=len(body),
            max_response_bytes=_MAX_RESPONSE_BYTES,
            metadata={"request_body_sha256": hashlib.sha256(body).hexdigest(),
                      "request_body_length": len(body)},
        )

        def sender(timeout: float) -> TransportDispatchResult[BrokerResponse]:
            request = Request(url, data=body, headers=headers, method=blind_case.method)
            try:
                response = self.transport(request, timeout=timeout)
            except HTTPError as error:
                response = error
            try:
                response_body = response.read(_MAX_RESPONSE_BYTES)
                response_headers = dict(getattr(response, "headers", {}) or {})
                response_url = response.geturl()
                status = int(getattr(response, "status", getattr(response, "code", 0)))
            finally:
                response.close()
            broker_response = BrokerResponse(status, response_url, response_headers, response_body)
            return TransportDispatchResult(
                broker_response, len(response_body),
                {"response_body_sha256": hashlib.sha256(response_body).hexdigest(),
                 "response_body_length": len(response_body)},
            )

        try:
            started = self.clock()
            operation_id, response = broker.dispatch(spec, sender)
        except ValidationTransportError:
            return ReproductionObservation(
                outcome="blocked", signal_type=blind_case.signal_types[0], signal_observed=False,
                details={"reason": "current_policy_rejected"},
                content_sha256=hashlib.sha256(b"").hexdigest(), content_length=0,
                policy_allowed=False,
            )
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
