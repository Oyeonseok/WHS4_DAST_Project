"""Generic HTTP ReproductionPort whose behavior is supplied by bounded adapters."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Callable, Mapping
from urllib.parse import urljoin, urlsplit

from aidast.recon.policy import TargetPolicy

from ..contracts.models import BlindCase
from ..contracts.models import ReproductionObservation
from .request_broker import (ValidationCredentialError, ValidationPolicyRejection,
                             ValidationRequestBroker)
from .credentials import credential_unsupported_reason
from ..contracts.runtime_contract import (HttpRuntimeContract, evaluate_http_response,
                               render_http_request, _json_path)


class HttpReproductionPort:
    """Execute one profile-selected attempt through the durable safe broker.

    ``request_builder`` resolves runtime slots but the broker independently
    enforces the staged method/endpoint and current TargetPolicy. ``evaluator``
    receives only the bounded response and returns structured signal metadata.
    """

    requires_request_ledger = True

    def __init__(self, *,
                 request_builder: Callable[[BlindCase, str, int, int], tuple[str, Mapping[str, str], bytes | None]] | None = None,
                 evaluator: Callable[[str, object], Mapping] | None = None,
                 transport: Callable | None = None,
                 credential_resolver: Callable[[str], Mapping[str, str]] | None = None,
                 clock: Callable[[], float] = time.monotonic):
        self.request_builder, self.evaluator = request_builder, evaluator
        self.transport, self.credential_resolver = transport, credential_resolver
        self.clock = clock

    def unsupported_reason(self, blind_case: BlindCase) -> str | None:
        """Return a stable preflight reason when this HTTP adapter cannot replay a case."""
        if blind_case.target_kind != "finding":
            return "http_adapter_does_not_support_chain"
        if (blind_case.runtime_contract or {}).get("runtime_kind") not in {None, "http"}:
            return "http_runtime_contract_kind_unsupported"
        if self.request_builder is None and blind_case.runtime_contract is None:
            return "http_runtime_contract_missing"
        if blind_case.credential_references and self.credential_resolver is None:
            return "credential_resolver_missing"
        for reference in blind_case.credential_references:
            reason = credential_unsupported_reason(
                self.credential_resolver, reference,
                destination_url=blind_case.endpoint,
            )
            if reason is not None:
                return reason
        return None

    def execute(self, blind_case: BlindCase, *, attempt_kind: str, batch_no: int,
                ordinal: int, attempt_id: str, db_path: Path, scan_id: str,
                stage_run_id: str, case_id: str, policy: TargetPolicy) -> ReproductionObservation:
        unsupported = self.unsupported_reason(blind_case)
        if unsupported is not None:
            raise ValueError(unsupported)
        runtime = None
        if self.request_builder is None:
            if blind_case.runtime_contract is None:
                raise ValueError("HTTP replay requires a staged runtime contract")
            runtime = HttpRuntimeContract.model_validate(blind_case.runtime_contract)
            attempt = runtime.for_attempt(attempt_kind)
            endpoint = blind_case.endpoint
            if attempt.endpoint_template is not None:
                if attempt_kind != "negative_control" or blind_case.method not in {"GET", "HEAD"}:
                    raise ValueError("alternate control endpoints require a read-only negative control")
                base = urlsplit(blind_case.endpoint)
                endpoint = urljoin(
                    f"{base.scheme}://{base.netloc}/", attempt.endpoint_template.lstrip("/"),
                )
            url, headers, data = render_http_request(endpoint, attempt.request)
        else:
            url, headers, data = self.request_builder(blind_case, attempt_kind, batch_no, ordinal)
        broker = ValidationRequestBroker(
            db_path=db_path, scan_id=scan_id, stage_run_id=stage_run_id,
            case_id=case_id, attempt_id=attempt_id, blind_case=blind_case,
            policy=policy, transport=self.transport,
            credential_resolver=self.credential_resolver,
            credential_references=(() if runtime is not None
                                   and runtime.for_attempt(attempt_kind).identity_mode == "anonymous" else None),
            request_boundary=((blind_case.method, url) if runtime is not None
                              and runtime.for_attempt(attempt_kind).endpoint_template is not None else None),
        )
        try:
            started = self.clock()
            response = broker.request(url, method=blind_case.method, headers=headers, data=data)
        except ValidationPolicyRejection:
            return ReproductionObservation(
                outcome="blocked", signal_type=blind_case.signal_types[0],
                signal_observed=False, details={"reason": "current_policy_rejected"},
                content_sha256=hashlib.sha256(b"").hexdigest(), content_length=0,
                policy_allowed=False,
            )
        except ValidationCredentialError:
            return ReproductionObservation(
                outcome="blocked", signal_type=blind_case.signal_types[0],
                signal_observed=False, blocker_axis="identity_auth",
                details={"reason": "credential_resolution_failed"},
                content_sha256=hashlib.sha256(b"").hexdigest(), content_length=0,
            )
        duration_ms = max(0.0, (self.clock() - started) * 1000)
        if self.evaluator is None:
            if runtime is None:
                raise ValueError("HTTP replay requires an evaluator or runtime contract")
            evaluation = evaluate_http_response(
                response, runtime.for_attempt(attempt_kind).assertions,
                duration_ms=duration_ms,
            )
        else:
            evaluation = dict(self.evaluator(attempt_kind, response))
        observed = evaluation.pop("signal_observed", None)
        if type(observed) is not bool:
            raise ValueError("signal evaluator must return a boolean signal_observed")
        blocker = evaluation.pop("blocker_axis", None)
        explicit = evaluation.pop("explicit_non_exploit", False)
        details = {
            "response_status": response.status_code, "response_url": response.url,
            "response_headers": response.headers,
            "response_body_sha256": hashlib.sha256(response.body).hexdigest(),
            "response_bytes": len(response.body), "evaluation": evaluation,
            "request_ids": broker.request_ids,
        }
        if runtime is not None and runtime.session_verification is not None and attempt_kind != "positive_control":
            proof = self._verify_session(
                blind_case, runtime, response, attempt_kind=attempt_kind,
                attempt_id=attempt_id, db_path=db_path, scan_id=scan_id,
                stage_run_id=stage_run_id, case_id=case_id, policy=policy,
            )
            details["protected_access"] = proof
            details["request_ids"].extend(proof.get("request_ids", []))
            # A public verification resource cannot prove an authentication boundary.
            if attempt_kind == "negative_control" and proof.get("protected_fields_observed") is True:
                observed = True
        return ReproductionObservation(
            outcome="blocked" if blocker else "observed" if observed else "not_observed",
            signal_type=blind_case.signal_types[0], signal_observed=observed,
            blocker_axis=blocker, details=details,
            content_sha256=hashlib.sha256(response.body).hexdigest(),
            content_length=len(response.body), explicit_non_exploit=bool(explicit),
        )

    def _verify_session(self, blind_case, runtime, response, *, attempt_kind,
                        attempt_id, db_path, scan_id, stage_run_id, case_id, policy):
        verification = runtime.session_verification
        token = None
        if attempt_kind == "target":
            try:
                token = _json_path(json.loads(response.body), verification.token_path)
            except (ValueError, UnicodeDecodeError):
                pass
            if (not isinstance(token, str) or not token or len(token) > 16_384
                    or any(ord(c) <= 32 for c in token)):
                return {"verified": False, "reason": "fresh_session_token_missing", "request_ids": []}
        url, headers, data = render_http_request(
            urljoin(blind_case.endpoint, verification.endpoint_template), verification.request,
        )
        # The fresh credential is resolved in memory and never stored in the contract.
        broker = ValidationRequestBroker(
            db_path=db_path, scan_id=scan_id, stage_run_id=stage_run_id, case_id=case_id,
            attempt_id=attempt_id, blind_case=blind_case, policy=policy,
            transport=self.transport, credential_references=("fresh-replay-session",) if token else (),
            credential_resolver=lambda reference: {"Authorization": "Bearer " + token},
            request_boundary=("GET", url), max_redirects=0,
        )
        try:
            started = self.clock()
            protected = broker.request(url, method="GET", headers=headers, data=data)
            evaluation = evaluate_http_response(
                protected, verification.assertions,
                duration_ms=max(0.0, (self.clock() - started) * 1000),
            )
            json_ids = {a.assertion_id for a in verification.assertions
                        if a.kind in {"json_equals", "json_path_nonempty_string"}}
            fields_observed = all(a["passed"] for a in evaluation["assertions"]
                                  if a["assertion_id"] in json_ids)
            verified = 200 <= protected.status_code < 300 and evaluation["signal_observed"]
            return {"verified": bool(verified), "response_status": protected.status_code,
                    "protected_fields_observed": fields_observed,
                    "evaluation": evaluation, "request_ids": broker.request_ids,
                    "response_body_sha256": hashlib.sha256(protected.body).hexdigest(),
                    "reason": "protected_session_verified" if verified else "protected_session_not_verified"}
        except (ValidationPolicyRejection, ValidationCredentialError):
            return {"verified": False, "reason": "session_verification_blocked", "request_ids": broker.request_ids}
