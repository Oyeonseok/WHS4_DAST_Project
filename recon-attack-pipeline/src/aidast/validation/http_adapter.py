"""Generic HTTP ReproductionPort whose behavior is supplied by bounded adapters."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Callable, Mapping

from aidast.recon.policy import TargetPolicy

from .blind import BlindCase
from .reproduction import ReproductionObservation
from .request_broker import ValidationPolicyRejection, ValidationRequestBroker


class HttpReproductionPort:
    """Execute one profile-selected attempt through the durable safe broker.

    ``request_builder`` resolves runtime slots but the broker independently
    enforces the staged method/endpoint and current TargetPolicy. ``evaluator``
    receives only the bounded response and returns structured signal metadata.
    """

    def __init__(self, *,
                 request_builder: Callable[[BlindCase, str, int, int], tuple[str, Mapping[str, str], bytes | None]],
                 evaluator: Callable[[str, object], Mapping], transport: Callable | None = None,
                 credential_resolver: Callable[[str], Mapping[str, str]] | None = None):
        self.request_builder, self.evaluator = request_builder, evaluator
        self.transport, self.credential_resolver = transport, credential_resolver

    def execute(self, blind_case: BlindCase, *, attempt_kind: str, batch_no: int,
                ordinal: int, attempt_id: str, db_path: Path, scan_id: str,
                stage_run_id: str, case_id: str, policy: TargetPolicy) -> ReproductionObservation:
        url, headers, data = self.request_builder(blind_case, attempt_kind, batch_no, ordinal)
        broker = ValidationRequestBroker(
            db_path=db_path, scan_id=scan_id, stage_run_id=stage_run_id,
            case_id=case_id, attempt_id=attempt_id, blind_case=blind_case,
            policy=policy, transport=self.transport,
            credential_resolver=self.credential_resolver,
        )
        try:
            response = broker.request(url, method=blind_case.method, headers=headers, data=data)
        except ValidationPolicyRejection:
            return ReproductionObservation(
                outcome="blocked", signal_type=blind_case.signal_types[0],
                signal_observed=False, details={"reason": "current_policy_rejected"},
                content_sha256=hashlib.sha256(b"").hexdigest(), content_length=0,
                policy_allowed=False,
            )
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
        return ReproductionObservation(
            outcome="blocked" if blocker else "observed" if observed else "not_observed",
            signal_type=blind_case.signal_types[0], signal_observed=observed,
            blocker_axis=blocker, details=details,
            content_sha256=hashlib.sha256(response.body).hexdigest(),
            content_length=len(response.body), explicit_non_exploit=bool(explicit),
        )
