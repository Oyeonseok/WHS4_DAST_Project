"""Classify endpoint evidence without treating a tool report as an HTTP response."""

from __future__ import annotations

from typing import Literal

VerificationStatus = Literal["candidate", "observed", "verified"]


def successful_response(status: object) -> bool:
    return type(status) is int and 200 <= status < 300


def result_verification_status(item: dict) -> VerificationStatus:
    if item.get("verification_status") == "candidate":
        return "candidate"
    evidence = item.get("evidence")
    if isinstance(evidence, dict) and successful_response(evidence.get("response_status")):
        return "verified"
    return "observed"
