"""Target-specific immutable contracts for native impact development."""

from __future__ import annotations

from typing import Annotated, Any, Literal
from urllib.parse import unquote, urlsplit

from pydantic import Field, field_validator, model_validator

from .models import Digest, Identifier, StrictContract
from .runtime_contract import HttpRequestTemplate, ResponseAssertion


class ImpactPreconditionObservation(StrictContract):
    """Non-secret marker receipt from a previously verified safe request."""

    source_request_id: Identifier
    response_sha256: Digest
    response_status: int = Field(ge=100, le=599)
    marker_json_path: tuple[str, ...] = Field(min_length=1, max_length=8)
    marker_assertion_id: Identifier

    @field_validator("marker_json_path", mode="before")
    @classmethod
    def json_array_path(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value


class ImpactDevelopmentActionContract(StrictContract):
    contract_id: Identifier
    path_id: Identifier
    endpoint_template: Annotated[str, Field(min_length=1, max_length=4096)]
    method: Literal["GET", "HEAD", "OPTIONS"]
    request: HttpRequestTemplate
    assertions: tuple[ResponseAssertion, ...] = Field(min_length=1, max_length=16)
    credential_roles: tuple[Identifier, ...] = Field(default=(), max_length=16)
    precondition_observation: ImpactPreconditionObservation | None = None

    @field_validator("assertions", "credential_roles", mode="before")
    @classmethod
    def json_arrays(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def bounded_action(self) -> "ImpactDevelopmentActionContract":
        parsed = urlsplit(self.endpoint_template)
        decoded = unquote(parsed.path)
        if (
            not self.endpoint_template.startswith("/")
            or parsed.scheme or parsed.netloc or parsed.query or parsed.fragment
            or ".." in decoded.split("/") or "\\" in decoded
        ):
            raise ValueError("impact endpoint_template must be a literal origin-relative path")
        if len(self.credential_roles) != len(set(self.credential_roles)):
            raise ValueError("impact credential roles must be unique")
        identifiers = [item.assertion_id for item in self.assertions]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("impact assertions must have unique IDs")
        if not any(item.kind != "status_equals" for item in self.assertions):
            raise ValueError("impact success requires more than an HTTP status assertion")
        if (self.precondition_observation is not None
                and self.precondition_observation.marker_assertion_id not in identifiers):
            raise ValueError("impact marker observation must name a declared assertion")
        return self


class ImpactDevelopmentRuntimeContract(StrictContract):
    schema_version: Literal[1]
    actions: tuple[ImpactDevelopmentActionContract, ...] = Field(min_length=1, max_length=3)

    @field_validator("actions", mode="before")
    @classmethod
    def json_array_actions(cls, value: Any) -> Any:
        return tuple(value) if isinstance(value, list) else value

    @model_validator(mode="after")
    def unique_actions(self) -> "ImpactDevelopmentRuntimeContract":
        ids = [item.contract_id for item in self.actions]
        paths = [item.path_id for item in self.actions]
        if len(ids) != len(set(ids)) or len(paths) != len(set(paths)):
            raise ValueError("impact actions must have unique contract and path IDs")
        return self


def impact_action_document(action: ImpactDevelopmentActionContract) -> dict[str, Any]:
    """Keep the version-one digest stable when the new receipt is absent."""
    document = action.model_dump(mode="json")
    if document["precondition_observation"] is None:
        document.pop("precondition_observation")
    return document


def impact_contract_document(contract: ImpactDevelopmentRuntimeContract) -> dict[str, Any]:
    document = contract.model_dump(mode="json")
    document["actions"] = [impact_action_document(action) for action in contract.actions]
    return document
