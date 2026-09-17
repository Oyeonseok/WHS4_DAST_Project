from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from aidast.attack.executor_factory import select_executor
from aidast.attack.idor import DualIdentityIdorExecutor
from aidast.attack.policy_executor import PolicyServiceAttackExecutor
from aidast.attack.skill_agent import AuthorizedTest
from aidast.core.request_broker import BrokerResponse


def authorized_test() -> AuthorizedTest:
    return AuthorizedTest(
        test_id="test",
        task_id="task",
        endpoint_id="endpoint",
        skill_ids=("hunt-idor",),
        title="Bounded read",
        description="Observe the approved endpoint",
    )


def response(status: int, body: bytes = b"ok") -> BrokerResponse:
    return BrokerResponse(
        status_code=status,
        url="https://example.test/item/1",
        headers={"content-type": "text/plain"},
        body=body,
    )


def service(status: int, body: bytes = b"ok") -> Mock:
    result = Mock()
    result.request.return_value = (response(status, body), "receipt")
    return result


def test_policy_executor_dispatches_only_the_resolved_intent() -> None:
    policy_service = service(200)
    intent = SimpleNamespace(method="HEAD", url="https://example.test/item/1")
    executor = PolicyServiceAttackExecutor(
        policy_service,
        lambda test, hypothesis_id: intent,
        lambda task, skills: (authorized_test(),),
    )

    result = executor.execute(authorized_test(), hypothesis_id="hypothesis")

    policy_service.request.assert_called_once_with(intent)
    assert (result.outcome, result.method, result.url) == (
        "supports",
        "HEAD",
        "https://example.test/item/1",
    )


@pytest.mark.parametrize(
    ("status_a", "body_a", "status_b", "body_b", "expected"),
    [
        (403, b"denied", 200, b"object", "supports"),
        (200, b"same", 200, b"same", "supports"),
        (200, b"account-a", 200, b"account-b", "refutes"),
    ],
)
def test_idor_requires_a_denial_or_equal_successful_representation(
    status_a: int,
    body_a: bytes,
    status_b: int,
    body_b: bytes,
    expected: str,
) -> None:
    identity_a = service(status_a, body_a)
    identity_b = service(status_b, body_b)
    executor = DualIdentityIdorExecutor(
        identity_a,
        identity_b,
        lambda test, hypothesis_id, identity: SimpleNamespace(
            method="GET",
            url="https://example.test/item/1",
            identity_role=identity,
        ),
    )

    result = executor.execute(authorized_test(), hypothesis_id="hypothesis")

    assert result.outcome == expected
    assert result.identity_role == "identity_b"
    identity_a.request.assert_called_once()
    identity_b.request.assert_called_once()


def test_executor_factory_requires_two_explicit_identities_for_idor() -> None:
    with pytest.raises(ValueError, match="two approved identity services"):
        select_executor(
            skill_id="hunt-idor",
            service=service(200),
            test_provider=lambda task, skills: (),
            intent_resolver=Mock(),
        )

    ordinary = select_executor(
        skill_id="hunt-xss",
        service=service(200),
        test_provider=lambda task, skills: (),
        intent_resolver=Mock(),
    )
    assert isinstance(ordinary, PolicyServiceAttackExecutor)
