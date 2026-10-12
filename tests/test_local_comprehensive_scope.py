"""The local comprehensive Juice Shop profile stays black-box and bounded."""

from aidast.orchestration.scope import ScopeCoordinator
from scripts import prepare_local_lab_scopes as lab


def test_comprehensive_juice_scope_grants_bounded_mutations_without_answers():
    scope = lab.LAB_SCOPES["juice-shop-comprehensive-5001"]
    document = lab._document(scope)
    ScopeCoordinator._require_grounded_analysis(document.source, document.analysis)

    rules = document.analysis.execution_rules
    assert rules.allowed_methods.values == [
        "GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE",
    ]
    assert rules.request_limits[0].maximum == 1
    assert {item.field: item.value for item in rules.option_limits} == {
        "concurrency": 2,
        "timeout_seconds": 20,
        "max_depth": 3,
        "max_requests": 2000,
    }
    assert "서버 소스" in document.source.text
    assert "사용을 금지" in document.source.text
    assert "PUT, PATCH, DELETE 요청을 금지" not in document.source.text


def test_comprehensive_scope_publishes_through_integrity_bundle(tmp_path):
    scope = lab.LAB_SCOPES["juice-shop-comprehensive-5001"]
    destination = lab._publish(
        scope, output_root=tmp_path / "Scope", approved_by="local-test-operator",
    )

    document, _ = ScopeCoordinator(destination).load_approved_scope()
    assert document.analysis.in_scope_assets[0].asset == "http://127.0.0.1:5001/"
    assert (destination / "Approval.json").is_file()
    assert (destination / "Manifest.json").is_file()
