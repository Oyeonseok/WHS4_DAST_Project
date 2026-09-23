"""Teammate Recon surface behavior preserved through the merge."""

from aidast.recon import judgment
from aidast.recon.tools.endpoint_discovery import _deduplicate_results


def test_dynamic_paths_and_queries_keep_one_normalized_surface() -> None:
    rows = [
        {"method": "GET", "path": "/users/123?q=one", "url": "https://example.test/users/123?q=one", "source": "katana"},
        {"method": "GET", "path": "/users/456?q=two", "url": "https://example.test/users/456?q=two", "source": "browser"},
    ]

    surface = judgment.merge_and_normalize(rows)

    assert len(surface) == 1
    assert surface[0]["normalized_path"] == "/users/:id"
    assert surface[0]["query_signature"] == "q"
    assert surface[0]["source_tools"] == {"katana", "browser"}


def test_repeated_variable_segments_are_learned_without_collapsing_static_paths() -> None:
    rows = [
        {"method": "GET", "path": f"/users/{value}", "source": "katana"}
        for value in ("alice", "bravo", "charlie", "delta", "echo")
    ]

    surface = judgment.merge_and_normalize(rows)

    assert len(surface) == 1
    assert surface[0]["normalized_path"] == "/users/:param"


def test_adaptive_learning_is_separate_for_each_http_method() -> None:
    rows = [
        {"method": "GET", "path": f"/users/{value}", "source": "katana"}
        for value in ("alice", "bravo", "charlie", "delta", "echo")
    ]
    rows.append({"method": "POST", "path": "/users/alice", "source": "browser"})

    assert {(row["method"], row["normalized_path"]) for row in judgment.merge_and_normalize(rows)} == {
        ("GET", "/users/:param"), ("POST", "/users/alice"),
    }


def test_redirect_loop_is_excluded_from_surface() -> None:
    rows = [
        {"method": "GET", "path": "/locale/locale/locale/", "source": "crawler"},
        {"method": "GET", "path": "/api/items", "source": "crawler"},
    ]

    assert [row["path"] for row in judgment.merge_and_normalize(rows)] == ["/api/items"]


def test_query_shape_omits_values_and_marks_repeated_keys() -> None:
    query_signature = getattr(judgment, "query_signature", None)

    assert query_signature is not None
    assert query_signature("/search?q=secret&tag=a&tag=b") == "q&tag[]"


def test_redirect_loop_does_not_enter_discovery_seeds() -> None:
    rows = [
        {"method": "GET", "path": "/login/login/login", "source": "katana"},
        {"method": "GET", "path": "/api/items", "source": "katana"},
    ]

    assert [row["path"] for row in _deduplicate_results(rows)] == ["/api/items"]
