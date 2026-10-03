"""Request shapes reflect captured request encoding without exposing values."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing

import pytest

from aidast.attack.coverage import _request_shapes


def captured_shape(*, headers: object, body: str,
                   response_content_type: str = "application/json") -> list[dict]:
    with closing(sqlite3.connect(":memory:")) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("""CREATE TABLE http_transactions (
            http_transaction_id TEXT, endpoint_id TEXT, method TEXT,
            request_headers TEXT, request_body BLOB, content_type TEXT,
            captured_at TEXT)""")
        conn.execute("""INSERT INTO http_transactions VALUES
            ('captured','endpoint','POST',?,?,?,'2026-10-03')""",
            (json.dumps(headers) if headers is not None else None,
             body, response_content_type))
        return _request_shapes(conn, "endpoint")


@pytest.mark.parametrize("body", ["1", '{"input":"private-value"}'])
def test_text_plain_request_is_not_json_because_response_is_json(body: str) -> None:
    assert captured_shape(
        headers={"Content-Type": "text/plain;charset=UTF-8"}, body=body,
    ) == []


@pytest.mark.parametrize("media_type", [
    "application/json; charset=UTF-8", "application/problem+json",
])
def test_json_request_shape_uses_request_header_even_with_html_response(
    media_type: str,
) -> None:
    shapes = captured_shape(
        headers={"CONTENT-TYPE": media_type, "Authorization": "private-token"},
        body='{"input":"private-value","enabled":true}',
        response_content_type="text/html",
    )
    assert shapes == [{
        "method": "POST", "encoding": "json",
        "fields": {"input": "string", "enabled": "boolean"},
    }]
    assert "private" not in json.dumps(shapes)


def test_form_request_shape_does_not_use_json_response_encoding() -> None:
    assert captured_shape(
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body="input=private-value&empty=",
    ) == [{
        "method": "POST", "encoding": "form",
        "fields": {"input": "string", "empty": "string"},
    }]


@pytest.mark.parametrize("headers", [None, {}, {"Accept": "application/json"}])
def test_missing_request_content_type_infers_only_json_containers(
    headers: object,
) -> None:
    assert captured_shape(
        headers=headers, body='{"input":"private-value"}',
        response_content_type="text/html",
    ) == [{"method": "POST", "encoding": "json", "fields": {"input": "string"}}]
    assert captured_shape(headers=headers, body="1") == []
    assert captured_shape(headers=headers, body="input=private-value") == []


@pytest.mark.parametrize("headers", [
    [], {"Content-Type": 1},
    {"Content-Type": "application/json", "content-type": "text/plain"},
])
def test_invalid_or_ambiguous_request_headers_do_not_infer_encoding(
    headers: object,
) -> None:
    assert captured_shape(headers=headers, body='{"input":"private-value"}') == []


def test_publicly_declared_body_schema_is_used_without_field_values() -> None:
    with closing(sqlite3.connect(":memory:")) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("""CREATE TABLE http_transactions (
            http_transaction_id TEXT, endpoint_id TEXT, method TEXT,
            request_headers TEXT, request_body BLOB, content_type TEXT,
            captured_at TEXT)""")
        conn.execute("CREATE TABLE endpoints (endpoint_id TEXT, method TEXT)")
        conn.execute("""CREATE TABLE parameters (
            endpoint_id TEXT, location TEXT, name TEXT, data_type TEXT)""")
        conn.execute("INSERT INTO endpoints VALUES ('endpoint','POST')")
        conn.executemany("INSERT INTO parameters VALUES ('endpoint','json',?,?)", [
            ("email", "string"), ("remember", "boolean"), ("age", "integer"),
        ])

        shapes = _request_shapes(conn, "endpoint")

    assert shapes == [{
        "method": "POST", "encoding": "json",
        "fields": {"age": "number", "email": "string", "remember": "boolean"},
    }]
    assert "example" not in json.dumps(shapes)


def test_observed_collection_response_supplies_value_free_write_schema() -> None:
    with closing(sqlite3.connect(":memory:")) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("""CREATE TABLE endpoints (
            endpoint_id TEXT, origin_id TEXT, method TEXT, normalized_path TEXT)""")
        conn.execute("""CREATE TABLE parameters (
            endpoint_id TEXT, location TEXT, name TEXT, data_type TEXT)""")
        conn.execute("""CREATE TABLE http_transactions (
            http_transaction_id TEXT, endpoint_id TEXT, method TEXT,
            request_headers TEXT, request_body BLOB, response_body BLOB,
            response_status INTEGER, content_type TEXT, captured_at TEXT)""")
        conn.executemany("INSERT INTO endpoints VALUES (?,?,?,?)", [
            ("write", "origin", "POST", "/api/Items"),
            ("read", "origin", "GET", "/api/Items"),
        ])
        conn.execute("""INSERT INTO http_transactions VALUES
            ('response','read','GET',NULL,NULL,?,200,'application/json','2026-10-03')""",
            (json.dumps({"data": [{
                "id": 17, "name": "private product", "enabled": True,
                "labels": ["private"], "metadata": {"secret": "private"},
                "createdAt": "private timestamp",
            }]}),),
        )

        shapes = _request_shapes(conn, "write")

    assert shapes == [{
        "method": "POST", "encoding": "json",
        "fields": {
            "enabled": "boolean", "id": "number", "labels": "array",
            "metadata": "object", "name": "string",
        },
        "evidence": "observed_collection_response_schema",
    }]
    assert "private" not in json.dumps(shapes)
