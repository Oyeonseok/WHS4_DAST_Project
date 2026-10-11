"""Real collection IDs retain denied detail probes as observed evidence only."""
import json

import pytest

from aidast.recon.tools import api_secondary_discovery as secondary
from aidast.recon.verification import result_verification_status


def _discover(monkeypatch, status, *, control_status=500, media='application/json',
              body=b'{"error":"denied"}', collection=None):
    requests = []
    def request(url, **kwargs):
        requests.append(url)
        if url.endswith('main.js'):
            return 200, {'content-type': 'application/javascript'}, b'http.get("/api/Items")'
        if '__aidast_missing_control__' in url:
            return control_status, {'content-type': media if control_status == status else 'application/json'}, (
                body if control_status == status else b'{"error":"missing"}')
        assert url == 'https://example.test/api/Items/7', url
        return status, {'content-type': media}, body
    monkeypatch.setattr(secondary, '_http_request', request)
    records = [{
        'method': 'GET', 'url': 'https://example.test/api/Items', 'response_status': 200,
        'response_headers': {'content-type': 'application/json'}, 'capture_bodies': True,
        'policy_blocked': False, 'response_body': json.dumps(
            {'data': [{'id': 7}]} if collection is None else collection),
    }]
    rows = secondary.discover_adaptive_js_api_candidates('https://example.test/',
        [{'path': '/main.js'}, {'method': 'GET', 'path': '/api/Items'}], observed_responses=records)
    return rows, requests


@pytest.mark.parametrize('status,access,media,body', [
    (401, 'authentication_required', 'application/json', b'{"error":"denied"}'),
    (403, 'forbidden', 'application/json', b'{"error":"denied"}'),
    (401, 'authentication_required', 'text/html', b'<html><body>Unauthorized</body></html>'),
])
def test_observed_collection_id_keeps_denied_detail_without_refetch(monkeypatch, status, access, media, body):
    rows, requests = _discover(monkeypatch, status, media=media, body=body)
    assert [r['path'] for r in rows] == ['/api/Items/7']
    assert rows[0]['discovery_kind'] == 'collection_detail_access_denied'
    assert result_verification_status(rows[0]) == 'observed'
    assert rows[0]['evidence']['access_status'] == access
    assert rows[0]['evidence']['collection_url'] == 'https://example.test/api/Items'
    assert 'https://example.test/api/Items' not in requests


@pytest.mark.parametrize('status,options', [
    (401, {'control_status': 401}),
    (403, {'body': secondary._POLICY_BLOCK_BODY}),
    (200, {'media': 'text/html', 'body': b'<html>SPA shell</html>'}),
    (401, {'control_status': 401, 'media': 'text/html'}),
    (404, {}), (500, {}),
])
def test_denied_detail_rejects_fallback_policy_and_non_route_errors(monkeypatch, status, options):
    rows, _ = _discover(monkeypatch, status, **options)
    assert rows == []


@pytest.mark.parametrize('collection', [
    {'data': []}, {'data': [{'id': '../private'}, {'id': True}]},
    {'error': 'denied', 'data': [{'id': 7}]},
])
def test_no_detail_probe_without_a_valid_observed_id(monkeypatch, collection):
    rows, requests = _discover(monkeypatch, 401, collection=collection)
    assert rows == []
    assert not any(url.endswith('/7') or 'private' in url for url in requests)


def test_denied_detail_accepts_a_query_bearing_collection_url():
    row = secondary._verified_collection_detail(
        'https://example.test/api/Items/7', 'https://example.test/api/Items?limit=10',
        403, {'content-type': 'application/json'}, b'{"error":"denied"}',
        missing_control=(404, {'content-type': 'application/json'}, b'{"error":"missing"}',
                         'https://example.test/api/__aidast_missing_control__'))
    assert row is not None
    assert row['path'] == '/api/Items/7'
    assert result_verification_status(row) == 'observed'


@pytest.mark.parametrize('detail_url', [
    'https://outside.test/api/Items/7', 'https://example.test/api/Other/7',
])
def test_denied_detail_cannot_attach_to_an_unrelated_collection(detail_url):
    assert secondary._verified_collection_detail(
        detail_url, 'https://example.test/api/Items',
        403, {'content-type': 'application/json'}, b'{"error":"denied"}',
        missing_control=(404, {'content-type': 'application/json'}, b'{"error":"missing"}',
                         'https://example.test/api/__aidast_missing_control__')) is None
