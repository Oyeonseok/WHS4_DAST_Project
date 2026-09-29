"""Denied explicit GET routes remain observed without becoming verified."""
import json

import pytest

from aidast.recon import db
from aidast.recon.annotations import ObservationRecorder, sanitize_evidence
from aidast.recon.surface import export_surface
from aidast.recon.tools import api_secondary_discovery as secondary


def _discover(monkeypatch, status, *, script='http.get("/api/private")',
              control_status=500, body=b'{"error":"denied"}', media='application/json'):
    def request(url, **kwargs):
        if url.endswith('main.js'):
            return 200, {'content-type': 'application/javascript'}, script.encode()
        if '__aidast_missing_control__' in url:
            return control_status, {'content-type': 'application/json'}, (
                body if control_status == status else b'{"error":"missing"}')
        return status, {'content-type': media}, body
    monkeypatch.setattr(secondary, '_http_request', request)
    return secondary.discover_adaptive_js_api_candidates(
        'https://example.test/', [{'path': '/main.js'}])


@pytest.mark.parametrize('status,access', [(401, 'authentication_required'), (403, 'forbidden')])
def test_explicit_get_denial_survives_broken_missing_route_handler(monkeypatch, status, access, tmp_path):
    rows = _discover(monkeypatch, status)
    assert [r['path'] for r in rows] == ['/api/private']
    assert rows[0]['evidence']['access_status'] == access
    assert rows[0]['evidence']['response_status'] == status
    conn = db.init_db(tmp_path / 'recon.db')
    try:
        db.insert_scan(conn, scan_id='scan', scope_type='test', scope_value='local')
        asset = db.insert_asset(conn, scan_id='scan', identifier='example.test', asset_type='DOMAIN')
        origin = db.upsert_origin(conn, asset_id=asset, scheme='https', host='example.test',
                                  port=443, base_url='https://example.test/')
        ObservationRecorder(conn, origin_id=origin, scan_id='scan').record('adaptive_js', rows)
        surface = json.loads(export_surface(conn, scan_id='scan', output_path=tmp_path / 'Surface.json').read_text())
        endpoint = surface['origins'][0]['endpoints'][0]
        assert endpoint['path'] == '/api/private'
        assert endpoint['verification_status'] == 'observed'
        assert endpoint['observations'][0]['evidence']['access_status'] == access
        assert endpoint['observations'][0]['evidence']['control_status'] == 500
    finally:
        conn.close()


@pytest.mark.parametrize('options', [
    {'script': 'const hint="/api/private"'},
    {'script': 'http.post("/api/private",body)'},
    {'control_status': 401},
    {'body': secondary._POLICY_BLOCK_BODY},
    {'media': 'text/html'},
])
def test_denial_does_not_turn_generic_hints_or_fallbacks_into_routes(monkeypatch, options):
    assert _discover(monkeypatch, 401, **options) == []


def test_policy_proxy_denial_is_never_collected(monkeypatch):
    assert _discover(monkeypatch, 403, body=secondary._POLICY_BLOCK_BODY) == []


@pytest.mark.parametrize('value', [[], {}, True, None, 'verified'])
def test_malformed_access_metadata_does_not_interrupt_observation_export(value):
    assert sanitize_evidence({'access_status': value}) == {}
