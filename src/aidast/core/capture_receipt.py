"""Stdlib HTTP descriptor and opaque capture receipt, also usable via runpy.

Preparation describes an intended urllib one-hop request. Receipt issuance hashes
an already observed physical request; it never adds headers or rebuilds its body.
Neither API performs IO. A producer must not issue a receipt for streamed/missing
request bytes, approximate decoded bodies, or incomplete final headers.
"""
from __future__ import annotations

import hashlib
import math
from pathlib import Path
import runpy
from urllib.parse import urlsplit
import urllib.request

_guard = runpy.run_path(str(Path(__file__).with_name('exclusion_guard.py')))


def prepare_http_request(url, *, method='GET', headers=None, body=None, context=None):
    """Freeze final direct urllib headers/body; callers must disable opener.addheaders.

Use body=None at dispatch when returned bytes are empty AND Content-Length is
absent. Proxies, cookies and browser transports require their own final descriptor.
URL authorization belongs to the existing caller boundary; strict exclusion
canonicalization belongs to admission and receipt issuance, not wire preparation.
"""
    method = _guard['_method'](method)
    normalized = dict(_guard['_headers'](headers))
    if 'transfer-encoding' in normalized:
        raise ValueError('streaming HTTP framing is unavailable for preparation')
    raw = _guard['_body'](body)
    host = urlsplit(url).netloc
    if 'host' in normalized and normalized['host'].lower() != host.lower():
        raise ValueError('Host differs from request origin')
    normalized['host'] = host
    normalized.setdefault('user-agent', f'Python-urllib/{urllib.request.__version__}')
    normalized.setdefault('accept-encoding', 'identity')
    normalized['connection'] = 'close'
    if body is not None or method in {'POST', 'PUT', 'PATCH'}:
        if 'content-length' in normalized and normalized['content-length'] != str(len(raw)):
            raise ValueError('Content-Length differs from complete request body')
        normalized['content-length'] = str(len(raw))
        if body is not None:
            normalized.setdefault('content-type', 'application/x-www-form-urlencoded')
    elif 'content-length' in normalized and normalized['content-length'] != '0':
        raise ValueError('Content-Length differs from empty request body')
    final = {name.title(): value for name, value in normalized.items()}
    return dict(url=url, method=method, headers=final, body=raw, context=context)


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def make_capture_receipt(*, url, method, headers, body, response_body, captured_at, context=None):
    """Issue only after full actual wire capture, before request redaction.

response_body must be the exact bytes stored in http_transactions, even when the
producer bounds/redacts them. captured_at is the observation epoch, not ingestion
or preparation time. None body means unavailable and is rejected; b'' is empty.
"""
    if not isinstance(body, bytes) or not isinstance(response_body, bytes):
        raise ValueError('capture receipt requires complete actual body bytes')
    if type(captured_at) not in {int, float} or not math.isfinite(captured_at) or captured_at <= 0:
        raise ValueError('capture receipt requires a finite observation time')
    return {'version': '1', 'complete': True,
            'request_key': _guard['request_key'](url, method, headers, body, context=context),
            'url_sha256': _sha(url.encode()), 'method': _guard['_method'](method),
            'body_sha256': _sha(body), 'body_bytes': len(body),
            'response_sha256': _sha(response_body), 'response_bytes': len(response_body),
            'captured_at': float(captured_at)}


def validate_capture_receipt(value, *, url, method, response_body):
    """Validate the receipt's association with the stored transaction bytes.

This is an application provenance contract, not a signature against local writers.
Opaque request_key cannot be reconstructed from sanitized capture columns.
"""
    fields = {'version','complete','request_key','url_sha256','method','body_sha256',
              'body_bytes','response_sha256','response_bytes','captured_at'}
    if not isinstance(value, dict) or set(value) != fields or value['version'] != '1' or value['complete'] is not True:
        raise ValueError('invalid complete capture receipt')
    for field in ('request_key','url_sha256','body_sha256','response_sha256'):
        digest = value[field]
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
            raise ValueError('invalid capture digest')
    for field in ('body_bytes','response_bytes'):
        if type(value[field]) is not int or value[field] < 0:
            raise ValueError('invalid capture byte length')
    stamp=value['captured_at']
    if type(stamp) not in {float,int} or not math.isfinite(stamp) or stamp <= 0:
        raise ValueError('invalid capture timestamp')
    if (value['url_sha256'] != _sha(url.encode()) or value['method'] != _guard['_method'](method)
            or value['response_sha256'] != _sha(response_body) or value['response_bytes'] != len(response_body)):
        raise ValueError('capture receipt does not match stored transaction')
    return dict(value)


def urllib_request_data(descriptor):
    """Avoid urllib synthesizing Content-Type for a zero-byte physical request."""
    return descriptor['body'] or None
