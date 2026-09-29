"""Bounded, dependency-free exclusion admission; also loaded through runpy.

True predicates exclude, false predicates leave baseline authorization unchanged,
and unknown predicates hold. No classification or network I/O occurs here.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import time
from collections.abc import Mapping
from urllib.parse import parse_qsl, unquote, urlsplit


MAX_DEPTH = 8
MAX_NODES = 128
MAX_RULES = 128
MAX_BINDINGS = 16384
MAX_BODY_BYTES = 1_048_576
_ID = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}\Z')
_SHA = re.compile(r'[0-9a-f]{64}\Z')
_TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_BAD_PERCENT = re.compile(r'%(?![0-9a-fA-F]{2})')
_FIELDS = {'host', 'path', 'method', 'query', 'json_body', 'form_body', 'semantic', 'unsupported'}


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _text(value, maximum=4096, *, empty=False):
    if not isinstance(value, str) or len(value) > maximum or (not empty and not value.strip()):
        raise ValueError('invalid bounded text')
    if any(ord(char) < 32 and char not in '\n\r\t' for char in value):
        raise ValueError('invalid text control character')
    # Reject lone surrogates before hashing or handing text to transports.
    value.encode('utf-8')
    return value


def _identifier(value):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError('invalid identifier')
    return value


def _digest(value):
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError('invalid SHA256 digest')
    return value


def _shape(value, allowed, required):
    if not isinstance(value, dict) or set(value) - set(allowed) or not set(required) <= set(value):
        raise ValueError('invalid object shape')


def _list(value, maximum, *, minimum=0):
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ValueError('invalid bounded list')
    return value


def _unique_strings(value, maximum, *, identifiers=False):
    values = _list(value, maximum)
    parsed = [(_identifier(item) if identifiers else _text(item)) for item in values]
    if len(set(parsed)) != len(parsed):
        raise ValueError('duplicate list values')
    return parsed


def _percent_decode(value):
    if _BAD_PERCENT.search(value):
        raise ValueError('malformed percent encoding')
    return unquote(value, encoding='utf-8', errors='strict')


def _path(value):
    if not value.startswith('/') or len(value) > 8192:
        raise ValueError('invalid absolute path')
    # Separators, double decoding, path parameters and dot segments vary across
    # proxies/frameworks: refusing them is safer than choosing an interpretation.
    if re.search(r'%(?:2f|5c|25|3f|23|3b)', value, re.I):
        raise ValueError('ambiguous encoded path')
    decoded = _percent_decode(value)
    if any(ord(c) < 33 or ord(c) == 127 for c in decoded) or any(c in decoded for c in '\\;?#'):
        raise ValueError('ambiguous path characters')
    if '//' in decoded or any(p in {'.', '..'} for p in decoded.split('/')):
        raise ValueError('ambiguous path segments')
    return decoded


def _url(url):
    _text(url, 16384)
    if any(ord(c) < 33 or ord(c) == 127 for c in url) or '\\' in url or '#' in url:
        raise ValueError('malformed URL')
    parsed = urlsplit(url)
    if parsed.scheme not in {'http', 'https'} or not parsed.netloc or '@' in parsed.netloc:
        raise ValueError('unsupported URL origin')
    if not parsed.hostname or parsed.netloc.endswith(':'):
        raise ValueError('missing URL host or port')
    host = parsed.hostname.encode('idna').decode('ascii').lower()
    if ':' in host:
        host = str(ipaddress.IPv6Address(host))
    elif not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9.])?', host) or '..' in host:
        raise ValueError('invalid URL host')
    port = parsed.port if parsed.port is not None else (443 if parsed.scheme == 'https' else 80)
    if not 1 <= port <= 65535:
        raise ValueError('invalid URL port')
    path = _path(parsed.path or '/')
    _percent_decode(parsed.query)
    return (parsed.scheme, host, port, path, parsed.query)


def _method(method):
    if not isinstance(method, str) or len(method) > 32 or not _TOKEN.fullmatch(method):
        raise ValueError('invalid HTTP method')
    return method.upper()


def _headers(headers):
    if headers is None:
        return []
    items = list(headers.items()) if isinstance(headers, Mapping) else headers
    if not isinstance(items, (list, tuple)) or len(items) > 256:
        raise ValueError('invalid bounded headers')
    result, seen, size = [], {}, 0
    for pair in items:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            raise ValueError('invalid header pair')
        name, value = pair
        if not isinstance(name, str) or not _TOKEN.fullmatch(name) or len(name) > 256:
            raise ValueError('invalid header name')
        _text(value, 16384, empty=True)
        if any(ord(c) < 32 and c != '\t' or ord(c) == 127 for c in value):
            raise ValueError('invalid header value')
        name = name.lower()
        if name in seen and seen[name] != value:
            raise ValueError('conflicting case-insensitive duplicate headers')
        seen[name] = value
        result.append([name, value])
        size += len(name) + len(value)
    if size > 65536:
        raise ValueError('headers too large')
    return sorted(result)


def _body(body):
    if body is None:
        return b''
    if isinstance(body, str):
        return body.encode('utf-8')
    if isinstance(body, (bytes, bytearray, memoryview)):
        return bytes(body)
    raise ValueError('body requires complete bytes or text')


def _context(context):
    if context is None:
        return None
    if not isinstance(context, dict):
        raise ValueError('context must be a trusted JSON object')
    count = [0]

    def visit(value, depth):
        count[0] += 1
        if depth > MAX_DEPTH or count[0] > MAX_NODES:
            raise ValueError('context too complex')
        if isinstance(value, dict):
            for key, item in value.items():
                _text(key, 128)
                visit(item, depth + 1)
        elif isinstance(value, list):
            for item in value:
                visit(item, depth + 1)
        elif isinstance(value, str):
            _text(value, 4096, empty=True)
        elif value is not None and type(value) not in (int, float, bool):
            raise ValueError('context must contain JSON data')
        elif type(value) in (int, float) and (not math.isfinite(value) or abs(value) > 1e100):
            raise ValueError('invalid context number')

    visit(context, 1)
    if len(_json(context).encode('utf-8')) > 16384:
        raise ValueError('context too large')
    return context


def request_key(url, method, headers=None, body=None, *, context=None) -> str:
    """Hash full canonical request identity; never return credentials/body text.

    Context is trusted application-supplied JSON (transport/action/session identity).
    Callers must use matching context during preparation and physical admission.
    """
    identity = dict(url=_url(url), method=_method(method), headers=_headers(headers),
                    body_sha256=hashlib.sha256(_body(body)).hexdigest(), context=_context(context))
    return hashlib.sha256(_json(identity).encode('utf-8')).hexdigest()


def validate_exclusion_predicate(data) -> dict:
    _shape(data, {'key', 'field', 'operator', 'name', 'value'}, {'key', 'field', 'operator'})
    key = _identifier(data['key'])
    field, operator = data['field'], data['operator']
    if field not in _FIELDS or operator not in {'equals', 'prefix', 'present'}:
        raise ValueError('unsupported predicate grammar')
    name, value = data.get('name'), data.get('value')
    if name is not None:
        _text(name, 512, empty=field == 'json_body')
    if value is not None:
        _text(value, 4096, empty=True)
    if operator == 'prefix' and field != 'path':
        raise ValueError('prefix only supports segment-bounded paths')
    if operator == 'present' and value is not None:
        raise ValueError('present has no comparison value')
    if operator != 'present' and value is None:
        raise ValueError('comparison requires a value')
    if field in {'query', 'form_body', 'json_body'}:
        if name is None:
            raise ValueError('parameter or pointer name is required')
        if field == 'json_body' and (name and not name.startswith('/') or re.search(r'~(?![01])', name) or len(name.split('/')) > 17):
            raise ValueError('invalid bounded JSON pointer')
    elif name is not None:
        raise ValueError('name is only supported for parameter predicates')
    if field in {'semantic', 'unsupported'} and (operator != 'equals' or not value or not value.strip()):
        raise ValueError('semantic or unsupported conditions need a description')
    if field == 'path' and value is not None:
        _path(value)
    if field == 'method' and value is not None and _method(value) != value:
        raise ValueError('method literals must use canonical uppercase')
    if field == 'host' and value is not None:
        if _url('https://' + value + '/')[1] != value or ':' in value:
            raise ValueError('host must be canonical without port')
    return dict(key=key, field=field, operator=operator, name=name, value=value)


def validate_exclusion_expression(data) -> dict:
    seen, count = set(), [0]

    def visit(node, depth):
        count[0] += 1
        if depth > MAX_DEPTH or count[0] > MAX_NODES:
            raise ValueError('exclusion expression exceeds complexity bounds')
        _shape(node, {'operator', 'predicate', 'children'}, {'operator'})
        operator = node['operator']
        children = _list(node.get('children', []), MAX_NODES)
        pred = node.get('predicate')
        if operator == 'predicate':
            if pred is None or children:
                raise ValueError('predicate expression requires exactly one predicate')
            pred = validate_exclusion_predicate(pred)
            if pred['key'] in seen:
                raise ValueError('duplicate predicate IDs in a rule')
            seen.add(pred['key'])
        elif operator in {'all', 'any', 'not'}:
            if pred is not None or not children or operator == 'not' and len(children) != 1:
                raise ValueError('invalid expression arity')
        else:
            raise ValueError('unsupported expression operator')
        return dict(operator=operator, predicate=pred, children=[visit(c, depth + 1) for c in children])

    return visit(data, 1)


def _predicates(expression):
    if expression['operator'] == 'predicate':
        yield expression['predicate']
    for child in expression['children']:
        yield from _predicates(child)


def validate_scope_exclusion(data) -> dict:
    _shape(data, {'key', 'label', 'source_quote', 'target_assets', 'condition'}, {'key', 'label', 'source_quote', 'condition'})
    result = dict(key=_identifier(data['key']), label=_text(data['label'], 160),
        source_quote=_text(data['source_quote'], 16000),
        target_assets=_unique_strings(data.get('target_assets', []), 512),
        condition=validate_exclusion_expression(data['condition']))
    for pred in _predicates(result['condition']):
        if pred['field'] in {'semantic', 'unsupported'}:
            continue
        for literal in (pred['name'], pred['value']):
            if literal and literal not in result['source_quote']:
                raise ValueError('concrete predicate literals must be grounded in the source quote')
    return result


def _rules(rules):
    rows = [validate_scope_exclusion(rule) for rule in _list(rules, MAX_RULES)]
    if len({rule['key'] for rule in rows}) != len(rows):
        raise ValueError('duplicate rule keys')
    return rows


def rule_digest(rules) -> str:
    """Digest normalized rules, including quotes, bindings, and default fields."""
    return hashlib.sha256(_json(_rules(rules)).encode('utf-8')).hexdigest()


def _asset_host_envelope(asset):
    """Recognize only literal hosts and leading DNS wildcards; else unknown.

    Paths, schemes and ports deliberately never prove alias disjointness. This
    is applicability analysis, not a new scope authorization parser.
    """
    try:
        _text(asset)
        if any(ord(c) < 33 or ord(c) == 127 for c in asset) or '\\' in asset:
            return None
        if '://' in asset:
            parsed = urlsplit(asset)
            if (parsed.scheme not in {'http', 'https'} or not parsed.hostname
                    or '@' in parsed.netloc or parsed.query or parsed.fragment
                    or parsed.netloc.endswith(':')):
                return None
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                return None
            host = parsed.hostname
        else:
            host = asset
        wildcard = host.startswith('*.')
        host = host[2:] if wildcard else host
        host = host.encode('idna').decode('ascii').lower().rstrip('.')
        try:
            address = ipaddress.ip_address(host)
            return None if wildcard else (str(address), False)
        except ValueError:
            pass
        # Resolver-dependent abbreviated/octal/hex IPv4 spellings cannot prove
        # disjointness from a literal address (for example 127.1 vs 127.0.0.1).
        if re.fullmatch(r'(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*', host):
            return None
        if len(host) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                                      for label in host.split('.')):
            return None
        return host, wildcard
    except (ValueError, TypeError, UnicodeError):
        return None


def exclusion_applicability(rule, target_asset):
    """Return apply, disjoint or overlap without rewriting source bindings.

    Nonidentical aliases with possibly intersecting host envelopes require an
    offline hold; no predicate/classification can resolve that mapping here.
    """
    assets = rule['target_assets']
    if not assets or target_asset in assets:
        return 'apply'
    selected = _asset_host_envelope(target_asset)
    for asset in assets:
        bound = _asset_host_envelope(asset)
        if selected is None or bound is None:
            return 'overlap'
        left, left_wildcard = selected
        right, right_wildcard = bound
        if (left == right or (left_wildcard and right.endswith('.' + left))
                or (right_wildcard and left.endswith('.' + right))):
            return 'overlap'
    return 'disjoint'


def validate_exclusion_policy(data) -> dict:
    """Return a detached, normalized snapshot or raise ValueError on invalid data."""
    required = {'schema_version', 'scope_digest', 'rule_digest', 'evidence_digest', 'target_asset', 'rules', 'semantic_bindings'}
    _shape(data, required | {'expires_at'}, required)
    if data['schema_version'] != '1':
        raise ValueError('unsupported exclusion schema version')
    rules = _rules(data['rules'])
    expected = hashlib.sha256(_json(rules).encode('utf-8')).hexdigest()
    if _digest(data['rule_digest']) != expected:
        raise ValueError('stale exclusion rule digest')
    memberships = {(rule['key'], p['key']) for rule in rules for p in _predicates(rule['condition']) if p['field'] == 'semantic'}
    bindings, seen = [], set()
    fields = {'request_key', 'rule_key', 'predicate_key', 'classification', 'evidence_ids'}
    for binding in _list(data['semantic_bindings'], MAX_BINDINGS):
        _shape(binding, fields, fields)
        request = _digest(binding['request_key'])
        rule, pred = _identifier(binding['rule_key']), _identifier(binding['predicate_key'])
        classification = binding['classification']
        if classification not in {'match', 'nonmatch', 'unknown'} or (rule, pred) not in memberships:
            raise ValueError('invalid semantic binding membership')
        identity = (request, rule, pred)
        if identity in seen:
            raise ValueError('duplicate semantic bindings')
        seen.add(identity)
        evidence = _unique_strings(binding['evidence_ids'], 64, identifiers=True)
        if classification != 'unknown' and not evidence:
            raise ValueError('usable semantic classification requires evidence')
        bindings.append(dict(request_key=request, rule_key=rule, predicate_key=pred,
                             classification=classification, evidence_ids=evidence))
    expires_at = data.get('expires_at')
    if expires_at is not None and (type(expires_at) not in (int, float) or not math.isfinite(expires_at) or expires_at <= 0):
        raise ValueError('invalid semantic expiry timestamp')
    return dict(schema_version='1', scope_digest=_digest(data['scope_digest']), rule_digest=expected,
                evidence_digest=_digest(data['evidence_digest']), target_asset=_text(data['target_asset']),
                rules=rules, semantic_bindings=bindings, expires_at=expires_at)


def _parameters(text):
    if len(text) > MAX_BODY_BYTES:
        raise ValueError('parameter data too large')
    if ';' in text:
        raise ValueError('ambiguous parameter separator')
    _percent_decode(text)
    pairs = parse_qsl(text, keep_blank_values=True, encoding='utf-8', errors='strict', max_num_fields=1024)
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError('ambiguous duplicate parameters')
        result[name] = value
    return result


def _json_body(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate JSON member')
            result[key] = value
        return result

    def constant(_):
        raise ValueError('non-finite JSON scalar')

    value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant)
    nodes = [0]

    def bound(item, depth):
        nodes[0] += 1
        if depth > 32 or nodes[0] > 8192:
            raise ValueError('JSON body too complex')
        if isinstance(item, dict):
            for child in item.values():
                bound(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                bound(child, depth + 1)
        elif isinstance(item, float) and not math.isfinite(item):
            raise ValueError('non-finite JSON number')

    bound(value, 1)
    return value


_MISSING = object()


def _pointer(value, pointer):
    if not pointer:
        return value
    for part in pointer[1:].split('/'):
        part = part.replace('~1', '/').replace('~0', '~')
        if isinstance(value, dict):
            value = value.get(part, _MISSING)
        elif isinstance(value, list) and re.fullmatch(r'0|[1-9][0-9]{0,8}', part):
            index = int(part)
            value = value[index] if index < len(value) else _MISSING
        else:
            return _MISSING
        if value is _MISSING:
            return value
    return value


def evaluate_exclusions(data, *, url, method='GET', headers=None, body=None,
                        body_available=False, identity_available=True, context=None, now=None) -> dict:
    """Evaluate an immutable compiled snapshot; malformed present guards hold."""
    if data is None:
        return dict(decision='continue', rule_keys=[], reason='legacy policy has no exclusion guard')
    try:
        policy = validate_exclusion_policy(data)
        applicable = [(rule, exclusion_applicability(rule, policy['target_asset'])) for rule in policy['rules']]
        applicable = [(rule, status) for rule, status in applicable if status != 'disjoint']
        if not applicable:
            return dict(decision='continue', rule_keys=[], reason='no applicable exclusions; baseline authorization still applies')
        if type(body_available) is not bool or type(identity_available) is not bool:
            raise ValueError('body availability must be explicit')
        origin = _url(url)
        method = _method(method)
        header_items = _headers(headers)
        header_map = dict(header_items)
        _context(context)
        current_time = time.time() if now is None else now
        if type(current_time) not in (int, float) or not math.isfinite(current_time):
            raise ValueError('invalid evaluation clock')
        raw = _body(body) if body_available else None
        fingerprint = request_key(url, method, header_items, raw, context=context) if body_available and identity_available else None
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        return dict(decision='hold', rule_keys=[], reason='invalid exclusion policy or ambiguous request context')

    bindings = {(b['request_key'], b['rule_key'], b['predicate_key']): b['classification']
                for b in policy['semantic_bindings']}
    parsed = {}

    def value_for(pred):
        field, name = pred['field'], pred['name']
        if isinstance(context, dict) and context.get('operation') == 'dom_action':
            # The enclosing document and an element's labels/links cannot attest
            # every resource or local effect of an arbitrary scripted control.
            raise ValueError('DOM action resource and request context are unavailable')
        if field == 'host':
            return origin[1]
        if field == 'path':
            return origin[3]
        if field == 'method':
            return method
        if field == 'query':
            if field not in parsed:
                parsed[field] = _parameters(origin[4])
            return parsed[field].get(name, _MISSING)
        if raw is None:
            raise ValueError('body is unavailable')
        if not raw:
            return _MISSING
        if len(raw) > MAX_BODY_BYTES:
            raise ValueError('body exceeds parsing limit')
        content_type = header_map.get('content-type', '')
        media = content_type.split(';', 1)[0].strip().lower()
        for parameter in content_type.split(';')[1:]:
            parameter_name, separator, parameter_value = parameter.strip().partition('=')
            if not separator or parameter_name.strip().lower() != 'charset' or parameter_value.strip().strip('"').lower() not in {'utf-8', 'utf8', 'us-ascii'}:
                raise ValueError('unsupported content type parameters')
        content_encoding = header_map.get('content-encoding', 'identity').strip().lower()
        if content_encoding != 'identity':
            raise ValueError('encoded body requires decoded evidence')
        if field == 'json_body':
            if media != 'application/json' and not (media.startswith('application/') and media.endswith('+json')):
                raise ValueError('JSON content type is unknown')
            if field not in parsed:
                parsed[field] = _json_body(raw)
            return _pointer(parsed[field], name)
        if media != 'application/x-www-form-urlencoded':
            raise ValueError('form content type is unknown')
        if field not in parsed:
            parsed[field] = _parameters(raw.decode('utf-8'))
        return parsed[field].get(name, _MISSING)

    def predicate_value(pred, rule_key):
        if pred['field'] == 'unsupported':
            return None
        if pred['field'] == 'semantic':
            if policy['expires_at'] is None or current_time >= policy['expires_at']:
                return None
            classification = bindings.get((fingerprint, rule_key, pred['key']), 'unknown')
            return {'match': True, 'nonmatch': False, 'unknown': None}[classification]
        try:
            value = value_for(pred)
            if pred['operator'] == 'present':
                return value is not _MISSING
            if value is _MISSING:
                return False
            expected = pred['value']
            if pred['field'] == 'path':
                expected = _path(expected)
            if pred['operator'] == 'prefix':
                prefix = expected.rstrip('/')
                return not prefix or value == prefix or value.startswith(prefix + '/')
            if isinstance(value, (dict, list)):
                return None
            if not isinstance(value, str):
                value = _json(value)
            return value == expected
        except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
            return None

    def expression_value(expr, key):
        operator = expr['operator']
        if operator == 'predicate':
            return predicate_value(expr['predicate'], key)
        values = [expression_value(child, key) for child in expr['children']]
        if operator == 'not':
            return None if values[0] is None else not values[0]
        if operator == 'all':
            return False if False in values else None if None in values else True
        return True if True in values else None if None in values else False

    denied, held, overlaps = [], [], []
    for rule, applicability in applicable:
        if applicability == 'overlap':
            held.append(rule['key'])
            overlaps.append(rule['key'])
            continue
        value = expression_value(rule['condition'], rule['key'])
        if value is True:
            denied.append(rule['key'])
        elif value is None:
            held.append(rule['key'])
    if denied:
        return dict(decision='deny', rule_keys=denied, reason='request matches an exclusion')
    if held:
        reason = ('overlapping approved asset bindings require offline applicability review'
                  if overlaps else 'exclusion requires unavailable or ambiguous evidence')
        return dict(decision='hold', rule_keys=held, reason=reason)
    return dict(decision='continue', rule_keys=[], reason='no exclusion matched; baseline authorization still applies')
