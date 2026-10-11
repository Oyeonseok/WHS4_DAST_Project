"""Local credential identity for transport caches; never include it in reports."""
import hashlib
import json
import re

_SENSITIVE_FIELD = re.compile(r'password|passwd|secret|token|authorization|cookie|api.?key|jwt|bearer|credential|csrf|xsrf|session', re.I)


def sensitive_field(name):
    return bool(_SENSITIVE_FIELD.search(name))

_TRANSPORT_HEADERS = {
    'host', 'user-agent', 'accept', 'accept-encoding', 'accept-language',
    'content-type', 'content-length', 'connection', 'cache-control', 'pragma',
    'origin', 'referer', 'priority', 'dnt', 'upgrade', 'x-requested-with',
}


def authentication_key(headers=None):
    values = {str(k).lower(): str(v) for k, v in (headers or {}).items()
              if str(k).lower() not in _TRANSPORT_HEADERS
              and not str(k).lower().startswith(('sec-', 'x-aidast-', 'access-control-'))}
    if 'cookie' in values:
        # Duplicate names can represent cookies with different paths. Their
        # wire order affects which value a server selects.
        values['cookie'] = ';'.join(part.strip() for part in values['cookie'].split(';') if part.strip())
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()


def has_authentication(headers=None):
    return authentication_key(headers) != authentication_key({})


def credential_values(headers=None):
    """In-memory model boundary redaction; never serialize this return value."""
    values = []
    for name, value in (headers or {}).items():
        if str(name).lower() == 'cookie':
            values.extend(part.partition('=')[2].strip() for part in str(value).split(';') if '=' in part)
        else:
            values.append(str(value))
            # Configured storage mappings can apply an arbitrary scheme to a
            # custom header too. Hide both the wire value and its payload.
            if has_authentication({name: value}) and ' ' in str(value):
                values.append(str(value).partition(' ')[2].strip())
    return tuple(value for value in values if value)
