"""Bounded in-memory evidence and request reuse across Recon discovery passes."""
from collections import OrderedDict
import hashlib
import json

from .request_identity import authentication_key


class AdaptiveDiscoveryState:
    def __init__(self):
        self.responses = OrderedDict()
        self.evidence = OrderedDict()
        self.scripts = OrderedDict()
        self.attempted = set()
        self.last_input = None
        self.detail_probes = 0
        self.request_count = 0
        self.evicted_evidence = 0
        self.evicted_responses = 0

    def _bound(self, values, size, maximum, *, counter=None):
        total = sum(size(value) for value in values.values())
        while values and (len(values) > 150 or total > maximum):
            _, value = values.popitem(last=False)
            total -= size(value)
            if counter:
                setattr(self, counter, getattr(self, counter) + 1)

    def observe(self, records, headers):
        auth = authentication_key(headers)
        for record in records:
            if not isinstance(record, dict) or record.get('method') != 'GET':
                continue
            if record.get('policy_blocked') or record.get('capture_bodies') is not True:
                continue
            identity = record.get('authentication_key')
            if identity is None:
                identity = authentication_key(record.get('request_headers') or {})
            if identity != auth:
                continue
            url, body = record.get('url'), record.get('response_body')
            if not isinstance(url, str) or not isinstance(body, (str, bytes)) or len(body) > 2_000_000:
                continue
            content = body.encode() if isinstance(body, str) else body
            key = (url, auth)
            self.evidence.pop(key, None)
            self.evidence[key] = record.copy()
            status = record.get('response_status')
            # Passive traffic has its own bounded evidence store. It must not
            # evict explicitly requested service/collection responses.
            if (('GET', url, auth) in self.attempted and type(status) is int
                    and isinstance(record.get('response_headers'), dict)):
                self.responses[('GET', url, auth)] = (status, record['response_headers'], content)
        self._bound(self.evidence, lambda row: len(row['response_body']), 8_000_000, counter='evicted_evidence')
        self._bound(self.responses, lambda row: len(row[2]), 20_000_000, counter='evicted_responses')

    def observations(self, headers):
        auth = authentication_key(headers)
        return [row for (url, identity), row in self.evidence.items() if identity == auth]

    def begin(self, endpoints, headers):
        urls = sorted({str(row.get('url') or row.get('path') or '') for row in endpoints})
        bodies = sorted((row['url'], hashlib.sha256(
            row['response_body'].encode() if isinstance(row['response_body'], str) else row['response_body']
        ).hexdigest()) for row in self.observations(headers))
        key = hashlib.sha256(json.dumps([authentication_key(headers), urls, bodies]).encode()).hexdigest()
        if key == self.last_input:
            return False
        self.last_input = key
        return True

    def request(self, fetch, url, **options):
        headers = options.get('headers')
        key = (options.get('method', 'GET'), url, authentication_key(headers))
        if key in self.responses:
            return self.responses[key]
        row = self.evidence.get((url, key[2]))
        if row is not None:
            body = row['response_body']
            return row['response_status'], row['response_headers'], body.encode() if isinstance(body, str) else body
        if key in self.attempted:
            return None, {}, b''
        self.attempted.add(key)
        self.request_count += 1
        result = fetch(url, **options)
        self.responses[key] = result
        status, response_headers, body = result
        media = next((str(v).split(';', 1)[0].lower() for k, v in response_headers.items()
                      if k.lower() == 'content-type'), '')
        if type(status) is int and 200 <= status < 300 and (media in {
                'text/html', 'application/xhtml+xml', 'application/json'} or media.endswith('+json')):
            self.observe([dict(method='GET', url=url, response_status=status,
                response_headers=response_headers, response_body=body, capture_bodies=True,
                authentication_key=authentication_key(headers))], headers)
        self._bound(self.responses, lambda row: len(row[2]), 20_000_000, counter='evicted_responses')
        return result

    def script(self, url, body, headers, parse):
        key = (url, hashlib.sha256(body).hexdigest(), authentication_key(headers))
        if key not in self.scripts:
            text = body.decode('utf-8', errors='replace')
            self.scripts[key] = (text, *parse(text))
            self._bound(self.scripts, lambda row: len(row[0]), 20_000_000)
        self.scripts.move_to_end(key)
        return self.scripts[key]

    def script_urls(self, headers):
        auth = authentication_key(headers)
        return list(dict.fromkeys(url for url, digest, identity in self.scripts if identity == auth))

    def parsed_scripts(self, headers):
        auth = authentication_key(headers)
        return {url: parsed for (url, digest, identity), parsed in self.scripts.items() if identity == auth}

    def prune_inline_scripts(self, document_urls, inline_urls, headers):
        auth = authentication_key(headers)
        for key in list(self.scripts):
            url, digest, identity = key
            if (identity == auth and '#inline-dom-' in url
                    and url.split('#inline-dom-', 1)[0] in document_urls and url not in inline_urls):
                del self.scripts[key]
