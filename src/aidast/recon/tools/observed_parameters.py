"""Bind explicit DOM reads to GET templates without executing site JavaScript.

Values stay local. Duplicate DOM IDs, missing values, mutated variables and
unrelated documents do not establish a binding. No application vocabulary.
"""
from dataclasses import dataclass
from html.parser import HTMLParser
from itertools import islice
import re
from urllib.parse import quote, urljoin, urlsplit

from .html_scripts import declared_script_urls
from .js_api_paths import _literals, extract_js_api_paths, literal_call_method
from .js_argument_bindings import _structure
from .js_fetch_bindings import _written, _declared, _global_written

_ID = r'[A-Za-z_$][\w$]*'
_SECRET = re.compile(r'password|passwd|secret|token|authorization|cookie|api.?key|jwt|bearer|credential|csrf|xsrf|session', re.I)


def field_key(name):
    return re.sub(r'[-_]', '', name).casefold()


def scalar(value):
    if type(value) not in (str, int):
        return None
    value = str(value)
    return value if value.strip() and len(value) <= 256 and value not in {'.', '..'} and not any(
        ord(c) < 32 or ord(c) == 127 for c in value) else None


class _Fields(HTMLParser):
    def __init__(self):
        super().__init__()
        self.elements = []
        self.stack = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if len(self.elements) >= 2000:
            return
        item = dict(tag=tag, attrs=values, text=[], options=[])
        self.elements.append(item)
        if tag == 'option':
            parent = next((e for e in reversed(self.stack) if e['tag'] == 'select'), None)
            if parent is not None:
                parent['options'].append(item)
        if tag not in {'input', 'img', 'br', 'hr', 'meta', 'link', 'source', 'wbr', 'area', 'embed', 'param', 'col'}:
            self.stack.append(item)

    def handle_endtag(self, tag):
        for index in range(len(self.stack)-1, -1, -1):
            if self.stack[index]['tag'] == tag:
                del self.stack[index:]
                break

    def handle_data(self, text):
        for item in self.stack:
            if sum(map(len, item['text'])) < 1024:
                item['text'].append(text)

    def value(self, item, attribute):
        attrs = item['attrs']
        if (item['tag'] in {'script', 'style'} or attrs.get('type', '').lower() == 'password'
                or any(_SECRET.search(str(attrs.get(k) or '')) for k in ('id', 'name'))):
            return None
        if attribute == 'value':
            if item['tag'] == 'select':
                selected = [o for o in item['options'] if 'selected' in o['attrs']]
                if len(selected) > 1:
                    return None
                option = selected[0] if selected else next(iter(item['options']), None)
                return scalar(option['attrs'].get('value', ''.join(option['text']))) if option else None
            if item['tag'] not in {'input', 'textarea', 'option', 'data', 'output'}:
                return None
            if item['tag'] == 'input' and attrs.get('type', 'text').lower() not in {'text', 'hidden', 'number', 'email', 'search', 'tel'}:
                return None
            return scalar(attrs.get('value', ''.join(item['text'])))
        return scalar(''.join(item['text']))

    def by_id(self, dom_id, attribute):
        items = [e for e in self.elements if e['attrs'].get('id') == dom_id]
        return self.value(items[0], attribute) if len(items) == 1 else None


@dataclass(frozen=True)
class DomGet:
    path: str
    template: str
    document_url: str
    source_script: str
    field: str


def bind_dom_gets(scripts, documents):
    results = []
    for document_url, document in islice(documents, 50):
        fields = _Fields()
        fields.feed(document)
        sources = set(declared_script_urls(document, document_url))
        for source, script in islice(scripts.items(), 40):
            if source not in sources and not source.startswith(document_url + '#inline-dom-'):
                continue
            code, ends, parents = _structure(script)
            if any(_declared(code, name) or _global_written(code, name)
                   or re.search(r'\bfunction\s+'+name+r'\b|\([^()]*\b'+name+r'\b[^()]*\)\s*(?:=>|\{)', code)
                   for name in ('document', 'fetch')):
                continue
            literals = _literals(script)
            locations = []
            extract_js_api_paths(script, literal_call_method,
                location_callback=lambda p, m, a, b: locations.append((p, m, a, b)))
            for literal in literals:
                if not literal.value or not re.search(r'\bdocument\.getElementById\(\s*$', code[max(0,literal.start-80):literal.start]):
                    continue
                suffix = re.match(r'\s*\)\s*\.\s*(value|textContent|innerText)\b', code[literal.end:])
                prefix = re.search(r'\b(?:const|let)\s+('+_ID+r')\s*=\s*document\.getElementById\(\s*$',
                                   code[max(0,literal.start-180):literal.start])
                if prefix is None or suffix is None:
                    continue
                tail = code[literal.end + suffix.end():]
                if not re.match(r'\s*;', tail):
                    continue  # The whole initializer must be the DOM read.
                value = fields.by_id(literal.value, suffix[1])
                if value is None:
                    continue
                name = prefix[1]
                start = literal.end + suffix.end()
                enclosing = [end for opening, end in ends.items() if opening < literal.start < end]
                end = min(enclosing) if enclosing else len(script)
                remainder = code[start:end]
                if (_written(remainder, name) or re.search(r'(?:\+\+|--)\s*'+re.escape(name)+r'\b', remainder)
                        or re.search(r'\b(?:const|let|var)\s+'+re.escape(name)+r'\b|\bfunction\b|=>', remainder)
                        or re.search(r'\b(?:fetch|document)\s*=|\b(?:const|let|var)\s+(?:fetch|document)\b', code)):
                    continue
                for template, method, position, _ in locations:
                    if not start <= position < end or method != 'GET' or template.count('${') != 1:
                        continue
                    expression = '${'+name+'}'
                    if expression not in template:
                        continue
                    path = template.replace(expression, quote(value, safe=''))
                    if not path.startswith('/') or path.startswith('//') or any(c in path for c in '{}\\\r\n'):
                        continue
                    results.append(DomGet(path, template, document_url, source, literal.value))
                    if len(results) >= 100:
                        return results
    return results


def observed_named_values(documents):
    """Exact named DOM fields for declared schema parameters; ambiguous values skip."""
    values = {}
    for _, document in islice(documents, 50):
        fields = _Fields()
        fields.feed(document)
        for item in fields.elements:
            if item['tag'] not in {'input', 'select', 'textarea', 'span', 'output', 'data'}:
                continue
            attribute = 'value' if item['tag'] in {'input', 'select', 'textarea', 'data'} else 'textContent'
            for name in (item['attrs'].get('id'), item['attrs'].get('name')):
                if not name or _SECRET.search(name):
                    continue
                value = fields.value(item, attribute)
                if value is not None:
                    values.setdefault(field_key(name), set()).add(value)
    return {name: list(items) for name, items in values.items() if len(items) == 1}
