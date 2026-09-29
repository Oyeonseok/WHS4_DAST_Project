"""Bounded native-fetch provenance, without executing JS or inventing identifiers.

Supports direct array callbacks and select option values passed through an
explicit HTML onchange handler. Unresolved aliases and mutated values fail closed.
"""
from __future__ import annotations

from collections import Counter
from html.parser import HTMLParser
from itertools import islice
import re

from .js_api_paths import _literals, extract_js_api_paths, literal_call_method
from .js_argument_bindings import ResponseArgumentBinding, _structure

_ID = r'[A-Za-z_$][\w$]*'
_WRITE = r'(?:\+\+|--|(?:\*\*|<<|>>>?|[+*/%&|^?-])?=(?!=|>))'


class _SelectHandlers(HTMLParser):
    def __init__(self):
        super().__init__()
        self.handlers = []

    def handle_starttag(self, tag, attrs):
        if tag != 'select':
            return
        values = dict(attrs)
        match = re.fullmatch(r'\s*('+_ID+r')\(\s*(?:this\.value|event\.target\.value)\s*\)\s*;?\s*',
                             values.get('onchange') or '')
        if values.get('id') and match:
            self.handlers.append((values['id'], match[1]))


def _written(code, name):
    return re.search(r'(?<![\w$.])'+re.escape(name)+r'(?:\s*(?:\.\s*'+_ID+r'|\[[^\]]*\]))*\s*'+_WRITE, code) is not None


def _declared(code, name):
    return re.search(r'\b(?:const|let|var|import)\b[^;=\n]*\b'+re.escape(name)+r'\b', code) is not None


def _global_written(code, name):
    return (_written(code, name) or re.search(
        r'\b(?:window|globalThis|self)\s*\.\s*'+re.escape(name)+r'\s*'+_WRITE, code) is not None)


def extract_fetch_response_bindings(scripts: dict[str, str], *, documents=()) -> list[ResponseArgumentBinding]:
    handlers = _SelectHandlers()
    for document in islice(documents, 50):
        if isinstance(document, str) and len(document) <= 2_000_000:
            handlers.feed(document)
            handlers.reset()
    functions = []
    structures = []
    for source, script in islice(scripts.items(), 40):
        if not isinstance(script, str) or len(script) > 20_000_000:
            continue
        code, ends, parents = _structure(script)
        structures.append((source, script, code, ends, parents))
    if any(_declared(code, 'fetch') or _global_written(code, 'fetch')
           or re.search(r'\b(?:function|class)\s+fetch\b', code)
           for _, _, code, _, _ in structures):
        return []
    for source, script, code, ends, parents in structures:
        literals = _literals(script)
        for match in re.finditer(r'\b(?:async\s+)?function\s+('+_ID+r')\s*\(([^()]*)\)\s*\{', code):
            opening = match.end()-1
            end = ends.get(opening)
            if end is None or parents.get(opening) is not None:
                continue
            if (re.search(r'\b(?:fetch|document)\b', match[2])
                    or _declared(code[opening+1:end], 'document')
                    or re.search(r'\bfunction\b', code[opening+1:end])):
                continue
            functions.append((source, script, code, literals, ends, match[1], match[2].strip(), opening+1, end))
    counts = Counter(row[5] for row in functions)
    targets = {}
    for source, script, code, literals, ends, name, parameter, start, end in functions:
        if (counts[name] != 1 or not re.fullmatch(_ID, parameter) or _written(code[start:end], parameter)
                or _declared(code[start:end], parameter)
                or any(_global_written(row[2], name) for row in structures)):
            continue
        for literal in literals:
            if (start <= literal.start < literal.end <= end and literal.value
                    and literal_call_method(script, literal.start, literal.end) == 'GET'):
                if '=>' in code[start:literal.start]:
                    continue
                # The complete function supplies method and path validation;
                # no dynamic expression other than its unchanged parameter.
                valid = dict(extract_js_api_paths(script[start:end], literal_call_method))
                path = literal.value
                if (valid.get(path) == 'GET' and path.count('${') == 1
                        and '${'+parameter+'}' in path):
                    targets.setdefault(name, []).append((path, source))

    results = set()
    for source, script, code, literals, ends, name, parameter, start, end in functions:
        if counts[name] != 1:
            continue
        body = code[start:end]
        for fetch in re.finditer(r'\b(?:const|let)\s+('+_ID+r')\s*=\s*await\s+fetch\s*\(', body):
            fetch_end = start+fetch.end()
            literal = next((lit for lit in literals if fetch_end <= lit.start < end
                            and not script[fetch_end:lit.start].strip()), None)
            if (literal is None or not literal.value or not literal.value.startswith('/')
                    or literal.value.startswith('//') or '${' in literal.value
                    or literal_call_method(script, literal.start, literal.end) != 'GET'):
                continue
            response = fetch[1]
            parsed = re.search(r'\b(?:const|let)\s+('+_ID+r')\s*=\s*await\s+'+re.escape(response)+r'\.json\(\s*\)', code[literal.end:end])
            if parsed is None:
                continue
            data = parsed[1]
            parsed_end = literal.end+parsed.end()
            if _written(code[literal.end:end], response) or _written(code[parsed_end:end], data):
                continue
            source_path = literal.value

            # A direct callback retains the response's named collection path.
            callback = re.compile(r'\b'+re.escape(data)+r'((?:\.'+_ID+r')*)\.(?:map|forEach)\(\s*('+_ID+r')\s*=>\s*\{')
            for match in callback.finditer(code, parsed_end, end):
                closing = ends.get(match.end()-1)
                if closing is None:
                    continue
                row = match[2]
                if (_written(code[match.end():closing], row) or _declared(code[match.end():closing], row)
                        or re.search(r'\bfunction\b|=>', code[match.end():closing])):
                    continue
                for item in literals:
                    if not match.end() <= item.start < item.end <= closing or not item.value:
                        continue
                    if not re.fullmatch(r'\s*(?:await\s+)?fetch\s*\(\s*', code[match.end():item.start]):
                        continue
                    field = re.search(r'\$\{'+re.escape(row)+r'\.('+_ID+r')\}', item.value)
                    if (field and item.value.count('${') == 1
                            and literal_call_method(script, item.start, item.end) == 'GET'
                            and (item.value, 'GET') in extract_js_api_paths(script[match.end():closing], literal_call_method)):
                        results.add(ResponseArgumentBinding(item.value, source_path, field[1], (source,),
                                                            tuple(match[1].lstrip('.').split('.')) if match[1] else ()))

            # Rendered options have provenance only when the exact select ID
            # declares a handler passing its own value to a known GET function.
            for render in literals:
                if not parsed_end <= render.start < render.end <= end or not render.value:
                    continue
                assignment = re.search(r'\b('+_ID+r')\.innerHTML\s*=\s*$', code[max(start,render.start-256):render.start])
                if assignment is None:
                    continue
                select = assignment[1]
                dom_literals = [lit for lit in literals if parsed_end <= lit.start < lit.end <= render.start
                    and lit.value and re.search(r'\b(?:const|let)\s+'+re.escape(select)+r'\s*=\s*document\.getElementById\(\s*$',
                                               code[parsed_end:lit.start])
                    and re.match(r'\s*\)', code[lit.end:render.start])]
                if len(dom_literals) != 1:
                    continue
                dom_literal = dom_literals[0]
                if re.search(r'\b'+re.escape(select)+r'\s*'+_WRITE, code[dom_literal.end:render.start]):
                    continue
                select_id = dom_literal.value
                mapped = re.search(r'\$\{'+re.escape(data)+r'((?:\.'+_ID+r')*)\.map\(\s*('+_ID+r')\s*=>\s*`([^`]*)`\s*\)\.join\(\s*(["\'])\4\s*\)\s*\}', render.value)
                if mapped is None:
                    continue
                field = re.search(r'<option\b[^>]*\bvalue\s*=\s*(["\'])\$\{'+re.escape(mapped[2])+r'\.('+_ID+r')\}\1', mapped[3], re.I)
                if field is None:
                    continue
                for dom_id, handler in handlers.handlers:
                    if dom_id == select_id:
                        for template, target_source in targets.get(handler, ()):
                            results.add(ResponseArgumentBinding(template, source_path, field[2],
                                        tuple(sorted({source,target_source})), tuple(mapped[1].lstrip('.').split('.')) if mapped[1] else ()))
    return sorted(results, key=lambda b:(b.template,b.source_path,b.field,b.collection_path or ()))[:100]
