"""Conservative response-field provenance for dynamic GET arguments.

Recognizes injected services and a joined collection response whose ``find``
comparison ties a field to the argument of another GET service. This is a
bounded lexical pattern, not general JavaScript execution or a taint engine.
"""
from __future__ import annotations

from dataclasses import dataclass
from bisect import bisect_right
import re
from urllib.parse import parse_qsl, quote, urlsplit

from aidast.recon.tools.js_api_paths import _literals, extract_js_api_paths, literal_call_method
from .request_identity import sensitive_field

_ID = r'[A-Za-z_$][\w$]*'
_WRITE = r'(?:\+\+|--|(?:\*\*|<<|>>>?|[+*/%&|^?-])?=(?!=|>))'


def _closing_parenthesis(code, opening):
    depth = 0
    for index in range(opening, len(code)):
        if code[index] == '(':
            depth += 1
        elif code[index] == ')':
            depth -= 1
            if depth == 0:
                return index
    return None


def _preserving_service_return(code):
    returned = re.search(r'\breturn\s+(?:'+_ID+r'\.)+get\s*\(', code)
    if returned is None:
        return False
    closing = _closing_parenthesis(code, returned.end()-1)
    if closing is None:
        return False
    tail = code[closing+1:].strip().rstrip(';').strip()
    if not tail:
        return True
    pipe = re.match(r'\.pipe\s*\(', tail)
    if pipe is None:
        return False
    end = _closing_parenthesis(tail, pipe.end()-1)
    if end != len(tail)-1:
        return False
    operators = tail[pipe.end():end]
    index = 0
    while index < len(operators):
        operator = re.match(r'\s*'+_ID+r'\s*\(', operators[index:])
        if operator is None:
            return False
        opening = index+operator.end()-1
        closing = _closing_parenthesis(operators, opening)
        if closing is None:
            return False
        arrow = operators[opening+1:closing].strip()
        pattern = r'(?:('+_ID+r')|\(\s*('+_ID+r')\s*\))\s*=>\s*'
        match = re.match(pattern, arrow)
        if match is None:
            return False
        parameter = match.group(1) or match.group(2)
        expression = arrow[match.end():].strip()
        if not (expression in {parameter, parameter+'.data'}
                or re.fullmatch(r'\{\s*throw\s+'+re.escape(parameter)+r'\s*;?\s*\}', expression)):
            return False
        index = closing+1
        remainder = operators[index:].lstrip()
        if not remainder:
            return True
        if not remainder.startswith(','):
            return False
        index = len(operators)-len(remainder)+1
    return False


@dataclass(frozen=True)
class ResponseArgumentBinding:
    template: str
    source_path: str
    field: str
    source_scripts: tuple[str, ...]
    collection_path: tuple[str, ...] | None = None


def _structure(script: str):
    pieces = []
    cursor = 0
    for literal in _literals(script):
        pieces.extend((script[cursor:literal.start], ' ' * (literal.end-literal.start)))
        cursor = literal.end
    pieces.append(script[cursor:])
    code = ''.join(pieces)
    stack = []
    ends = {}
    parents = {}
    for index, char in enumerate(code):
        if char == '{':
            parents[index] = stack[-1] if stack else None
            stack.append(index)
        elif char == '}' and stack:
            ends[stack.pop()] = index
    return code, ends, parents


def _classes(script: str):
    code, ends, parents = _structure(script)
    openings = sorted(parents)

    def owner_at(position):
        offset = bisect_right(openings, position)-1
        owner = openings[offset] if offset >= 0 else None
        while owner is not None and ends.get(owner, -1) < position:
            owner = parents.get(owner)
        return owner

    declarations = {}
    declaration_pattern = re.compile(r'\bfunction\s+('+_ID+r')\s*\(|(?<![\w$.])('+_ID+r')\s*=(?!=|>)')
    for declaration in declaration_pattern.finditer(code):
        name = declaration.group(1) or declaration.group(2)
        canonical = not declaration.group(1) and bool(re.match(r'\s*\(\s*\(\s*\)\s*=>', code[declaration.end():declaration.end()+50]))
        declarations.setdefault(name, []).append((owner_at(declaration.start()), canonical))
    for match in re.finditer(r'\bclass(?:\s+('+_ID+r'))?\s*\{', code):
        start = match.end()-1
        end = ends.get(start)
        if end is None:
            continue
        ancestor = parents.get(start)
        enclosing_scopes = {None, ancestor}
        shadowed_scope = False
        while ancestor is not None:
            header = code[max(0, ancestor-256):ancestor]
            params = re.search(r'(?:\bfunction\s*\*?\s*'+_ID+r'?\s*)?\(([^()]*)\)\s*(?:=>\s*)?$', header)
            bare_arrow = re.search(r'\b('+_ID+r')\s*=>\s*$', header)
            if (params and params.group(1).strip()) or bare_arrow:
                shadowed_scope = True
                break
            ancestor = parents.get(ancestor)
            enclosing_scopes.add(ancestor)
        if shadowed_scope:
            continue
        outer = re.search(r'('+_ID+r')\s*=\s*\(\s*\(\s*\)\s*=>\s*\{\s*$', code[max(0, match.start()-160):match.start()])
        token = outer.group(1) if outer else match.group(1)
        methods = []
        index = start+1
        while index < end:
            if code[index] == '{' and index in ends:
                signature = re.search(r'('+_ID+r')\s*\(\s*([^()]*)\s*\)\s*$', code[max(start+1,index-256):index])
                if signature:
                    params = signature.group(2).strip()
                    if not params or re.fullmatch(_ID+r'(?:\s*,\s*'+_ID+r')*', params):
                        methods.append((signature.group(1), params.split(',')[0].strip(), index, ends[index]))
                index = ends[index]+1
            else:
                index += 1
        preamble_end = methods[0][2] if methods else end
        # Drop the first method signature; retain class field declarations.
        if methods:
            signature = re.search(r'('+_ID+r')\s*\([^()]*\)\s*$', code[start+1:preamble_end])
            preamble_end = start+1+signature.start() if signature else preamble_end
        preamble = script[start+1:preamble_end]
        injections = {}
        for injection in re.finditer(r'\b('+_ID+r')\s*=\s*(inject|h(?:\$\d+)?)\(\s*('+_ID+r')\s*\)', code[start+1:preamble_end]):
            receiver, factory, service = injection.groups()
            factory_override = any(owner in enclosing_scopes for owner, _ in declarations.get(factory, []))
            service_override = any(owner in enclosing_scopes and not canonical for owner, canonical in declarations.get(service, []))
            if not factory_override and not service_override:
                injections.setdefault(receiver, set()).add(service)
        for receiver in list(injections):
            if (len(re.findall(r'\b'+re.escape(receiver)+r'\s*=', code[start+1:preamble_end])) != 1
                    or any(re.search(r'\bthis\.'+re.escape(receiver)+r'\s*'+_WRITE, code[a+1:b]) for _, _, a, b in methods)):
                del injections[receiver]
        yield token, preamble, injections, methods, code, script, ends


def extract_response_argument_bindings(scripts: dict[str, str]) -> list[ResponseArgumentBinding]:
    """No target-specific routes or field names are supplied to this analysis."""
    classes = []
    definitions = {}
    for script_url, script in scripts.items():
        for token, preamble, injections, methods, code, original, ends in _classes(script):
            classes.append((script_url, injections, methods, code, ends))
            if not token:
                continue
            for method, param, start, end in methods:
                method_code = code[start+1:end]
                if not _preserving_service_return(method_code):
                    continue
                if param and (re.search(r'\b'+re.escape(param)+r'\s*'+_WRITE, method_code)
                              or re.search(r'(?:\+\+|--)\s*\b'+re.escape(param)+r'\b', method_code)):
                    continue
                synthetic = 'class Service{'+preamble+method+'('+param+'){'+original[start+1:end]+'}}'
                paths = [(path, verb) for path, verb in extract_js_api_paths(synthetic, literal_call_method) if verb == 'GET']
                if len(paths) != 1:
                    continue
                path = paths[0][0]
                if '${' in path and (not param or path.count('${') != 1 or '${'+param+'}' not in path):
                    continue
                definitions.setdefault((token, method), set()).add((path, script_url))

    def resolve(injections, receiver, method):
        tokens = injections.get(receiver, set())
        if len(tokens) != 1:
            return None
        options = definitions.get((next(iter(tokens)), method), set())
        paths = {path for path, _ in options}
        if len(paths) != 1:
            return None
        return next(iter(paths)), {url for _, url in options}

    results = set()
    subscribe = re.compile(r'\.subscribe\s*\(\s*\(\s*\{([^{}]*)\}\s*\)\s*=>\s*\{')
    for script_url, injections, methods, code, ends in classes:
        for _, _, start, end in methods:
            body = code[start+1:end]
            for subscription in subscribe.finditer(body):
                callback_start = start+1+subscription.end()-1
                callback_end = ends.get(callback_start)
                if callback_end is None or callback_end-callback_start > 8192:
                    continue
                aliases = re.findall(r'('+_ID+r')\s*:\s*('+_ID+r')', subscription.group(1))
                absolute_subscription = start+1+subscription.start()
                statement_start = max(start+1, absolute_subscription-4096)
                statement_start = max(statement_start, code.rfind(';', statement_start, absolute_subscription)+1)
                statement = code[statement_start:absolute_subscription]
                joined_objects = []
                for joined in re.finditer(r'(?<![\w$.])'+_ID+r'\s*\(\s*\{', statement):
                    opening = statement_start+joined.end()-1
                    closing = ends.get(opening)
                    if closing is not None and closing < absolute_subscription:
                        suffix = code[closing+1:absolute_subscription].strip()
                        direct = re.fullmatch(r'\)+', suffix)
                        # Angular's compiled switch-map join followed by
                        # lifecycle cleanup; no response projection is supported.
                        lifecycle = ('.pipe(' in statement[:joined.start()]
                                     and re.fullmatch(r'\)+\s*,\s*'+_ID+r'\(\s*this\.destroyRef\s*\)\s*\)', suffix))
                        if direct or lifecycle:
                            joined_objects.append(code[opening+1:closing])
                after = code[callback_start+1:callback_end]
                if re.search(r'\bfunction\b', after):
                    continue
                for label, alias in aliases:
                    if (re.search(r'\b'+re.escape(alias)+r'\s*'+_WRITE, after)
                            or re.search(r'\b(?:let|const|var)\s+'+re.escape(alias)+r'\b', after)
                            or re.search(r'\b'+re.escape(alias)+r'\s*=>|\([^()]*\b'+re.escape(alias)+r'\b[^()]*\)\s*=>', after)):
                        continue
                    source_pattern = r'\b'+re.escape(label)+r'\s*:\s*this\.('+_ID+r')\.('+_ID+r')\s*\([^()]*\)\s*(?=,|$)'
                    contexts = [(context, re.findall(source_pattern, context)) for context in joined_objects]
                    contexts = [(context, calls) for context, calls in contexts if calls]
                    if len(contexts) != 1 or len(set(contexts[0][1])) != 1:
                        continue
                    before, source_calls = contexts[0]
                    source = resolve(injections, *source_calls[0])
                    if source is None or '${' in urlsplit(source[0]).path:
                        continue
                    comparison = re.compile(r'\b'+re.escape(alias)+r'\.find\s*\(\s*('+_ID+r')\s*=>\s*\1\.('+_ID+r')\s*===\s*this\.('+_ID+r')\s*\)')
                    for link in comparison.finditer(after):
                        field, argument = link.group(2), link.group(3)
                        if re.search(r'\bthis\.'+re.escape(argument)+r'\s*'+_WRITE, after[:link.end()]):
                            continue
                        calls = re.findall(r'\bthis\.('+_ID+r')\.('+_ID+r')\s*\(\s*this\.'+re.escape(argument)+r'\s*\)', before)
                        for receiver, method in calls:
                            target = resolve(injections, receiver, method)
                            if target is None or '${' not in target[0]:
                                continue
                            sources = tuple(sorted({script_url} | source[1] | target[1]))
                            results.add(ResponseArgumentBinding(target[0], source[0], field, sources))
    return sorted(results, key=lambda binding: (binding.template, binding.source_path, binding.field, binding.source_scripts))[:100]


def source_request_matches(source_path: str, source_url: str) -> bool:
    """Match literal path/query constraints against the observed GET URL."""
    try:
        actual, expected = urlsplit(source_url), urlsplit(source_path)
        if '${' in expected.path or actual.path.rstrip('/') != expected.path.rstrip('/'):
            return False
        if expected.netloc and (actual.scheme, actual.netloc) != (expected.scheme, expected.netloc):
            return False
        if not expected.query:
            return True
        expected_query = parse_qsl(expected.query, keep_blank_values=True)
        actual_query = parse_qsl(actual.query, keep_blank_values=True)
        if len(expected_query) != len(actual_query):
            return False
        expected_query.sort(key=lambda pair: pair[0])
        actual_query.sort(key=lambda pair: pair[0])
        for (key, value), (actual_key, actual_value) in zip(expected_query, actual_query):
            if key != actual_key or sensitive_field(key):
                return False
            if '${' in value:
                if not re.fullmatch(r'\$\{[\w.$]+\}', value) or not actual_value or len(actual_value) > 256:
                    return False
                if any(ord(c) < 32 or ord(c) == 127 for c in actual_value):
                    return False
            elif actual_value != value:
                return False
        return True
    except (ValueError, TypeError):
        return False


def bind_response_values(binding: ResponseArgumentBinding, source_url: str, payload, *, limit: int = 3) -> list[str]:
    """Use actual collection values; quote them as one complete URL segment."""
    if (limit <= 0 or sensitive_field(binding.field) or any(sensitive_field(k) for k in (binding.collection_path or ()))
            or not source_request_matches(binding.source_path, source_url)):
        return []
    if binding.collection_path is None:
        rows = payload.get('data') if isinstance(payload, dict) else payload
    else:
        rows = payload
        for field in binding.collection_path:
            rows = rows.get(field) if isinstance(rows, dict) else None
    if not isinstance(rows, list):
        return []
    paths = []
    for row in rows[:100]:
        value = row.get(binding.field) if isinstance(row, dict) else None
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            continue
        value = str(value)
        if not value or len(value) > 256 or value in {'.', '..'} or any(ord(c)<32 or ord(c)==127 for c in value):
            continue
        path = re.sub(r'\$\{[^{}]+\}', lambda _: quote(value, safe=''), binding.template, count=1)
        if path not in paths:
            paths.append(path)
        if len(paths) >= max(0, limit):
            break
    return paths
