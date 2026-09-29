"""Static JS URL fragments, without evaluating code or guessing path values.

Recognizes quoted literals, origin-prefixed templates and class-local URL bases.
Unresolved path expressions remain templates for subsequent evidence-based binding.
This is a small lexical analyzer, not a general JavaScript interpreter.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

_IDENTIFIER = re.compile(r'[A-Za-z_$][\w$]*')

@dataclass(frozen=True)
class _Literal:
    start: int
    end: int
    value: str | None


def _quoted_end(script: str, start: int, depth: int = 0) -> int | None:
    """Keep nested template expressions inside their enclosing string."""
    if depth > 32:
        return None
    quote = script[start]
    index = start + 1
    while index < len(script):
        if script[index] == "\\":
            index += 2
        elif script[index] == quote:
            return index + 1
        elif quote == '`' and script.startswith('${', index):
            index += 2
            braces = 1
            regex_allowed = True
            while index < len(script) and braces:
                if script.startswith(('//', '/*'), index):
                    line = script.startswith('//', index)
                    end = script.find('\n' if line else '*/', index + 2)
                    if end < 0:
                        return None
                    index = end + (1 if line else 2)
                elif script[index] in "\"'`":
                    end = _quoted_end(script, index, depth + 1)
                    if end is None:
                        return None
                    index = end
                    regex_allowed = False
                elif script[index] == '/' and regex_allowed:
                    index += 1
                    character_class = False
                    while index < len(script):
                        char = script[index]
                        if char == '\\':
                            index += 2
                            continue
                        if char == '[':
                            character_class = True
                        elif char == ']':
                            character_class = False
                        elif char == '/' and not character_class:
                            index += 1
                            while index < len(script) and script[index].isalpha():
                                index += 1
                            break
                        elif char in '\r\n':
                            return None
                        index += 1
                    regex_allowed = False
                elif token := _IDENTIFIER.match(script, index):
                    regex_allowed = token[0] in {'return','throw','case','void','typeof','delete','yield','await','new'}
                    index += len(token[0])
                else:
                    braces += (script[index] == '{') - (script[index] == '}')
                    if not script[index].isspace():
                        regex_allowed = script[index] in "([{=,:;!?&|+-*%^~/"
                    index += 1
            if braces:
                return None
        else:
            index += 1
    return None


def _literals(script: str) -> list[_Literal]:
    """Single-pass scanner; unterminated/escaped strings cannot backtrack."""
    result = []
    index = 0
    regex_allowed = True
    identifier = re.compile(r"[A-Za-z_$][\w$]*")
    while index < len(script):
        start = index
        if script.startswith("//", index):
            end = script.find("\n", index + 2)
            index = len(script) if end < 0 else end
            result.append(_Literal(start, index, None))
        elif script.startswith("/*", index):
            end = script.find("*/", index + 2)
            index = len(script) if end < 0 else end + 2
            result.append(_Literal(start, index, None))
        elif script[index] == "/" and regex_allowed:
            index += 1
            in_character_class = False
            while index < len(script):
                char = script[index]
                if char == "\\":
                    index += 2
                    continue
                if char == "[":
                    in_character_class = True
                elif char == "]":
                    in_character_class = False
                elif char == "/" and not in_character_class:
                    index += 1
                    while index < len(script) and script[index].isalpha():
                        index += 1
                    break
                elif char in "\r\n":
                    break
                index += 1
            result.append(_Literal(start, index, None))
            regex_allowed = False
        elif script[index] in "\"'`":
            regex_allowed = False
            end = _quoted_end(script, index)
            if end is not None:
                result.append(_Literal(start, end, script[start + 1:end - 1]))
                index = end
            else:
                result.append(_Literal(start, len(script), None))
                index = len(script)
        elif script[index].isspace():
            index += 1
        elif token := identifier.match(script, index):
            regex_allowed = token.group() in {"return", "throw", "case", "void", "typeof", "delete", "yield", "await", "new"}
            index = token.end()
        else:
            regex_allowed = script[index] in "([{=,:;!?&|+-*%^~/"
            index += 1
    return result


def extract_js_module_references(script: str) -> list[str]:
    """Literal JS assets in imports and assigned dependency tables, in order.

    The caller resolves relative URLs and enforces origin, policy and graph
    limits. Comments, regexes and unresolved template values are excluded.
    """
    references = []
    seen = set()
    literals = _literals(script)
    http_arguments = _http_argument_methods(script, literals)
    skips = {literal.start: literal for literal in literals}
    array_positions = set()
    arrays: list[bool] = []
    index = 0
    while index < len(script):
        literal = skips.get(index)
        if literal is not None:
            if arrays and arrays[-1]:
                array_positions.add(index)
            index = literal.end
            continue
        if script[index] == '[':
            prefix = _without_comments(script[max(0, index - 256):index])
            named = re.search(r'\b[\w$]*(?:deps|dependencies|chunks|modules|files)\s*=\s*$', prefix, re.I)
            vite = '__vite__mapDeps' in prefix and re.search(r'\b[\w$]+\.f\s*=\s*$', prefix)
            arrays.append(bool((arrays and arrays[-1]) or named or vite))
        elif script[index] == ']' and arrays:
            arrays.pop()
        index += 1
    for literal in literals:
        value = literal.value
        if (not value or len(value) > 2048 or '${' in value or '\\' in value
                or any(char.isspace() for char in value)):
            continue
        try:
            parsed = urlsplit(value)
        except ValueError:
            continue
        if (parsed.username or parsed.password
                or not parsed.path.lower().endswith(('.js', '.mjs'))):
            continue
        if literal.start in http_arguments or literal_call_method(script, literal.start, literal.end) is not None:
            continue
        prefix = _without_comments(script[max(0, literal.start - 256):literal.start])
        imported = re.search(r'\bimport\s*(?:\(\s*)?$', prefix) or re.search(
            r'\b(?:import|export)\b[^;()]*\bfrom\s*$|\}\s*from\s*$', prefix)
        worker = re.search(r'\bnew\s+(?:Worker|SharedWorker)\s*\(\s*(?:new\s+URL\s*\(\s*)?$', prefix)
        if not (imported or worker or literal.start in array_positions):
            continue
        if value not in seen:
            references.append(value)
            seen.add(value)
    return references


def _http_argument_methods(script: str, literals: list[_Literal]) -> dict[int, str]:
    """Mark strings inside known HTTP arguments, including nested URL wrappers."""
    skips = {literal.start: literal for literal in literals}
    call_pattern = re.compile(
        r'(?:\.\s*(?P<dot>get|post|put|patch|delete|head|options)'
        r'|\[\s*[\"\'](?P<bracket>get|post|put|patch|delete|head|options)[\"\']\s*\]'
        r'|\b(?P<fetch>fetch))\s*$', re.I)
    stack: list[str | None] = []
    methods = {}
    index = 0
    while index < len(script):
        literal = skips.get(index)
        if literal is not None:
            if stack and stack[-1] is not None:
                methods[index] = stack[-1]
            index = literal.end
            continue
        if script[index] == '(':
            prefix = script[max(0, index - 160):index]
            call = call_pattern.search(prefix)
            if call is None and ('/*' in prefix or '//' in prefix):
                call = call_pattern.search(_without_comments(prefix))
            method = ((call.group('dot') or call.group('bracket') or 'UNKNOWN').upper()
                      if call else stack[-1] if stack else None)
            stack.append(method)
        elif script[index] == ')' and stack:
            stack.pop()
        index += 1
    return methods


_CLASS = re.compile(r'\bclass(?:\s+[\w$]+)?(?:\s+extends\s+[\w.$]+)?\s*$')
_PROPERTY = re.compile(r'(?:^|[;{},])\s*(?P<receiver>this\.)?(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?:[\w.$]+\s*\+\s*)?$')
_CONCAT = re.compile(r'\.\s*(?:get|post|put|patch|delete|head|options)\s*\(\s*this\.(?P<name>[\w$]+)\s*\+\s*$', re.I)
_INTERPOLATION = re.compile(r'\$\{([^{}]+)\}')
_API = re.compile(r'^/(?:api|rest)(?:/|$)', re.I)


def _literal_scopes(script: str, literals: list[_Literal]) -> dict:
    skips = {match.start: match.end for match in literals}
    stack: list[int | None] = []
    classes: list[tuple[int, int]] = []
    ends = {}
    positions = {}
    index = 0
    while index < len(script):
        if index in skips:
            if classes:
                positions[index] = (classes[-1][0], len(stack) - classes[-1][1])
            index = skips[index]
            continue
        char = script[index]
        if char == '{':
            start = index + 1 if _CLASS.search(script[max(0, index - 160):index]) else None
            stack.append(start)
            if start is not None:
                classes.append((start, len(stack)))
        elif char == '}' and stack:
            start = stack.pop()
            if start is not None:
                ends[start] = index
                classes.pop()
        index += 1
    return {position: ((start, ends[start]), depth)
            for position, (start, depth) in positions.items() if start in ends}


def _without_comments(text: str) -> str:
    parts = []
    previous = 0
    for token in _literals(text):
        if token.value is None:
            parts.append(text[previous:token.start])
            parts.append(" ")
            previous = token.end
    parts.append(text[previous:])
    return "".join(parts)


def _skip_trivia(script: str, index: int) -> int:
    while index < len(script):
        if script[index].isspace():
            index += 1
        elif script.startswith("/*", index):
            end = script.find("*/", index + 2)
            index = len(script) if end < 0 else end + 2
        elif script.startswith("//", index):
            end = script.find("\n", index + 2)
            index = len(script) if end < 0 else end
        else:
            break
    return index


def literal_call_method(script: str, start: int, end: int) -> str | None:
    prefix = _without_comments(script[max(0, start - 160):start])
    methods = "get|post|put|patch|delete|head|options"
    call = re.search(
        rf"(?:\.\s*(?P<dot>{methods})|\[\s*['\"](?P<bracket>{methods})['\"]\s*\])"
        r"\s*\(\s*(?:\(\s*)*(?:[\w.$]+\s*\+\s*)?$", prefix, re.I,
    )
    if call:
        return (call.group("dot") or call.group("bracket")).upper()
    fetch = re.search(r"\bfetch\s*\((?P<wrappers>(?:\s*\()*)\s*$", prefix)
    if fetch is None:
        return None
    # Common one-argument calls need no scan of the following bundle text.
    cursor = _skip_trivia(script, end)
    for _ in range(fetch.group("wrappers").count("(")):
        if cursor >= len(script) or script[cursor] != ")":
            return "UNKNOWN"
        cursor = _skip_trivia(script, cursor + 1)
    if cursor < len(script) and script[cursor] == ")":
        return "GET"
    if cursor >= len(script) or script[cursor] != ",":
        return "UNKNOWN"
    tail = _without_comments(script[cursor:cursor + 4096])
    options = tail[1:].lstrip()
    if not options.startswith("{"):
        return "UNKNOWN"
    skips = {token.start: token.end for token in _literals(options)}
    depth = 1
    index = field_start = 1
    fields = []
    while index < len(options) and depth:
        if index in skips:
            index = skips[index]
            continue
        char = options[index]
        if char in "{[(":
            depth += 1
        elif char in "}])":
            depth -= 1
            if depth == 0:
                fields.append(options[field_start:index])
        elif char == ',' and depth == 1:
            fields.append(options[field_start:index])
            field_start = index + 1
        index += 1
    if depth:
        return "UNKNOWN"
    method = "GET"
    for field in fields:
        field = field.strip()
        if not field:
            continue
        key = re.match(r"(?:([\w$]+)|['\"]([\w$]+)['\"])\s*:", field)
        if key is None:
            return "UNKNOWN"
        if (key.group(1) or key.group(2)) == "method":
            value = re.fullmatch(r"\s*(['\"])([A-Za-z]+)\1\s*", field[key.end():])
            if value is None:
                return "UNKNOWN"
            method = value.group(2).upper()
    return method


def _join_static_literals(script: str, literals: list[_Literal]) -> list[_Literal]:
    """Fold adjacent string literals, preserving source coordinates for GET evidence."""
    at = {literal.start: index for index, literal in enumerate(literals)}
    direct_argument = re.compile(
        r'(?:\.\s*(?:get|post|put|patch|delete|head|options)'
        r'|\[\s*[\"\'](?:get|post|put|patch|delete|head|options)[\"\']\s*\]'
        r'|\bfetch)\s*\(\s*$', re.I)
    assignment = re.compile(r'(?:^|[;{},])\s*(?:this\.)?[A-Za-z_$][\w$]*\s*=\s*$')
    result = []
    index = 0
    while index < len(literals):
        first = literals[index]
        last_index = index
        value = first.value
        parts = [value]
        if value is not None and '${' not in value:
            while True:
                cursor = _skip_trivia(script, literals[last_index].end)
                if cursor >= len(script) or script[cursor] != '+':
                    break
                next_index = at.get(_skip_trivia(script, cursor + 1))
                if next_index is None:
                    break
                next_value = literals[next_index].value
                if next_value is None or '${' in next_value:
                    break
                parts.append(next_value)
                last_index = next_index
        if last_index == index:
            result.append(first)
            index += 1
            continue
        cursor = _skip_trivia(script, literals[last_index].end)
        prefix = _without_comments(script[max(0, first.start - 160):first.start])
        whole_argument = (direct_argument.search(prefix) or _CONCAT.search(prefix)) and (
            cursor < len(script) and script[cursor] in ',)')
        whole_assignment = assignment.search(prefix) and (
            cursor == len(script) or script[cursor] in ';},')
        if whole_argument or whole_assignment:
            result.append(_Literal(first.start, literals[last_index].end, ''.join(parts)))
        else:
            # Preserve unresolved expressions without rescanning every suffix.
            result.extend(literals[index:last_index + 1])
        index = last_index + 1
    return result


def extract_js_api_paths(
    script: str, method_at: Callable[[str, int, int], str | None],
    *, location_callback: Callable[[str, str | None, int, int], None] | None = None,
    include_class_get_anchors: bool = False,
) -> list[tuple[str, str | None]]:
    """Return path expressions and their HTTP method evidence in source order."""
    literals = _join_static_literals(script, _literals(script))
    http_arguments = _http_argument_methods(script, literals)
    scopes = _literal_scopes(script, literals)

    def scope_at(position: int) -> tuple[int, int] | None:
        info = scopes.get(position)
        return info[0] if info is not None else None

    # Distinct classes often use the same property name for different APIs.
    # Resolve only an unambiguous base inside the enclosing class.
    bases: dict[tuple[tuple[int, int], str], set[str | None]] = {}
    for match in literals:
        value = match.value
        if value is None:
            continue
        scope = scope_at(match.start)
        assignment = _PROPERTY.search(script[max(0, match.start - 160):match.start])
        if scope is not None and assignment:
            nesting = scopes[match.start][1]
            if assignment.group('receiver') or nesting == 0:
                cursor = _skip_trivia(script, match.end)
                continuation = script[cursor:cursor + 1]
                newline = '\n' in script[match.end:cursor] or '\r' in script[match.end:cursor]
                complete = '${' not in value and (
                    not continuation or continuation in ';},)'
                    or (newline and continuation not in '+-*/%?.[&|^=<>!:'))
                bases.setdefault((scope, assignment.group('name')), set()).add(value if complete else None)

    def resolve_base(scope, name: str) -> str | None:
        values = bases.get((scope, name), set())
        return next(iter(values)) if len(values) == 1 else None

    results = []
    for match in literals:
        value = match.value
        if value is None:
            continue
        method = method_at(script, match.start, match.end)
        if method is None:
            enclosing_method = http_arguments.get(match.start)
            if enclosing_method not in {None, "GET"}:
                method = enclosing_method
        scope = scope_at(match.start)
        concat = _CONCAT.search(script[max(0, match.start - 160):match.start])
        if concat:
            base = resolve_base(scope, concat.group('name'))
            if base is not None:
                value = base + value
            elif not _API.match(value):
                continue
        if value.startswith('${'):
            leading = _INTERPOLATION.match(value)
            if leading is None:
                continue
            expression = leading.group(1).strip()
            base = resolve_base(scope, expression.removeprefix('this.')) if expression.startswith('this.') else None
            remainder = value[leading.end():]
            if base is not None:
                value = base + remainder
            elif _API.match(remainder) or (method == 'GET' and remainder.startswith('/')):
                if expression.startswith('this.') and (scope, expression.removeprefix('this.')) in bases:
                    continue
                if not re.fullmatch(r'[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*', expression):
                    continue
                # The leading expression is an origin prefix; never send it as
                # a host. The caller still restricts candidates to its origin.
                value = remainder
            else:
                continue
        value = value.replace('\\/', '/')
        api_path = bool(_API.match(value))
        # Keep unresolved GET arguments as templates, never as request URLs.
        # Only a whole segment containing a simple variable/member is supported.
        path_segments = value.split('?', 1)[0].split('/')
        supported_segments = all(
            not any(char in segment for char in '{}')
            or re.fullmatch(r'\$\{[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\}', segment)
            for segment in path_segments
        )
        explicit_path = (method == 'GET' and value.startswith('/') and not value.startswith('//')
                         and not any(char.isspace() or ord(char) < 32 for char in value)
                         and supported_segments
                         and script.startswith((')', ','), _skip_trivia(script, match.end)))
        if (api_path or explicit_path) and len(value) <= 512 and '\\' not in value:
            results.append((value, method))
            if location_callback is not None:
                location_callback(value, method, match.start, match.end)
    # Model-only source anchors must not reorder the existing collector's
    # bounded detail jobs. Callers opt in when building model evidence.
    if not include_class_get_anchors:
        return results
    # A literal class field can also be the complete GET argument. Preserve
    # the actual argument's range; never reinterpret a property declaration
    # or a commented/POST call as GET evidence.
    pieces=[];cursor=0
    for token in literals:
        pieces.extend((script[cursor:token.start],' '*(token.end-token.start)))
        cursor=token.end
    pieces.append(script[cursor:]);code=''.join(pieces)
    class_scopes={info[0] for info in scopes.values()}
    direct=re.compile(r'\.\s*get\s*\(\s*(?P<argument>this\.(?P<name>[A-Za-z_$][\w$]*))\s*\)',re.I)
    for match in direct.finditer(code):
        owners=[owner for owner in class_scopes if owner[0]<=match.start()<owner[1]]
        if not owners:
            continue
        owner=min(owners,key=lambda s:s[1]-s[0]);name=match['name']
        # A class interval is not a proof of `this`: static methods and nested
        # ordinary functions use another receiver. Fail closed for those scopes.
        stack=[]
        for position in range(owner[0]-1,match.start()):
            if code[position]=='{':
                stack.append(position)
            elif code[position]=='}' and stack:
                stack.pop()
        method_seen=False;wrong_receiver=False
        for opening in stack[1:]:
            prefix=code[max(owner[0],opening-256):opening]
            if re.search(r'\bfunction\s*\*?(?:\s*[\w$]+)?\s*\([^()]*\)\s*$',prefix):
                wrong_receiver=True;break
            method_header=re.search(r'(?:^|[;{}])\s*(?P<static>static\s+)?(?:async\s+)?[\w$]+\s*\([^()]*\)\s*$',prefix)
            if method_header:
                if method_seen or method_header['static']:
                    wrong_receiver=True;break
                method_seen=True
        if wrong_receiver or not method_seen:
            continue
        base=resolve_base(owner,name)
        if (not isinstance(base,str) or not base.startswith('/') or base.startswith('//')
                or len(base)>512 or any(c.isspace() or c in '{}\\' or ord(c)<32 for c in base)):
            continue
        receiver=r'\bthis\s*(?:\.\s*'+re.escape(name)+r'\b|\[[^\]]+\])'
        mutation=r'(?:\+\+|--|(?:\*\*|<<|>>>?|&&|\|\||\?\?|[+*/%&|^?-])?=(?!=|>))'
        body=code[owner[0]:owner[1]]
        # Receiver assignments can depend on arguments or arbitrary calls.
        # Only class field declarations (without this.) are resolved here.
        if (re.search(receiver+r'\s*'+mutation,body) or re.search(r'\bdelete\s+'+receiver,body)
                or re.search(r'(?:\+\+|--)\s*'+receiver,body)
                or re.search(r'\[[^;{}]*'+receiver+r'[^;{}]*\]\s*=',body)):
            continue
        results.append((base,'GET'))
        if location_callback is not None:
            location_callback(base,'GET',match.start('argument'),match.end('argument'))
    return results
