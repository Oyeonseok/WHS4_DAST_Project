"""Bounded original JS regions connected by lexical names, not proven data flow."""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from html.parser import HTMLParser
import re

from .js_argument_bindings import _structure
from .js_api_paths import _literals

_ID = r'[A-Za-z_$][\w$]*'
_CALL = re.compile(r'(?<![\w$])('+_ID+r')\s*\(')
_CONTROL = {'if','for','while','switch','catch','with'}
_HEADER = re.compile(
    r'\b(?:async\s+)?function\s+(?P<function>'+_ID+r')\s*\([^()]*\)\s*\{'
    r'|(?<![\w$])(?P<arrow>'+_ID+r')\s*=\s*(?:async\s*)?(?:\([^()]*\)|'+_ID+r')\s*=>\s*'
    r'|(?<![\w$])(?P<method>'+_ID+r')\s*\([^()]*\)\s*\{')


class DocumentScripts(HTMLParser):
    """Only executable inline JS and event attributes; never forward HTML bodies."""
    def __init__(self, *, include_event_handlers=True):
        super().__init__(convert_charrefs=False)
        self.items = []
        self.active = None
        self.include_event_handlers = include_event_handlers

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == 'script':
            media = (values.get('type') or '').strip().lower()
            self.active = [] if not values.get('src') and media in {
                '', 'module', 'text/javascript', 'application/javascript'} else None
        for name, value in attrs:
            if self.include_event_handlers and name.startswith('on') and len(name)<=64 and len(tag)<=64 and value and len(value) <= 4000 and len(self.items)<40:
                dom_id=values.get('id') or ''
                self.items.append({'text':value,'kind':'event_handler','event':name,
                                   'dom_id':dom_id if len(dom_id)<=256 else '', 'tag':tag})

    def handle_data(self, data):
        if self.active is not None:
            self.active.append(data)

    def handle_endtag(self, tag):
        if tag == 'script' and self.active is not None:
            text = ''.join(self.active)
            if text.strip() and len(text)<=100_000 and len(self.items)<40:
                self.items.append({'text':text,'kind':'inline_script'})
            self.active = None


@dataclass(frozen=True)
class Region:
    url: str
    start: int
    end: int
    name: str
    kind: str


def _expression_end(code, start):
    stack = []
    for index in range(start, min(len(code),start+12_000)):
        char = code[index]
        if char in '([{':
            stack.append(char)
        elif char in ')]}':
            if not stack:
                return index
            stack.pop()
        elif not stack and char in ';,\n':
            return index
    return min(len(code),start+12_000)


class SourceRegions:
    """Indexes context candidates. Ambiguous names never establish cross-script edges."""
    def __init__(self, scripts, metadata):
        self.regions = []
        self.calls = {}
        self.names = defaultdict(list)
        self.classes = defaultdict(list)
        self.codes = {}
        self.dom_regions = defaultdict(list)
        self.metadata = metadata
        for url, script in scripts.items():
            code, ends, _ = _structure(script)
            self.codes[url] = code
            for opening, end in ends.items():
                header_start=max(0,opening-160)
                header=re.search(r'\bclass(?:\s+'+_ID+r')?(?:\s+extends\s+[\w.$]+)?\s*$',code[header_start:opening])
                if header:
                    self.classes[url].append(Region(url,header_start+header.start(),end+1,'','class_context'))
            for match in _HEADER.finditer(code):
                if len(self.regions)>=20_000:
                    break
                name = match['function'] or match['arrow'] or match['method']
                if name in _CONTROL:
                    continue
                body = match.end()
                if match['arrow']:
                    while body<len(code) and code[body].isspace():
                        body+=1
                    end = ends.get(body) if body<len(code) and code[body]=='{' else _expression_end(code,body)
                else:
                    end = ends.get(body-1)
                if end is None:
                    continue
                region = Region(url,match.start(),min(len(script),end+1),name,'function_context')
                self.regions.append(region)
                self.names[name].append(region)
                self.calls[region] = set(_CALL.findall(code[body:min(end,body+12_000)]))
                if len(self.regions)>=20_000:
                    break
            if metadata.get(url,{}).get('kind')=='event_handler':
                region=Region(url,0,len(script),'','event_handler')
                self.regions.append(region)
                self.calls[region]=set(_CALL.findall(code))
            elif metadata.get(url,{}).get('kind')=='inline_script':
                region=Region(url,0,len(script),'','inline_script')
                self.regions.append(region)
                self.calls[region]=set(_CALL.findall(code))
            for literal in _literals(script):
                if not literal.value or '${' in literal.value:
                    continue
                prefix=code[max(0,literal.start-80):literal.start]
                dom_id=None
                if re.search(r'\bdocument\.getElementById\s*\(\s*$',prefix):
                    dom_id=literal.value
                elif re.search(r'\bdocument\.querySelector\s*\(\s*$',prefix) and re.fullmatch(r'#[\w-]+',literal.value):
                    dom_id=literal.value[1:]
                if dom_id:
                    self.dom_regions[dom_id].extend(r for r in self.regions if r.url==url
                        and r.start<=literal.start and r.end>=literal.end and r.end-r.start<=12_000)
        self.incoming = defaultdict(list)
        for region, calls in self.calls.items():
            for name in calls:
                if len(self.names[name])==1:
                    self.incoming[self.names[name][0]].append(region)

    def related(self, url, start, end):
        containing=[r for r in self.regions if r.url==url and r.start<=start and r.end>=end]
        queue=deque((r,0) for r in sorted(containing,key=lambda r:r.end-r.start)[:2])
        selected=[];seen=set()
        while queue and len(selected)<8:
            region,depth=queue.popleft()
            if region in seen:
                continue
            seen.add(region)
            selected.append(region)
            if depth>=2:
                continue
            neighbors=list(self.incoming.get(region,()))
            dom_id=self.metadata.get(region.url,{}).get('dom_id')
            if dom_id:
                neighbors.extend(self.dom_regions.get(dom_id,()))
            neighbors.extend(self.names[name][0] for name in sorted(self.calls.get(region,()))
                             if len(self.names[name])==1)
            queue.extend((r,depth+1) for r in neighbors[:8])
        owners=[r for r in self.classes[url] if r.start<=start and r.end>=end and r.end-r.start<=12_000]
        return sorted(owners,key=lambda r:r.end-r.start)[:1]+selected
