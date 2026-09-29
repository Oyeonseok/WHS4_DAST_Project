"""Extract declared executable script references without executing document code."""
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit


class _ScriptReferences(HTMLParser):
    def __init__(self, limit: int):
        super().__init__()
        self.base = None
        self.sources = []
        self.limit = limit

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "base" and self.base is None and "href" in values:
            self.base = values["href"] or ""
        if tag != "script" or len(self.sources) >= self.limit:
            return
        kind = (values.get("type") or "").strip().lower()
        if kind not in {"", "module", "text/javascript", "application/javascript",
                        "text/ecmascript", "application/ecmascript"}:
            return
        if values.get("src"):
            self.sources.append(values["src"])


def declared_script_urls(body: str, document_url: str, *, max_references: int = 500) -> list[str]:
    parser = _ScriptReferences(max(0, max_references))
    parser.feed(body)
    try:
        base = urljoin(document_url, parser.base) if parser.base is not None else document_url
    except ValueError:
        return []
    urls = []
    for reference in parser.sources:
        try:
            parsed = urlsplit(urljoin(base, reference))
            if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
                continue
            url = urlunsplit(parsed._replace(fragment=""))
            if url not in urls:
                urls.append(url)
        except ValueError:
            continue
    return urls
