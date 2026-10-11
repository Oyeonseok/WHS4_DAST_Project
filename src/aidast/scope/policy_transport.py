"""Isolated bounded public HTTPS document capture, with DNS-pinned TLS."""
from __future__ import annotations

import http.client
import io
import ipaddress
import queue
import socket
import ssl
import threading
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

from pydantic import AwareDatetime, Field

from aidast.scope.models import ObservedPolicyLink, StrictModel

MAX_RESPONSE_BYTES = 1024 * 1024
MAX_EVIDENCE_CHARS = 120000
TIMEOUT_SECONDS = 15


class PolicyReferenceError(ValueError):
    pass


class CapturedPolicyDocument(StrictModel):
    requested_url: str
    final_url: str
    captured_at: AwareDatetime
    text: str = Field(min_length=1, max_length=MAX_EVIDENCE_CHARS)
    observed_links: list[ObservedPolicyLink] = Field(default_factory=list, max_length=128)


class _DocumentHTML(HTMLParser):
    def __init__(self, url):
        super().__init__(convert_charrefs=True)
        self.url, self.parts, self.links = url, [], []
        self.hidden = 0
        self.anchor = None

    def handle_starttag(self, tag, attrs):
        if tag in {'script', 'style', 'noscript', 'template'}:
            self.hidden += 1
        if self.hidden:
            return
        if tag in {'p', 'div', 'br', 'li', 'h1', 'h2', 'h3', 'tr'}:
            self.parts.append('\n')
        if tag == 'a':
            href = dict(attrs).get('href')
            self.anchor = (href, []) if href and len(self.links) < 128 else None

    def handle_endtag(self, tag):
        if tag in {'script', 'style', 'noscript', 'template'} and self.hidden:
            self.hidden -= 1
        if tag == 'a' and self.anchor:
            href, labels = self.anchor
            destination = urljoin(self.url, href)
            if len(destination) <= 4096:
                self.links.append(ObservedPolicyLink(candidate_id=len(self.links), url=destination,
                    label=' '.join(''.join(labels).split())[:512], source_url=self.url))
            self.anchor = None
        if tag in {'p', 'div', 'li', 'h1', 'h2', 'h3', 'tr'}:
            self.parts.append('\n')

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)
            if self.anchor:
                self.anchor[1].append(data)


def parse_document(body: bytes, content_type: str, url: str) -> tuple[str, list[ObservedPolicyLink]]:
    media = content_type.split(';')[0].strip().lower()
    if media not in {'text/plain', 'text/html', 'application/xhtml+xml'}:
        raise PolicyReferenceError('unsupported document content type')
    # An explicit unsupported charset is a failed capture, never silently garbled evidence.
    charset = 'utf-8'
    for param in content_type.split(';')[1:]:
        key, _, value = param.strip().partition('=')
        if key.lower() == 'charset':
            charset = value.strip('"\' ')
    try:
        decoded = body.decode(charset, errors='strict')
    except (LookupError, UnicodeError) as exc:
        raise PolicyReferenceError('unreadable document encoding') from exc
    if media == 'text/plain':
        text, links = decoded.strip(), []
    else:
        parser = _DocumentHTML(url)
        parser.feed(decoded)
        parser.close()
        text = '\n'.join(' '.join(line.split()) for line in ''.join(parser.parts).splitlines() if line.strip())
        links = parser.links
    if not text.strip() or '\x00' in text:
        raise PolicyReferenceError('document has no readable text')
    if len(text) > MAX_EVIDENCE_CHARS:
        raise PolicyReferenceError('document exceeds combined evidence budget')
    return text, links


class _RawResponseLimitExceeded(RuntimeError):
    # HTTPResponse converts ValueError while parsing chunk sizes; preserve this
    # transport failure until the public reader translates it at its boundary.
    pass


class _CappedResponseInput(io.RawIOBase):
    """Bound every plaintext HTTP input byte before buffering or parsing.

    The cap includes status lines, headers, chunk framing and trailers. Never
    probe beyond the allowance: a response needing more input at the boundary is
    unresolved, including an EOF-delimited response whose completion is unproven.
    """
    def __init__(self, raw, limit):
        self.raw = raw
        self.remaining = limit

    def readable(self):
        return True

    def readinto(self, target):
        if not len(target):
            return 0
        if self.remaining <= 0:
            raise _RawResponseLimitExceeded('reference exceeds raw response byte budget')
        count = self.raw.readinto(memoryview(target)[:self.remaining])
        if count is not None:
            self.remaining -= count
        return count

    def close(self):
        try:
            self.raw.close()
        finally:
            super().close()


class _BoundedResponseSocket:
    def __init__(self, sock):
        self.sock = sock

    def makefile(self, mode):
        # An unbuffered source is essential: no underlying read-ahead may bypass
        # the counter. HTTPResponse receives buffering only above that counter.
        raw = self.sock.makefile(mode, buffering=0)
        return io.BufferedReader(_CappedResponseInput(raw, MAX_RESPONSE_BYTES))


class _BoundedHTTPResponse(http.client.HTTPResponse):
    def __init__(self, sock, *args, **kwargs):
        super().__init__(_BoundedResponseSocket(sock), *args, **kwargs)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port, address, timeout):
        super().__init__(host, port=port, timeout=timeout, context=ssl.create_default_context())
        self.address = address

    def connect(self):
        address = ipaddress.ip_address(self.address)
        raw = socket.socket(socket.AF_INET6 if address.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
        deadline = time.monotonic() + self.timeout
        raw.settimeout(self.timeout)
        self.sock = raw
        try:
            # Numeric connect bypasses DNS after validation; TLS verifies the original hostname.
            raw.connect((self.address, self.port))
            raw.settimeout(max(0.001, deadline - time.monotonic()))
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except BaseException:
            raw.close()
            raise


class PublicPolicyDocumentReader:
    """No browser context, auth, cookies, environment proxies or custom headers."""
    def __init__(self, *, resolver=None, connection_factory=None):
        self.resolver = resolver or socket.getaddrinfo
        self.connection_factory = connection_factory or _PinnedHTTPSConnection

    def _addresses(self, hostname, port, deadline):
        results = queue.Queue(maxsize=1)
        def resolve():
            try:
                results.put(self.resolver(hostname, port, type=socket.SOCK_STREAM))
            except Exception as exc:
                results.put(exc)
        threading.Thread(target=resolve, daemon=True).start()
        try:
            value = results.get(timeout=max(0.001, deadline - time.monotonic()))
        except queue.Empty as exc:
            raise PolicyReferenceError('reference DNS lookup timed out') from exc
        if isinstance(value, Exception):
            raise PolicyReferenceError('reference DNS lookup failed') from value
        addresses = {ipaddress.ip_address(item[4][0]) for item in value}
        if not addresses or any(not a.is_global or a.is_multicast or a.is_reserved for a in addresses):
            raise PolicyReferenceError('reference resolves to a non-public address')
        return sorted(str(a) for a in addresses)

    def read(self, url: str) -> CapturedPolicyDocument:
        requested_url, current = url, url
        deadline = time.monotonic() + TIMEOUT_SECONDS
        for redirects in range(4):
            if len(current) > 4096 or any(ord(c) <= 32 or ord(c) == 127 for c in current) or '\\' in current:
                raise PolicyReferenceError('malformed reference URL')
            try:
                parsed = urlsplit(current)
                if parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None or parsed.password is not None:
                    raise PolicyReferenceError('reference must be credential-free public HTTPS')
                port = parsed.port or 443
                hostname = parsed.hostname.encode('idna').decode('ascii')
            except (ValueError, UnicodeError) as exc:
                raise PolicyReferenceError('invalid reference URL') from exc
            addresses = self._addresses(hostname, port, deadline)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PolicyReferenceError('reference request timed out')
            connection = self.connection_factory(hostname, port, addresses[0], remaining)
            connection.response_class = _BoundedHTTPResponse
            wire_socket = [None]
            response = None
            timed_out = threading.Event()
            def expire(connection=connection, wire_socket=wire_socket, timed_out=timed_out):
                timed_out.set()
                active = connection.sock or wire_socket[0]
                if active is not None:
                    try:
                        active.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
            watchdog = threading.Timer(remaining, expire)
            watchdog.daemon = True
            watchdog.start()
            try:
                path = urlunsplit(('', '', parsed.path or '/', parsed.query, ''))
                connection.request('GET', path, headers={'Accept': 'text/html, text/plain, application/xhtml+xml'})
                wire_socket[0] = connection.sock
                response = connection.getresponse()
                if response.status in {301, 302, 303, 307, 308}:
                    location = response.getheader('Location')
                    if not location or redirects == 3:
                        raise PolicyReferenceError('reference redirect limit or missing location')
                    current = urljoin(current, location)
                    continue
                if response.status != 200:
                    raise PolicyReferenceError(f'reference HTTP status {response.status}')
                if response.getheader('Content-Encoding', 'identity').lower() != 'identity':
                    raise PolicyReferenceError('unsupported compressed reference response')
                length = response.getheader('Content-Length')
                if length is not None and (not length.isdecimal() or int(length) > MAX_RESPONSE_BYTES):
                    raise PolicyReferenceError('reference exceeds response byte budget')
                # Keep an independent decoded-body cap for injected readers;
                # the production raw cap is already enforced below HTTP parsing.
                budget = MAX_RESPONSE_BYTES
                body = bytearray()
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise PolicyReferenceError('reference request timed out')
                    if connection.sock is not None:
                        connection.sock.settimeout(remaining)
                    chunk = response.read1(min(65536, max(1, budget + 1 - len(body))))
                    body.extend(chunk)
                    if len(body) > budget:
                        raise PolicyReferenceError('reference exceeds response byte budget')
                    if not chunk:
                        break
                if length is not None and len(body) != int(length):
                    raise PolicyReferenceError('incomplete reference response body')
                if timed_out.is_set() or time.monotonic() > deadline:
                    raise PolicyReferenceError('reference request timed out')
                text, links = parse_document(bytes(body), response.getheader('Content-Type', ''), current)
                return CapturedPolicyDocument(requested_url=requested_url, final_url=current,
                    captured_at=datetime.now(timezone.utc), text=text, observed_links=links)
            except _RawResponseLimitExceeded as exc:
                raise PolicyReferenceError(str(exc)) from exc
            except (OSError, http.client.HTTPException) as exc:
                raise PolicyReferenceError('reference public HTTPS capture failed') from exc
            finally:
                watchdog.cancel()
                if response is not None:
                    response.close()
                connection.close()
        raise PolicyReferenceError('reference redirect limit exceeded')
