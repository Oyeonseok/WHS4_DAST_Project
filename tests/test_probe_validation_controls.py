"""Local probe evidence must never come from a followed redirect."""

from io import BytesIO
from urllib.error import HTTPError

from scripts import probe_validation_controls as probe


def test_probe_records_redirect_instead_of_following_it(monkeypatch) -> None:
    class FakeOpener:
        def open(self, request, timeout):
            raise HTTPError(request.full_url, 302, "Found",
                            {"Location": "http://other.example/elsewhere"}, BytesIO(b""))

    def fake_build_opener(handler):
        assert handler is probe._NoRedirect
        assert handler().redirect_request(None, None, 302, "Found", {},
                                          "http://other.example/elsewhere") is None
        return FakeOpener()

    monkeypatch.setattr(probe, "build_opener", fake_build_opener)
    status, digest, length = probe.fetch_status_and_digest("http://127.0.0.1:3001/start")

    assert status == 302
    assert len(digest) == 64
    assert length == 0
