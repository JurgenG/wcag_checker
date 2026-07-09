"""Tests for the HTTP/HTTPS transport posture probe.

Probes the captured site's apex and www variants over both HTTP and
HTTPS to surface common hygiene issues: missing HTTPS, HTTP→HTTPS
redirect not configured, apex/www served independently, one variant
not resolving.

Probing happens at analysis time (not capture time — the bundle stays
pristine). The HTTP fetcher is injectable so unit tests stay
hermetic.
"""

from __future__ import annotations

from leak_inspector.http_posture import (
    HostProbe,
    TransportPosture,
    probe_transport,
)


def _make_fetcher(routes: dict[str, dict | None]):
    """Build a deterministic fetcher from a {url: response_dict} map.

    ``response_dict`` shape:
        {"status": int, "final_url": str}
    ``None`` means the fetch failed (DNS / connection refused / timeout).
    """
    def fetcher(url: str) -> dict | None:
        return routes.get(url)
    return fetcher


# --- HostProbe contract ----------------------------------------------------


def test_host_probe_redirects_to_https_detection() -> None:
    p = HostProbe(
        host="example.be",
        http_responded=True, https_responded=True,
        http_status=301, https_status=200,
        http_final_url="https://example.be/",
        https_final_url="https://example.be/",
    )
    assert p.http_redirects_to_https is True


def test_host_probe_no_redirect_when_http_final_is_still_http() -> None:
    p = HostProbe(
        host="example.be",
        http_responded=True, https_responded=True,
        http_status=200, https_status=200,
        http_final_url="http://example.be/",
        https_final_url="https://example.be/",
    )
    assert p.http_redirects_to_https is False


def test_host_probe_resolves_when_either_scheme_responds() -> None:
    p = HostProbe(
        host="example.be",
        http_responded=False, https_responded=True,
        http_status=None, https_status=200,
        http_final_url=None, https_final_url="https://example.be/",
    )
    assert p.resolves is True


def test_host_probe_does_not_resolve_when_both_fail() -> None:
    p = HostProbe(
        host="example.be",
        http_responded=False, https_responded=False,
        http_status=None, https_status=None,
        http_final_url=None, https_final_url=None,
    )
    assert p.resolves is False


# --- probe_transport: apex + www site --------------------------------------


def test_probe_apex_site_with_www_alternate() -> None:
    """Captured at ``https://example.be/`` — apex is primary, www is alternate."""
    fetcher = _make_fetcher({
        "http://example.be/":      {"status": 301, "final_url": "https://example.be/"},
        "https://example.be/":     {"status": 200, "final_url": "https://example.be/"},
        "http://www.example.be/":  {"status": 301, "final_url": "https://example.be/"},
        "https://www.example.be/": {"status": 301, "final_url": "https://example.be/"},
    })
    posture = probe_transport(
        landing_url="https://example.be/", base_domain="example.be",
        fetcher=fetcher,
    )
    assert posture is not None
    assert posture.primary.host == "example.be"
    assert posture.alternate is not None
    assert posture.alternate.host == "www.example.be"
    assert posture.primary.https_responded is True
    assert posture.primary.http_redirects_to_https is True


def test_probe_www_site_with_apex_alternate() -> None:
    """Captured at ``https://www.example.be/`` — www is primary, apex is alternate."""
    fetcher = _make_fetcher({
        "http://example.be/":      None,
        "https://example.be/":     None,
        "http://www.example.be/":  {"status": 301, "final_url": "https://www.example.be/"},
        "https://www.example.be/": {"status": 200, "final_url": "https://www.example.be/"},
    })
    posture = probe_transport(
        landing_url="https://www.example.be/", base_domain="example.be",
        fetcher=fetcher,
    )
    assert posture is not None
    assert posture.primary.host == "www.example.be"
    assert posture.alternate is not None
    assert posture.alternate.host == "example.be"
    assert posture.alternate.resolves is False


# --- probe_transport: subdomain site (no alternate) ------------------------


def test_probe_subdomain_site_has_no_alternate() -> None:
    """A site at ``commune.foo.be`` doesn't get apex/www testing — the apex
    of foo.be may be a completely different organisation."""
    fetcher = _make_fetcher({
        "http://commune.foo.be/":  {"status": 301, "final_url": "https://commune.foo.be/"},
        "https://commune.foo.be/": {"status": 200, "final_url": "https://commune.foo.be/"},
    })
    posture = probe_transport(
        landing_url="https://commune.foo.be/", base_domain="foo.be",
        fetcher=fetcher,
    )
    assert posture is not None
    assert posture.primary.host == "commune.foo.be"
    assert posture.alternate is None


# --- probe_transport: HTTPS broken ----------------------------------------


def test_probe_when_https_is_broken_on_primary() -> None:
    """HTTPS doesn't respond — primary.https_responded is False."""
    fetcher = _make_fetcher({
        "http://example.be/":      {"status": 200, "final_url": "http://example.be/"},
        "https://example.be/":     None,
        "http://www.example.be/":  {"status": 200, "final_url": "http://www.example.be/"},
        "https://www.example.be/": None,
    })
    posture = probe_transport(
        landing_url="http://example.be/", base_domain="example.be",
        fetcher=fetcher,
    )
    assert posture.primary.https_responded is False
    assert posture.primary.http_responded is True


def test_probe_when_http_is_absent() -> None:
    """HTTPS-only site — primary.http_responded is False, https works."""
    fetcher = _make_fetcher({
        "http://example.be/":      None,
        "https://example.be/":     {"status": 200, "final_url": "https://example.be/"},
        "http://www.example.be/":  None,
        "https://www.example.be/": {"status": 301, "final_url": "https://example.be/"},
    })
    posture = probe_transport(
        landing_url="https://example.be/", base_domain="example.be",
        fetcher=fetcher,
    )
    assert posture.primary.http_responded is False
    assert posture.primary.https_responded is True


# --- probe_transport: missing inputs --------------------------------------


def test_probe_returns_none_without_base_domain() -> None:
    """A bundle with no parseable base_domain can't be probed meaningfully."""
    posture = probe_transport(
        landing_url="https://example.be/", base_domain="",
        fetcher=lambda url: None,
    )
    assert posture is None


def test_probe_returns_none_without_landing_url() -> None:
    posture = probe_transport(
        landing_url="", base_domain="example.be",
        fetcher=lambda url: None,
    )
    assert posture is None


# --- probe_transport: only probes four URLs maximum -----------------------


def test_probe_makes_exactly_four_requests_for_apex_site() -> None:
    """Bounded probe budget: HTTP+HTTPS × apex+www = 4 requests, no more."""
    calls: list[str] = []
    def fetcher(url: str) -> dict | None:
        calls.append(url)
        return {"status": 200, "final_url": url}
    probe_transport(
        landing_url="https://example.be/", base_domain="example.be",
        fetcher=fetcher,
    )
    assert len(calls) == 4
    assert set(calls) == {
        "http://example.be/",
        "https://example.be/",
        "http://www.example.be/",
        "https://www.example.be/",
    }


def test_probe_makes_exactly_two_requests_for_subdomain_site() -> None:
    calls: list[str] = []
    def fetcher(url: str) -> dict | None:
        calls.append(url)
        return {"status": 200, "final_url": url}
    probe_transport(
        landing_url="https://commune.foo.be/", base_domain="foo.be",
        fetcher=fetcher,
    )
    assert len(calls) == 2
    assert set(calls) == {
        "http://commune.foo.be/",
        "https://commune.foo.be/",
    }


# --- SSRF guard ------------------------------------------------------------


import pytest


def _record_urlopen_calls(monkeypatch) -> list:
    """Patch the http_posture.probe module's opener so any open is recorded.

    The SSRF guard should reject private URLs *before* the opener
    runs, so a passing test sees an empty list of attempted opens.
    """
    from leak_inspector.http_posture import probe as hp_probe
    calls: list[str] = []

    class _RecordingOpener:
        def open(self, req, timeout=None):  # noqa: ARG002
            calls.append(req.full_url if hasattr(req, "full_url") else str(req))
            raise AssertionError("opener.open() should not be called for a guarded URL")

    monkeypatch.setattr(hp_probe, "_OPENER", _RecordingOpener())
    return calls


@pytest.mark.parametrize(
    "url",
    [
        "http://10.0.0.5:8500/",
        "http://127.0.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
    ],
)
def test_default_fetcher_refuses_private_host_url(monkeypatch, url: str) -> None:
    """Private addresses in the URL are refused *before* opening any connection."""
    from leak_inspector.http_posture.probe import _http_get
    calls = _record_urlopen_calls(monkeypatch)
    assert _http_get(url) is None
    assert calls == []


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "gopher://example.com/",
    ],
)
def test_default_fetcher_refuses_non_http_scheme(monkeypatch, url: str) -> None:
    from leak_inspector.http_posture.probe import _http_get
    calls = _record_urlopen_calls(monkeypatch)
    assert _http_get(url) is None
    assert calls == []
