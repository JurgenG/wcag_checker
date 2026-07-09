"""Tests for the Cloudflare Zaraz (server-side tag manager) detector.

Zaraz executes third-party tools (GA4, Meta Pixel, TikTok, …)
server-side at Cloudflare's edge. The browser only ever talks to the
site's *own* domain under Cloudflare's reserved path namespace
``/cdn-cgi/zaraz/`` (init script ``i.js`` documented in Cloudflare's
"Load Zaraz manually" guide). Which vendors run behind it is not
browser-visible — the module flags the proxy itself.

Because the requests are first-party by registrable domain, the hit
must carry the ``(fp-proxy)`` marker so the privacy/resilience
overrides count it.
"""

from __future__ import annotations

import pytest

from leak_inspector.events import RequestEvent
from leak_inspector.modules.base import (
    CAT_HTTP_TRAFFIC, IMPACT_HIGH, all_modules,
)


def _module():
    for module in all_modules():
        if module.module_id == "cloudflare_zaraz":
            return module
    raise AssertionError("cloudflare_zaraz module not registered")


def _request(host: str, path: str, query: str = "") -> RequestEvent:
    url = f"https://{host}{path}" + (f"?{query}" if query else "")
    return RequestEvent(
        event_id=1, timestamp="2026-06-05T10:00:00Z", type="request",
        context_id=None, payload={}, method="POST", url=url, host=host,
        headers={}, request_body=None, initiator=None,
        response_status=200, response_mime=None, response_headers={},
    )


# --- identity ----------------------------------------------------------------


def test_module_is_registered() -> None:
    assert _module() is not None


def test_module_identity() -> None:
    m = _module()
    assert m.vendor == "Cloudflare, Inc."
    assert m.legal_jurisdiction == "US"
    assert m.sovereignty_notes


# --- matches() ---------------------------------------------------------------


@pytest.mark.parametrize(
    "host,path",
    [
        # Reserved Cloudflare path namespace on the OPERATOR's domain —
        # first-party-looking by design.
        ("www.example.be", "/cdn-cgi/zaraz/i.js"),
        ("www.example.be", "/cdn-cgi/zaraz/s.js"),
        ("www.example.be", "/cdn-cgi/zaraz/t"),
        ("shop.example.be", "/cdn-cgi/zaraz/t"),
    ],
)
def test_matches_zaraz_paths(host: str, path: str) -> None:
    assert _module().matches(_request(host, path)) is True


@pytest.mark.parametrize(
    "host,path",
    [
        ("www.example.be", "/cdn-cgi/challenge-platform/h/g"),  # other cdn-cgi
        ("www.example.be", "/zaraz/t"),                          # not reserved
        ("www.example.be", "/index.html"),
    ],
)
def test_does_not_match_other_paths(host: str, path: str) -> None:
    assert _module().matches(_request(host, path)) is False


# --- parse() — the (fp-proxy) marker drives the scoring overrides ----------


def test_parse_attaches_fp_proxy_marker() -> None:
    hit = _module().parse(_request("www.example.be", "/cdn-cgi/zaraz/t"))
    markers = [p for p in hit.params if p.key.startswith("(fp-proxy)")]
    assert markers, "Zaraz hit must carry the (fp-proxy) marker"
    assert markers[0].privacy_impact == IMPACT_HIGH
    assert markers[0].category == CAT_HTTP_TRAFFIC


def test_parse_records_hit_basics() -> None:
    hit = _module().parse(_request("www.example.be", "/cdn-cgi/zaraz/t", "z=1"))
    assert hit.module_id == "cloudflare_zaraz"
    assert hit.host == "www.example.be"
    assert any(p.key == "z" for p in hit.params)
