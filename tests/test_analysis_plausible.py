"""Same-host attribution + ASN enrichment for Plausible.

A host that served ``/api/event`` with the Plausible JSON body is a
confirmed Plausible collector. Loader scripts (``/js/script*.js``,
``/js/plausible*.js``) on that same host are attributed to Plausible
even though the module's own ``matches()`` is conservative about generic
``/js/script.js`` paths. The host's ASN/country is then attached to
every Plausible hit on that host (skipped for hosted Plausible Cloud).
"""

from __future__ import annotations

import json

from leak_inspector.analysis import analyze_events
from leak_inspector.bundle.manifest import Manifest
from leak_inspector.dns_posture.types import IPInfo
from leak_inspector.events import RequestEvent, TYPE_REQUEST


def _manifest() -> Manifest:
    return Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="t1", ended_at="t2",
        target_url="https://example.be", base_domain="example.be",
        browser={}, profile="p", landing_url="https://example.be/",
    )


def _req(
    event_id: int, host: str, path: str,
    method: str = "GET", body: str | None = None,
) -> RequestEvent:
    return RequestEvent(
        event_id=event_id, timestamp="t", type=TYPE_REQUEST,
        context_id=None, payload={},
        method=method, url=f"https://{host}{path}", host=host,
        headers={}, request_body=body, initiator=None,
        response_status=200, response_mime=None, response_headers={},
    )


def _api_body(domain: str = "example.be") -> str:
    return json.dumps({
        "name": "pageview", "url": f"https://{domain}/p",
        "domain": domain, "referrer": "",
    })


def _fake() -> IPInfo:
    return IPInfo(
        address="198.51.100.1", version=4,
        asn=24940, as_org="Hetzner Online GmbH",
        country_code="DE", country_name="Germany",
    )


def _urls(hits, module_id: str) -> set[str]:
    return {h.url for h in hits if h.module_id == module_id}


# --- same-host attribution for the loader ----------------------------------


def test_loader_on_confirmed_plausible_host_is_attributed() -> None:
    """``/js/script.js`` on a host that also served ``/api/event`` becomes a Plausible hit."""
    m = _manifest()
    events = [
        _req(1, "stats.example.be", "/api/event", method="POST", body=_api_body()),
        _req(2, "stats.example.be", "/js/script.js"),
    ]
    analysis = analyze_events(m, events)
    assert "https://stats.example.be/js/script.js" in _urls(analysis.hits, "plausible")
    assert all(
        e.url != "https://stats.example.be/js/script.js"
        for e in analysis.untracked_requests
    )


def test_attribution_works_when_loader_precedes_collect() -> None:
    """Two-pass: the loader request can appear before the ``/api/event`` POST."""
    m = _manifest()
    events = [
        _req(1, "stats.example.be", "/js/script.js"),
        _req(2, "stats.example.be", "/api/event", method="POST", body=_api_body()),
    ]
    analysis = analyze_events(m, events)
    assert "https://stats.example.be/js/script.js" in _urls(analysis.hits, "plausible")


def test_loader_without_confirmed_host_stays_untracked() -> None:
    """No ``/api/event`` anywhere → generic ``/js/script.js`` stays unclassified."""
    m = _manifest()
    events = [_req(1, "cdn.example.net", "/js/script.js")]
    analysis = analyze_events(m, events)
    assert _urls(analysis.hits, "plausible") == set()
    assert {e.url for e in analysis.untracked_requests} == {
        "https://cdn.example.net/js/script.js"
    }


# --- ASN enrichment --------------------------------------------------------


def test_self_hosted_plausible_gets_infra_hosting_param() -> None:
    """Every Plausible hit on a self-hosted collector carries (infra) hosting."""
    m = _manifest()
    events = [
        _req(1, "plausible.imio.be", "/api/event", method="POST", body=_api_body()),
        _req(2, "plausible.imio.be", "/js/script.js"),
    ]
    fake = _fake()
    analysis = analyze_events(
        m, events,
        host_enricher=lambda host: fake if host == "plausible.imio.be" else None,
    )
    for hit in analysis.hits:
        if hit.module_id != "plausible":
            continue
        infra = [p for p in hit.params if p.key == "(infra) hosting"]
        assert len(infra) == 1, f"missing (infra) hosting on {hit.url}"
        assert "AS24940" in infra[0].value


def test_hosted_plausible_cloud_skips_enrichment() -> None:
    """plausible.io subdomains are NOT enriched."""
    m = _manifest()
    events = [_req(1, "plausible.io", "/api/event", method="POST", body=_api_body())]
    calls: list[str] = []

    def spy(host: str):
        calls.append(host)
        return _fake()

    analysis = analyze_events(m, events, host_enricher=spy)
    assert calls == []
    hit = next(h for h in analysis.hits if h.module_id == "plausible")
    assert not any(p.key == "(infra) hosting" for p in hit.params)


def test_enrichment_cached_per_host() -> None:
    m = _manifest()
    events = [
        _req(1, "plausible.imio.be", "/api/event", method="POST", body=_api_body()),
        _req(2, "plausible.imio.be", "/api/event", method="POST", body=_api_body()),
    ]
    calls: list[str] = []

    def spy(host: str):
        calls.append(host)
        return _fake()

    analyze_events(m, events, host_enricher=spy)
    assert calls.count("plausible.imio.be") == 1


def test_enrichment_failure_leaves_no_annotation() -> None:
    m = _manifest()
    events = [_req(1, "plausible.imio.be", "/api/event", method="POST", body=_api_body())]
    analysis = analyze_events(m, events, host_enricher=lambda host: None)
    hit = next(h for h in analysis.hits if h.module_id == "plausible")
    assert not any(p.key == "(infra) hosting" for p in hit.params)
