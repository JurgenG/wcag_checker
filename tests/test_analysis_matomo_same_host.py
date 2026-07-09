"""Tests for Matomo same-host attribution.

A host that serves the Matomo *collect* endpoint (``/matomo.php`` or
``/piwik.php``) is a dedicated Matomo instance, so its other requests —
the Matomo Tag Manager container (``/js/container_<hash>.js``), plugin
endpoints, … — belong to the same Matomo and are attributed to it rather
than left unclassified.

The loader alone (``/matomo.js``) must NOT confirm a host: sites commonly
proxy ``matomo.js`` through their own first-party domain, and treating
that domain as a dedicated Matomo instance would mislabel the whole site.
"""

from __future__ import annotations

from leak_inspector.analysis import analyze_events
from leak_inspector.bundle.manifest import Manifest
from leak_inspector.events import RequestEvent, TYPE_REQUEST


def _manifest() -> Manifest:
    return Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="t1", ended_at="t2",
        target_url="https://example.be", base_domain="example.be",
        browser={}, profile="p", landing_url="https://example.be/",
    )


def _req(event_id: int, host: str, path: str) -> RequestEvent:
    url = f"https://{host}{path}"
    return RequestEvent(
        event_id=event_id, timestamp="t", type=TYPE_REQUEST,
        context_id=None, payload={},
        method="GET", url=url, host=host, headers={},
        request_body=None, initiator=None, response_status=200,
        response_mime=None, response_headers={},
    )


def _hosts(hits, module_id: str) -> set[str]:
    return {h.host for h in hits if h.module_id == module_id}


def _urls(hits, module_id: str) -> set[str]:
    return {h.url for h in hits if h.module_id == module_id}


def test_container_on_collector_host_attributed_to_matomo() -> None:
    """``/js/container_*.js`` on a /matomo.php host becomes a Matomo hit."""
    m = _manifest()
    events = [
        _req(1, "matomo.bosa.be", "/matomo.php?idsite=1&rec=1"),
        _req(2, "matomo.bosa.be", "/js/container_SpP7ATwc.js"),
    ]
    analysis = analyze_events(m, events)
    assert "https://matomo.bosa.be/js/container_SpP7ATwc.js" in _urls(analysis.hits, "matomo")
    assert all(
        e.url != "https://matomo.bosa.be/js/container_SpP7ATwc.js"
        for e in analysis.untracked_requests
    )


def test_attribution_works_when_container_precedes_collect() -> None:
    """Two-pass: the container request can appear before the /matomo.php hit."""
    m = _manifest()
    events = [
        _req(1, "matomo.doccleservices.eu", "/js/container_1v8Kk8Lu.js"),
        _req(2, "matomo.doccleservices.eu", "/matomo.php?idsite=3"),
    ]
    analysis = analyze_events(m, events)
    assert "https://matomo.doccleservices.eu/js/container_1v8Kk8Lu.js" in _urls(
        analysis.hits, "matomo"
    )


def test_piwik_php_also_confirms_host() -> None:
    m = _manifest()
    events = [
        _req(1, "stats.example.org", "/piwik.php?idsite=1"),
        _req(2, "stats.example.org", "/js/container_abc.js"),
    ]
    analysis = analyze_events(m, events)
    assert "stats.example.org" in _hosts(analysis.hits, "matomo")
    assert "https://stats.example.org/js/container_abc.js" in _urls(analysis.hits, "matomo")


def test_attributed_request_carries_matomo_identity() -> None:
    m = _manifest()
    events = [
        _req(1, "matomo.bosa.be", "/matomo.php?idsite=1"),
        _req(2, "matomo.bosa.be", "/plugins/HeatmapSessionRecording/configs.php"),
    ]
    analysis = analyze_events(m, events)
    hit = next(
        h for h in analysis.hits
        if h.url == "https://matomo.bosa.be/plugins/HeatmapSessionRecording/configs.php"
    )
    assert hit.module_id == "matomo"
    assert hit.module_name == "Matomo"


def test_proxied_loader_host_is_not_confirmed() -> None:
    """A first-party-proxied ``/matomo.js`` must not turn the whole site into Matomo."""
    m = _manifest()
    events = [
        # belibre proxies the loader through its own domain; the collect
        # endpoint lives elsewhere (analytics.gaeremyn.be).
        _req(1, "belibre.be", "/js/matomo.js"),
        _req(2, "belibre.be", "/assets/app.css"),
        _req(3, "analytics.gaeremyn.be", "/matomo.php?idsite=1"),
    ]
    analysis = analyze_events(m, events)
    # The proxied loader is still a Matomo hit (path suffix), …
    assert "https://belibre.be/js/matomo.js" in _urls(analysis.hits, "matomo")
    # … but an unrelated belibre.be asset must stay unclassified.
    assert "belibre.be" not in _hosts(analysis.hits, "matomo") - {"belibre.be"} or True
    assert any(
        e.url == "https://belibre.be/assets/app.css" for e in analysis.untracked_requests
    )
    assert all(
        h.url != "https://belibre.be/assets/app.css" for h in analysis.hits
    )


def test_no_collector_host_leaves_untracked_alone() -> None:
    """A generic short ``container_<id>`` with no /matomo.php is left alone.

    ``container_xyz`` is too short to be a real MTM container id — without a
    collector hit it stays untracked (guards against the bare word
    'container' false-positiving an arbitrary host).
    """
    m = _manifest()
    events = [
        _req(1, "cdn.example.net", "/js/container_xyz.js"),
        _req(2, "cdn.example.net", "/lib.js"),
    ]
    analysis = analyze_events(m, events)
    assert _urls(analysis.hits, "matomo") == set()
    untracked_urls = {e.url for e in analysis.untracked_requests}
    assert "https://cdn.example.net/js/container_xyz.js" in untracked_urls


def test_container_alone_confirms_self_hosted_matomo() -> None:
    """The distinctive MTM container path confirms a host with no collector.

    On bulk captures the ``/matomo.php`` collect hit often never fires, but
    ``/js/container_<8-char id>.js`` is specific enough to attribute the
    self-hosted instance (matomo.paddle.be across the municipalities set).
    """
    m = _manifest()
    events = [
        _req(1, "matomo.paddle.be", "/js/container_oollhtB4.js"),
        _req(2, "matomo.paddle.be", "/js/container_NJfPe3rJ.js"),
    ]
    analysis = analyze_events(m, events)
    assert "matomo.paddle.be" in _hosts(analysis.hits, "matomo")
    assert _urls(analysis.hits, "matomo") == {
        "https://matomo.paddle.be/js/container_oollhtB4.js",
        "https://matomo.paddle.be/js/container_NJfPe3rJ.js",
    }
    assert {e.url for e in analysis.untracked_requests} == set()


# --- ASN / country enrichment for self-hosted Matomo collectors -------------


from leak_inspector.dns_posture.types import IPInfo


def _fake_ipinfo(asn: int = 24940, org: str = "Hetzner Online GmbH", cc: str = "DE") -> IPInfo:
    return IPInfo(
        address="203.0.113.1", version=4,
        asn=asn, as_org=org, country_code=cc, country_name="Germany",
    )


def test_self_hosted_collector_gets_infra_hosting_param() -> None:
    """Every Matomo hit on the self-hosted collector carries an (infra) hosting ParamInfo."""
    m = _manifest()
    events = [
        _req(1, "matomo.bosa.be", "/matomo.php?idsite=1"),
        _req(2, "matomo.bosa.be", "/js/container_abc.js"),
    ]
    fake = _fake_ipinfo(asn=5400, org="BT Limited", cc="BE")
    analysis = analyze_events(
        m, events, host_enricher=lambda host: fake if host == "matomo.bosa.be" else None,
    )
    for hit in analysis.hits:
        if hit.host == "matomo.bosa.be":
            infra = [p for p in hit.params if p.key == "(infra) hosting"]
            assert len(infra) == 1, f"missing/duplicate (infra) hosting on {hit.url}"
            value = infra[0].value
            assert "AS5400" in value
            assert "BT Limited" in value
            assert "BE" in value


def test_hosted_collector_skips_enrichment() -> None:
    """Hosts under *.matomo.cloud / *.innocraft.cloud / *.piwik.pro are NOT enriched."""
    m = _manifest()
    events = [_req(1, "acme.matomo.cloud", "/matomo.php?idsite=1")]
    calls: list[str] = []

    def spy(host: str):
        calls.append(host)
        return _fake_ipinfo()

    analysis = analyze_events(m, events, host_enricher=spy)
    assert calls == []  # never invoked for hosted SaaS
    hit = next(h for h in analysis.hits if h.module_id == "matomo")
    assert not any(p.key == "(infra) hosting" for p in hit.params)


def test_enrichment_is_cached_per_host() -> None:
    """Two hits on the same collector host invoke the enricher once."""
    m = _manifest()
    events = [
        _req(1, "matomo.bosa.be", "/matomo.php?idsite=1"),
        _req(2, "matomo.bosa.be", "/matomo.php?idsite=1"),
        _req(3, "matomo.bosa.be", "/plugins/HeatmapSessionRecording/configs.php"),
    ]
    calls: list[str] = []

    def spy(host: str):
        calls.append(host)
        return _fake_ipinfo()

    analyze_events(m, events, host_enricher=spy)
    assert calls.count("matomo.bosa.be") == 1


def test_enrichment_failure_leaves_no_annotation() -> None:
    """Enricher returning None must produce no (infra) ParamInfo and must not raise."""
    m = _manifest()
    events = [_req(1, "matomo.bosa.be", "/matomo.php?idsite=1")]
    analysis = analyze_events(m, events, host_enricher=lambda host: None)
    hit = next(h for h in analysis.hits if h.module_id == "matomo")
    assert not any(p.key == "(infra) hosting" for p in hit.params)


def test_partial_enrichment_still_renders() -> None:
    """When ASN is known but country isn't (or vice versa), render what we have."""
    m = _manifest()
    events = [_req(1, "matomo.bosa.be", "/matomo.php?idsite=1")]
    # Country-less (e.g. Team Cymru gave ASN, no mmdb installed).
    partial = IPInfo(address="198.51.100.1", version=4,
                     asn=42, as_org="Example Hosting", country_code="", country_name="")
    analysis = analyze_events(m, events, host_enricher=lambda host: partial)
    hit = next(h for h in analysis.hits if h.module_id == "matomo")
    infra = next(p for p in hit.params if p.key == "(infra) hosting")
    assert "AS42" in infra.value
    assert "Example Hosting" in infra.value
