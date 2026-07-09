"""Tests for ASN/country enrichment of self-hosted Snowplow collector hosts.

Mirrors the Matomo same-host attribution pass: the analyzer recognises a
self-hosted Snowplow instance and asks the configured ``host_enricher`` for
its ASN/country, then attaches one ``(infra) hosting`` ParamInfo to every
Snowplow hit on that host. Hosted Snowplow BDP hosts (``*.snplow.net`` /
``*.snowplowanalytics.com``) are NOT enriched — they live on Snowplow's
known infrastructure.
"""

from __future__ import annotations

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


def _req(event_id: int, host: str, path: str) -> RequestEvent:
    url = f"https://{host}{path}"
    return RequestEvent(
        event_id=event_id, timestamp="t", type=TYPE_REQUEST,
        context_id=None, payload={},
        method="GET", url=url, host=host, headers={},
        request_body=None, initiator=None, response_status=200,
        response_mime=None, response_headers={},
    )


def _fake() -> IPInfo:
    return IPInfo(
        address="198.51.100.1", version=4,
        asn=24940, as_org="Hetzner Online GmbH",
        country_code="DE", country_name="Germany",
    )


def test_self_hosted_snowplow_gets_infra_hosting_param() -> None:
    """A self-hosted Snowplow collector carries an (infra) hosting ParamInfo on every hit."""
    m = _manifest()
    events = [_req(1, "sp.example.be", "/com.snowplowanalytics.snowplow/tp2?tv=js-3.0.0&e=pv")]
    fake = _fake()
    analysis = analyze_events(
        m, events, host_enricher=lambda host: fake if host == "sp.example.be" else None,
    )
    hit = next(h for h in analysis.hits if h.module_id == "snowplow")
    infra = [p for p in hit.params if p.key == "(infra) hosting"]
    assert len(infra) == 1
    assert "AS24940" in infra[0].value
    assert "Hetzner" in infra[0].value
    assert "DE" in infra[0].value


def test_hosted_snowplow_skips_enrichment() -> None:
    """Hosts under *.snplow.net / *.snowplowanalytics.com are NOT enriched."""
    m = _manifest()
    events = [_req(1, "acme.snplow.net", "/com.snowplowanalytics.snowplow/tp2?tv=js-3.0.0&e=pv")]
    calls: list[str] = []

    def spy(host: str):
        calls.append(host)
        return _fake()

    analysis = analyze_events(m, events, host_enricher=spy)
    assert calls == []
    hit = next(h for h in analysis.hits if h.module_id == "snowplow")
    assert not any(p.key == "(infra) hosting" for p in hit.params)


def test_enrichment_failure_leaves_no_annotation() -> None:
    """Enricher returning None must not produce an (infra) ParamInfo and must not raise."""
    m = _manifest()
    events = [_req(1, "sp.example.be", "/com.snowplowanalytics.snowplow/tp2?tv=js-3.0.0&e=pv")]
    analysis = analyze_events(m, events, host_enricher=lambda host: None)
    hit = next(h for h in analysis.hits if h.module_id == "snowplow")
    assert not any(p.key == "(infra) hosting" for p in hit.params)


def test_enrichment_cached_per_host_across_snowplow_hits() -> None:
    """Two Snowplow hits on the same host trigger one enricher call."""
    m = _manifest()
    events = [
        _req(1, "sp.example.be", "/com.snowplowanalytics.snowplow/tp2?tv=js-3.0.0&e=pv"),
        _req(2, "sp.example.be", "/com.snowplowanalytics.snowplow/tp2?tv=js-3.0.0&e=pp"),
    ]
    calls: list[str] = []

    def spy(host: str):
        calls.append(host)
        return _fake()

    analyze_events(m, events, host_enricher=spy)
    assert calls.count("sp.example.be") == 1


def test_matomo_and_snowplow_collector_hosts_both_enriched() -> None:
    """The runner enriches collector hosts from both modules in the same pass."""
    m = _manifest()
    events = [
        _req(1, "matomo.example.be", "/matomo.php?idsite=1"),
        _req(2, "sp.example.be", "/com.snowplowanalytics.snowplow/tp2?tv=js-3.0.0&e=pv"),
    ]
    seen = {"matomo.example.be": False, "sp.example.be": False}

    def enricher(host: str):
        if host in seen:
            seen[host] = True
        return _fake()

    analysis = analyze_events(m, events, host_enricher=enricher)
    assert seen == {"matomo.example.be": True, "sp.example.be": True}
    by_host = {h.host: h for h in analysis.hits}
    for host in ("matomo.example.be", "sp.example.be"):
        infra = [p for p in by_host[host].params if p.key == "(infra) hosting"]
        assert len(infra) == 1, f"missing infra annotation on {host}"
