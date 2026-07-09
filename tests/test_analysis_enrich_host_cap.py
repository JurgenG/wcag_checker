"""Tests for the per-analysis cap on ``host_enricher`` invocations.

A hostile bundle can fabricate thousands of distinct hostnames that
match the self-hosted-collector detectors (Matomo / Plausible /
Snowplow). Without a cap, every unique host would trigger an
``enrich_host`` call — A/AAAA DNS lookup + a Team Cymru WHOIS query.
That fans out N DNS + N WHOIS queries on bundle open, usable for
resolver-side recon or reflection.

The cap short-circuits enrichment after a fixed number of distinct
hosts and emits a single sentinel ``(infra) enrichment_capped``
ParamInfo on the first dropped hit so the truncation is visible in
the report rather than silent.
"""

from __future__ import annotations

from leak_inspector.analysis import analyze_events
from leak_inspector.analysis.runner import ENRICH_HOST_CAP
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


def _matomo_req(event_id: int, host: str) -> RequestEvent:
    """A matomo.php hit on ``host`` — counts as a self-hosted collector hit."""
    return RequestEvent(
        event_id=event_id, timestamp="t", type=TYPE_REQUEST,
        context_id=None, payload={},
        method="GET",
        url=f"https://{host}/matomo.php?idsite=1&rec=1",
        host=host, headers={},
        request_body=None, initiator=None, response_status=200,
        response_mime=None, response_headers={},
    )


def _fake_ipinfo() -> IPInfo:
    return IPInfo(
        address="203.0.113.1", version=4,
        asn=24940, as_org="Hetzner Online GmbH",
        country_code="DE", country_name="Germany",
    )


# --- The cap exists and has a sensible value -------------------------------


def test_cap_constant_is_sensible() -> None:
    """The constant must be exported and small enough to defeat amplification.

    Per the M1 audit: 'cap unique enrich_host targets per analysis
    (e.g. 50)'. Anything above ~100 starts to lose the defensive value;
    anything below ~10 risks truncating legitimate captures of large
    multi-tenant Matomo deployments.
    """
    assert 10 <= ENRICH_HOST_CAP <= 100


# --- Behaviour: enrichment short-circuits past the cap --------------------


def test_enrich_host_called_at_most_cap_times() -> None:
    """A bundle with many distinct collector hosts must not exceed the cap."""
    m = _manifest()
    # Build twice as many distinct collector hosts as the cap allows.
    fabricated_hosts = [f"matomo-{i}.example.be" for i in range(ENRICH_HOST_CAP * 2)]
    events = [_matomo_req(i + 1, host) for i, host in enumerate(fabricated_hosts)]

    calls: list[str] = []

    def spy(host: str):
        calls.append(host)
        return _fake_ipinfo()

    analyze_events(m, events, host_enricher=spy)
    # The enricher must NOT be called more times than the cap.
    assert len(calls) <= ENRICH_HOST_CAP, (
        f"enricher called {len(calls)} times — exceeds ENRICH_HOST_CAP={ENRICH_HOST_CAP}"
    )


def test_enriched_hits_below_cap_unaffected() -> None:
    """A normal-sized bundle (well below the cap) gets every host enriched."""
    m = _manifest()
    n = 5
    events = [_matomo_req(i + 1, f"matomo-{i}.example.be") for i in range(n)]

    calls: list[str] = []

    def spy(host: str):
        calls.append(host)
        return _fake_ipinfo()

    analyze_events(m, events, host_enricher=spy)
    assert sorted(calls) == sorted({f"matomo-{i}.example.be" for i in range(n)})


def test_dropped_hits_get_no_infra_hosting_param() -> None:
    """Hosts whose enrichment was short-circuited must not get a synthesised IPInfo."""
    m = _manifest()
    fabricated_hosts = [f"matomo-{i}.example.be" for i in range(ENRICH_HOST_CAP * 2)]
    events = [_matomo_req(i + 1, host) for i, host in enumerate(fabricated_hosts)]

    def fake(host: str):
        return _fake_ipinfo()

    analysis = analyze_events(m, events, host_enricher=fake)
    matomo_hits = [h for h in analysis.hits if h.module_id == "matomo"]
    # Hosts that DID get enriched get an (infra) hosting row.
    enriched = [
        h for h in matomo_hits
        if any(p.key == "(infra) hosting" for p in h.params)
    ]
    assert len(enriched) <= ENRICH_HOST_CAP


# --- Visibility: dropped hosts surface a sentinel marker ------------------


def test_first_dropped_hit_carries_capped_sentinel() -> None:
    """At least one hit beyond the cap carries an ``(infra) enrichment_capped`` row.

    Silent truncation reads as 'covered everything' when it didn't.
    Surfacing the cap-hit lets a human see that some collector hosts
    weren't enriched in this analysis.
    """
    m = _manifest()
    fabricated_hosts = [f"matomo-{i}.example.be" for i in range(ENRICH_HOST_CAP * 2)]
    events = [_matomo_req(i + 1, host) for i, host in enumerate(fabricated_hosts)]

    analysis = analyze_events(m, events, host_enricher=lambda h: _fake_ipinfo())
    sentinels = [
        p for h in analysis.hits for p in h.params
        if p.key == "(infra) enrichment_capped"
    ]
    assert sentinels, (
        "no (infra) enrichment_capped sentinel emitted — silent truncation"
    )
    # Cap-sentinel rows only fire when the cap was actually hit.
    assert any(str(ENRICH_HOST_CAP) in p.value for p in sentinels), (
        f"sentinel does not name the cap value ({ENRICH_HOST_CAP})"
    )


def test_no_sentinel_when_below_cap() -> None:
    """A bundle below the cap must not emit the sentinel."""
    m = _manifest()
    events = [_matomo_req(i + 1, f"matomo-{i}.example.be") for i in range(5)]
    analysis = analyze_events(m, events, host_enricher=lambda h: _fake_ipinfo())
    sentinels = [
        p for h in analysis.hits for p in h.params
        if p.key == "(infra) enrichment_capped"
    ]
    assert sentinels == []


# --- No enricher → cap is irrelevant --------------------------------------


def test_no_enricher_means_no_cap_logic_fires() -> None:
    """When the caller passes no host_enricher (hermetic path), nothing happens."""
    m = _manifest()
    fabricated_hosts = [f"matomo-{i}.example.be" for i in range(ENRICH_HOST_CAP * 2)]
    events = [_matomo_req(i + 1, host) for i, host in enumerate(fabricated_hosts)]
    analysis = analyze_events(m, events)  # no host_enricher
    sentinels = [
        p for h in analysis.hits for p in h.params
        if p.key == "(infra) enrichment_capped"
    ]
    assert sentinels == []
