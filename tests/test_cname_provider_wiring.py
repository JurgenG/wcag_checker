"""Tests that the CNAME-tail → provider lookup reaches every consumer.

Real bundles drive these — the chains baked into ``brecht.zip`` /
``cultuurkuur.zip`` / ``nbb.zip`` are what produce the assertions.
"""

from __future__ import annotations

from leak_inspector.analysis import analyze_events
from leak_inspector.bundle.reader import BundleReader
from leak_inspector.report.builder import build_report_document

from tests.fixtures.bundles import path as bundle_path


def _load(name: str):
    """Return an :class:`Analysis` from one of the test fixture bundles."""
    with BundleReader(bundle_path(name)) as b:
        return analyze_events(
            b.manifest, b.events(), cname_chains=b.cname_chains,
        )


# --- Hit.cdn_provider populated on real bundles ---------------------------


def test_hotjar_hit_on_cultuurkuur_is_tagged_with_provider() -> None:
    """cultuurkuur has metrics.hotjar.io → eks.hotjar.com — Hotjar
    vendor_own."""
    a = _load("cultuurkuur.zip")
    hotjar_hits = [
        h for h in a.hits
        if h.host.endswith("hotjar.io") or h.host.endswith("hotjar.com")
    ]
    assert hotjar_hits, "expected Hotjar hits in cultuurkuur"
    tagged = [h for h in hotjar_hits if h.cdn_provider is not None]
    assert tagged, "expected at least one Hotjar hit tagged with a CDN provider"
    assert tagged[0].cdn_provider.name == "Hotjar"


def test_facebook_hit_on_aalst_is_tagged_meta() -> None:
    """aalst has connect.facebook.net → fbcdn.net."""
    a = _load("aalst.zip")
    fb_hits = [
        h for h in a.hits
        if h.host.endswith("facebook.net") or h.host.endswith("facebook.com")
    ]
    assert fb_hits, "expected Facebook hits in aalst"
    tagged_meta = [
        h for h in fb_hits
        if h.cdn_provider is not None and "Meta" in h.cdn_provider.name
    ]
    assert tagged_meta, (
        "expected at least one Facebook hit tagged via fbcdn → Meta"
    )


# --- UnclassifiedHost.cdn_provider populated on real bundles --------------
#
# Anchored on the deliberately-foreign hindustantimes fixture: an Indian
# news site saturated with ad-tech whose hosts will never warrant an
# EU-public-sector module, so they stay reliably unclassified. (Brecht's
# old azureedge anchor moved to a Hit assertion once the azure_cdn module
# claimed it — see ``test_brecht_azureedge_hit_is_tagged_azure_front_door``.)


def test_unclassified_host_carries_cdn_provider_via_cname_chain() -> None:
    """An unclassified host gets explained by its CNAME chain — solving the
    'why is this unclassified, and whose infrastructure is it?' question.

    ``analytics.htmedia.in`` is Hindustan Times' own in-house analytics
    (HT Media Ltd, India), CNAME-fronted by Akamai — a stable foreign
    host the project will never classify."""
    a = _load("hindustantimes.zip")
    doc = build_report_document(a)
    htmedia = [
        u for u in doc.unclassified_hosts if u.host == "analytics.htmedia.in"
    ]
    assert htmedia, "expected analytics.htmedia.in among unclassified hosts"
    provider = htmedia[0].cdn_provider
    assert provider is not None
    assert provider.name == "Akamai"
    assert provider.jurisdiction == "US"


def test_brecht_azureedge_hit_is_tagged_azure_front_door() -> None:
    """Brecht's azureedge.net host is now claimed by the azure_cdn module;
    the CNAME tail still resolves to Azure Front Door on the resulting
    Hit (the same CNAME→provider wiring, via the Hit consumer)."""
    a = _load("brecht.zip")
    azure_hits = [h for h in a.hits if h.module_id == "azure_cdn"]
    assert azure_hits, "expected an azure_cdn hit on brecht"
    provider = azure_hits[0].cdn_provider
    assert provider is not None
    assert "Azure" in provider.name


# --- chains roundtrip ------------------------------------------------------


def test_analysis_carries_cname_chains() -> None:
    """The Analysis exposes the raw chains for downstream consumers
    (the report builder, future feature work)."""
    a = _load("brecht.zip")
    assert isinstance(a.cname_chains, dict)
    assert a.cname_chains, "expected at least one chain on brecht"
    # The known azureedge host is present in the dict (lowercased).
    keys = list(a.cname_chains)
    assert any("azureedge" in k for k in keys)
