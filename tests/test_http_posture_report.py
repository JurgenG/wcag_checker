"""Integration tests: transport posture data flows through to the report.

Pins the wiring across the pipeline phases: the *enrichment* producer
running the transport probe (injected fetcher, hermetic), storing the
posture in the bundle; then ``analyze_bundle`` consuming it offline
and ``build_report_document`` deriving findings. Uses a real bundle
on disk so the bundle reader, manifest, and event parsing are part of
the test surface.
"""

from __future__ import annotations

import shutil

import pytest

from leak_inspector.analysis import analyze_bundle
from leak_inspector.enrichment.producer import (
    _live_transport_prober,
    enrich_bundle,
    strip_enrichment,
)
from leak_inspector.report.builder import build_report_document

from tests.fixtures.bundles import path as bundle_path


def _enrich_with_transport_fetcher(bundle, fetcher, tls_prober=None) -> None:
    """Run a real enrichment whose only live piece is the transport
    prober, with the HTTP fetch replaced by ``fetcher``.

    Every other network seam is stubbed (TLS included) so the test stays
    hermetic; pass ``tls_prober`` to exercise the TLS-posture surfacing.
    """
    enrich_bundle(
        bundle,
        dns_lookup_fn=lambda domain: None,
        transport_prober=lambda *, landing_url, base_domain: (
            _live_transport_prober(
                landing_url=landing_url, base_domain=base_domain,
                fetcher=fetcher,
            )
        ),
        cms_prober=lambda events, base_url: None,
        hosts_enricher=lambda hosts: {},
        tls_prober=tls_prober or (lambda host: None),
        now_fn=lambda: "2026-06-07T16:00:00Z",
    )


def _ideal_https_fetcher(url: str) -> dict | None:
    if url.startswith("http://"):
        return {"status": 301, "final_url": url.replace("http://", "https://", 1)}
    return {"status": 200, "final_url": url}


def _broken_https_fetcher(url: str) -> dict | None:
    if url.startswith("https://"):
        return None
    return {"status": 200, "final_url": url}


@pytest.fixture
def bundle(tmp_path):
    target = tmp_path / "site.zip"
    shutil.copy(bundle_path("cultuurkuur.zip"), target)
    strip_enrichment(target)  # committed fixture carries a pinned artifact
    return target


def test_analyze_bundle_populates_transport_posture(bundle) -> None:
    _enrich_with_transport_fetcher(bundle, _ideal_https_fetcher)
    analysis = analyze_bundle(bundle)
    assert analysis.transport_posture is not None
    assert analysis.transport_posture.primary.https_responded is True


def test_analyze_bundle_populates_tls_posture(bundle) -> None:
    from leak_inspector.http_posture.tls import TLSPosture

    def fake_tls(host):
        return TLSPosture(
            host=host, connected=True, protocol="TLSv1.3",
            issuer="Let's Encrypt", days_until_expiry=42, verify_error="",
        )

    _enrich_with_transport_fetcher(
        bundle, _ideal_https_fetcher, tls_prober=fake_tls,
    )
    analysis = analyze_bundle(bundle)
    assert analysis.tls_posture is not None
    assert analysis.tls_posture.protocol == "TLSv1.3"
    assert analysis.tls_posture.days_until_expiry == 42


def test_high_severity_finding_when_tls_cert_invalid(bundle) -> None:
    from leak_inspector.http_posture.tls import TLSPosture

    def bad_tls(host):
        return TLSPosture(
            host=host, connected=True, protocol="TLSv1.2",
            verify_error="certificate has expired",
        )

    _enrich_with_transport_fetcher(
        bundle, _ideal_https_fetcher, tls_prober=bad_tls,
    )
    analysis = analyze_bundle(bundle)
    document = build_report_document(analysis)
    headlines = [f.headline for f in document.executive_summary.findings]
    assert any("certificate" in h.lower() for h in headlines), (
        f"expected a TLS certificate finding; got {headlines!r}"
    )


def test_high_severity_finding_when_https_broken(bundle) -> None:
    _enrich_with_transport_fetcher(bundle, _broken_https_fetcher)
    analysis = analyze_bundle(bundle)
    document = build_report_document(analysis)
    headlines = [f.headline for f in document.executive_summary.findings]
    assert any("HTTPS" in h for h in headlines), (
        f"expected a HTTPS-related finding; got {headlines!r}"
    )


def test_no_transport_finding_when_https_is_clean(bundle) -> None:
    _enrich_with_transport_fetcher(bundle, _ideal_https_fetcher)
    analysis = analyze_bundle(bundle)
    document = build_report_document(analysis)
    transport_headlines = [
        f.headline for f in document.executive_summary.findings
        if "HTTPS" in f.headline or "HTTP " in f.headline
        or "redirect" in f.headline.lower()
    ]
    assert transport_headlines == []
