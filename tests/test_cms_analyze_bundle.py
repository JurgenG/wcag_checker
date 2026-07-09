"""Integration test for the full CMS pipeline across the phase split.

Exercises the path unit tests can't reach, end to end across the
pipeline phases: the *enrichment* producer running passive detection
plus the version probe (injected fetcher, no network), storing the
result in the bundle; then ``analyze_bundle`` consuming it offline
and ``build_report_document`` applying EOL judgment.

Uses a real on-disk bundle so the bundle reader, manifest, and event
parsing are all included in the test surface.
"""

from __future__ import annotations

import shutil

import pytest

from leak_inspector.analysis import analyze_bundle
from leak_inspector.enrichment.producer import (
    _live_cms_prober,
    enrich_bundle,
    strip_enrichment,
)
from leak_inspector.report.builder import build_report_document

from tests.fixtures.bundles import path as bundle_path


def _enrich_with_cms_fetcher(bundle, fetcher) -> None:
    """Run a real enrichment whose only live piece is the CMS prober,
    with the HTTP fetch replaced by ``fetcher`` — the same seam the
    live probe exposes."""
    enrich_bundle(
        bundle,
        dns_lookup_fn=lambda domain: None,
        transport_prober=lambda *, landing_url, base_domain: None,
        cms_prober=lambda events, base_url: _live_cms_prober(
            events, base_url, fetcher=fetcher,
        ),
        hosts_enricher=lambda hosts: {},
        tls_prober=lambda host: None,
        now_fn=lambda: "2026-06-07T16:00:00Z",
    )


@pytest.fixture
def bundle(tmp_path):
    """Throwaway copy of the test-owned Drupal capture (originally
    www.aalst.be — kept under ``tests/fixtures/bundles/`` so a
    working-dataset regeneration can't break the suite)."""
    target = tmp_path / "drupal.zip"
    shutil.copy(bundle_path("aalst.zip"), target)
    strip_enrichment(target)  # committed fixture carries a pinned artifact
    return target


def test_probe_success_populates_version_and_evidence(bundle) -> None:
    """Fetcher returns a CHANGELOG.txt body at enrichment time → the
    version surfaces in the offline analysis."""
    fake_body = "Drupal 10.2.6, 2024-08-14\n----------------\n- Fix ...\n"
    _enrich_with_cms_fetcher(
        bundle, lambda url: fake_body if "CHANGELOG" in url else None,
    )

    analysis = analyze_bundle(bundle)
    fp = analysis.cms_fingerprint
    assert fp is not None
    assert fp.name == "Drupal"
    assert fp.version == "10.2.6"
    assert "version probed at" in fp.evidence


def test_probe_failure_records_attempt_in_evidence(bundle) -> None:
    """Fetcher returns None for every URL → fingerprint still has no
    version, but evidence makes the attempted probe visible."""
    _enrich_with_cms_fetcher(bundle, lambda url: None)

    analysis = analyze_bundle(bundle)
    fp = analysis.cms_fingerprint
    assert fp is not None
    assert fp.name == "Drupal"
    assert fp.version is None
    assert "version probe at" in fp.evidence
    assert "no result" in fp.evidence


def test_past_eol_drupal_7_flows_through_build_report_document(bundle) -> None:
    """End-to-end: probe returns a Drupal 7 version → ReportDocument
    carries the fingerprint with ``is_eol=True`` and the EOL note."""
    fake_body = "Drupal 7.99, 2024-08-14\n----------------\n"
    _enrich_with_cms_fetcher(
        bundle, lambda url: fake_body if "CHANGELOG" in url else None,
    )

    analysis = analyze_bundle(bundle)
    document = build_report_document(analysis)

    fp = document.cms_fingerprint
    assert fp is not None
    assert fp.name == "Drupal"
    assert fp.version == "7.99"
    assert fp.is_eol is True
    assert "Drupal 7" in fp.eol_note
    assert "2025-01-05" in fp.eol_note
