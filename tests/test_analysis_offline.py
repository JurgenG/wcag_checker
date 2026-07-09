"""``analyze_bundle`` consumes stored enrichment — strictly offline
(pipeline-split Phase 3).

The live probes are gone from the analysis phase: posture comes from
the bundle's ``enrichment.json`` (written at capture close), and an
un-enriched bundle yields an honest "posture not captured" rather
than a silent re-probe — silent fallback would staple today's DNS
onto last month's capture.

The offline guarantee is enforced for real: ``socket.getaddrinfo``
is rigged to explode for the duration of every test here.
"""

from __future__ import annotations

import shutil
import socket
from pathlib import Path

import pytest

from leak_inspector import modules  # noqa: F401  (registers detectors)
from leak_inspector.analysis import analyze_bundle
from leak_inspector.bundle.reader import BundleReader
from leak_inspector.dns_posture.types import DNSPosture, DNSSECStatus, IPInfo
from leak_inspector.enrichment import CMSVersionProbe, Enrichment
from leak_inspector.enrichment.producer import (
    strip_enrichment,
    write_enrichment,
)
from leak_inspector.http_posture.probe import HostProbe, TransportPosture

from tests.fixtures.bundles import path as bundle_path


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Any DNS/socket resolution during these tests is a failure."""
    def explode(*args, **kwargs):
        raise AssertionError("network touched during offline analysis")

    monkeypatch.setattr(socket, "getaddrinfo", explode)


def _transport() -> TransportPosture:
    return TransportPosture(
        primary=HostProbe(
            host="www.cultuurkuur.be", http_responded=True,
            https_responded=True, http_status=301, https_status=200,
            http_final_url="https://www.cultuurkuur.be/",
            https_final_url="https://www.cultuurkuur.be/",
        ),
        alternate=None,
    )


def _enrichment(**overrides) -> Enrichment:
    base = dict(
        enriched_at="2026-06-07T15:00:00Z",
        dns_posture=DNSPosture(
            domain="cultuurkuur.be",
            looked_up_at="2026-06-07T15:00:00Z",
            dnssec=DNSSECStatus(
                parent_has_ds=True, zone_has_dnskey=True, summary="signed",
            ),
        ),
        transport_posture=_transport(),
        cms_probe=None,
        host_ipinfo={},
    )
    base.update(overrides)
    return Enrichment(**base)


@pytest.fixture
def enriched_bundle(tmp_path) -> Path:
    target = tmp_path / "site.zip"
    shutil.copy(bundle_path("cultuurkuur.zip"), target)
    write_enrichment(target, _enrichment())
    return target


@pytest.fixture
def bare_bundle(tmp_path) -> Path:
    """A pre-enrichment-era bundle (the committed fixture's pinned
    enrichment stripped off)."""
    target = tmp_path / "bare.zip"
    shutil.copy(bundle_path("cultuurkuur.zip"), target)
    strip_enrichment(target)
    return target


# --- BundleReader exposure -----------------------------------------------------


def test_reader_returns_stored_enrichment(enriched_bundle) -> None:
    with BundleReader(enriched_bundle) as b:
        enrichment = b.enrichment
    assert enrichment == _enrichment()


def test_reader_returns_none_when_absent(bare_bundle) -> None:
    with BundleReader(bare_bundle) as b:
        assert b.enrichment is None


# --- offline consumption ---------------------------------------------------------


def test_posture_comes_from_the_artifact(enriched_bundle) -> None:
    analysis = analyze_bundle(enriched_bundle)
    assert analysis.dns_posture.dnssec.parent_has_ds is True
    assert analysis.transport_posture == _transport()
    assert analysis.enriched_at == "2026-06-07T15:00:00Z"


def test_unenriched_bundle_has_no_posture_and_no_silent_probe(bare_bundle) -> None:
    """No artifact → posture honestly absent (never re-probed)."""
    analysis = analyze_bundle(bare_bundle)
    assert analysis.dns_posture is None
    assert analysis.transport_posture is None
    assert analysis.enriched_at is None


def test_cms_probe_result_is_applied(tmp_path) -> None:
    """A stored version-probe result upgrades the passive fingerprint,
    with the same evidence wording the live probe used to add."""
    target = tmp_path / "site.zip"
    shutil.copy(bundle_path("nbb.zip"), target)
    # nbb's passive detection finds Drupal without a version.
    write_enrichment(target, _enrichment(cms_probe=CMSVersionProbe(
        platform="Drupal", version="10.2.1",
        probe_url="https://www.nbb.be/CHANGELOG.txt",
    )))
    analysis = analyze_bundle(target)
    assert analysis.cms_fingerprint.version == "10.2.1"
    assert "version probed at" in analysis.cms_fingerprint.evidence


def test_cms_probe_negative_result_is_noted(tmp_path) -> None:
    target = tmp_path / "site.zip"
    shutil.copy(bundle_path("nbb.zip"), target)
    write_enrichment(target, _enrichment(cms_probe=CMSVersionProbe(
        platform="Drupal", version=None,
        probe_url="https://www.nbb.be/CHANGELOG.txt",
    )))
    analysis = analyze_bundle(target)
    assert analysis.cms_fingerprint.version is None
    assert "hardened/removed" in analysis.cms_fingerprint.evidence


def test_passively_found_version_wins_over_stored_probe(tmp_path) -> None:
    """cultuurkuur's passive detection already finds Drupal '10' — a
    stored probe result must not override what the traffic itself
    showed."""
    target = tmp_path / "site.zip"
    shutil.copy(bundle_path("cultuurkuur.zip"), target)
    write_enrichment(target, _enrichment(cms_probe=CMSVersionProbe(
        platform="Drupal", version="9.9.9",
        probe_url="https://www.cultuurkuur.be/CHANGELOG.txt",
    )))
    analysis = analyze_bundle(target)
    assert analysis.cms_fingerprint.version == "10"


# --- report surface ---------------------------------------------------------


def test_document_carries_enriched_at(enriched_bundle) -> None:
    from leak_inspector.report.builder import build_report_document

    doc = build_report_document(analyze_bundle(enriched_bundle))
    assert doc.enriched_at == "2026-06-07T15:00:00Z"


def test_document_carries_section_timestamps(tmp_path) -> None:
    """Per-section timestamps survive offline analysis into the document."""
    from leak_inspector.report.builder import build_report_document

    target = tmp_path / "site.zip"
    shutil.copy(bundle_path("cultuurkuur.zip"), target)
    write_enrichment(target, _enrichment(section_timestamps={
        "dns": "2026-06-07T15:00:00Z",
        "cms-probe": "2026-06-19T09:00:00Z",
    }))
    doc = build_report_document(analyze_bundle(target))
    assert doc.section_timestamps["cms-probe"] == "2026-06-19T09:00:00Z"


def test_text_report_notes_a_reprobed_section(tmp_path) -> None:
    """A section whose timestamp differs from the baseline is called out
    so a mixed-age posture is not silently presented as one date."""
    from leak_inspector.report.builder import build_report_document
    from leak_inspector.report.text import render_text_document

    target = tmp_path / "site.zip"
    shutil.copy(bundle_path("cultuurkuur.zip"), target)
    write_enrichment(target, _enrichment(section_timestamps={
        "dns": "2026-06-07T15:00:00Z",
        "transport": "2026-06-07T15:00:00Z",
        "cms-probe": "2026-06-19T09:00:00Z",
    }))
    out = render_text_document(
        build_report_document(analyze_bundle(target)), color=False,
    )
    assert "2026-06-07T15:00:00Z" in out   # baseline
    assert "cms-probe" in out
    assert "2026-06-19T09:00:00Z" in out   # the re-probe time


def test_security_txt_comes_from_the_artifact(tmp_path) -> None:
    """The stored security.txt probe reaches Analysis + document offline."""
    from leak_inspector.http_posture.security_txt import SecurityTxtProbe
    from leak_inspector.report.builder import build_report_document

    probe = SecurityTxtProbe(
        url="https://www.cultuurkuur.be/.well-known/security.txt",
        found=True, status=200, content_type="text/plain", has_contact=True,
    )
    target = tmp_path / "site.zip"
    shutil.copy(bundle_path("cultuurkuur.zip"), target)
    write_enrichment(target, _enrichment(security_txt=probe))
    analysis = analyze_bundle(target)
    assert analysis.security_txt == probe
    assert build_report_document(analysis).security_txt == probe


def test_security_txt_none_when_artifact_predates_it(enriched_bundle) -> None:
    analysis = analyze_bundle(enriched_bundle)
    assert analysis.security_txt is None


def test_document_enriched_at_none_when_unenriched(bare_bundle) -> None:
    """The un-enriched document says so (renderers point the operator
    at the `leak-inspector enrich` command)."""
    from leak_inspector.report.builder import build_report_document

    doc = build_report_document(analyze_bundle(bare_bundle))
    assert doc.enriched_at is None
    assert doc.dns_posture is None
    assert doc.transport_posture is None


_BELGIUM_MAX = Path("captures/belgium-max.zip")


@pytest.mark.skipif(
    not _BELGIUM_MAX.is_file(),
    reason="working-dataset bundle captures/belgium-max.zip not present",
)
def test_host_ipinfo_feeds_the_self_hosted_collector_seam(tmp_path) -> None:
    """The stored host map satisfies the same seam the live enricher
    filled: a self-hosted Matomo collector host (matomo.bosa.be, with
    real /matomo.php hits) gets its IPInfo offline. (The seam's
    behavior inside analyze_events is covered hermetically by
    test_analysis_snowplow_asn.py and friends; this proves
    analyze_bundle threads the stored map into it.)"""
    target = tmp_path / "site.zip"
    shutil.copy(_BELGIUM_MAX, target)
    info = IPInfo(
        address="203.0.113.80", version=4, asn=64500,
        as_org="Example Hosting", country_code="BE", country_name="Belgium",
    )
    write_enrichment(target, _enrichment(
        host_ipinfo={"matomo.bosa.be": info},
    ))
    analysis = analyze_bundle(target)
    matomo_hits = [h for h in analysis.hits if h.module_id == "matomo"]
    assert matomo_hits
    geo_params = [
        p for hit in matomo_hits for p in hit.params
        if "AS64500" in str(p.value) or "Example Hosting" in str(p.value)
    ]
    assert geo_params, "stored IPInfo never reached the collector params"
