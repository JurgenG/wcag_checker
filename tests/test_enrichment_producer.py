"""Tests for the enrichment producer (pipeline-split Phase 2).

``enrich_bundle`` runs the live-network phase once and stores the
result as the ``enrichment.json`` entry inside the capture zip. All
tests are hermetic: every network-touching step is an injectable seam
(``dns_lookup_fn`` / ``transport_prober`` / ``cms_prober`` /
``hosts_enricher``), so fakes prove the orchestration, the zip
round-trip, idempotence and soft-fail behavior without one packet.
Real lookups are exercised out-of-band (the retrofit run in Phase 4).
"""

from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path

import pytest

from leak_inspector.bundle.reader import BundleReader
from leak_inspector.dns_posture.types import DNSPosture, IPInfo
from leak_inspector.enrichment import (
    ENRICHMENT_SECTIONS,
    ENRICHMENT_ZIP_ENTRY,
    CMSVersionProbe,
    Enrichment,
    enrichment_from_json,
)
from leak_inspector.enrichment.producer import (
    ENRICH_ALL_HOSTS_CAP,
    enrich_bundle,
    read_enrichment,
    strip_enrichment,
    write_enrichment,
)
from leak_inspector.http_posture.probe import HostProbe, TransportPosture
from leak_inspector.http_posture.tls import TLSPosture

from tests.fixtures.bundles import path as bundle_path


# --- fakes -------------------------------------------------------------------


def _fake_dns(domain: str) -> DNSPosture:
    return DNSPosture(domain=domain, looked_up_at="2026-06-07T13:00:00Z")


def _fake_transport(*, landing_url: str, base_domain: str) -> TransportPosture:
    return TransportPosture(
        primary=HostProbe(
            host=base_domain, http_responded=True, https_responded=True,
            http_status=301, https_status=200,
            http_final_url=f"https://{base_domain}/",
            https_final_url=f"https://{base_domain}/",
        ),
        alternate=None,
    )


def _fake_hosts_enricher(hosts: list[str]) -> dict[str, IPInfo | None]:
    return {
        h: IPInfo(address="203.0.113.1", version=4, asn=64500, as_org="Fake")
        for h in hosts
    }


def _fake_cms(events, base_url: str) -> CMSVersionProbe | None:
    return CMSVersionProbe(
        platform="Drupal", version="10.1",
        probe_url=f"{base_url}CHANGELOG.txt",
    )


def _fake_security_txt(host: str):
    from leak_inspector.http_posture.security_txt import SecurityTxtProbe

    return SecurityTxtProbe(
        url=f"https://{host}/.well-known/security.txt",
        found=True, status=200, content_type="text/plain", has_contact=True,
    )


def _fake_tls(host: str) -> TLSPosture:
    return TLSPosture(
        host=host, connected=True, protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        cert_not_after="2026-09-01T00:00:00Z", days_until_expiry=86,
        issuer="Let's Encrypt", subject_cn=host, verify_error="",
        legacy_tls10="rejected", legacy_tls11="rejected",
    )


_SEAMS = dict(
    dns_lookup_fn=_fake_dns,
    transport_prober=_fake_transport,
    cms_prober=_fake_cms,
    hosts_enricher=_fake_hosts_enricher,
    security_txt_prober=_fake_security_txt,
    tls_prober=_fake_tls,
    now_fn=lambda: "2026-06-07T13:00:05Z",
)


@pytest.fixture
def bundle(tmp_path) -> Path:
    """A throwaway copy of a real capture bundle, reset to its
    pre-enrichment state (the committed fixtures carry a pinned
    enrichment; these tests exercise first-enrichment semantics)."""
    target = tmp_path / "site.zip"
    shutil.copy(bundle_path("cultuurkuur.zip"), target)
    strip_enrichment(target)
    return target


# --- building ----------------------------------------------------------------


def test_enrich_bundle_fills_every_section(bundle) -> None:
    enrichment, created = enrich_bundle(bundle, **_SEAMS)
    assert created is True
    assert enrichment.enriched_at == "2026-06-07T13:00:05Z"
    assert enrichment.dns_posture.domain == "cultuurkuur.be"
    assert enrichment.transport_posture.primary.https_responded is True
    assert enrichment.cms_probe.platform == "Drupal"
    assert enrichment.security_txt.found is True
    assert enrichment.tls_posture.connected is True
    assert enrichment.errors == []


def test_tls_probed_on_the_landing_host(bundle) -> None:
    """The TLS probe targets the host the visitor actually landed on."""
    seen: list[str] = []

    def recording(host: str):
        seen.append(host)
        return _fake_tls(host)

    enrich_bundle(bundle, **{**_SEAMS, "tls_prober": recording})
    assert seen == ["www.cultuurkuur.be"]


def test_tls_probe_soft_fails(bundle) -> None:
    def explode(host: str):
        raise RuntimeError("handshake blew up")

    enrichment, _ = enrich_bundle(bundle, **{**_SEAMS, "tls_prober": explode})
    assert enrichment.tls_posture is None
    assert any(e.startswith("TLS probe") for e in enrichment.errors)
    # The other sections are unaffected.
    assert enrichment.dns_posture is not None


def test_partial_refresh_tls_only(bundle) -> None:
    """``--refresh tls`` re-probes only TLS, leaving the rest verbatim."""
    first, _ = enrich_bundle(bundle, **_SEAMS)

    def explode(*a, **k):
        raise AssertionError("unrelated section must not be re-probed")

    def new_tls(host):
        return TLSPosture(host=host, connected=True, protocol="TLSv1.2")

    refreshed, _ = enrich_bundle(
        bundle, sections=frozenset({"tls"}),
        dns_lookup_fn=explode, transport_prober=explode,
        hosts_enricher=explode, security_txt_prober=explode,
        cms_prober=explode, tls_prober=new_tls,
        now_fn=lambda: "2026-06-19T09:00:00Z",
    )
    assert refreshed.tls_posture.protocol == "TLSv1.2"
    assert refreshed.section_timestamps["tls"] == "2026-06-19T09:00:00Z"
    assert refreshed.dns_posture == first.dns_posture
    assert refreshed.enriched_at == "2026-06-07T13:00:05Z"


def test_security_txt_probed_on_the_landing_host(bundle) -> None:
    """The probe targets the host the visitor actually landed on."""
    seen: list[str] = []

    def recording(host: str):
        seen.append(host)
        return _fake_security_txt(host)

    enrich_bundle(bundle, **{**_SEAMS, "security_txt_prober": recording})
    assert seen == ["www.cultuurkuur.be"]


def test_security_txt_probe_soft_fails(bundle) -> None:
    def explode(host: str):
        raise RuntimeError("probe blew up")

    enrichment, _ = enrich_bundle(
        bundle, **{**_SEAMS, "security_txt_prober": explode},
    )
    assert enrichment.security_txt is None
    assert any("security.txt" in e for e in enrichment.errors)
    # The other sections are unaffected.
    assert enrichment.dns_posture is not None


def test_enrich_bundle_enriches_all_request_hosts(bundle) -> None:
    enrichment, _ = enrich_bundle(bundle, **_SEAMS)
    hosts = set(enrichment.host_ipinfo)
    # The capture's own host and a known third-party host are covered.
    assert "www.cultuurkuur.be" in hosts
    assert any("google" in h for h in hosts)
    assert all(info is not None for info in enrichment.host_ipinfo.values())


def test_host_list_is_capped_and_deterministic(bundle, monkeypatch) -> None:
    """A hostile bundle with thousands of fabricated hosts must not fan
    out unbounded lookups; the cap keeps the prefix stable (sorted)."""
    from leak_inspector.enrichment import producer as producer_module
    monkeypatch.setattr(producer_module, "ENRICH_ALL_HOSTS_CAP", 5)
    seen: list[list[str]] = []

    def recording_enricher(hosts):
        seen.append(list(hosts))
        return {h: None for h in hosts}

    enrich_bundle(bundle, **{**_SEAMS, "hosts_enricher": recording_enricher})
    assert len(seen) == 1
    assert len(seen[0]) == 5
    assert seen[0] == sorted(seen[0])


# --- persistence into the zip --------------------------------------------------


def test_enrichment_is_written_into_the_bundle(bundle) -> None:
    enrichment, _ = enrich_bundle(bundle, **_SEAMS)
    with zipfile.ZipFile(bundle) as zf:
        raw = zf.read(ENRICHMENT_ZIP_ENTRY).decode("utf-8")
    assert enrichment_from_json(raw) == enrichment


def test_bundle_stays_readable_after_enrichment(bundle) -> None:
    enrich_bundle(bundle, **_SEAMS)
    with BundleReader(bundle) as b:
        assert b.manifest.base_domain == "cultuurkuur.be"
        assert sum(1 for _ in b.events()) > 0


def test_read_enrichment_round_trips(bundle) -> None:
    enrichment, _ = enrich_bundle(bundle, **_SEAMS)
    assert read_enrichment(bundle) == enrichment


def test_read_enrichment_absent_returns_none(bundle) -> None:
    assert read_enrichment(bundle) is None


# --- idempotence / refresh ------------------------------------------------------


def test_second_enrich_is_a_no_op_returning_existing(bundle) -> None:
    first, created1 = enrich_bundle(bundle, **_SEAMS)

    def explode(*a, **k):
        raise AssertionError("network seam must not be called on a no-op")

    second, created2 = enrich_bundle(
        bundle,
        dns_lookup_fn=explode, transport_prober=explode,
        cms_prober=explode, hosts_enricher=explode,
        now_fn=lambda: "2099-01-01T00:00:00Z",
    )
    assert created1 is True and created2 is False
    assert second == first


def test_full_enrich_stamps_every_section_at_enriched_at(bundle) -> None:
    """A full enrichment records one per-section timestamp per section,
    all equal to the baseline ``enriched_at``."""
    enrichment, _ = enrich_bundle(bundle, **_SEAMS)
    assert set(enrichment.section_timestamps) == set(ENRICHMENT_SECTIONS)
    assert all(
        ts == enrichment.enriched_at
        for ts in enrichment.section_timestamps.values()
    )


def test_partial_refresh_reruns_only_the_named_section(bundle) -> None:
    """``sections={...}`` re-probes only those sections; the others are
    never touched and the baseline ``enriched_at`` is preserved."""
    first, _ = enrich_bundle(bundle, **_SEAMS)

    def explode(*a, **k):
        raise AssertionError("unrelated section must not be re-probed")

    def new_cms(events, base_url):
        return CMSVersionProbe(
            platform="Drupal", version="11.0",
            probe_url=f"{base_url}core/CHANGELOG.txt",
        )

    refreshed, created = enrich_bundle(
        bundle,
        sections=frozenset({"cms-probe"}),
        dns_lookup_fn=explode, transport_prober=explode,
        hosts_enricher=explode, security_txt_prober=explode,
        cms_prober=new_cms,
        now_fn=lambda: "2026-06-19T09:00:00Z",
    )
    assert created is True
    # The baseline timestamp is the contemporaneous one, untouched.
    assert refreshed.enriched_at == first.enriched_at == "2026-06-07T13:00:05Z"
    # Only the cms-probe section changed and was re-stamped.
    assert refreshed.cms_probe.version == "11.0"
    assert refreshed.section_timestamps["cms-probe"] == "2026-06-19T09:00:00Z"
    assert refreshed.section_timestamps["dns"] == "2026-06-07T13:00:05Z"
    # Untouched sections are preserved verbatim.
    assert refreshed.dns_posture == first.dns_posture
    assert refreshed.transport_posture == first.transport_posture
    # And the partial update is what got persisted.
    assert read_enrichment(bundle).cms_probe.version == "11.0"


def test_partial_refresh_upgrades_artifact_version(bundle) -> None:
    """Writing per-section data must label the artifact at the current
    schema version, even when merging into an older one."""
    from leak_inspector.enrichment import ENRICHMENT_VERSION

    first, _ = enrich_bundle(bundle, **_SEAMS)
    first.version = 1  # simulate an artifact written by an older build
    write_enrichment(bundle, first)

    refreshed, _ = enrich_bundle(
        bundle, sections=frozenset({"cms-probe"}),
        **{**_SEAMS, "now_fn": lambda: "2026-06-19T09:00:00Z"},
    )
    assert refreshed.version == ENRICHMENT_VERSION


def test_partial_refresh_without_existing_enrichment_raises(bundle) -> None:
    """Selective refresh has nothing to merge into on an un-enriched
    bundle — refuse rather than silently doing a full enrich."""
    with pytest.raises(ValueError, match="run a full enrich first"):
        enrich_bundle(bundle, sections=frozenset({"cms-probe"}), **_SEAMS)


def test_partial_refresh_keeps_other_sections_errors(bundle) -> None:
    """Refreshing one section must not drop another section's recorded
    warning, but does add its own freshly-computed one."""
    def dns_boom(domain):
        raise OSError("resolver down")

    first, _ = enrich_bundle(bundle, **{**_SEAMS, "dns_lookup_fn": dns_boom})
    assert any("DNS posture" in e for e in first.errors)

    def cms_boom(events, base_url):
        raise RuntimeError("changelog 500")

    refreshed, _ = enrich_bundle(
        bundle, sections=frozenset({"cms-probe"}),
        **{**_SEAMS, "cms_prober": cms_boom},
    )
    assert any("DNS posture" in e for e in refreshed.errors)
    assert any("CMS version probe" in e for e in refreshed.errors)


def test_partial_refresh_clears_stale_error_for_that_section(bundle) -> None:
    """A section that failed before but now succeeds must not keep its
    stale error after a selective refresh."""
    def cms_boom(events, base_url):
        raise RuntimeError("changelog 500")

    enrich_bundle(bundle, **{**_SEAMS, "cms_prober": cms_boom})
    refreshed, _ = enrich_bundle(
        bundle, sections=frozenset({"cms-probe"}), **_SEAMS,
    )
    assert not any("CMS version probe" in e for e in refreshed.errors)


def test_refresh_replaces_the_artifact(bundle) -> None:
    enrich_bundle(bundle, **_SEAMS)
    refreshed, created = enrich_bundle(
        bundle, refresh=True,
        **{**_SEAMS, "now_fn": lambda: "2026-07-01T00:00:00Z"},
    )
    assert created is True
    assert refreshed.enriched_at == "2026-07-01T00:00:00Z"
    # Exactly one enrichment entry in the zip — replaced, not duplicated.
    with zipfile.ZipFile(bundle) as zf:
        names = [n for n in zf.namelist() if n == ENRICHMENT_ZIP_ENTRY]
    assert len(names) == 1
    assert read_enrichment(bundle).enriched_at == "2026-07-01T00:00:00Z"


# --- soft-fail -----------------------------------------------------------------


def test_failed_sections_are_recorded_not_raised(bundle) -> None:
    """One section blowing up must not lose the others — the artifact
    records the failure in plain language instead."""
    def dns_boom(domain):
        raise OSError("resolver unreachable")

    enrichment, created = enrich_bundle(
        bundle, **{**_SEAMS, "dns_lookup_fn": dns_boom},
    )
    assert created is True
    assert enrichment.dns_posture is None
    assert enrichment.transport_posture is not None  # others survived
    assert any("dns" in e.lower() for e in enrichment.errors)
    # And the partial artifact is what got persisted.
    assert read_enrichment(bundle).dns_posture is None


# --- base_domain SSRF guard ----------------------------------------------------
#
# The DNS-posture lookup feeds the manifest's ``base_domain`` to the analyst's
# resolver. A hostile bundle could set it to a non-public name (``localhost``,
# a raw IP, an internal TLD) for resolver-side reconnaissance. The producer
# refuses to query anything that is not a public registrable domain.


def _patch_base_domain(bundle: Path, value: str) -> None:
    """Rewrite the zip's ``manifest.json`` with a different ``base_domain``."""
    with zipfile.ZipFile(bundle) as zf:
        names = zf.namelist()
        blobs = {n: zf.read(n) for n in names}
    manifest = json.loads(blobs["manifest.json"])
    manifest["base_domain"] = value
    blobs["manifest.json"] = json.dumps(manifest).encode("utf-8")
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as zf:
        for n in names:
            zf.writestr(n, blobs[n])


@pytest.mark.parametrize(
    "name, expected",
    [
        ("example.com", True),
        ("cultuurkuur.be", True),
        ("metrics.example.co.uk", True),
        ("localhost", False),
        ("internal", False),
        ("10.0.0.5", False),
        ("127.0.0.1", False),
        ("foo", False),
        ("", False),
    ],
)
def test_is_public_registrable_domain(name: str, expected: bool) -> None:
    from leak_inspector.enrichment.producer import _is_public_registrable_domain
    assert _is_public_registrable_domain(name) is expected


def test_dns_posture_skipped_for_non_public_base_domain(bundle) -> None:
    _patch_base_domain(bundle, "localhost")

    def dns_must_not_run(domain):
        raise AssertionError(
            "resolver must not be queried for a non-public base_domain"
        )

    enrichment, created = enrich_bundle(
        bundle, **{**_SEAMS, "dns_lookup_fn": dns_must_not_run},
    )
    assert created is True
    assert enrichment.dns_posture is None
    assert any("base_domain" in e for e in enrichment.errors)
    # The guard is scoped to the DNS posture — the other sections still ran.
    assert enrichment.transport_posture is not None
    assert enrichment.cms_probe is not None
