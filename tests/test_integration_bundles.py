"""Integration tests pinning exact properties of frozen capture bundles.

Each fixture bundle in ``tests/fixtures/bundles/`` has known
properties. This file asserts them precisely. The point is signal,
not coverage breadth: if the personal-data counter regresses, the
classifier loses a seed, the third-party-host filter inverts, or
the CNAME-provider lookup breaks, **at least one of these tests
fails** — that's what the unit-test suite I had before mostly didn't
do, because the synthetic fixtures were shaped to make every branch
green.

If a real bundle's properties drift (because the underlying analyser
changed how it counts something), the right fix is usually to verify
the new number is correct and update the ground-truth value here —
not to weaken the assertion.

Each helper loads its bundle via :func:`analyze_events` (the hermetic
path; no DNS / transport / CMS network calls). The integration with
``analyze_bundle`` is exercised separately in
``test_cms_analyze_bundle.py`` and ``test_http_posture_report.py``.
"""

from __future__ import annotations

import pytest

from leak_inspector.analysis import analyze_events
from leak_inspector.bundle.reader import BundleReader
from leak_inspector.modules.base import CAT_IDENTIFIER, CAT_PII
from leak_inspector.report.builder import build_report_document

from tests.fixtures.bundles import path as bundle_path


def _document(name: str):
    """Run the hermetic pipeline on a frozen test bundle."""
    with BundleReader(bundle_path(name)) as b:
        analysis = analyze_events(
            b.manifest, b.events(), cname_chains=b.cname_chains,
        )
    return analysis, build_report_document(analysis)


def _distinct_third_party_personal_fields(analysis) -> set[tuple[str, str, str]]:
    """Set of distinct ``(vendor, category, canonical_key)`` triples.

    One entry per (vendor, category, distinct field key). The same
    Google Analytics ``cid`` cookie sent on 100 beacons is ONE entry,
    not 100 — that's the honest "how many distinct identifiers are
    leaking" count.
    """
    from leak_inspector.report.builder import _canonical_key
    out: set[tuple[str, str, str]] = set()
    for hit in analysis.hits:
        if not analysis.is_third_party_host(hit.host):
            continue
        for p in hit.params:
            if p.category in (CAT_PII, CAT_IDENTIFIER):
                out.add((hit.module_name, p.category, _canonical_key(p.key)))
    return out


def _third_party_pii_field_count(analysis) -> int:
    """Distinct personal-data field count — the honest "fields leaking" total."""
    return len(_distinct_third_party_personal_fields(analysis))


def _third_party_trackers_with_pii(analysis) -> set[str]:
    """Module names of third-party trackers that emitted PII/identifier fields."""
    names: set[str] = set()
    for hit in analysis.hits:
        if not analysis.is_third_party_host(hit.host):
            continue
        if any(p.category in (CAT_PII, CAT_IDENTIFIER) for p in hit.params):
            names.add(hit.module_name)
    return names


def _modules_fired(analysis) -> set[str]:
    """Distinct third-party tracker module_ids that fired."""
    return {
        hit.module_id for hit in analysis.hits
        if analysis.is_third_party_host(hit.host)
    }


# ===========================================================================
# BRECHT — Belgian municipal site, Drupal, gov_flanders + Google Fonts +
#          an Azure CDN (azureedge.net) host. Zero third-party PII outflow.
#          The Azure-fronted host is now classified by the azure_cdn module.
# ===========================================================================


class TestBrecht:
    """Pinned properties of ``brecht.zip``."""

    @pytest.fixture
    def both(self):
        return _document("brecht.zip")

    def test_modules_fired_is_gov_flanders_google_fonts_azure_cdn(self, both):
        analysis, _ = both
        assert _modules_fired(analysis) == {
            "gov_flanders", "google_fonts", "azure_cdn",
        }

    def test_zero_third_party_pii_fields(self, both):
        analysis, _ = both
        assert _third_party_pii_field_count(analysis) == 0

    def test_no_third_party_trackers_with_pii(self, both):
        analysis, _ = both
        assert _third_party_trackers_with_pii(analysis) == set()

    def test_personal_data_line_is_canonical_zero_case(self, both):
        _, doc = both
        assert doc.verdict.personal_data_line == (
            "No citizen personal data was observed leaving the website "
            "during this scan."
        )

    def test_verdict_sentence_counts_two_external_vendors(self, both):
        _, doc = both
        # 3 modules (gov_flanders, google_fonts, azure_cdn), 0 unclassified
        # = 3 external vendors; the Azure CDN is the expected-infrastructure one.
        assert doc.verdict.top_sentences[0] == (
            "The site contacted 3 external vendors, 1 of which is "
            "expected infrastructure."
        )

    def test_azureedge_host_is_classified_by_azure_cdn(self, both):
        """The Azure-fronted host is now claimed by the azure_cdn module, so
        nothing remains unclassified on brecht."""
        analysis, doc = both
        assert doc.unclassified_hosts == []
        azure_hits = [h for h in analysis.hits if h.module_id == "azure_cdn"]
        assert azure_hits, "expected an azure_cdn hit on brecht"
        host = azure_hits[0]
        assert host.host == "rumst-p2-brecht.azureedge.net"
        # The CNAME tail still resolves to Azure Front Door (US) on the hit.
        assert host.cdn_provider is not None
        assert host.cdn_provider.name == "Azure Front Door"
        assert host.cdn_provider.jurisdiction == "US"

    def test_no_hidden_extraterritorial_finding(self, both):
        """Brecht's first-party host has no CNAME hop — finding stays silent."""
        _, doc = both
        assert not [
            f for f in doc.executive_summary.findings
            if f.kind == "hidden_extraterritorial_infra"
        ]


# ===========================================================================
# CULTUURKUUR — cultural-sector portal with heavy commercial trackers.
#               2 distinct third-party personal fields (GA4 cid + sid);
#               property/operator-scoped IDs classify as technical.
# ===========================================================================


class TestCultuurkuur:
    """Pinned properties of ``cultuurkuur.zip``."""

    @pytest.fixture
    def both(self):
        return _document("cultuurkuur.zip")

    def test_exactly_two_distinct_third_party_personal_fields(self, both):
        """Two distinct (vendor, category, canonical-key) triples. If
        the counter regresses to raw-occurrence counting (the same cid
        cookie sent on every beacon counted N times) this number jumps
        to ~57 and the test fires; if property-scoped IDs (tid, GTM
        container id, Maps key, Hotjar site_id) regress back to
        identifier it climbs back toward 8."""
        analysis, _ = both
        assert _third_party_pii_field_count(analysis) == 2

    def test_distinct_personal_fields_per_vendor_breakdown(self, both):
        """The 2 distinct fields, broken down per vendor. Pins the exact
        per-tracker distribution so a regression in any single tracker's
        param classification surfaces here."""
        analysis, _ = both
        from collections import Counter
        counts = Counter(
            vendor for vendor, _, _ in
            _distinct_third_party_personal_fields(analysis)
        )
        assert dict(counts) == {
            "Google Analytics 4": 2,  # cid, sid
        }

    def test_personal_fields_originate_from_ga4_only(self, both):
        """Google Ads / Maps / GTM / Hotjar ship only property-scoped
        keys (tid, id, key, site_id) here — technical, not personal."""
        analysis, _ = both
        assert _third_party_trackers_with_pii(analysis) == {
            "Google Analytics 4",
        }

    def test_twelve_distinct_third_party_modules_fire(self, both):
        analysis, _ = both
        assert _modules_fired(analysis) == {
            "addtoany", "cloudflare_cdn", "cookie_script", "ga4", "google_ads",
            "google_fonts", "google_maps", "google_misc", "googletagmanager",
            "gstatic", "hotjar", "youtube",
        }

    def test_personal_data_line_reports_distinct_count_and_trackers(self, both):
        _, doc = both
        assert doc.verdict.personal_data_line == (
            "2 distinct personal-data fields observed leaving via 1 tracker: "
            "Google Analytics 4."
        )

    def test_unclassified_host_is_the_known_one(self, both):
        # static.addtoany.com is now classified (addtoany module); only the
        # Popupsmart popup host remains unclassified on cultuurkuur.
        _, doc = both
        hosts = {u.host for u in doc.unclassified_hosts}
        assert hosts == {
            "cdn.popupsmart.com",
        }

    def test_google_subdomains_caught_by_catch_all(self, both):
        """``cse.google.com`` (Custom Search) and ``clients1.google.com``
        (the /generate_204 connectivity check) are ``*.google.com`` subdomains
        the catch-all now owns — they must not fall through to unclassified."""
        analysis, doc = both
        gm_hosts = {h.host for h in analysis.hits if h.module_id == "google_misc"}
        assert {"cse.google.com", "clients1.google.com"} <= gm_hosts
        unclassified = {u.host for u in doc.unclassified_hosts}
        assert "cse.google.com" not in unclassified
        assert "clients1.google.com" not in unclassified


# ===========================================================================
# NBB — National Bank of Belgium. www.nbb.be is fronted by Cloudflare US.
#       Fires the hidden_extraterritorial_infra finding exactly once.
# ===========================================================================


class TestNBB:
    """Pinned properties of ``nbb.zip``."""

    @pytest.fixture
    def both(self):
        return _document("nbb.zip")

    def test_modules_fired_are_cookiebot_gtm_matomo(self, both):
        analysis, _ = both
        assert _modules_fired(analysis) == {"cookiebot", "googletagmanager", "matomo"}

    def test_no_distinct_third_party_personal_fields(self, both):
        """NBB embeds Google Tag Manager, but GTM only passes its
        container id — property-scoped, classified technical. No
        visitor data leaves."""
        analysis, _ = both
        assert _third_party_pii_field_count(analysis) == 0
        assert _distinct_third_party_personal_fields(analysis) == set()

    def test_hidden_extraterritorial_finding_fires_exactly_once(self, both):
        """www.nbb.be (first-party) CNAMEs into Cloudflare (US)."""
        _, doc = both
        findings = [
            f for f in doc.executive_summary.findings
            if f.kind == "hidden_extraterritorial_infra"
        ]
        assert len(findings) == 1
        f = findings[0]
        assert f.severity == "high"
        assert f.source == "capture"
        assert "www.nbb.be" in f.headline
        assert "Cloudflare" in f.headline
        assert "Cloudflare" in f.detail
        assert "FISA 702" in f.detail  # exposure context surfaces

    def test_finding_action_is_actionable(self, both):
        """The action text names a concrete remediation step, not generic prose."""
        _, doc = both
        finding = next(
            f for f in doc.executive_summary.findings
            if f.kind == "hidden_extraterritorial_infra"
        )
        assert "SCC" in finding.action or "SCCs" in finding.action
        assert "Cloudflare" in finding.action
