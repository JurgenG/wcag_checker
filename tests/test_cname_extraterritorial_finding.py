"""Tests for the "hidden extraterritorial infrastructure" finding.

Fires when the captured site's own (first-party) host CNAMEs into a
US-jurisdiction provider. The visible URL is a ``.be`` /
governmental domain, but the traffic terminates on US-controlled
infrastructure (Cloudflare, Akamai, Azure, AWS, Fastly) — a
Schrems II / CLOUD Act exposure that the URL alone hides.

Scope is deliberately tight:

* Only **first-party** hosts trigger the finding. Third-party vendor
  hosts (Google, Meta, Hotjar) already produce the existing
  "vendor under extra-territorial jurisdiction" Schrems II finding;
  re-firing here would double-flag the same exposure.
* Only **US** tails fire. EU / unknown tails do not.
"""

from __future__ import annotations

from leak_inspector.analysis import analyze_events
from leak_inspector.bundle.reader import BundleReader
from leak_inspector.report.builder import build_report_document

from tests.fixtures.bundles import path as bundle_path


_KIND = "hidden_extraterritorial_infra"


def _document(name: str):
    with BundleReader(bundle_path(name)) as b:
        analysis = analyze_events(
            b.manifest, b.events(), cname_chains=b.cname_chains,
        )
    return build_report_document(analysis)


def _findings_of_kind(document, kind: str):
    return [
        f for f in document.executive_summary.findings if f.kind == kind
    ]


# --- Real-bundle integration ---------------------------------------------


def test_nbb_fires_finding_for_first_party_on_cloudflare_us() -> None:
    """NBB: www.nbb.be → www.nbb.be.cdn.cloudflare.net. The bank's own
    apex is fronted by Cloudflare US — finding fires."""
    document = _document("nbb.zip")
    findings = _findings_of_kind(document, _KIND)
    assert findings, (
        "expected hidden_extraterritorial_infra finding on NBB "
        "(first-party host fronted by Cloudflare US)"
    )
    # Severity should be high — first-party traffic terminating
    # offshore is a baseline Schrems II concern.
    assert findings[0].severity == "high"
    # Detail / headline name the provider so the auditor can act.
    text = (findings[0].headline + " " + findings[0].detail).lower()
    assert "cloudflare" in text


def test_brecht_does_not_fire_finding_for_clean_first_party() -> None:
    """Brecht's first-party host (www.brecht.be) has no CNAME hop, so
    nothing reveals an extraterritorial provider — finding stays silent.

    (The azureedge host on Brecht IS Azure-fronted, but it is a
    different registrable domain, so it falls under 'third-party
    unclassified' rather than 'first-party hosted on US infra'.)
    """
    document = _document("brecht.zip")
    assert _findings_of_kind(document, _KIND) == []


# --- Wiring on the executive summary ---------------------------------------


def test_finding_carries_source_capture() -> None:
    """The finding describes capture-side traffic (not DNS records), so
    it goes under the 'Website' group when the source split is rendered."""
    document = _document("nbb.zip")
    findings = _findings_of_kind(document, _KIND)
    assert findings
    assert findings[0].source == "capture"


def test_finding_is_deduplicated_per_host() -> None:
    """A single host fires the finding at most once even if many of its
    requests share the same Cloudflare-tail CNAME chain."""
    document = _document("nbb.zip")
    findings = _findings_of_kind(document, _KIND)
    # NBB only has one first-party host with a US tail (www.nbb.be) —
    # the finding count should reflect that.
    assert len(findings) == 1
