"""Tests for the positive DNSSEC-signed finding.

A signed zone is a security positive: cache-poisoning attacks against
its DNS records fail. Surfacing it as an explicit green finding in
the executive summary (instead of burying it in the DNS-posture section
only) lets a manager see "this is done right" alongside the actionable
problems.

Three cases pinned here:

1. ``parent_has_ds + zone_has_dnskey`` → positive 🟢 ``LOW`` finding
   tagged ``kind="dnssec_signed"``, source ``"dns"``, no action.
2. ``parent_has_ds = False or zone_has_dnskey = False`` → existing
   negative 🟡 ``MEDIUM`` finding fires (regression guard).
3. ``posture.dnssec is None`` → no DNSSEC finding emitted at all.
"""

from __future__ import annotations

from leak_inspector.analysis.runner import Analysis
from leak_inspector.bundle.manifest import Manifest
from leak_inspector.dns_posture.types import DNSPosture, DNSSECStatus
from leak_inspector.modules.base import IMPACT_LOW, IMPACT_MEDIUM
from leak_inspector.report.builder import build_report_document


def _manifest() -> Manifest:
    return Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="2026-06-04T00:00:00Z",
        ended_at="2026-06-04T00:01:00Z",
        target_url="https://belgium.be/", base_domain="belgium.be",
        browser={}, profile="p", landing_url="https://belgium.be/",
    )


def _analysis(dnssec: DNSSECStatus | None) -> Analysis:
    posture = (
        DNSPosture(
            domain="belgium.be",
            looked_up_at="2026-06-04T00:00:00Z",
            dnssec=dnssec,
        )
        if dnssec is not None
        else DNSPosture(
            domain="belgium.be",
            looked_up_at="2026-06-04T00:00:00Z",
        )
    )
    return Analysis(
        manifest=_manifest(),
        hits=[],
        untracked_requests=[],
        visited_pages=["https://belgium.be/"],
        dns_posture=posture,
    )


def _no_posture_analysis() -> Analysis:
    """Analysis without a ``dns_posture`` at all — hermetic / analyze_events path."""
    return Analysis(
        manifest=_manifest(),
        hits=[],
        untracked_requests=[],
        visited_pages=["https://belgium.be/"],
    )


# --- 1. Signed zone → positive finding -------------------------------------


def test_signed_zone_emits_positive_low_finding() -> None:
    doc = build_report_document(_analysis(DNSSECStatus(
        parent_has_ds=True,
        zone_has_dnskey=True,
        summary="Zone is DNSSEC-signed (DS at parent + DNSKEY in zone).",
    )))
    signed_findings = [
        f for f in doc.executive_summary.findings
        if f.kind == "dnssec_signed"
    ]
    assert len(signed_findings) == 1
    finding = signed_findings[0]
    assert finding.severity == IMPACT_LOW
    assert "DNSSEC" in finding.headline
    # A positive finding asserts no action; the action field stays empty so
    # nothing is appended to RECOMMENDED ACTIONS.
    assert finding.action == ""
    # Sourced from the DNS posture — drives the website / back-office split.
    assert finding.source == "dns"


def test_signed_zone_does_not_emit_negative_finding() -> None:
    """The MEDIUM 'not signed' finding must NOT fire when the zone IS signed."""
    doc = build_report_document(_analysis(DNSSECStatus(
        parent_has_ds=True, zone_has_dnskey=True,
    )))
    negative_findings = [
        f for f in doc.executive_summary.findings
        if "not DNSSEC-signed" in f.headline
    ]
    assert negative_findings == []


# --- 2. Unsigned / broken-chain zones → existing negative finding ---------


def test_unsigned_zone_still_emits_medium_finding() -> None:
    doc = build_report_document(_analysis(DNSSECStatus(
        parent_has_ds=False,
        zone_has_dnskey=False,
        summary="Zone is not DNSSEC-signed.",
    )))
    negative = [
        f for f in doc.executive_summary.findings
        if "not DNSSEC-signed" in f.headline
    ]
    assert len(negative) == 1
    assert negative[0].severity == IMPACT_MEDIUM
    assert negative[0].source == "dns"
    # And no positive finding sneaks in.
    assert not any(f.kind == "dnssec_signed" for f in doc.executive_summary.findings)


def test_broken_chain_emits_medium_not_positive() -> None:
    """Parent DS without zone DNSKEY (or vice versa) is a broken chain, not a positive."""
    doc = build_report_document(_analysis(DNSSECStatus(
        parent_has_ds=True,
        zone_has_dnskey=False,
        summary="Parent publishes DS but the zone serves no DNSKEY.",
    )))
    assert not any(f.kind == "dnssec_signed" for f in doc.executive_summary.findings)
    negative = [
        f for f in doc.executive_summary.findings
        if "DNSSEC" in f.headline and "not" in f.headline.lower()
    ]
    assert len(negative) == 1


# --- 3. No DNS posture → no DNSSEC finding either way --------------------


def test_no_posture_emits_no_dnssec_finding() -> None:
    """Hermetic analyze_events runs with no DNS posture — must not crash, must not fire."""
    doc = build_report_document(_no_posture_analysis())
    dnssec_findings = [
        f for f in doc.executive_summary.findings
        if "DNSSEC" in f.headline or f.kind == "dnssec_signed"
    ]
    assert dnssec_findings == []


def test_posture_with_none_dnssec_emits_no_dnssec_finding() -> None:
    """A DNS posture that exists but couldn't determine DNSSEC must stay silent."""
    doc = build_report_document(_analysis(dnssec=None))
    dnssec_findings = [
        f for f in doc.executive_summary.findings
        if "DNSSEC" in f.headline or f.kind == "dnssec_signed"
    ]
    assert dnssec_findings == []
