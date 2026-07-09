"""Tests that the builder tags known findings with a stable ``kind``.

The ``kind`` field is what the action-metadata map joins on. If the
builder forgets to set it, the metadata can't attach to the finding
at render time. These tests pin the wire-up.
"""

from __future__ import annotations

from leak_inspector.analysis.runner import Analysis
from leak_inspector.bundle.manifest import Manifest
from leak_inspector.dns_posture.types import DMARCRecord, DNSPosture
from leak_inspector.report.builder import build_report_document


def _manifest() -> Manifest:
    return Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="2026-05-30T00:00:00Z",
        ended_at="2026-05-30T00:01:00Z",
        target_url="https://example.be/", base_domain="example.be",
        browser={}, profile="p", landing_url="https://example.be/",
    )


def _analysis_with_dmarc_policy(policy: str) -> Analysis:
    """Build an Analysis whose DNS posture has a DMARC record at the
    given policy. ``policy=""`` or ``"none"`` is the monitor-only case
    that should produce a ``dmarc_p_none``-tagged finding."""
    posture = DNSPosture(
        domain="example.be",
        looked_up_at="2026-05-30T00:00:00Z",
        dmarc=DMARCRecord(
            raw=f"v=DMARC1; p={policy}",
            policy=policy,
            subdomain_policy="",
            pct=100,
            rua=[], ruf=[],
        ),
    )
    return Analysis(
        manifest=_manifest(),
        hits=[],
        untracked_requests=[],
        visited_pages=["https://example.be/"],
        dns_posture=posture,
    )


def test_dmarc_p_none_finding_is_tagged_with_kind() -> None:
    """The 'DMARC in monitor-only mode' finding must carry
    kind='dmarc_p_none' so action-metadata can attach."""
    document = build_report_document(_analysis_with_dmarc_policy(policy="none"))
    dmarc_findings = [
        f for f in document.executive_summary.findings
        if "DMARC" in f.headline and "monitor-only" in f.headline
    ]
    assert len(dmarc_findings) == 1
    assert dmarc_findings[0].kind == "dmarc_p_none"


def test_dmarc_p_quarantine_finding_is_not_tagged_p_none() -> None:
    """A correctly-configured DMARC policy must NOT carry the p_none kind.

    Stronger policies (quarantine, reject) currently produce no
    finding at all, but if they ever do, they must not collide on
    the kind slug.
    """
    document = build_report_document(_analysis_with_dmarc_policy(policy="quarantine"))
    p_none_findings = [
        f for f in document.executive_summary.findings
        if f.kind == "dmarc_p_none"
    ]
    assert p_none_findings == []
