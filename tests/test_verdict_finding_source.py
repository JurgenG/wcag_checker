"""Tests for item 5 of the verdict layer — Finding.source split.

Adds a ``source`` field on :class:`Finding` so the executive summary
can group findings under two labelled headings:

* **Website** — findings derived from the live capture (request
  traffic, transport posture, vendor-jurisdiction rollups, etc.).
  Default for any Finding constructed without an explicit source.
* **Back-office** — findings derived from DNS posture (DMARC, SPF,
  DKIM, MX, TXT verifications, DNSSEC, CAA, ...).

The split is honest: a website with perfect HTTPS but a misconfigured
DMARC record has a different remediation owner and a different risk
profile than a website with good DNS but a third-party tracking leak.
"""

from __future__ import annotations

from leak_inspector.analysis.runner import Analysis
from leak_inspector.bundle.manifest import Manifest
from leak_inspector.dns_posture.types import DMARCRecord, DNSPosture
from leak_inspector.report.builder import build_report_document
from leak_inspector.report.document import Finding


# --- Finding.source contract ----------------------------------------------


def test_finding_default_source_is_capture() -> None:
    """Default — existing callers stay backwards-compatible."""
    f = Finding(severity="medium", badge="🟡", headline="x", detail="d", action="a")
    assert f.source == "capture"


def test_finding_accepts_explicit_dns_source() -> None:
    f = Finding(
        severity="medium", badge="🟡", headline="x", detail="d", action="a",
        source="dns",
    )
    assert f.source == "dns"


# --- builder wires DNS findings with source="dns" -------------------------


def _manifest() -> Manifest:
    return Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="2026-05-30T00:00:00Z",
        ended_at="2026-05-30T00:01:00Z",
        target_url="https://example.be/", base_domain="example.be",
        browser={}, profile="p", landing_url="https://example.be/",
    )


def _analysis_with_dns_finding() -> Analysis:
    """A bundle whose DNS posture has DMARC p=none — exactly one DNS
    finding, no capture findings."""
    posture = DNSPosture(
        domain="example.be",
        looked_up_at="2026-05-30T00:00:00Z",
        dmarc=DMARCRecord(
            raw="v=DMARC1; p=none",
            policy="none", subdomain_policy="", pct=100,
            rua=[], ruf=[],
        ),
    )
    return Analysis(
        manifest=_manifest(),
        hits=[], untracked_requests=[],
        visited_pages=["https://example.be/"],
        dns_posture=posture,
    )


def test_dmarc_finding_has_source_dns() -> None:
    document = build_report_document(_analysis_with_dns_finding())
    dmarc_findings = [
        f for f in document.executive_summary.findings
        if "DMARC" in f.headline
    ]
    assert len(dmarc_findings) >= 1
    for f in dmarc_findings:
        assert f.source == "dns", (
            f"DNS-derived finding {f.headline!r} should carry source='dns'"
        )


def test_no_capture_finding_carries_source_dns() -> None:
    """Defensive: capture-side findings (transport, GDPR, replay, etc.)
    must NEVER carry source='dns'."""
    document = build_report_document(_analysis_with_dns_finding())
    for f in document.executive_summary.findings:
        if f.source != "dns":
            assert f.source == "capture", (
                f"unexpected source {f.source!r} on {f.headline!r}"
            )


