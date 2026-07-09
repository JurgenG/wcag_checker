"""The consolidated 'missing security headers' executive finding.

When the capture observed the main document's response (so the header
posture is *known*) and one or more of the six evaluated headers is
absent, the report surfaces a single consolidated finding — not six
separate lines. Severity is MEDIUM when Content-Security-Policy (the
one meaningful header) is among the missing, otherwise LOW.

When no document response was observed (``security_headers is None``)
the report stays silent — the certainty rule, mirroring the score.
"""

from __future__ import annotations

from leak_inspector.analysis.runner import Analysis
from leak_inspector.bundle.manifest import Manifest
from leak_inspector.modules.base import IMPACT_LOW, IMPACT_MEDIUM
from leak_inspector.report.builder import build_report_document


def _manifest() -> Manifest:
    return Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0",
        session_id="s", started_at="t1", ended_at="t2",
        target_url="https://x.be/", base_domain="x.be",
        browser={}, profile="p", landing_url="https://x.be/",
    )


def _doc_findings(security_headers):
    analysis = Analysis(manifest=_manifest())
    analysis.security_headers = security_headers
    document = build_report_document(analysis)
    return document.executive_summary.findings


def _header_findings(findings):
    return [f for f in findings if f.kind == "security_headers_missing"]


def test_no_finding_when_headers_not_observed() -> None:
    """security_headers is None → silent (never measured)."""
    assert _header_findings(_doc_findings(None)) == []


def test_no_finding_when_all_headers_present() -> None:
    all_present = {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()",
    }
    assert _header_findings(_doc_findings(all_present)) == []


def test_medium_finding_when_csp_is_among_the_missing() -> None:
    """Empty header set → CSP missing → MEDIUM, and the headline counts
    all six."""
    findings = _header_findings(_doc_findings({}))
    assert len(findings) == 1
    assert findings[0].severity == IMPACT_MEDIUM
    assert "6" in findings[0].headline


def test_low_finding_when_only_minor_headers_missing() -> None:
    """CSP present, one minor header absent → LOW."""
    headers = {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "strict-origin-when-cross-origin",
        # permissions-policy missing
    }
    findings = _header_findings(_doc_findings(headers))
    assert len(findings) == 1
    assert findings[0].severity == IMPACT_LOW
    assert "Permissions-Policy" in findings[0].detail


def test_finding_lists_the_missing_headers() -> None:
    headers = {"strict-transport-security": "max-age=1"}  # only HSTS present
    findings = _header_findings(_doc_findings(headers))
    assert len(findings) == 1
    detail = findings[0].detail
    for label in (
        "Content-Security-Policy", "X-Content-Type-Options",
        "X-Frame-Options", "Referrer-Policy", "Permissions-Policy",
    ):
        assert label in detail
    # The present one is not listed as missing.
    assert "Strict-Transport-Security" not in detail
