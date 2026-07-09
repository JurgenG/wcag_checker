"""Composite ScoreBreakdown + report wiring.

The three dimension scores compose into a single ``ScoreBreakdown``
with total = round(³√(resilience × security × privacy) × 10), which
yields a 0-100 final score. Renderers surface it in the report
header.
"""

from __future__ import annotations

import json

from leak_inspector.analysis.runner import Analysis
from leak_inspector.bundle.manifest import Manifest
from leak_inspector.dns_posture.types import (
    CAARecord, DMARCRecord, DNSPosture, DNSSECStatus, IPInfo, SPFRecord,
)
from leak_inspector.http_posture.probe import HostProbe, TransportPosture
from leak_inspector.modules.base import (
    CAT_IDENTIFIER, IMPACT_MEDIUM, Hit, ParamInfo, all_modules,
)
from leak_inspector.report import build_report_document
from leak_inspector.report.document import CookieEntry, SCHEMA_VERSION


# --- helpers ---------------------------------------------------------------


def _manifest(*, base: str = "example.be") -> Manifest:
    return Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="2026-06-05T00:00:00Z",
        ended_at="2026-06-05T00:01:00Z",
        target_url=f"https://{base}/", base_domain=base,
        browser={}, profile="p", landing_url=f"https://{base}/",
    )


def _full_posture_analysis() -> Analysis:
    """An Analysis with both transport AND DNS posture present.

    Picks values that produce a known-good profile: resilience=10,
    security=10, privacy=10, total = round(³√1000 × 10) = 100.
    """
    tp = TransportPosture(
        primary=HostProbe(
            host="example.be",
            http_responded=True, https_responded=True,
            http_status=301, https_status=200,
            http_final_url="https://example.be/",
            https_final_url="https://example.be/",
        ),
        alternate=None,
    )
    dp = DNSPosture(
        domain="example.be", looked_up_at="t",
        dnssec=DNSSECStatus(parent_has_ds=True, zone_has_dnskey=True),
        dmarc=DMARCRecord(raw="v=DMARC1; p=reject", policy="reject"),
        spf=SPFRecord(raw="v=spf1 -all", final_qualifier="-all"),
        caa=CAARecord(raw_records=["0 issue \"letsencrypt.org\""]),
        aaaa_records=[IPInfo(address="2a02:1800::1", version=6)],
    )
    return Analysis(
        manifest=_manifest(),
        hits=[], untracked_requests=[],
        visited_pages=["https://example.be/"],
        transport_posture=tp, dns_posture=dp, cookies=[],
        security_headers={
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
            "x-frame-options": "SAMEORIGIN",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "geolocation=()",
        },
    )


# --- ReportDocument wiring ------------------------------------------------


def test_report_document_has_score_attribute() -> None:
    from leak_inspector.report.score_v2 import ScoreView
    doc = build_report_document(_full_posture_analysis())
    assert doc.score is not None
    assert isinstance(doc.score, ScoreView)
    # Clean full-posture, no trackers → the logistic anchor — ceil(90.0)=91;
    # perfection (100) is an asymptote, never exactly reached.
    assert doc.score.total == 91


def test_report_document_score_is_none_for_hermetic_analysis() -> None:
    a = _full_posture_analysis()
    a.transport_posture = None
    a.dns_posture = None
    doc = build_report_document(a)
    assert doc.score is None


def test_schema_version_bumped_for_score_field() -> None:
    """v5 introduced the 0-10/geometric/resilience reshape."""
    assert SCHEMA_VERSION >= 5


# --- JSON serialization ---------------------------------------------------


def test_json_includes_score_breakdown() -> None:
    from leak_inspector.report.json_reporter import write_document_json
    doc = build_report_document(_full_posture_analysis())
    payload = json.loads(write_document_json(doc))
    assert "score" in payload
    assert payload["score"]["total"] == 91
    assert payload["score"]["resilience"]["stars"] == 91
    assert payload["score"]["security"]["stars"] == 91
    assert payload["score"]["privacy"]["stars"] == 91
    assert payload["score"]["resilience"]["max_stars"] == 100
    assert payload["score"]["resilience"]["rationale"]


def test_json_uses_resilience_not_sovereignty_key() -> None:
    """v5 rename: top-level dimension key is ``resilience`` not ``sovereignty``."""
    from leak_inspector.report.json_reporter import write_document_json
    doc = build_report_document(_full_posture_analysis())
    payload = json.loads(write_document_json(doc))
    assert "resilience" in payload["score"]
    assert "sovereignty" not in payload["score"]


def test_json_score_field_is_null_for_hermetic() -> None:
    from leak_inspector.report.json_reporter import write_document_json
    a = _full_posture_analysis()
    a.transport_posture = None
    a.dns_posture = None
    doc = build_report_document(a)
    payload = json.loads(write_document_json(doc))
    assert payload["score"] is None


# --- Text rendering -------------------------------------------------------


def test_text_renderer_includes_score_line() -> None:
    from leak_inspector.report.text import render_text_document
    doc = build_report_document(_full_posture_analysis())
    out = render_text_document(doc, color=False)
    assert "100" in out
    assert "resilience" in out.lower()
    assert "security" in out.lower()
    assert "privacy" in out.lower()


def test_text_renderer_uses_emoji_glyphs() -> None:
    """Resilience / Security / Privacy each prefixed with their emoji."""
    from leak_inspector.report.text import render_text_document
    doc = build_report_document(_full_posture_analysis())
    out = render_text_document(doc, color=False)
    assert "🛡️" in out
    assert "🔐" in out
    assert "🕶️" in out


def test_text_renderer_omits_score_when_none() -> None:
    from leak_inspector.report.text import render_text_document
    a = _full_posture_analysis()
    a.transport_posture = None
    a.dns_posture = None
    doc = build_report_document(a)
    out = render_text_document(doc, color=False)
    assert "resilience × security × privacy" not in out.lower()
    assert "🛡️" not in out


# --- Markdown rendering ---------------------------------------------------


def test_markdown_renderer_includes_score() -> None:
    from leak_inspector.report.markdown import render_markdown_document
    doc = build_report_document(_full_posture_analysis())
    out = render_markdown_document(doc, detailed=True)
    assert "100" in out
    assert "resilience" in out.lower()
    assert "🛡️" in out


# --- HTML rendering -------------------------------------------------------


def test_html_renderer_includes_score() -> None:
    from leak_inspector.report.html import render_html_document
    doc = build_report_document(_full_posture_analysis())
    out = render_html_document(doc)
    assert "100" in out
    assert "resilience" in out.lower()
    assert "security" in out.lower()
    assert "privacy" in out.lower()
    assert "🛡️" in out
