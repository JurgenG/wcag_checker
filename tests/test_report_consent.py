"""Tests that consent state surfaces in the report document (Phase 4).

Data-level only (per house rules): assert the ``ReportDocument``
carries the consent state and that the executive summary gains the
right findings. No rendering / string-format assertions.
"""

from __future__ import annotations

import pytest

from leak_inspector import modules  # noqa: F401  (registers detectors)
from leak_inspector.analysis.runner import analyze_events
from leak_inspector.bundle.reader import BundleReader
from leak_inspector.report.builder import build_report_document

from tests.fixtures.bundles import path as bundle_path


def _document(name: str):
    with BundleReader(bundle_path(name)) as b:
        analysis = analyze_events(
            b.manifest, b.events(), cname_chains=b.cname_chains,
        )
    return build_report_document(analysis)


def _finding_kinds(doc) -> set[str]:
    return {f.kind for f in doc.executive_summary.findings}


def _finding(doc, kind):
    return next(
        f for f in doc.executive_summary.findings if f.kind == kind
    )


def test_document_carries_consent_state() -> None:
    doc = _document("doccle-reject.zip")
    assert doc.consent is not None
    assert doc.consent.state == "rejected"


def test_post_reject_finding_is_high_and_names_vendors() -> None:
    doc = _document("doccle-reject.zip")
    assert "consent_post_reject" in _finding_kinds(doc)
    f = _finding(doc, "consent_post_reject")
    assert f.severity == "high"
    # Vendors that kept tracking after the reject are named.
    assert "Microsoft Clarity" in f.detail
    assert "Google Analytics 4" in f.detail


def test_post_reject_finding_cites_consent_mode_corroboration() -> None:
    """doccle-reject's beacons carry gcs=G100 (storage denied) — the
    finding cites that on-the-wire corroboration."""
    doc = _document("doccle-reject.zip")
    f = _finding(doc, "consent_post_reject")
    assert "Consent Mode" in f.detail
    assert "denied" in f.detail.lower()


def test_pre_consent_finding_present_when_tracking_precedes_decision() -> None:
    doc = _document("doccle-reject.zip")
    assert "consent_pre_decision" in _finding_kinds(doc)
    f = _finding(doc, "consent_pre_decision")
    assert f.severity == "high"
    assert "Google Analytics 4" in f.detail


def test_accept_session_has_no_consent_findings() -> None:
    """Accepted sessions make no consent-violation claim (boundary can't
    separate pre-accept from post-accept), so neither finding fires."""
    doc = _document("doccle-accept.zip")
    assert doc.consent.state == "accepted"
    kinds = _finding_kinds(doc)
    assert "consent_pre_decision" not in kinds
    assert "consent_post_reject" not in kinds


def test_clean_no_interaction_has_no_consent_findings() -> None:
    doc = _document("nbb.zip")
    assert doc.consent.state == "none"
    kinds = _finding_kinds(doc)
    assert "consent_pre_decision" not in kinds
    assert "consent_post_reject" not in kinds


def test_unknown_consent_emits_no_violation_findings() -> None:
    doc = _document("kbc.zip")
    assert doc.consent.state == "unknown"
    kinds = _finding_kinds(doc)
    assert "consent_pre_decision" not in kinds
    assert "consent_post_reject" not in kinds


# --- the consent status line covers every state ------------------------------


def test_consent_line_unknown_with_banner_names_the_cmp() -> None:
    """kbc: TrustArc banner detected, decision unreadable — the line
    says so instead of staying silent."""
    from leak_inspector.report.text import _consent_line

    line = _consent_line(_document("kbc.zip").consent)
    assert line is not None
    assert "TrustArc" in line
    assert "unknown" in line.lower()


def test_consent_line_unknown_without_banner() -> None:
    from leak_inspector.report.text import _consent_line

    line = _consent_line(_document("brecht.zip").consent)
    assert line == "Consent: no known consent banner detected"


def test_consent_line_none_state_says_no_choice() -> None:
    from leak_inspector.report.text import _consent_line

    line = _consent_line(_document("nbb.zip").consent)
    assert "no choice" in line


def test_consent_line_none_state_names_the_banner() -> None:
    """nbb: Cookiebot drew the banner but the visitor never decided —
    the line names the banner instead of an anonymous 'banner shown'."""
    from leak_inspector.report.text import _consent_line

    line = _consent_line(_document("nbb.zip").consent)
    assert "Cookiebot" in line


def test_consent_line_none_state_names_markup_detected_banner() -> None:
    """A markup-detected self-hosted banner on a none-state capture was
    named in the data but silent in the consent line (the LCP Approach-B
    follow-up). Synthetic: no committed fixture combines a decodable CMP
    (state none needs one) with a markup-only banner name."""
    from leak_inspector.analysis.consent import ConsentState
    from leak_inspector.report.text import _consent_line

    consent = ConsentState(
        state="none",
        cmp_names=("self-hosted consent banner (LCP/Icordis)",),
    )
    line = _consent_line(consent)
    assert "LCP/Icordis" in line
    assert "no choice" in line


def test_consent_line_absent_only_without_consent_pass() -> None:
    from leak_inspector.report.text import _consent_line

    assert _consent_line(None) is None
