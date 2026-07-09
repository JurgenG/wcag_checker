"""Tests that the missing-SRI supply-chain finding surfaces in the report.

Data-level only (per house rules): assert the executive summary gains the
right finding with the right severity / kind / named hosts. No bundle
fixture carries page-source data yet, so the emitter is driven from a
synthetic ``Analysis`` carrying ``missing_sri``.
"""

from __future__ import annotations

import json
from pathlib import Path

from leak_inspector.analysis.runner import Analysis, analyze_bundle
from leak_inspector.analysis.sri import MissingSRI, ProtectedSRI
from leak_inspector.modules.base import IMPACT_LOW
from leak_inspector.bundle import (
    BUNDLE_SCHEMA_VERSION,
    Manifest,
    TOOL_NAME,
    write_bundle,
)
from leak_inspector.report.builder import (
    _build_sri_findings,
    _build_sri_protected_findings,
    build_report_document,
)


def _manifest() -> Manifest:
    return Manifest.from_dict({
        "bundle_schema": BUNDLE_SCHEMA_VERSION,
        "tool": TOOL_NAME,
        "tool_version": "0.1.0",
        "session_id": "s",
        "started_at": "2026-06-08T00:00:00Z",
        "ended_at": "2026-06-08T00:01:00Z",
        "target_url": "https://example.com/",
        "base_domain": "example.com",
        "browser": {"name": "firefox", "version": "151"},
        "profile": "default",
        "landing_url": "https://example.com/",
    })


def _analysis(missing: list[MissingSRI]) -> Analysis:
    return Analysis(manifest=_manifest(), missing_sri=missing)


def test_no_missing_sri_emits_nothing() -> None:
    assert _build_sri_findings(_analysis([])) == []


def test_missing_sri_emits_medium_finding_naming_hosts() -> None:
    analysis = _analysis([
        MissingSRI("https://cdn.opecloud.com/ope-var.js", "cdn.opecloud.com"),
        MissingSRI("https://gabe.hit.gemius.pl/x.js", "gabe.hit.gemius.pl"),
    ])
    findings = _build_sri_findings(analysis)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "medium"
    assert f.kind == "sri_missing"
    assert "2 third-party scripts" in f.headline
    assert "cdn.opecloud.com" in f.detail
    assert "gabe.hit.gemius.pl" in f.detail


def test_missing_sri_finding_counts_distinct_hosts() -> None:
    """Two scripts from one host count as one host but two scripts."""
    analysis = _analysis([
        MissingSRI("https://cdn.net/a.js", "cdn.net"),
        MissingSRI("https://cdn.net/b.js", "cdn.net"),
    ])
    f = _build_sri_findings(analysis)[0]
    assert "2 third-party scripts" in f.headline
    assert "1 third-party host" in f.detail


def test_missing_sri_finding_truncates_long_host_lists() -> None:
    analysis = _analysis([
        MissingSRI(f"https://h{i}.net/s.js", f"h{i}.net") for i in range(9)
    ])
    f = _build_sri_findings(analysis)[0]
    assert "+3 more" in f.detail


def test_missing_sri_finding_counts_stylesheets_separately() -> None:
    analysis = _analysis([
        MissingSRI("https://cdn.net/a.js", "cdn.net"),
        MissingSRI("https://cdn.net/b.js", "cdn.net"),
        MissingSRI("https://cdn.net/site.css", "cdn.net", kind="stylesheet"),
    ])
    f = _build_sri_findings(analysis)[0]
    assert "2 third-party scripts and 1 stylesheet" in f.headline


def test_missing_sri_finding_stylesheets_only() -> None:
    analysis = _analysis([
        MissingSRI("https://cdn.net/site.css", "cdn.net", kind="stylesheet"),
        MissingSRI("https://other.net/x.css", "other.net", kind="stylesheet"),
    ])
    f = _build_sri_findings(analysis)[0]
    assert "2 third-party stylesheets" in f.headline
    assert "script" not in f.headline


# --- positive finding: third-party subresources protected with SRI ----------


def _analysis_protected(protected: list[ProtectedSRI]) -> Analysis:
    return Analysis(manifest=_manifest(), protected_sri=protected)


def test_no_protected_sri_emits_nothing() -> None:
    assert _build_sri_protected_findings(_analysis_protected([])) == []


def test_protected_sri_emits_positive_low_finding() -> None:
    analysis = _analysis_protected([
        ProtectedSRI("https://cdn.jsdelivr.net/lib.js", "cdn.jsdelivr.net"),
        ProtectedSRI("https://unpkg.com/x.css", "unpkg.com", kind="stylesheet"),
    ])
    findings = _build_sri_protected_findings(analysis)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == IMPACT_LOW
    assert f.kind == "sri_protected"
    # A positive finding asserts no action.
    assert f.action == ""
    assert "Subresource Integrity" in f.headline
    assert "cdn.jsdelivr.net" in f.detail
    assert "unpkg.com" in f.detail


def test_protected_sri_counts_distinct_hosts() -> None:
    analysis = _analysis_protected([
        ProtectedSRI("https://cdn.net/a.js", "cdn.net"),
        ProtectedSRI("https://cdn.net/b.js", "cdn.net"),
    ])
    f = _build_sri_protected_findings(analysis)[0]
    assert "2 third-party scripts" in f.headline
    assert "1 third-party host" in f.detail


def test_protected_and_missing_sri_coexist_in_document() -> None:
    """A site with some protected and some unprotected gets both findings."""
    analysis = Analysis(
        manifest=_manifest(),
        protected_sri=[ProtectedSRI("https://cdn.net/lib.js", "cdn.net")],
        missing_sri=[MissingSRI("https://tracker.net/t.js", "tracker.net")],
    )
    doc = build_report_document(analysis)
    kinds = {f.kind for f in doc.executive_summary.findings}
    assert "sri_protected" in kinds
    assert "sri_missing" in kinds


# --- end-to-end through the real document path (offline bundle) -------------


def test_sri_finding_surfaces_in_built_document(tmp_path: Path) -> None:
    """analyze_bundle -> build_report_document carries the finding through."""
    session = tmp_path / "session"
    session.mkdir()
    (session / "events.jsonl").write_text("", encoding="utf-8")
    (session / "page_source.html").write_text("<html></html>", encoding="utf-8")
    (session / "page_source.scripts.json").write_text(json.dumps([
        {"url": "https://tracker.example/t.js", "integrity": None,
         "crossorigin": None, "sha256": None, "status": "200"},
    ]), encoding="utf-8")
    out = tmp_path / "bundle.zip"
    write_bundle(session, _manifest(), out)

    doc = build_report_document(analyze_bundle(out))
    kinds = {f.kind for f in doc.executive_summary.findings}
    assert "sri_missing" in kinds
