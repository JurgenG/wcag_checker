"""Tests for JS-set (browser-jar / ``document.cookie``) cookie surfacing.

The cookie overview was historically built only from ``Set-Cookie``
response headers, so cookies set client-side (GA's ``_ga``, Meta's
``_fbp``, …) never reached the report even though capture records the
first-party jar (``driver.get_cookies()``) into the bundle's storage
snapshots. These tests pin the analysis-layer surfacing: the pure
jar→``CookieEntry`` helper, and ``analyze_bundle`` folding the jar
cookies into ``Analysis.cookies`` (first-party, deduped, no value).
"""

from __future__ import annotations

from leak_inspector.analysis.runner import _jar_cookie_to_entry, analyze_bundle
from tests.fixtures.bundles import path as bundle_path


# A fixed reference epoch (2026-06-08T00:00:00Z) for lifetime maths.
_REF_EPOCH = 1780963200.0


# --- pure jar→entry helper -------------------------------------------------


def test_jar_cookie_persistent_cross_site_is_high_impact() -> None:
    raw = {
        "name": "_ga", "value": "GA1.1.x", "domain": ".example.be",
        "path": "/", "secure": True, "httpOnly": False,
        "sameSite": "None", "expiry": _REF_EPOCH + 400 * 86400,
    }
    entry = _jar_cookie_to_entry(
        raw, host="example.be", is_first_party=True, ref_epoch=_REF_EPOCH,
    )
    assert entry is not None
    assert entry.name == "_ga"
    assert entry.host == "example.be"
    assert entry.is_first_party is True
    assert entry.source == "stored"
    assert entry.secure is True
    assert entry.same_site == "none"
    assert entry.lifetime_days is not None and entry.lifetime_days > 365
    assert entry.lifetime_human.endswith("y")
    assert entry.privacy_impact == "high"
    # The value (an identifier) is never carried onto the entry.
    assert not hasattr(entry, "value")


def test_jar_cookie_without_expiry_is_session() -> None:
    raw = {"name": "PHPSESSID", "domain": "example.be", "httpOnly": True}
    entry = _jar_cookie_to_entry(
        raw, host="example.be", is_first_party=True, ref_epoch=_REF_EPOCH,
    )
    assert entry is not None
    assert entry.lifetime_human == "session"
    assert entry.lifetime_days is None
    assert entry.http_only is True


def test_jar_cookie_without_name_is_dropped() -> None:
    entry = _jar_cookie_to_entry(
        {"value": "x"}, host="example.be", is_first_party=True,
        ref_epoch=_REF_EPOCH,
    )
    assert entry is None


# --- analyze_bundle integration (real fixtures) ----------------------------


def test_analyze_bundle_surfaces_js_cookies() -> None:
    """doccle-accept's JS-set GA/Meta/Ads cookies now reach the overview."""
    analysis = analyze_bundle(bundle_path("doccle-accept.zip"))
    names = {c.name for c in analysis.cookies or []}
    assert {"_ga", "_fbp", "_gcl_au"} <= names


def test_surfaced_js_cookies_are_first_party_and_sourced() -> None:
    analysis = analyze_bundle(bundle_path("doccle-accept.zip"))
    ga = next(c for c in analysis.cookies if c.name == "_ga")
    assert ga.is_first_party is True
    assert ga.source == "stored"


def test_surfaced_js_tracker_cookies_are_labelled() -> None:
    """A recognised tracker cookie carries the vendor + module_id."""
    analysis = analyze_bundle(bundle_path("doccle-accept.zip"))
    ga = next(c for c in analysis.cookies if c.name == "_ga")
    assert ga.vendor == "Google Analytics"
    assert ga.tracker_module_id == "ga4"
    fbp = next(c for c in analysis.cookies if c.name == "_fbp")
    assert fbp.vendor == "Meta Pixel"


def test_benign_js_cookie_keeps_host_vendor() -> None:
    """A non-tracker first-party cookie is not attributed to a vendor."""
    analysis = analyze_bundle(bundle_path("doccle-accept.zip"))
    lang = next((c for c in analysis.cookies if c.name == "pll_language"), None)
    assert lang is not None
    assert lang.tracker_module_id == ""
    assert lang.vendor == lang.host


def test_no_duplicate_cookie_rows() -> None:
    """Jar cookies are deduped against Set-Cookie entries (name + host)."""
    analysis = analyze_bundle(bundle_path("doccle-accept.zip"))
    keys = [(c.name, c.host) for c in analysis.cookies or []]
    assert len(keys) == len(set(keys))


# --- informational finding -------------------------------------------------


def test_first_party_tracking_cookie_finding_emitted() -> None:
    """A LOW finding names the first-party tracking cookies + vendors."""
    from leak_inspector.report.builder import build_report_document

    doc = build_report_document(analyze_bundle(bundle_path("doccle-accept.zip")))
    finding = next(
        (f for f in doc.executive_summary.findings
         if f.kind == "first_party_tracking_cookies"),
        None,
    )
    assert finding is not None
    assert finding.severity == "low"
    assert "Google Analytics" in finding.detail


def test_no_tracking_cookie_finding_when_vendor_absent_from_hits() -> None:
    """Cross-checked against hits: a labelled cookie whose module never
    fired in the capture is not named (certain-data attribution).
    """
    from leak_inspector.report.builder import (
        _build_first_party_tracking_cookie_findings,
    )

    analysis = analyze_bundle(bundle_path("doccle-accept.zip"))
    # Drop all hits → no vendor can be certainly attributed.
    analysis.hits = []
    assert _build_first_party_tracking_cookie_findings(analysis) == []
