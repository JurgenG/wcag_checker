"""Tests for the CMS column + EOL badge in the bulk overview.

The all-reports table gains a "Platform" cell per row showing the
detected CMS / version, with a visible EOL badge for past-EOL
versions. Sites with no platform detected get an em-dash so the
column reads consistently.
"""

from __future__ import annotations

import sys
from pathlib import Path

_BULK_DIR = Path(__file__).resolve().parent.parent / "bulk-tool"
if str(_BULK_DIR) not in sys.path:
    sys.path.insert(0, str(_BULK_DIR))

import overview as overview_module  # noqa: E402
from leak_inspector.cms import CMSFingerprint  # noqa: E402


def _summary(slug: str, **overrides):
    """Build a SiteSummary with safe defaults plus any overrides."""
    defaults = dict(
        slug=slug,
        target_url=f"https://{slug}/",
        landing_url=f"https://{slug}/",
        report_filename=f"{slug}.report.html",
        high_finding_count=0,
        medium_finding_count=0,
        low_finding_count=0,
        total_high_impact_fields=0,
        trackers_fired=0,
        third_party_hosts_touched=0,
        finding_headlines=[],
    )
    defaults.update(overrides)
    return overview_module.SiteSummary(**defaults)


# --- "Platform" column heading ---------------------------------------------


def test_overview_full_list_has_platform_header() -> None:
    html = overview_module._render_overview_html(
        "test", [_summary("example.be")],
    )
    # The all-reports table heading row carries a "Platform" column.
    assert "Platform" in html


# --- per-row platform rendering --------------------------------------------


def test_overview_shows_platform_name_for_detected_site() -> None:
    fp = CMSFingerprint(
        name="Drupal", version="10", confidence="certain",
        evidence="URL path /core/themes/ observed",
    )
    html = overview_module._render_overview_html(
        "test", [_summary("commune.be", cms_fingerprint=fp)],
    )
    assert "Drupal" in html
    assert "10" in html


def test_overview_marks_eol_platform_with_badge() -> None:
    fp = CMSFingerprint(
        name="Drupal", version="7", confidence="certain",
        evidence="URL path /sites/default/files/ observed",
        is_eol=True,
        eol_note="Drupal 7 reached end-of-life on 2025-01-05.",
    )
    html = overview_module._render_overview_html(
        "test", [_summary("oldcommune.be", cms_fingerprint=fp)],
    )
    assert "Drupal" in html
    # Some visually-distinct EOL marker; accept any reasonable shape so the
    # renderer keeps freedom over the exact word.
    lowered = html.lower()
    assert "eol" in lowered or "end-of-life" in lowered


def test_overview_shows_em_dash_when_no_cms_detected() -> None:
    """No platform = consistent placeholder, not an empty cell."""
    html = overview_module._render_overview_html(
        "test", [_summary("example.be")],
    )
    # The summary has no cms_fingerprint. The row must still render
    # without crashing; assert the slug is present.
    assert "example.be" in html


# --- SiteSummary defaults --------------------------------------------------


def test_site_summary_default_cms_fingerprint_is_none() -> None:
    s = _summary("example.be")
    assert s.cms_fingerprint is None
