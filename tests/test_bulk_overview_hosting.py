"""Tests for the hosting-sovereignty breakdown in the bulk overview.

The overview aggregates where each site's first-party hosting resolves —
by country (physical location of the first IP) and by provider — plus an
EU / non-EU / unknown split. These tests pin the aggregation data, not
the rendered bars.
"""

from __future__ import annotations

import sys
from pathlib import Path

_BULK_DIR = Path(__file__).resolve().parent.parent / "bulk-tool"
if str(_BULK_DIR) not in sys.path:
    sys.path.insert(0, str(_BULK_DIR))

import overview as overview_module  # noqa: E402

from leak_inspector.dns_posture.sovereignty import asn_to_provider
from leak_inspector.dns_posture.types import IPInfo


def _ip(country: str, as_org: str = "Example Hosting BV", asn: int = 64500):
    return IPInfo(address="203.0.113.1", version=4, asn=asn,
                  as_org=as_org, country_code=country)


def _summary(slug: str, ip: IPInfo | None):
    from overview import SiteSummary

    return SiteSummary(
        slug=slug, target_url="", landing_url="",
        report_filename=f"{slug}.report.html",
        high_finding_count=0, medium_finding_count=0, low_finding_count=0,
        total_high_impact_fields=0, trackers_fired=0,
        third_party_hosts_touched=0, finding_headlines=[],
        first_party_ip=ip,
    )


# --- by country -----------------------------------------------------------


def test_country_counts_group_and_sort_by_reach() -> None:
    rows = [
        _summary("a", _ip("BE")),
        _summary("b", _ip("BE")),
        _summary("c", _ip("US")),
    ]
    counts = overview_module._hosting_country_counts(rows)
    assert counts[0] == ("BE", 2)     # most-hosted country first
    assert ("US", 1) in counts


def test_country_counts_skip_sites_without_known_country() -> None:
    rows = [_summary("a", _ip("BE")), _summary("b", None),
            _summary("c", _ip(""))]
    counts = overview_module._hosting_country_counts(rows)
    assert counts == [("BE", 1)]


# --- by provider ----------------------------------------------------------


def test_provider_counts_group_by_friendly_label() -> None:
    rows = [
        _summary("a", _ip("BE", as_org="Combell NV")),
        _summary("b", _ip("BE", as_org="Combell NV")),
        _summary("c", _ip("DE", as_org="Hetzner Online GmbH")),
    ]
    counts = dict(overview_module._hosting_provider_counts(rows))
    # Grouped under whatever asn_to_provider collapses the org to.
    assert counts[asn_to_provider("Combell NV")] == 2
    assert counts[asn_to_provider("Hetzner Online GmbH")] == 1


def test_provider_counts_skip_sites_without_org() -> None:
    rows = [_summary("a", _ip("BE", as_org="")), _summary("b", None)]
    assert overview_module._hosting_provider_counts(rows) == []


# --- EU / non-EU / unknown split -----------------------------------------


def test_eu_split_classifies_by_country() -> None:
    rows = [
        _summary("eu1", _ip("BE")),
        _summary("eu2", _ip("FR")),
        _summary("non", _ip("US")),
        _summary("unk1", None),
        _summary("unk2", _ip("")),
    ]
    eu, non_eu, unknown = overview_module._hosting_eu_split(rows)
    assert eu == 2
    assert non_eu == 1
    assert unknown == 2


# --- section render boundary ---------------------------------------------


def test_hosting_section_empty_when_no_hosting_data() -> None:
    # No IP at all, and an IP with neither a known country nor an org —
    # nothing to break down on either axis.
    rows = [_summary("a", None), _summary("b", _ip("", as_org=""))]
    assert overview_module._render_hosting_sovereignty(rows) == ""


def test_hosting_section_renders_when_data_present() -> None:
    rows = [_summary("a", _ip("BE", as_org="Combell NV")),
            _summary("b", _ip("US", as_org="Amazon.com Inc."))]
    html = overview_module._render_hosting_sovereignty(rows)
    assert "Hosting sovereignty" in html
    assert "BE" in html and "US" in html
