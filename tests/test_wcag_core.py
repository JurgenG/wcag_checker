# wcag_checker — record a real human-driven browsing session and audit
# the visited pages for WCAG 2.2 accessibility conformance.
# Copyright (C) 2026 Jurgen Gaeremyn
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Tests for the WCAG 2.2 criteria registry and core dataclasses."""

from __future__ import annotations

import pytest

from leak_inspector.wcag.core import (
    CRITERIA_BY_ID,
    CRITERIA_REGISTRY,
    WCAG_22_CRITERIA_COUNT,
    Finding,
    WcagCriterion,
    criterion,
)


def test_registry_has_all_87_wcag22_criteria():
    assert len(CRITERIA_REGISTRY) == WCAG_22_CRITERIA_COUNT == 87


def test_criterion_ids_are_unique():
    ids = [c.id for c in CRITERIA_REGISTRY]
    assert len(ids) == len(set(ids))


def test_levels_and_tiers_are_valid():
    for c in CRITERIA_REGISTRY:
        assert c.level in ("A", "AA", "AAA"), c
        assert c.automatable in ("full", "partial", "manual"), c
        assert c.name, c
        # ids look like N.N.N
        parts = c.id.split(".")
        assert len(parts) == 3 and all(p.isdigit() for p in parts), c


def test_criteria_by_id_matches_registry():
    assert set(CRITERIA_BY_ID) == {c.id for c in CRITERIA_REGISTRY}
    for c in CRITERIA_REGISTRY:
        assert CRITERIA_BY_ID[c.id] is c


def test_criterion_lookup():
    assert criterion("1.4.3").name == "Contrast (Minimum)"
    assert criterion("1.4.3").level == "AA"
    assert criterion("nonexistent") is None


@pytest.mark.parametrize(
    "cid, level",
    [
        # The nine criteria WCAG 2.2 added over 2.1 must all be present.
        ("2.4.11", "AA"),
        ("2.4.12", "AAA"),
        ("2.4.13", "AAA"),
        ("2.5.7", "AA"),
        ("2.5.8", "AA"),
        ("3.2.6", "A"),
        ("3.3.7", "A"),
        ("3.3.8", "AA"),
        ("3.3.9", "AAA"),
    ],
)
def test_wcag22_new_criteria_present(cid, level):
    c = criterion(cid)
    assert c is not None, f"{cid} missing from registry"
    assert c.level == level


@pytest.mark.parametrize(
    "cid, tier",
    [
        # Full-automation anchors (seed data from the build guide appendix).
        ("1.1.1", "full"),
        ("1.3.1", "full"),
        ("1.4.3", "full"),
        ("1.4.6", "full"),
        ("2.4.1", "full"),
        ("3.1.1", "full"),
        ("4.1.2", "full"),
        # Partial-automation anchors.
        ("2.4.4", "partial"),
        ("1.4.10", "partial"),
        ("2.5.8", "partial"),
        # Manual anchors.
        ("1.3.3", "manual"),
        ("3.3.1", "manual"),
    ],
)
def test_seed_automatability_tiers(cid, tier):
    assert criterion(cid).automatable == tier


def test_tier_distribution_is_honest():
    """Most criteria are manual — a tool that claimed otherwise would lie."""
    tiers = [c.automatable for c in CRITERIA_REGISTRY]
    full = tiers.count("full")
    partial = tiers.count("partial")
    manual = tiers.count("manual")
    assert full + partial + manual == 87
    # Manual must dominate; full must never be the plurality.
    assert manual > full + partial
    assert full < manual


def test_finding_is_constructible():
    f = Finding(
        criterion="1.1.1",
        severity="error",
        message="image has no alt text",
        selector="img.hero",
        url="https://example.com/",
    )
    assert f.criterion == "1.1.1"
    assert f.severity == "error"
    assert f.selector == "img.hero"


def test_wcag_criterion_is_frozen():
    c = WcagCriterion("1.1.1", "Non-text Content", "A", "full")
    with pytest.raises(Exception):
        c.id = "9.9.9"  # type: ignore[misc]
