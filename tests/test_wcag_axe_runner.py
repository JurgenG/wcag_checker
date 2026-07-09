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

"""Tests for axe-core output normalization.

Hermetic: no browser, no network. Everything is exercised against a
canned axe results dict shaped like ``Axe.run`` output.
"""

from __future__ import annotations

import pytest

from leak_inspector.wcag.axe_runner import (
    criteria_from_tags,
    normalize_results,
)

URL = "https://example.test/page"


@pytest.fixture
def axe_results() -> dict:
    """A canned axe results dict covering the normalization branches."""
    return {
        "violations": [
            {
                "id": "color-contrast",
                "impact": "serious",
                "tags": ["cat.color", "wcag2aa", "wcag143"],
                "help": "Elements must meet minimum color contrast ratio",
                "helpUrl": "https://dequeuniversity.com/rules/axe/4.10/color-contrast",
                "nodes": [
                    {"target": [".hero > p"], "failureSummary": "Fix contrast"},
                    {"target": ["#footer"], "failureSummary": "Fix contrast too"},
                ],
            },
            {
                "id": "region",
                "impact": "minor",
                "tags": ["cat.keyboard", "best-practice"],
                "help": "All page content should be landmarks",
                "helpUrl": "https://example/region",
                "nodes": [{"target": ["div"], "failureSummary": "wrap it"}],
            },
            {
                "id": "meta-viewport",
                "impact": "critical",
                "tags": ["wcag2aa", "wcag144", "wcag1410"],
                "help": "Zooming and scaling must not be disabled",
                "helpUrl": "https://example/viewport",
                "nodes": [{"target": ["meta"], "failureSummary": "allow zoom"}],
            },
        ],
        "incomplete": [
            {
                "id": "color-contrast",
                "impact": "serious",
                "tags": ["wcag2aa", "wcag143"],
                "help": "Elements must meet minimum color contrast ratio",
                "helpUrl": "https://example/contrast",
                "nodes": [{"target": ["span.badge"], "failureSummary": "check bg"}],
            }
        ],
    }


class TestTagMapping:
    def test_single_digit_criterion(self) -> None:
        assert criteria_from_tags(["wcag2aa", "wcag143"]) == ["1.4.3"]

    def test_two_digit_criterion(self) -> None:
        assert criteria_from_tags(["wcag1410"]) == ["1.4.10"]
        assert criteria_from_tags(["wcag2411"]) == ["2.4.11"]

    def test_level_and_category_tags_rejected(self) -> None:
        assert criteria_from_tags(["wcag2a", "wcag21aa", "cat.color"]) == []

    def test_best_practice_maps_to_nothing(self) -> None:
        assert criteria_from_tags(["best-practice"]) == []

    def test_unregistered_criterion_dropped(self) -> None:
        # 9.9.9 parses structurally but is not a real WCAG criterion.
        assert criteria_from_tags(["wcag999"]) == []

    def test_multiple_criteria_deduped_and_ordered(self) -> None:
        assert criteria_from_tags(["wcag144", "wcag1410", "wcag144"]) == [
            "1.4.4",
            "1.4.10",
        ]

    def test_non_string_tags_ignored(self) -> None:
        assert criteria_from_tags([None, 143, "wcag143"]) == ["1.4.3"]


class TestNormalizeResults:
    def test_best_practice_result_dropped(self, axe_results: dict) -> None:
        findings = normalize_results(axe_results, URL)
        assert all("region" not in f.message for f in findings)

    def test_violation_expands_per_node(self, axe_results: dict) -> None:
        contrast = [
            f
            for f in normalize_results(axe_results, URL)
            if f.criterion == "1.4.3" and f.severity == "error"
        ]
        selectors = {f.selector for f in contrast}
        assert selectors == {".hero > p", "#footer"}

    def test_multi_criterion_result_expands_per_criterion(
        self, axe_results: dict
    ) -> None:
        viewport = [
            f for f in normalize_results(axe_results, URL) if "meta-viewport" in f.message
        ]
        assert {f.criterion for f in viewport} == {"1.4.4", "1.4.10"}

    def test_critical_impact_is_error(self, axe_results: dict) -> None:
        viewport = next(
            f for f in normalize_results(axe_results, URL) if "meta-viewport" in f.message
        )
        assert viewport.severity == "error"

    def test_minor_impact_would_be_warning(self) -> None:
        results = {
            "violations": [
                {
                    "id": "x",
                    "impact": "minor",
                    "tags": ["wcag143"],
                    "help": "h",
                    "helpUrl": "u",
                    "nodes": [{"target": ["a"]}],
                }
            ]
        }
        assert normalize_results(results, URL)[0].severity == "warning"

    def test_incomplete_is_needs_review(self, axe_results: dict) -> None:
        incomplete = [
            f
            for f in normalize_results(axe_results, URL)
            if f.selector == "span.badge"
        ]
        assert incomplete and all(f.severity == "needs-review" for f in incomplete)

    def test_message_carries_rule_id_summary_and_url(self, axe_results: dict) -> None:
        f = next(f for f in normalize_results(axe_results, URL) if f.selector == "#footer")
        assert "[color-contrast]" in f.message
        assert "Fix contrast too" in f.message
        assert "See https://" in f.message

    def test_url_is_recorded(self, axe_results: dict) -> None:
        assert all(f.url == URL for f in normalize_results(axe_results, URL))

    def test_nested_frame_target_joined(self) -> None:
        results = {
            "violations": [
                {
                    "id": "x",
                    "impact": "serious",
                    "tags": ["wcag143"],
                    "help": "h",
                    "helpUrl": "u",
                    "nodes": [{"target": ["iframe#f", "button.go"]}],
                }
            ]
        }
        assert normalize_results(results, URL)[0].selector == "iframe#f button.go"

    def test_empty_results_yield_no_findings(self) -> None:
        assert normalize_results({}, URL) == []


class TestCriterionOwnership:
    """2.5.8 is owned by keyboard_nav; axe results mapping to it are dropped."""

    def test_axe_target_size_result_dropped(self) -> None:
        # The exact tag set axe-core 4.10.2 ships on its target-size rule.
        results = {
            "violations": [
                {
                    "id": "target-size",
                    "impact": "serious",
                    "tags": ["cat.sensory-and-visual-cues", "wcag22aa", "wcag258"],
                    "help": "h",
                    "helpUrl": "u",
                    "nodes": [{"target": ["a.small"]}],
                }
            ]
        }
        assert normalize_results(results, URL) == []

    def test_other_criteria_on_same_result_survive(self) -> None:
        # Only 2.5.8 is dropped; a co-tagged criterion is still reported.
        results = {
            "violations": [
                {
                    "id": "x",
                    "impact": "serious",
                    "tags": ["wcag258", "wcag143"],
                    "help": "h",
                    "helpUrl": "u",
                    "nodes": [{"target": ["a"]}],
                }
            ]
        }
        criteria = {f.criterion for f in normalize_results(results, URL)}
        assert criteria == {"1.4.3"}

    def test_tag_mapper_itself_is_unchanged(self) -> None:
        # The drop lives in normalization, not the mechanical tag mapper.
        assert criteria_from_tags(["wcag258"]) == ["2.5.8"]