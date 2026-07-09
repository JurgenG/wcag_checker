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

"""Tests for the focus/keyboard evaluators.

Hermetic: each check's pure evaluator is exercised against a known-good
fixture (no findings) and a known-bad fixture (a candidate finding). No
live browser is used — the gathering half (``check_*``) is what talks to
the driver; these tests target the decision half (``evaluate_*``).
"""

from __future__ import annotations

from leak_inspector.wcag.keyboard_nav import (
    MIN_TARGET_PX,
    evaluate_focus_visible,
    evaluate_no_keyboard_trap,
    evaluate_tab_order,
    evaluate_target_size,
)

URL = "https://example.test/"

# A computed-style snapshot with a clear focus ring, and the same element
# with no ring (used as before/after pairs).
_RING = {
    "outlineStyle": "solid",
    "outlineWidth": "2px",
    "outlineColor": "rgb(0, 95, 204)",
    "boxShadow": "none",
    "borderTopWidth": "1px",
    "borderTopColor": "rgb(0, 0, 0)",
    "backgroundColor": "rgba(0, 0, 0, 0)",
    "textDecorationLine": "none",
}
_NO_RING = {**_RING, "outlineStyle": "none", "outlineWidth": "0px"}


class TestFocusVisible:
    def test_good_focus_ring_appears(self) -> None:
        record = {
            "selector": "a.link",
            "gotFocus": True,
            "stylesBefore": _NO_RING,
            "stylesAfter": _RING,
            "obscured": False,
        }
        assert evaluate_focus_visible([record], URL) == []

    def test_bad_no_style_change_flags_247(self) -> None:
        record = {
            "selector": "a.link",
            "gotFocus": True,
            "stylesBefore": _NO_RING,
            "stylesAfter": _NO_RING,
            "obscured": False,
        }
        findings = evaluate_focus_visible([record], URL)
        assert [f.criterion for f in findings] == ["2.4.7"]
        assert findings[0].severity == "needs-review"
        assert findings[0].selector == "a.link"

    def test_bad_obscured_flags_2411(self) -> None:
        record = {
            "selector": "button",
            "gotFocus": True,
            "stylesBefore": _NO_RING,
            "stylesAfter": _RING,  # ring is fine…
            "obscured": True,  # …but focus is covered
        }
        findings = evaluate_focus_visible([record], URL)
        assert [f.criterion for f in findings] == ["2.4.11"]

    def test_unfocusable_element_skipped(self) -> None:
        record = {
            "selector": "div",
            "gotFocus": False,
            "stylesBefore": _NO_RING,
            "stylesAfter": _NO_RING,
            "obscured": True,
        }
        assert evaluate_focus_visible([record], URL) == []


class TestTargetSize:
    def test_good_meets_minimum(self) -> None:
        record = {
            "selector": "button",
            "width": MIN_TARGET_PX,
            "height": MIN_TARGET_PX,
            "inline": False,
        }
        assert evaluate_target_size([record], URL) == []

    def test_bad_too_small_flags_258(self) -> None:
        record = {"selector": ".icon", "width": 20, "height": 20, "inline": False}
        findings = evaluate_target_size([record], URL)
        assert [f.criterion for f in findings] == ["2.5.8"]
        assert "20×20" in findings[0].message

    def test_inline_target_is_excepted(self) -> None:
        record = {"selector": "a", "width": 10, "height": 10, "inline": True}
        assert evaluate_target_size([record], URL) == []

    def test_zero_size_skipped(self) -> None:
        record = {"selector": "a", "width": 0, "height": 0, "inline": False}
        assert evaluate_target_size([record], URL) == []


class TestTabOrder:
    def test_good_no_positive_tabindex(self) -> None:
        records = [
            {"selector": "a", "tabindex": None},
            {"selector": "button", "tabindex": 0},
            {"selector": "div", "tabindex": -1},
        ]
        assert evaluate_tab_order(records, URL) == []

    def test_bad_positive_tabindex_flags_243(self) -> None:
        records = [{"selector": "#jump", "tabindex": 5}]
        findings = evaluate_tab_order(records, URL)
        assert [f.criterion for f in findings] == ["2.4.3"]
        assert "5" in findings[0].message


class TestNoKeyboardTrap:
    def test_good_focus_advances(self) -> None:
        sequence = ["a", "button", "input", "select", None]
        assert evaluate_no_keyboard_trap(sequence, URL) == []

    def test_bad_stuck_element_flags_212(self) -> None:
        sequence = ["a", "#trap", "#trap", "#trap", "b"]
        findings = evaluate_no_keyboard_trap(sequence, URL)
        assert [f.criterion for f in findings] == ["2.1.2"]
        assert findings[0].selector == "#trap"

    def test_stuck_element_reported_once(self) -> None:
        sequence = ["#trap"] * 6
        findings = evaluate_no_keyboard_trap(sequence, URL)
        assert len(findings) == 1

    def test_none_gaps_do_not_form_a_run(self) -> None:
        # Focus leaving the page (None) between repeats is not a trap.
        sequence = ["#x", None, "#x", None, "#x"]
        assert evaluate_no_keyboard_trap(sequence, URL) == []