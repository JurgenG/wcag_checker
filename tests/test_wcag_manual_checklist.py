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

"""Tests for the manual-review checklist generator.

Hermetic: pure registry-derived data in, strings out. No browser.
"""

from __future__ import annotations

import json

from leak_inspector.wcag.manual_checklist import (
    NOTE,
    build_checklist,
    render_json,
    render_markdown,
)

URLS = ["https://example.test/b", "https://example.test/a"]


class TestBuildChecklist:
    def test_includes_only_manual_and_partial_a_aa(self) -> None:
        checklist = build_checklist(URLS)
        tiers = {c.automatable for c in checklist.criteria}
        levels = {c.level for c in checklist.criteria}
        assert tiers == {"manual", "partial"}
        assert levels <= {"A", "AA"}

    def test_excludes_full_tier(self) -> None:
        ids = {c.id for c in build_checklist(URLS).criteria}
        assert "1.4.3" not in ids  # 1.4.3 is full → axe decides it
        assert "1.1.1" not in ids  # also full

    def test_expected_counts(self) -> None:
        # A + AA review scope: 27 manual + 19 partial = 46.
        criteria = build_checklist(URLS).criteria
        manual = [c for c in criteria if c.automatable == "manual"]
        partial = [c for c in criteria if c.automatable == "partial"]
        assert len(manual) == 27
        assert len(partial) == 19
        assert len(criteria) == 46

    def test_known_criteria_present(self) -> None:
        ids = {c.id for c in build_checklist(URLS).criteria}
        assert "1.2.1" in ids  # manual
        assert "2.4.3" in ids  # partial

    def test_urls_deduped_and_sorted(self) -> None:
        checklist = build_checklist(["https://x/b", "https://x/a", "https://x/b"])
        assert checklist.urls == ("https://x/a", "https://x/b")

    def test_generated_at_passthrough(self) -> None:
        assert build_checklist(URLS, generated_at="T").generated_at == "T"


class TestRenderMarkdown:
    def test_section_per_url_with_checkboxes(self) -> None:
        out = render_markdown(build_checklist(URLS))
        assert out.startswith("# WCAG 2.2 AA manual-review checklist")
        assert "## https://example.test/a" in out
        assert "## https://example.test/b" in out
        assert "- [ ] 1.2.1 Audio-only and Video-only (Prerecorded) (A)" in out

    def test_full_tier_criterion_absent(self) -> None:
        out = render_markdown(build_checklist(URLS))
        assert "1.4.3 Contrast" not in out

    def test_tier_groups_present(self) -> None:
        out = render_markdown(build_checklist(URLS))
        assert "### Needs human judgement (manual)" in out
        assert "### Confirm automated candidates (partial)" in out

    def test_empty_urls_note(self) -> None:
        out = render_markdown(build_checklist([]))
        assert "No pages were recorded" in out
        assert "## http" not in out


class TestRenderJson:
    def test_valid_and_structured(self) -> None:
        data = json.loads(render_json(build_checklist(URLS, generated_at="T")))
        assert data["generated_at"] == "T"
        assert data["note"] == NOTE
        assert data["urls"] == ["https://example.test/a", "https://example.test/b"]
        assert len(data["criteria"]) == 46
        assert {"id", "name", "level", "tier"} == set(data["criteria"][0])