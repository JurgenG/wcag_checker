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

"""Tests for the WCAG report builder and its four renderers.

Hermetic: pure data in, strings out. No browser, no network, no files.
"""

from __future__ import annotations

import json

import pytest

from leak_inspector.wcag.core import Finding
from leak_inspector.wcag.reporter import (
    DISCLAIMER,
    build_report,
    render_html,
    render_json,
    render_markdown,
    render_text,
)

URL = "https://example.test/"


def _f(criterion: str, severity: str, *, selector: str = "a", url: str = URL) -> Finding:
    return Finding(
        criterion=criterion,
        severity=severity,  # type: ignore[arg-type]
        message=f"issue on {criterion}",
        selector=selector,
        url=url,
    )


@pytest.fixture
def findings() -> list[Finding]:
    # Deliberately unsorted and spanning three criteria + severities.
    return [
        _f("1.4.10", "needs-review", selector=".reflow"),
        _f("1.4.3", "error", selector=".btn", url="https://example.test/a"),
        _f("1.4.3", "warning", selector=".foot", url="https://example.test/b"),
        _f("1.4.9", "error", selector="h1"),
    ]


class TestBuildReport:
    def test_groups_by_criterion(self, findings: list[Finding]) -> None:
        doc = build_report(findings)
        assert [c.criterion.id for c in doc.criteria] == ["1.4.3", "1.4.9", "1.4.10"]

    def test_numeric_sort_puts_410_after_49(self, findings: list[Finding]) -> None:
        ids = [c.criterion.id for c in build_report(findings).criteria]
        assert ids.index("1.4.9") < ids.index("1.4.10")

    def test_status_fail_when_error_or_warning(self, findings: list[Finding]) -> None:
        doc = build_report(findings)
        by_id = {c.criterion.id: c for c in doc.criteria}
        assert by_id["1.4.3"].status == "fail"
        assert by_id["1.4.10"].status == "needs-review"

    def test_findings_ordered_most_severe_first(self, findings: list[Finding]) -> None:
        doc = build_report(findings)
        contrast = next(c for c in doc.criteria if c.criterion.id == "1.4.3")
        assert [f.severity for f in contrast.findings] == ["error", "warning"]

    def test_criterion_metadata_from_registry(self, findings: list[Finding]) -> None:
        doc = build_report(findings)
        contrast = next(c for c in doc.criteria if c.criterion.id == "1.4.3")
        assert contrast.criterion.name == "Contrast (Minimum)"
        assert contrast.criterion.level == "AA"
        assert contrast.criterion.automatable == "full"

    def test_unregistered_criterion_dropped(self) -> None:
        doc = build_report([_f("9.9.9", "error")])
        assert doc.criteria == ()

    def test_urls_inferred_from_findings(self, findings: list[Finding]) -> None:
        doc = build_report(findings)
        assert doc.summary.urls == (
            "https://example.test/",
            "https://example.test/a",
            "https://example.test/b",
        )

    def test_explicit_urls_union_with_findings(self, findings: list[Finding]) -> None:
        doc = build_report(findings, urls=["https://example.test/clean"])
        assert "https://example.test/clean" in doc.summary.urls

    def test_summary_severity_counts(self, findings: list[Finding]) -> None:
        sev = build_report(findings).summary.findings_by_severity
        assert sev == {"error": 2, "warning": 1, "needs-review": 1}

    def test_summary_scope_is_a_and_aa_only(self, findings: list[Finding]) -> None:
        summary = build_report(findings).summary
        tier_total = sum(summary.by_tier.values())
        # Every in-scope criterion falls in exactly one tier bucket.
        assert tier_total == summary.total_in_scope
        # AAA criteria are excluded, so the scope is well below all 87.
        assert summary.total_in_scope < 87

    def test_generated_at_passthrough(self, findings: list[Finding]) -> None:
        doc = build_report(findings, generated_at="2026-07-09T10:00:00Z")
        assert doc.generated_at == "2026-07-09T10:00:00Z"

    def test_empty_findings(self) -> None:
        doc = build_report([])
        assert doc.criteria == ()
        assert doc.summary.criteria_with_findings == 0
        assert doc.summary.findings_by_severity == {
            "error": 0,
            "warning": 0,
            "needs-review": 0,
        }


class TestRenderJson:
    def test_valid_json_round_trips(self, findings: list[Finding]) -> None:
        doc = build_report(findings, generated_at="T")
        data = json.loads(render_json(doc))
        assert data["generated_at"] == "T"
        assert data["disclaimer"] == DISCLAIMER
        assert [c["id"] for c in data["criteria"]] == ["1.4.3", "1.4.9", "1.4.10"]

    def test_criterion_payload_shape(self, findings: list[Finding]) -> None:
        data = json.loads(render_json(build_report(findings)))
        contrast = next(c for c in data["criteria"] if c["id"] == "1.4.3")
        assert contrast["status"] == "fail"
        assert contrast["level"] == "AA"
        assert contrast["findings"][0]["severity"] == "error"

    def test_empty_is_valid_json(self) -> None:
        data = json.loads(render_json(build_report([])))
        assert data["criteria"] == []


class TestRenderHumanFormats:
    def test_text_has_disclaimer_and_criterion(self, findings: list[Finding]) -> None:
        out = render_text(build_report(findings))
        assert "WCAG 2.2 AA audit" in out
        assert "conformance" in out  # disclaimer present
        assert "1.4.3" in out

    def test_markdown_has_headings_and_disclaimer(self, findings: list[Finding]) -> None:
        out = render_markdown(build_report(findings))
        assert out.startswith("# WCAG 2.2 AA audit")
        assert "### 1.4.3 Contrast (Minimum)" in out
        assert f"> {DISCLAIMER}" in out

    def test_html_is_self_contained_and_escaped(self) -> None:
        finding = Finding(
            criterion="1.4.3",
            severity="error",
            message="bad <script> & 'quote'",
            selector="a[href='x']",
            url="https://x/?a=1&b=2",
        )
        out = render_html(build_report([finding]))
        assert "<!DOCTYPE html>" in out
        assert "http" not in _external_asset_refs(out)  # no external CSS/JS/img
        assert "<script>" not in out  # message was escaped
        assert "&lt;script&gt;" in out
        assert "&amp;" in out

    def test_all_formats_state_no_findings_when_empty(self) -> None:
        empty = build_report([])
        assert "No automated findings." in render_text(empty)
        assert "No automated findings." in render_markdown(empty)
        assert "No automated findings." in render_html(empty)


def _external_asset_refs(html_out: str) -> str:
    """Concatenate any src=/href= attribute values that load a URL."""
    refs = []
    for token in ("src=", "href="):
        start = 0
        while (idx := html_out.find(token, start)) != -1:
            refs.append(html_out[idx : idx + 60])
            start = idx + 1
    return " ".join(refs)
