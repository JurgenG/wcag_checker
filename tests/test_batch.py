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

"""Tests for the batch-audit runner.

Hermetic: no browser. ``run_batch`` is driven with a fake launched driver
and a canned ``audit_page`` (raising for a designated URL to exercise
continue-on-error); the pure list/slug/summary helpers are tested
directly.
"""

from __future__ import annotations

import json

from leak_inspector import batch
from leak_inspector.batch import (
    SiteResult,
    read_urls,
    render_summary_html,
    render_summary_json,
    render_summary_markdown,
    run_batch,
    site_slug,
)
from leak_inspector.wcag.core import Finding


class TestReadUrls:
    def test_one_url_per_line_skips_blanks_comments_dedupes(self, tmp_path) -> None:
        f = tmp_path / "list.csv"
        f.write_text(
            "https://a.be\n\n  # a comment\nhttps://b.be\nhttps://a.be\n  https://c.be  \n",
            encoding="utf-8",
        )
        assert read_urls(f) == [
            (None, "https://a.be"),
            (None, "https://b.be"),
            (None, "https://c.be"),
        ]

    def test_two_column_name_and_website(self, tmp_path) -> None:
        f = tmp_path / "municipalities.csv"
        f.write_text(
            "naam,website\nAalst,https://aalst.be\nAalter,https://www.aalter.be\n",
            encoding="utf-8",
        )
        # header row skipped; name paired with the URL field
        assert read_urls(f) == [
            ("Aalst", "https://aalst.be"),
            ("Aalter", "https://www.aalter.be"),
        ]

    def test_url_field_found_regardless_of_column_order(self, tmp_path) -> None:
        f = tmp_path / "list.csv"
        f.write_text("https://x.be,X-town\n", encoding="utf-8")
        assert read_urls(f) == [("X-town", "https://x.be")]


class TestSiteSlug:
    def test_host_becomes_slug(self) -> None:
        assert site_slug("https://publiq.be", set()) == "publiq.be"

    def test_path_and_query_dropped(self) -> None:
        assert site_slug("https://x.be/a?b=1", set()) == "x.be"

    def test_collision_gets_suffix(self) -> None:
        taken: set[str] = set()
        assert site_slug("https://x.be/a", taken) == "x.be"
        assert site_slug("https://x.be/b", taken) == "x.be-2"

    def test_missing_host_falls_back(self) -> None:
        assert site_slug("not-a-url", set()) == "site"


def _finding(sev: str) -> Finding:
    return Finding(criterion="1.4.3", severity=sev, message="m", selector="a", url="u")


def _urls(*items: str) -> list[tuple[str | None, str]]:
    """(None, url) entries as read_urls returns for a plain one-per-line list."""
    return [(None, u) for u in items]


class _FakeDriver:
    def __init__(self) -> None:
        self.last = ""

    def get(self, url: str) -> None:
        self.last = url


class _FakeLaunched:
    def __init__(self, driver) -> None:
        self.driver = driver


class _FakeDriverCM:
    def __init__(self, driver) -> None:
        self._driver = driver

    def __enter__(self):
        return _FakeLaunched(self._driver)

    def __exit__(self, *exc) -> bool:
        return False


class TestRunBatch:
    def _patch(self, monkeypatch):
        monkeypatch.setattr(
            batch,
            "launch_driver",
            lambda *, headless=False, width=None: _FakeDriverCM(_FakeDriver()),
        )
        monkeypatch.setattr(batch, "wait_until_settled", lambda driver: driver.last)
        monkeypatch.setattr(batch, "capture_text_view", lambda driver, url: None)

        def fake_audit(driver, url, screenshot_dir):
            if "boom" in url:
                raise RuntimeError("nope")
            return [_finding("error"), _finding("needs-review")]

        monkeypatch.setattr(batch, "audit_page", fake_audit)

    def test_audits_each_site_and_writes_reports(self, monkeypatch, tmp_path) -> None:
        self._patch(monkeypatch)
        result = run_batch(
            _urls("https://a.be", "https://b.be"), tmp_path, source="list.csv"
        )
        assert [s.status for s in result.sites] == ["audited", "audited"]
        # Each site got its own report (default format: html) + checklist.
        assert (tmp_path / "a.be" / "report.html").exists()
        assert (tmp_path / "a.be" / "manual-checklist.md").exists()
        assert (tmp_path / "b.be" / "report.html").exists()
        assert result.sites[0].error_count == 1
        assert result.sites[0].needs_review_count == 1

    def test_formats_passed_through_per_site(self, monkeypatch, tmp_path) -> None:
        self._patch(monkeypatch)
        run_batch(_urls("https://a.be"), tmp_path, formats=("json", "jira-tickets"))
        assert (tmp_path / "a.be" / "results.json").exists()
        assert (tmp_path / "a.be" / "jira").is_dir()
        assert not (tmp_path / "a.be" / "report.html").exists()

    def test_failure_is_recorded_and_run_continues(self, monkeypatch, tmp_path) -> None:
        self._patch(monkeypatch)
        result = run_batch(
            _urls("https://boom.be", "https://ok.be"), tmp_path
        )
        by_slug = {s.slug: s for s in result.sites}
        assert by_slug["boom.be"].status == "failed"
        assert "nope" in by_slug["boom.be"].error
        assert by_slug["ok.be"].status == "audited"  # run continued
        # Failed site wrote no report; audited one did.
        assert not (tmp_path / "boom.be" / "report.html").exists()
        assert (tmp_path / "ok.be" / "report.html").exists()

    def test_failure_error_is_single_line(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setattr(
            batch,
            "launch_driver",
            lambda *, headless=False, width=None: _FakeDriverCM(_FakeDriver()),
        )
        monkeypatch.setattr(batch, "wait_until_settled", lambda driver: driver.last)
        monkeypatch.setattr(batch, "capture_text_view", lambda driver, url: None)

        def multiline_audit(driver, url, screenshot_dir):
            raise RuntimeError("first line\nstack frame 1\nstack frame 2")

        monkeypatch.setattr(batch, "audit_page", multiline_audit)
        result = run_batch(_urls("https://x.be"), tmp_path)
        err = result.sites[0].error
        assert "\n" not in err
        assert err == "RuntimeError: first line"

    def test_name_labels_site_and_titles_report(self, monkeypatch, tmp_path) -> None:
        self._patch(monkeypatch)
        result = run_batch([("Aalst", "https://aalst.be")], tmp_path)
        site = result.sites[0]
        assert site.name == "Aalst"
        assert site.slug == "aalst.be"  # folder still from the URL host
        data = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
        assert data["sites"][0]["name"] == "Aalst"
        # the name titles the per-site report
        assert "Aalst" in (tmp_path / "aalst.be" / "report.html").read_text(
            encoding="utf-8"
        )

    def test_reading_view_written_per_site_when_captured(
        self, monkeypatch, tmp_path
    ) -> None:
        from leak_inspector.wcag.text_view import PageTextView, TextNode

        self._patch(monkeypatch)
        view = PageTextView(
            url="x", title="T", nodes=(TextNode(role="heading", name="Hi", level=1),)
        )
        monkeypatch.setattr(batch, "capture_text_view", lambda driver, url: view)
        run_batch(_urls("https://a.be"), tmp_path)
        assert (tmp_path / "a.be" / "text-view.md").exists()

    def test_limit_caps_the_number_audited(self, monkeypatch, tmp_path) -> None:
        self._patch(monkeypatch)
        result = run_batch(
            _urls("https://a.be", "https://b.be", "https://c.be"), tmp_path, limit=2
        )
        assert len(result.sites) == 2

    def test_summary_files_written_with_totals(self, monkeypatch, tmp_path) -> None:
        self._patch(monkeypatch)
        run_batch(_urls("https://a.be", "https://boom.be"), tmp_path, source="list.csv")
        data = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
        assert data["totals"] == {"sites": 2, "audited": 1, "failed": 1}
        assert data["source"] == "list.csv"
        assert (tmp_path / "summary.md").exists()
        assert (tmp_path / "summary.html").exists()


class TestSummaryRendering:
    def _sites(self) -> list[SiteResult]:
        return [
            SiteResult("https://a.be", "a.be", None, "audited", None, 2, 1, 5, 3),
            SiteResult("https://b.be", "b.be", None, "failed", "Timeout: boom", 0, 0, 0, 0),
        ]

    def test_named_site_uses_name_as_label(self) -> None:
        sites = [
            SiteResult("https://aalst.be", "aalst.be", "Aalst", "audited",
                       None, 1, 0, 2, 1),
        ]
        md = render_summary_markdown(sites)
        assert "[Aalst](aalst.be/report.html)" in md
        assert "https://aalst.be" in md  # url still shown as a detail
        assert ">Aalst</a>" in render_summary_html(sites)

    def test_markdown_has_row_per_site_and_marks_failure(self) -> None:
        md = render_summary_markdown(self._sites(), generated_at="T", source="s")
        assert "[https://a.be](a.be/report.html)" in md
        assert "**failed**: Timeout: boom" in md
        assert "1 audited, 1 failed" in md

    def test_json_links_only_audited_and_carries_counts(self) -> None:
        data = json.loads(render_summary_json(self._sites()))
        rows = {r["slug"]: r for r in data["sites"]}
        assert rows["a.be"]["report"] == "a.be/report.html"
        assert rows["a.be"]["findings"] == {"error": 2, "warning": 1, "needs-review": 5}
        assert rows["b.be"]["report"] is None
        assert rows["b.be"]["status"] == "failed"
