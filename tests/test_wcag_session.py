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

"""Tests for the session runner's pure seams.

Hermetic: no browser, no network. The report-writing seam is exercised
against tmp_path; the audit loop is driven with a fake driver and a
canned audit function (all WebDriver access is faked).
"""

from __future__ import annotations

import json
import queue

import pytest
from selenium.common.exceptions import WebDriverException

from leak_inspector.session import _run_audit_loop, write_reports
from leak_inspector.wcag.core import Finding


def _finding(criterion: str, severity: str, url: str) -> Finding:
    return Finding(
        criterion=criterion,
        severity=severity,  # type: ignore[arg-type]
        message="x",
        selector="a",
        url=url,
    )


class _FakeDriver:
    """Fake driver: stays open for ``open_ticks`` polls, then 'closes'.

    ``window_handles`` returns a handle while ``open_ticks`` remain, then
    raises like a closed session. ``current_url`` returns the scripted URL.
    """

    def __init__(self, url: str, open_ticks: int) -> None:
        self._url = url
        self._open_ticks = open_ticks

    @property
    def window_handles(self) -> list[str]:
        if self._open_ticks <= 0:
            raise WebDriverException("window closed")
        self._open_ticks -= 1
        return ["w1"]

    @property
    def current_url(self) -> str:
        return self._url


class TestRunAuditLoop:
    def test_audits_on_queued_request_and_records_url(self) -> None:
        driver = _FakeDriver("https://x/a", open_ticks=3)
        q: queue.Queue[str] = queue.Queue()
        q.put("x")  # one hotkey press pending

        def audit_fn(_driver, url):
            return [_finding("1.4.3", "error", url)]

        findings, urls = _run_audit_loop(driver, q, poll_interval=0, audit_fn=audit_fn)
        assert urls == ["https://x/a"]
        assert [f.criterion for f in findings] == ["1.4.3"]

    def test_no_requests_yields_nothing(self) -> None:
        driver = _FakeDriver("https://x/a", open_ticks=2)
        q: queue.Queue[str] = queue.Queue()

        def audit_fn(_driver, url):  # pragma: no cover - must not be called
            raise AssertionError("audit_fn called with no queued request")

        findings, urls = _run_audit_loop(driver, q, poll_interval=0, audit_fn=audit_fn)
        assert findings == []
        assert urls == []

    def test_same_url_recorded_once(self) -> None:
        driver = _FakeDriver("https://x/a", open_ticks=5)
        q: queue.Queue[str] = queue.Queue()
        q.put("a")
        q.put("a")  # two presses on the same page

        def audit_fn(_driver, url):
            return [_finding("2.4.3", "needs-review", url)]

        findings, urls = _run_audit_loop(driver, q, poll_interval=0, audit_fn=audit_fn)
        # Both presses drain in one tick → one audit, URL recorded once.
        assert urls == ["https://x/a"]
        assert len(findings) == 1

    def test_on_audit_called_with_url_and_finding_count(self) -> None:
        driver = _FakeDriver("https://x/a", open_ticks=3)
        q: queue.Queue[str] = queue.Queue()
        q.put("x")
        calls: list[tuple[str, int]] = []

        def audit_fn(_driver, url):
            return [_finding("1.4.3", "error", url), _finding("2.4.3", "needs-review", url)]

        _run_audit_loop(
            driver,
            q,
            poll_interval=0,
            audit_fn=audit_fn,
            on_audit=lambda url, n: calls.append((url, n)),
        )
        assert calls == [("https://x/a", 2)]


class TestAuditPage:
    def test_captures_evidence_when_dir_given(self, monkeypatch) -> None:
        from leak_inspector import session
        from leak_inspector.wcag import axe_runner, keyboard_nav, screenshot

        base = _finding("1.4.3", "error", "https://x/a")
        monkeypatch.setattr(axe_runner, "audit", lambda d, u: [base])
        monkeypatch.setattr(keyboard_nav, "run_all", lambda d, u: [])

        calls: dict[str, object] = {}

        def fake_capture(driver, findings, screenshot_dir):
            calls.update(findings=findings, screenshot_dir=screenshot_dir)
            return [_finding("1.4.3", "error", "https://x/a")]

        monkeypatch.setattr(screenshot, "capture_findings", fake_capture)
        out = session.audit_page("driver", "https://x/a", "shots")
        assert calls["screenshot_dir"] == "shots"
        assert calls["findings"] == [base]
        assert len(out) == 1

    def test_skips_capture_without_dir(self, monkeypatch) -> None:
        from leak_inspector import session
        from leak_inspector.wcag import axe_runner, keyboard_nav, screenshot

        monkeypatch.setattr(axe_runner, "audit", lambda d, u: [])
        monkeypatch.setattr(keyboard_nav, "run_all", lambda d, u: [])

        def fail(*args, **kwargs):  # pragma: no cover - must not be called
            raise AssertionError("capture_findings called without a screenshot dir")

        monkeypatch.setattr(screenshot, "capture_findings", fail)
        assert session.audit_page("driver", "https://x/a") == []


class TestWriteReports:
    def test_writes_all_five_files(self, tmp_path) -> None:
        findings = [_finding("1.4.3", "error", "https://x/a")]
        written = write_reports(
            tmp_path / "out", findings, ["https://x/a"], generated_at="T"
        )
        assert set(written) == {
            "results.json",
            "report.txt",
            "report.md",
            "report.html",
            "manual-checklist.md",
        }
        for path in written.values():
            assert path.exists() and path.read_text(encoding="utf-8")

    def test_results_json_valid_and_carries_findings(self, tmp_path) -> None:
        findings = [_finding("1.4.3", "error", "https://x/a")]
        written = write_reports(tmp_path, findings, ["https://x/a"], generated_at="T")
        data = json.loads(written["results.json"].read_text(encoding="utf-8"))
        assert data["generated_at"] == "T"
        assert [c["id"] for c in data["criteria"]] == ["1.4.3"]

    def test_checklist_lists_the_route(self, tmp_path) -> None:
        written = write_reports(tmp_path, [], ["https://x/a"], generated_at="T")
        md = written["manual-checklist.md"].read_text(encoding="utf-8")
        assert "## https://x/a" in md
        assert "- [ ] " in md

    def test_html_carries_disclaimer(self, tmp_path) -> None:
        written = write_reports(tmp_path, [], ["https://x/a"])
        assert "conformance" in written["report.html"].read_text(encoding="utf-8")

    def test_creates_missing_output_dir(self, tmp_path) -> None:
        nested = tmp_path / "deep" / "out"
        write_reports(nested, [], ["https://x/a"])
        assert (nested / "results.json").exists()

    def test_empty_run_still_writes(self, tmp_path) -> None:
        written = write_reports(tmp_path, [], [])
        assert written["results.json"].exists()
        data = json.loads(written["results.json"].read_text(encoding="utf-8"))
        assert data["criteria"] == []


class TestCli:
    def test_parser_defaults(self) -> None:
        from leak_inspector.cli import build_parser

        args = build_parser().parse_args(["https://x/a"])
        assert args.url == "https://x/a"
        assert str(args.out) == "reports"
        assert args.headless is False
        assert args.once is False

    def test_main_invokes_session(self, monkeypatch, tmp_path) -> None:
        from pathlib import Path

        from leak_inspector import cli, session
        from leak_inspector.session import SessionResult

        calls: dict[str, object] = {}

        def fake_run(url, out, *, headless, on_audit=None):
            calls.update(url=url, out=out, headless=headless, on_audit=on_audit)
            return SessionResult(
                audited_urls=("https://x/a",),
                findings=[],
                output_dir=Path(out),
                written={},
            )

        monkeypatch.setattr(session, "run_session", fake_run)
        rc = cli.main(["https://x/a", "--out", str(tmp_path), "--headless"])
        assert rc == 0
        assert calls["url"] == "https://x/a"
        assert calls["headless"] is True
        assert callable(calls["on_audit"])  # CLI wires the per-audit feedback

    def test_once_flag_invokes_run_once_not_session(
        self, monkeypatch, tmp_path
    ) -> None:
        from pathlib import Path

        from leak_inspector import cli, session
        from leak_inspector.session import SessionResult

        calls: dict[str, object] = {}

        def fake_once(url, out, *, headless):
            calls.update(url=url, out=out, headless=headless)
            return SessionResult(
                audited_urls=("https://x/a",),
                findings=[],
                output_dir=Path(out),
                written={},
            )

        def fail_session(*a, **k):  # pragma: no cover - must not be called
            raise AssertionError("run_session called in --once mode")

        monkeypatch.setattr(session, "run_once", fake_once)
        monkeypatch.setattr(session, "run_session", fail_session)
        rc = cli.main(["https://x/a", "--once", "--out", str(tmp_path)])
        assert rc == 0
        assert calls["url"] == "https://x/a"
        assert calls["headless"] is False
