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

"""Tests for the full-page screenshot evidence gatherer.

Hermetic: no browser. A fake driver models the two live calls — an
``execute_script`` highlight (returns whether the selector matched) and a
full-page screenshot (returns bytes, or raises to simulate refusal) — so
the capture/dedup/skip/cleanup logic is exercised against real filesystem
writes without a live page.
"""

from __future__ import annotations

from leak_inspector.wcag import screenshot
from leak_inspector.wcag.core import Finding
from selenium.common.exceptions import WebDriverException


class _FakeDriver:
    """Models the highlight + full-page-screenshot calls the capture makes.

    ``present`` is the set of selectors that "match" an element. The
    highlight script (called with the selector as an argument) returns
    whether it matched; the unhighlight script (no argument) is counted.
    ``shot_ok=False`` makes the screenshot call raise.
    """

    def __init__(self, present, *, shot_ok: bool = True) -> None:
        self._present = set(present)
        self._shot_ok = shot_ok
        self.highlighted: list[str] = []
        self.unhighlights = 0

    def execute_script(self, script: str, *args):
        if args:  # highlight — argument is the CSS selector
            selector = args[0]
            self.highlighted.append(selector)
            return selector in self._present
        self.unhighlights += 1  # unhighlight — no argument
        return None

    def get_full_page_screenshot_as_png(self) -> bytes:
        if not self._shot_ok:
            raise WebDriverException("full-page screenshot refused")
        return b"\x89PNG\r\n\x1a\n"


def _finding(selector: str | None, url: str = "https://x/a") -> Finding:
    return Finding(
        criterion="1.4.3",
        severity="error",
        message="m",
        selector=selector,
        url=url,
    )


def test_captures_full_page_and_sets_relative_path(tmp_path) -> None:
    out = tmp_path / "screenshots"
    driver = _FakeDriver({".btn"})

    result = screenshot.capture_findings(driver, [_finding(".btn")], out)

    path = result[0].screenshot
    assert path is not None
    assert path.startswith("screenshots/") and path.endswith(".png")
    assert (tmp_path / path).exists()
    assert driver.unhighlights == 1  # overlay cleaned up after the shot


def test_finding_without_selector_is_untouched(tmp_path) -> None:
    out = tmp_path / "screenshots"
    driver = _FakeDriver(set())

    result = screenshot.capture_findings(driver, [_finding(None)], out)

    assert result[0].screenshot is None
    assert not out.exists()  # nothing to capture → no directory created
    assert driver.highlighted == []


def test_missing_element_leaves_screenshot_unset(tmp_path) -> None:
    out = tmp_path / "screenshots"
    driver = _FakeDriver(set())  # ".gone" matches nothing

    result = screenshot.capture_findings(driver, [_finding(".gone")], out)

    assert result[0].screenshot is None
    assert driver.unhighlights == 0  # nothing was highlighted to clean up
    assert not out.exists()


def test_failed_screenshot_leaves_screenshot_unset_but_cleans_up(tmp_path) -> None:
    out = tmp_path / "screenshots"
    driver = _FakeDriver({".btn"}, shot_ok=False)

    result = screenshot.capture_findings(driver, [_finding(".btn")], out)

    assert result[0].screenshot is None
    assert driver.unhighlights == 1  # overlay still removed on failure


def test_same_element_captured_once_and_shared(tmp_path) -> None:
    out = tmp_path / "screenshots"
    driver = _FakeDriver({".btn"})
    findings = [_finding(".btn"), _finding(".btn")]  # one element, two criteria

    result = screenshot.capture_findings(driver, findings, out)

    assert driver.highlighted == [".btn"]  # shot just once
    assert result[0].screenshot == result[1].screenshot


def test_same_selector_on_different_urls_gets_distinct_files(tmp_path) -> None:
    out = tmp_path / "screenshots"
    driver = _FakeDriver({".btn"})
    findings = [_finding(".btn", url="https://x/a"), _finding(".btn", url="https://x/b")]

    result = screenshot.capture_findings(driver, findings, out)

    assert result[0].screenshot != result[1].screenshot


def test_input_findings_are_not_mutated(tmp_path) -> None:
    out = tmp_path / "screenshots"
    driver = _FakeDriver({".btn"})
    original = _finding(".btn")

    screenshot.capture_findings(driver, [original], out)

    assert original.screenshot is None
