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

"""Tests for the element-screenshot evidence gatherer.

Hermetic: no browser. A fake driver returns fake elements whose
``screenshot`` writes a small file, so the capture/dedup/skip logic and
the returned finding paths are exercised against real filesystem writes
without a live page.
"""

from __future__ import annotations

from leak_inspector.wcag import screenshot
from leak_inspector.wcag.core import Finding
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By


class _FakeElement:
    """A locatable element whose screenshot writes ``ok`` bytes or fails."""

    def __init__(self, ok: bool = True) -> None:
        self._ok = ok

    def screenshot(self, path: str) -> bool:
        if not self._ok:
            return False
        with open(path, "wb") as fh:
            fh.write(b"\x89PNG\r\n")
        return True


class _FakeDriver:
    """Resolves CSS selectors from a table; counts lookups for dedup checks.

    A selector absent from ``elements`` raises like a real missing element.
    """

    def __init__(self, elements: dict[str, _FakeElement]) -> None:
        self._elements = elements
        self.lookups: list[str] = []

    def find_element(self, by: str, selector: str) -> _FakeElement:
        assert by == By.CSS_SELECTOR
        self.lookups.append(selector)
        try:
            return self._elements[selector]
        except KeyError:
            raise NoSuchElementException(selector)


def _finding(selector: str | None, url: str = "https://x/a") -> Finding:
    return Finding(
        criterion="1.4.3",
        severity="error",
        message="m",
        selector=selector,
        url=url,
    )


def test_captures_element_and_sets_relative_path(tmp_path) -> None:
    out = tmp_path / "screenshots"
    driver = _FakeDriver({".btn": _FakeElement()})

    result = screenshot.capture_findings(driver, [_finding(".btn")], out)

    path = result[0].screenshot
    assert path is not None
    assert path.startswith("screenshots/") and path.endswith(".png")
    # The referenced file was actually written under the output dir.
    assert (tmp_path / path).exists()


def test_finding_without_selector_is_untouched(tmp_path) -> None:
    out = tmp_path / "screenshots"
    driver = _FakeDriver({})

    result = screenshot.capture_findings(driver, [_finding(None)], out)

    assert result[0].screenshot is None
    assert not out.exists()  # nothing to capture → no directory created
    assert driver.lookups == []


def test_missing_element_leaves_screenshot_unset(tmp_path) -> None:
    out = tmp_path / "screenshots"
    driver = _FakeDriver({})  # ".gone" not present

    result = screenshot.capture_findings(driver, [_finding(".gone")], out)

    assert result[0].screenshot is None


def test_failed_screenshot_leaves_screenshot_unset(tmp_path) -> None:
    out = tmp_path / "screenshots"
    driver = _FakeDriver({".btn": _FakeElement(ok=False)})

    result = screenshot.capture_findings(driver, [_finding(".btn")], out)

    assert result[0].screenshot is None


def test_same_element_captured_once_and_shared(tmp_path) -> None:
    out = tmp_path / "screenshots"
    driver = _FakeDriver({".btn": _FakeElement()})
    findings = [_finding(".btn"), _finding(".btn")]  # one element, two criteria

    result = screenshot.capture_findings(driver, findings, out)

    assert driver.lookups == [".btn"]  # located just once
    assert result[0].screenshot == result[1].screenshot


def test_same_selector_on_different_urls_gets_distinct_files(tmp_path) -> None:
    out = tmp_path / "screenshots"
    driver = _FakeDriver({".btn": _FakeElement()})
    findings = [_finding(".btn", url="https://x/a"), _finding(".btn", url="https://x/b")]

    result = screenshot.capture_findings(driver, findings, out)

    assert result[0].screenshot != result[1].screenshot


def test_input_findings_are_not_mutated(tmp_path) -> None:
    out = tmp_path / "screenshots"
    driver = _FakeDriver({".btn": _FakeElement()})
    original = _finding(".btn")

    screenshot.capture_findings(driver, [original], out)

    assert original.screenshot is None
