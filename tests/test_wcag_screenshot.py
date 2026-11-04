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

"""Tests for the cropped screenshot evidence gatherer.

Hermetic: no browser. A fake driver models the live calls the capture
makes — an ``execute_script`` locate+highlight (returns element geometry
when the selector matches, else ``None``), the BiDi
``browsing_context.capture_screenshot`` clip capture (returns base64 PNG
data, or raises to simulate refusal), and the ``execute_script``
unhighlight (no argument) — so the capture/crop/dedup/skip/cleanup logic
is exercised against real filesystem writes without a live page.
"""

from __future__ import annotations

import base64

from leak_inspector.wcag import screenshot
from leak_inspector.wcag.core import Finding
from selenium.common.exceptions import WebDriverException

#: Canned geometry a matched selector reports: a 50×70 element on a large
#: page (well away from every edge, so the expanded crop is not capped).
_GEOM = {"x": 100.0, "y": 200.0, "w": 50.0, "h": 70.0, "winW": 1000.0, "pageH": 2000.0}

#: A minimal PNG signature the fake capture returns (base64-encoded, as BiDi
#: delivers it).
_PNG_BYTES = b"\x89PNG\r\n\x1a\n"


class _FakeBiDi:
    """Models ``driver.browsing_context`` — only the clip capture is used."""

    def __init__(self, *, shot_ok: bool) -> None:
        self._shot_ok = shot_ok
        self.clips: list[dict] = []

    def capture_screenshot(self, *, context, origin, clip):
        if not self._shot_ok:
            raise WebDriverException("clip screenshot refused")
        self.clips.append(clip)
        return base64.b64encode(_PNG_BYTES).decode("ascii")


class _FakeDriver:
    """Models the locate+highlight, clip-capture, and unhighlight calls.

    ``present`` is the set of selectors that "match" an element; a matched
    selector reports :data:`_GEOM`. The locate+highlight script (called with
    the selector as an argument) returns the geometry dict or ``None``; the
    unhighlight script (no argument) is counted. ``shot_ok=False`` makes the
    BiDi capture raise.
    """

    def __init__(self, present, *, shot_ok: bool = True) -> None:
        self._present = set(present)
        self.highlighted: list[str] = []
        self.unhighlights = 0
        self.current_window_handle = "ctx-1"
        self.browsing_context = _FakeBiDi(shot_ok=shot_ok)

    def execute_script(self, script: str, *args):
        if args:  # locate+highlight — argument is the CSS selector
            selector = args[0]
            self.highlighted.append(selector)
            return dict(_GEOM) if selector in self._present else None
        self.unhighlights += 1  # unhighlight — no argument
        return None


def _finding(selector: str | None, url: str = "https://x/a") -> Finding:
    return Finding(
        criterion="1.4.3",
        severity="error",
        message="m",
        selector=selector,
        url=url,
    )


class TestExpandedBox:
    def test_expands_by_own_size_when_uncapped(self) -> None:
        # 50×70 element, far from every edge → 150×210 centred on it.
        box = screenshot._expanded_box(100, 200, 50, 70, 1000, 2000)
        assert box == {"x": 50, "y": 130, "width": 150, "height": 210}

    def test_caps_at_top_left_corner(self) -> None:
        # Element at the origin: left/top cannot go negative.
        box = screenshot._expanded_box(0, 0, 50, 70, 1000, 2000)
        assert box["x"] == 0 and box["y"] == 0
        assert box["width"] == 100 and box["height"] == 140  # only the right/below halves

    def test_width_caps_to_window_but_height_runs_the_page(self) -> None:
        # A tall element flush against the window's right edge: the width
        # caps to the window (win_w=1000) while the height is free to extend
        # down the page (page_h=2000), not limited to the window.
        box = screenshot._expanded_box(940, 1900, 50, 300, 1000, 2000)
        assert box["x"] == 890  # right caps to win_w=1000 → width 110
        assert box["width"] == 110
        # height expands by 300 above and below (→ 900) uncapped by the window;
        # only the page bottom (2000) trims it: top 1600 … bottom 2000.
        assert box["y"] == 1600 and box["height"] == 400


def test_captures_cropped_region_and_sets_relative_path(tmp_path) -> None:
    out = tmp_path / "screenshots"
    driver = _FakeDriver({".btn"})

    result = screenshot.capture_findings(driver, [_finding(".btn")], out)

    path = result[0].screenshot
    assert path is not None
    assert path.startswith("screenshots/") and path.endswith(".png")
    saved = tmp_path / path
    assert saved.exists()
    assert saved.read_bytes() == _PNG_BYTES  # base64 from BiDi decoded to bytes
    # The clip sent to BiDi is the expanded 150×210 box for the 50×70 element.
    assert driver.browsing_context.clips == [
        {"type": "box", "x": 50.0, "y": 130.0, "width": 150.0, "height": 210.0}
    ]
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
