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

"""Tests for the poll-based audit hotkey.

Hermetic: no browser. The spec parsing / JS builders are pure; the
``HotkeyWatcher`` is driven with a fake driver whose ``execute_script``
returns a canned count (or raises to simulate a transient WebDriver
error).
"""

from __future__ import annotations

import pytest
from selenium.common.exceptions import WebDriverException

from leak_inspector.capture.hotkey import (
    DEFAULT_HOTKEY,
    HotkeyWatcher,
    format_hotkey,
    hotkey_condition,
    poll_script,
)


class TestHotkeySpec:
    def test_default_is_f9(self) -> None:
        assert DEFAULT_HOTKEY == "f9"

    def test_condition_requires_exact_modifiers_and_code(self) -> None:
        cond = hotkey_condition("ctrl+alt+shift+a")
        assert "e.ctrlKey" in cond and "e.altKey" in cond and "e.shiftKey" in cond
        assert "!e.metaKey" in cond  # an unnamed modifier must be up
        assert "e.code === 'KeyA'" in cond

    def test_bare_function_key_requires_all_modifiers_up(self) -> None:
        cond = hotkey_condition("f9")
        assert cond.count("!e.") == 4
        assert "e.code === 'F9'" in cond

    def test_invalid_specs_raise(self) -> None:
        for bad in ["", "ctrl+alt", "ctrl+alt+ab", "f13", "ctrl+shift+@"]:
            with pytest.raises(ValueError):
                hotkey_condition(bad)

    def test_format_for_display(self) -> None:
        assert format_hotkey("ctrl+alt+shift+a") == "Ctrl+Alt+Shift+A"
        assert format_hotkey("f9") == "F9"


class TestPollScript:
    def test_embeds_condition_and_reads_counter(self) -> None:
        script = poll_script("f9")
        assert "e.code === 'F9'" in script
        # installs once per document and returns/clears the pending count
        assert "__wcagHotkeyInstalled" in script
        assert "__wcagHotkeyPending" in script
        assert "return n" in script

    def test_invalid_spec_raises(self) -> None:
        with pytest.raises(ValueError):
            poll_script("ctrl+alt")


class _FakeDriver:
    """execute_script returns queued counts; ``raise_once`` simulates a glitch."""

    def __init__(self, counts, *, raise_once: bool = False) -> None:
        self._counts = list(counts)
        self._raise_once = raise_once
        self.scripts: list[str] = []

    def execute_script(self, script: str):
        self.scripts.append(script)
        if self._raise_once:
            self._raise_once = False
            raise WebDriverException("mid-navigation")
        return self._counts.pop(0) if self._counts else 0


class TestHotkeyWatcher:
    def test_poll_returns_the_count(self) -> None:
        watcher = HotkeyWatcher(_FakeDriver([2]), hotkey="f9")
        assert watcher.poll() == 2

    def test_poll_runs_the_built_script(self) -> None:
        driver = _FakeDriver([0])
        HotkeyWatcher(driver, hotkey="ctrl+alt+shift+a").poll()
        assert "e.code === 'KeyA'" in driver.scripts[0]

    def test_webdriver_error_yields_zero(self) -> None:
        watcher = HotkeyWatcher(_FakeDriver([1], raise_once=True), hotkey="f9")
        assert watcher.poll() == 0  # transient glitch → 0, retried next tick

    def test_non_numeric_result_yields_zero(self) -> None:
        watcher = HotkeyWatcher(_FakeDriver([None]), hotkey="f9")
        assert watcher.poll() == 0

    def test_bad_hotkey_rejected_at_construction(self) -> None:
        with pytest.raises(ValueError):
            HotkeyWatcher(_FakeDriver([]), hotkey="ctrl+alt")
