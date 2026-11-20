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


class _FakeScript:
    """BiDi ``script`` module: per-tab queued counts; records each call."""

    def __init__(self, driver) -> None:
        self._driver = driver

    def execute(self, script: str, *, context_id: str):
        d = self._driver
        d.calls.append((context_id, script))
        if context_id in d.raise_in:
            d.raise_in.discard(context_id)
            raise WebDriverException("mid-navigation")
        queue = d.counts.get(context_id, [])
        value = queue.pop(0) if queue else 0
        return {"type": "number", "value": value}


class _SwitchTo:
    def __init__(self, driver) -> None:
        self._driver = driver

    def window(self, handle: str) -> None:
        self._driver.current = handle
        self._driver.switched.append(handle)


class _FakeDriver:
    """Tabs keyed by handle, each with queued press counts."""

    def __init__(self, counts, *, current="t1", raise_in=()) -> None:
        self.counts = {h: list(c) for h, c in counts.items()}
        self.current = current
        self.raise_in = set(raise_in)
        self.calls: list[tuple[str, str]] = []
        self.switched: list[str] = []
        self.script = _FakeScript(self)
        self.switch_to = _SwitchTo(self)

    @property
    def window_handles(self) -> list[str]:
        return list(self.counts)

    @property
    def current_window_handle(self) -> str:
        if self.current not in self.counts:
            raise WebDriverException("no such window")
        return self.current


class TestHotkeyWatcher:
    def test_poll_returns_the_count(self) -> None:
        watcher = HotkeyWatcher(_FakeDriver({"t1": [2]}), hotkey="f9")
        assert watcher.poll() == 2

    def test_poll_runs_the_built_script_in_every_tab(self) -> None:
        driver = _FakeDriver({"t1": [0], "t2": [0]})
        HotkeyWatcher(driver, hotkey="ctrl+alt+shift+a").poll()
        assert [ctx for ctx, _ in driver.calls] == ["t1", "t2"]
        assert all("e.code === 'KeyA'" in script for _, script in driver.calls)

    def test_press_in_other_tab_switches_driver_there(self) -> None:
        driver = _FakeDriver({"t1": [0], "t2": [1]})
        assert HotkeyWatcher(driver, hotkey="f9").poll() == 1
        assert driver.switched == ["t2"]

    def test_press_in_current_tab_does_not_switch(self) -> None:
        driver = _FakeDriver({"t1": [1], "t2": [1]})
        assert HotkeyWatcher(driver, hotkey="f9").poll() == 1
        assert driver.switched == []

    def test_press_after_current_tab_closed_switches_to_remaining_tab(self) -> None:
        driver = _FakeDriver({"t2": [1]}, current="t1")  # t1 was closed
        assert HotkeyWatcher(driver, hotkey="f9").poll() == 1
        assert driver.switched == ["t2"]

    def test_webdriver_error_yields_zero(self) -> None:
        driver = _FakeDriver({"t1": [1]}, raise_in={"t1"})
        watcher = HotkeyWatcher(driver, hotkey="f9")
        assert watcher.poll() == 0  # transient glitch → 0, retried next tick
        assert watcher.poll() == 1

    def test_non_numeric_result_yields_zero(self) -> None:
        watcher = HotkeyWatcher(_FakeDriver({"t1": [None]}), hotkey="f9")
        assert watcher.poll() == 0

    def test_bad_hotkey_rejected_at_construction(self) -> None:
        with pytest.raises(ValueError):
            HotkeyWatcher(_FakeDriver({}), hotkey="ctrl+alt")
