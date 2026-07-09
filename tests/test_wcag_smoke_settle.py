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

"""Tests for the smoke runner's page-settle wait.

Hermetic: no browser. A fake driver scripts a URL sequence (simulating a
client-side redirect) and a deterministic clock replaces wall-clock time,
so the redirect-race guard is exercised without any real waiting.
"""

from __future__ import annotations

import pytest
from selenium.common.exceptions import WebDriverException

from tools import wcag_smoke


class _FakeClock:
    """Monotonic clock that advances one second per call."""

    def __init__(self) -> None:
        self.t = 0.0

    def monotonic(self) -> float:
        self.t += 1.0
        return self.t


class _ScriptedDriver:
    """Returns ``current_url`` values from a list, last value repeating.

    ``readyState`` is reported complete unless ``ready`` is False. A URL of
    ``None`` in the script raises like a mid-navigation context loss.
    """

    def __init__(self, urls: list[str | None], *, ready: bool = True) -> None:
        self._urls = urls
        self._i = 0
        self._ready = ready

    @property
    def current_url(self) -> str:
        i = min(self._i, len(self._urls) - 1)
        self._i += 1
        url = self._urls[i]
        if url is None:
            raise WebDriverException("navigating")
        return url

    def execute_script(self, script: str) -> bool:
        return self._ready


@pytest.fixture(autouse=True)
def _no_real_time(monkeypatch):
    """Replace sleep with a no-op and monotonic with the fake clock."""
    monkeypatch.setattr(wcag_smoke.time, "sleep", lambda _s: None)
    monkeypatch.setattr(wcag_smoke.time, "monotonic", _FakeClock().monotonic)


def test_waits_through_client_side_redirect() -> None:
    # Two polls on the original URL, then a redirect that then holds.
    driver = _ScriptedDriver(["https://x/", "https://x/", "https://x/en/"])
    settled = wcag_smoke.wait_until_settled(driver, quiet=2.0, timeout=100.0)
    assert settled == "https://x/en/"


def test_stable_page_returns_that_url() -> None:
    driver = _ScriptedDriver(["https://x/page"])
    settled = wcag_smoke.wait_until_settled(driver, quiet=2.0, timeout=100.0)
    assert settled == "https://x/page"


def test_never_settles_returns_last_url_within_timeout() -> None:
    # URL changes every poll → never quiet; must stop at timeout, not hang.
    driver = _ScriptedDriver([f"https://x/{n}" for n in range(50)])
    settled = wcag_smoke.wait_until_settled(driver, quiet=2.0, timeout=5.0)
    assert settled.startswith("https://x/")


def test_not_ready_does_not_settle_early() -> None:
    # readyState never complete → falls through to the timeout return.
    driver = _ScriptedDriver(["https://x/"], ready=False)
    settled = wcag_smoke.wait_until_settled(driver, quiet=1.0, timeout=4.0)
    assert settled == "https://x/"
