"""Tests for the capture-layer driver helpers.

These exercise pure-function paths (``_build_options``) that don't need
a real Firefox binary or geckodriver — actual driver launch is exercised
by the live ``wcag-checker`` run.
"""

from __future__ import annotations

from pathlib import Path

from leak_inspector.capture.driver import _build_options


class _FakeDriver:
    """Minimal stand-in exposing the two window-rect calls we use."""

    def __init__(self, width: int = 1280, height: int = 800) -> None:
        self.size = {"width": width, "height": height}

    def get_window_size(self) -> dict[str, int]:
        return dict(self.size)

    def set_window_size(self, width: int, height: int) -> None:
        self.size = {"width": width, "height": height}


class _ClampingDriver(_FakeDriver):
    """Fake that mimics Firefox's minimum-window-width clamp."""

    def __init__(self, minimum: int = 500) -> None:
        super().__init__()
        self._minimum = minimum

    def set_window_size(self, width: int, height: int) -> None:
        self.size = {"width": max(width, self._minimum), "height": height}


def test_set_window_width_changes_width_and_keeps_height() -> None:
    """A responsive-layout audit sets the chosen width, leaving height as-is."""
    from leak_inspector.capture.driver import _set_window_width

    driver = _FakeDriver(width=1280, height=800)
    _set_window_width(driver, 375)
    assert driver.size == {"width": 375, "height": 800}


def test_set_window_width_warns_when_firefox_clamps(capsys) -> None:
    """A width below Firefox's floor is clamped; the operator is warned so a
    wider-than-asked audit is not mistaken for the requested mobile layout."""
    from leak_inspector.capture.driver import _set_window_width

    _set_window_width(_ClampingDriver(minimum=500), 375)
    err = capsys.readouterr().err
    assert "375" in err and "500" in err


def test_set_window_width_silent_when_honoured(capsys) -> None:
    """No warning when the requested width is actually achieved."""
    from leak_inspector.capture.driver import _set_window_width

    _set_window_width(_FakeDriver(width=1280, height=800), 768)
    assert capsys.readouterr().err == ""


def test_build_options_includes_profile_path(tmp_path: Path) -> None:
    """The default options invocation still wires the profile dir through."""
    options = _build_options(tmp_path)
    args = list(options.arguments)
    assert "-profile" in args
    assert str(tmp_path) in args


def test_build_options_headless_false_omits_headless_arg(tmp_path: Path) -> None:
    """Default behaviour (no flag) preserves the visible-browser capture mode."""
    options = _build_options(tmp_path)
    assert "--headless" not in options.arguments
    assert "-headless" not in options.arguments


def test_build_options_headless_true_adds_headless_arg(tmp_path: Path) -> None:
    """Opt-in flag adds the Firefox ``--headless`` argument so the window
    stays hidden while the capture still drives a real Firefox (so
    BiDi events, the page itself, and the screenshot all still work)."""
    options = _build_options(tmp_path, headless=True)
    assert "--headless" in options.arguments


def test_build_options_headless_keeps_bidi_capability(tmp_path: Path) -> None:
    """Headless mode must NOT disable BiDi — capture depends on it."""
    options = _build_options(tmp_path, headless=True)
    assert options.capabilities.get("webSocketUrl") is True


def test_build_options_headless_keeps_stealth_prefs(tmp_path: Path) -> None:
    """Stealth / noise prefs apply equally in headless mode."""
    from leak_inspector.capture.driver import STEALTH_PREFS, NOISE_PREFS
    options = _build_options(tmp_path, headless=True)
    # FirefoxOptions stores prefs in a dict accessible via .preferences
    for key in STEALTH_PREFS:
        assert key in options.preferences
    for key in NOISE_PREFS:
        assert key in options.preferences


def test_build_options_applies_exposure_prefs(tmp_path: Path) -> None:
    """Default capture disables tracking protection so we record what a
    site *tries* to store, not just what survives the browser's defaults."""
    from leak_inspector.capture.driver import EXPOSURE_PREFS
    options = _build_options(tmp_path)
    for key, value in EXPOSURE_PREFS.items():
        assert options.preferences.get(key) == value


def test_exposure_prefs_accept_all_cookies() -> None:
    """The pref that actually lets third-party tracker cookies be stored is
    ``network.cookie.cookieBehavior == 0`` (accept all, unpartitioned)."""
    from leak_inspector.capture.driver import EXPOSURE_PREFS
    assert EXPOSURE_PREFS["network.cookie.cookieBehavior"] == 0
    assert EXPOSURE_PREFS["privacy.trackingprotection.enabled"] is False


def test_exposure_prefs_unblock_resource_lists_and_storage() -> None:
    """Standard ETP still blocks cryptomining/fingerprinting scripts from
    loading and partitions non-cookie storage. Disabling these lets the
    capture observe trackers that would otherwise never execute and the
    cross-site storage they attempt to persist."""
    from leak_inspector.capture.driver import EXPOSURE_PREFS
    assert EXPOSURE_PREFS["privacy.trackingprotection.cryptomining.enabled"] is False
    assert EXPOSURE_PREFS["privacy.trackingprotection.fingerprinting.enabled"] is False
    assert EXPOSURE_PREFS["privacy.partition.network_state"] is False


def test_exposure_prefs_set_custom_contentblocking_category() -> None:
    """The individual tracking-protection prefs only take effect when the
    governing category is ``custom``. With the default ``standard``
    category Firefox re-derives and overrides them at startup, so the
    cookieBehavior / trackingprotection values would be silently reset."""
    from leak_inspector.capture.driver import EXPOSURE_PREFS
    assert EXPOSURE_PREFS["browser.contentblocking.category"] == "custom"
