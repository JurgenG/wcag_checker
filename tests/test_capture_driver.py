"""Tests for the capture-layer driver helpers.

These exercise pure-function paths (``_build_options``) that don't need
a real Firefox binary or geckodriver — actual driver launch is tested
out-of-band via the bulk-tool smoke run.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from leak_inspector.capture.driver import _build_options


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


# --- Recorder forwards the flag --------------------------------------------


def test_recorder_default_is_visible() -> None:
    """Backward-compat: existing direct callers get a visible browser."""
    from leak_inspector.capture.recorder import Recorder
    r = Recorder("https://example.be", "/tmp/x.zip")
    assert r._headless is False


def test_recorder_accepts_headless_kwarg() -> None:
    from leak_inspector.capture.recorder import Recorder
    r = Recorder("https://example.be", "/tmp/x.zip", headless=True)
    assert r._headless is True


def test_recorder_forwards_headless_to_launch_driver(monkeypatch, tmp_path: Path) -> None:
    """Recorder.run() must pass ``headless`` through to launch_driver.

    We don't run a real capture — just intercept ``launch_driver`` and
    abort the run with an early error after the call is observed.
    """
    from leak_inspector.capture import recorder as recorder_module
    seen: list[bool] = []

    def fake_launch_driver(profile_path=None, *, headless=False):
        seen.append(headless)
        # Abort the capture cleanly — anything truthy that triggers the
        # except chain works, the goal is just to observe the kwarg.
        raise RuntimeError("smoke-test abort: launch_driver intercepted")

    monkeypatch.setattr(recorder_module, "launch_driver", fake_launch_driver)
    r = recorder_module.Recorder(
        "https://example.be",
        tmp_path / "x.zip",
        work_dir=tmp_path / "work",
        auto_close_after_load=1.0,
        headless=True,
    )
    with pytest.raises(RuntimeError, match="launch_driver intercepted"):
        r.run()
    assert seen == [True]


# --- Recorder: extra-screenshot filename derivation -------------------------


def test_capture_extra_screenshot_writes_timestamped_file(tmp_path: Path) -> None:
    """``_capture_extra_screenshot`` writes screenshot_<host>_<HHMMSS>.png."""
    from leak_inspector.capture.recorder import Recorder

    class FakeDriver:
        def get_screenshot_as_png(self) -> bytes:
            return b"\x89PNG-fake"

    Recorder._capture_extra_screenshot(
        FakeDriver(), tmp_path, host="www.example.be", hhmmss="143052",
    )
    expected = tmp_path / "screenshot_www.example.be_143052.png"
    assert expected.is_file()
    assert expected.read_bytes() == b"\x89PNG-fake"


def test_capture_extra_screenshot_sanitizes_path_traversal(tmp_path: Path) -> None:
    """A malformed host must never escape session_dir or use weird chars."""
    from leak_inspector.capture.recorder import Recorder

    class FakeDriver:
        def get_screenshot_as_png(self) -> bytes:
            return b"\x89PNG"

    Recorder._capture_extra_screenshot(
        FakeDriver(), tmp_path,
        host="../etc/passwd",  # path traversal attempt
        hhmmss="120000",
    )
    # No file (PNG or page-source sibling) escapes tmp_path; every name
    # derives from the sanitized host, so none carries traversal chars.
    children = list(tmp_path.iterdir())
    assert children  # something was written
    for child in children:
        assert child.parent == tmp_path
        assert ".." not in child.name
        assert "/" not in child.name


def test_capture_extra_screenshot_empty_host_falls_back(tmp_path: Path) -> None:
    """When the sentinel URL had no ?host=, we still get a writable name."""
    from leak_inspector.capture.recorder import Recorder

    class FakeDriver:
        def get_screenshot_as_png(self) -> bytes:
            return b"\x89PNG"

    Recorder._capture_extra_screenshot(
        FakeDriver(), tmp_path, host="", hhmmss="000000",
    )
    files = list(tmp_path.glob("screenshot_*.png"))
    assert len(files) == 1
    assert "000000" in files[0].name


def test_capture_extra_screenshot_soft_fails_on_webdriver_error(tmp_path: Path) -> None:
    """A Selenium error must not raise from the BiDi callback thread."""
    from leak_inspector.capture.recorder import Recorder
    from selenium.common.exceptions import WebDriverException

    class FailingDriver:
        def get_screenshot_as_png(self) -> bytes:
            raise WebDriverException("dead")

    # Must not raise.
    Recorder._capture_extra_screenshot(
        FailingDriver(), tmp_path, host="x.be", hhmmss="120000",
    )
    # No PNG written.
    assert not list(tmp_path.glob("screenshot_*.png"))


# --- Recorder: page source captured alongside each screenshot ---------------


class _PageDriver:
    """Screenshot-capable driver that also exposes the page-source members.

    ``execute_script`` returns ``[]`` so the page-source helper enumerates
    no ``<script src>`` and its default (network) fetcher never fires —
    keeping these tests offline without injecting a fetcher.
    """

    def __init__(self, page_source: str = "<html></html>") -> None:
        self._page_source = page_source

    def get_screenshot_as_png(self) -> bytes:
        return b"\x89PNG-fake"

    @property
    def page_source(self) -> str:
        return self._page_source

    def execute_script(self, _script: str):
        return []


def test_post_load_screenshot_also_writes_page_source(tmp_path: Path) -> None:
    """``_capture_screenshot`` pairs ``screenshot.png`` with ``page_source.html``."""
    from leak_inspector.capture.recorder import Recorder

    Recorder._capture_screenshot(_PageDriver("<html>raw &amp;</html>"), tmp_path)

    assert (tmp_path / "screenshot.png").is_file()
    assert (tmp_path / "page_source.html").read_text("utf-8") == \
        "<html>raw &amp;</html>"
    assert (tmp_path / "page_source.scripts.json").is_file()


def test_extra_screenshot_page_source_suffix_mirrors_png(tmp_path: Path) -> None:
    """The page-source suffix must match the timestamped PNG's, so Phase 3
    can pair ``page_source<suffix>.html`` with ``screenshot<suffix>.png``."""
    from leak_inspector.capture.recorder import Recorder

    Recorder._capture_extra_screenshot(
        _PageDriver(), tmp_path, host="www.example.be", hhmmss="143052",
    )

    assert (tmp_path / "screenshot_www.example.be_143052.png").is_file()
    assert (tmp_path / "page_source_www.example.be_143052.html").is_file()
    assert (tmp_path / "page_source_www.example.be_143052.scripts.json").is_file()


def test_failed_screenshot_writes_no_page_source(tmp_path: Path) -> None:
    """Page source is coupled to a successful screenshot — a dead driver
    that can't shoot the PNG must not leave an orphan ``page_source.html``."""
    from leak_inspector.capture.recorder import Recorder
    from selenium.common.exceptions import WebDriverException

    class FailingDriver:
        def get_screenshot_as_png(self) -> bytes:
            raise WebDriverException("dead")

    Recorder._capture_screenshot(FailingDriver(), tmp_path)
    Recorder._capture_extra_screenshot(
        FailingDriver(), tmp_path, host="x.be", hhmmss="120000",
    )

    assert not list(tmp_path.glob("page_source*"))
