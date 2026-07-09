"""Tests for auto-provisioning Firefox when it isn't already installed.

Selenium Manager already downloads Firefox + geckodriver on demand; the
behavior added here is the operator-facing wrapper: detect absence,
print a clear one-time message before the (silent, ~80 MB) download,
set the downloaded binary as the launch target, and turn a failed
download (offline / blocked) into an actionable error instead of a
Selenium stack trace.

The "absent" branch can't be exercised against a real binary (Firefox
is installed in dev/CI), so it is driven by mocking the detector and
the provisioning call — the seams exist precisely for that.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from leak_inspector.capture import driver as driver_module
from leak_inspector.capture.driver import firefox_available, launch_driver


class _AbortFirefox(RuntimeError):
    """Sentinel raised by the fake Firefox ctor to stop before a real launch."""


@pytest.fixture
def captured_options(monkeypatch):
    """Replace the Firefox ctor with one that records options and aborts."""
    seen: dict = {}

    def fake_firefox(*, options):
        seen["options"] = options
        raise _AbortFirefox("intercepted before real launch")

    monkeypatch.setattr(driver_module, "Firefox", fake_firefox)
    return seen


# --- detection ---------------------------------------------------------------


def test_firefox_available_true_in_this_environment() -> None:
    """Dev/CI has Firefox installed → the offline detector resolves it."""
    assert firefox_available() is True


# --- present: no provisioning, no message -----------------------------------


def test_present_firefox_does_not_provision_or_message(
    monkeypatch, capsys, tmp_path, captured_options
) -> None:
    monkeypatch.setattr(driver_module, "firefox_available", lambda: True)

    def boom() -> str:
        raise AssertionError("must not provision when Firefox is present")

    monkeypatch.setattr(driver_module, "_provision_firefox", boom)

    with pytest.raises(_AbortFirefox):
        launch_driver(profile_path=tmp_path)

    # System Firefox is left to Selenium's own resolver: binary_location unset.
    assert not captured_options["options"].binary_location
    assert "downloading" not in capsys.readouterr().err.lower()


# --- absent: provision, message, and point the launch at the download -------


def test_absent_firefox_provisions_with_message(
    monkeypatch, capsys, tmp_path, captured_options
) -> None:
    monkeypatch.setattr(driver_module, "firefox_available", lambda: False)
    monkeypatch.setattr(
        driver_module, "_provision_firefox", lambda: "/cache/firefox/bin"
    )

    with pytest.raises(_AbortFirefox):
        launch_driver(profile_path=tmp_path)

    # The downloaded binary becomes the launch target.
    assert captured_options["options"].binary_location == "/cache/firefox/bin"
    # The operator is told before the blocking download.
    err = capsys.readouterr().err.lower()
    assert "firefox" in err
    assert "download" in err


def test_absent_and_download_fails_raises_actionable_error(
    monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr(driver_module, "firefox_available", lambda: False)

    def fail() -> str:
        raise driver_module._FirefoxProvisionError(
            "Firefox is not installed and could not be downloaded "
            "(offline or blocked). Install Firefox manually, or run "
            "with network access for the one-time fetch."
        )

    monkeypatch.setattr(driver_module, "_provision_firefox", fail)

    with pytest.raises(driver_module._FirefoxProvisionError) as exc:
        launch_driver(profile_path=tmp_path)
    msg = str(exc.value).lower()
    assert "firefox" in msg
    assert "install" in msg


# --- the provisioning helper itself -----------------------------------------


def test_provision_firefox_failure_is_actionable(monkeypatch) -> None:
    """When Selenium Manager can't return a usable browser, the helper
    raises a guidance message, not a raw subprocess error."""
    class FakeManager:
        def binary_paths(self, args):
            raise OSError("network is unreachable")

    monkeypatch.setattr(driver_module, "SeleniumManager", lambda: FakeManager())

    with pytest.raises(driver_module._FirefoxProvisionError) as exc:
        driver_module._provision_firefox()
    msg = str(exc.value).lower()
    assert "firefox" in msg
    assert "install" in msg or "network" in msg


def test_provision_firefox_returns_browser_path(monkeypatch, tmp_path) -> None:
    fake_bin = tmp_path / "firefox"
    fake_bin.write_bytes(b"\x7fELF")  # any existing file

    class FakeManager:
        def binary_paths(self, args):
            assert "--browser" in args and "firefox" in args
            return {"browser_path": str(fake_bin), "driver_path": "/x/gecko"}

    monkeypatch.setattr(driver_module, "SeleniumManager", lambda: FakeManager())
    assert driver_module._provision_firefox() == str(fake_bin)
