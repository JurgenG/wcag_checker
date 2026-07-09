# leak_inspector — record what data a website leaks during a real
# human-driven browsing session.
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

"""Firefox driver setup with WebDriver BiDi enabled.

Builds a Selenium :class:`Firefox` driver configured for capture:

* WebDriver BiDi is enabled (``webSocketUrl`` capability).
* ``dom.webdriver.enabled = false`` so trackers see a normal browser and
  fire their regular code paths.
* Firefox's own outbound chatter (telemetry, auto-update checks,
  safe-browsing pings) is silenced so it does not appear in the capture.
* Enhanced Tracking Protection is turned off (see ``EXPOSURE_PREFS``) so
  the capture records what a site *tries* to store — including tracker
  cookies the browser would otherwise reject — rather than only what
  survives Firefox's defaults.
* Profile is either a freshly created temporary directory (default) or
  an existing Firefox profile passed in via ``profile_path`` for
  "what does this site leak about me when logged in" runs.

The launched driver is wrapped in a :class:`LaunchedDriver` that owns
the profile lifecycle and cleans up the temp directory on close.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from selenium.webdriver import Firefox
from selenium.webdriver.common.selenium_manager import SeleniumManager
from selenium.webdriver.firefox.options import Options as FirefoxOptions


#: The single stealth pref required by PROJECT.md. Hides ``navigator.webdriver``
#: so bot-detection JS sees the same value a hand-driven browser would.
STEALTH_PREFS: dict[str, Any] = {
    "dom.webdriver.enabled": False,
}

#: Disable Firefox's Enhanced Tracking Protection so the capture records
#: what a site *attempts* to store, not merely what survives the browser's
#: defaults. With ETP on (Firefox's default), known third-party tracker
#: cookies are rejected or partitioned, so a ``Set-Cookie`` from e.g.
#: ``px.ads.linkedin.com`` never lands and the storage snapshot can't see
#: it. Turning protection off — chiefly ``cookieBehavior = 0`` (accept all,
#: unpartitioned) — exposes the full set-cookie intent. The trade-off: this
#: is the "tracker intent" view, not the protected real-visitor view.
EXPOSURE_PREFS: dict[str, Any] = {
    # Governing pref: the individual tracking-protection prefs below only
    # stick when the category is "custom". With Firefox's default
    # "standard" category, the category owns those prefs and re-derives
    # them to the standard values at startup — silently clobbering every
    # override here. This line must be present for the rest to take effect.
    "browser.contentblocking.category": "custom",
    "privacy.trackingprotection.enabled": False,
    "privacy.trackingprotection.pbmode.enabled": False,
    "privacy.trackingprotection.socialtracking.enabled": False,
    "network.cookie.cookieBehavior": 0,
    # Cryptomining and fingerprinting lists stay on in Firefox's default
    # Standard mode and block the matching scripts from loading at all —
    # so the tracker never executes and the capture can't see it. Off.
    "privacy.trackingprotection.cryptomining.enabled": False,
    "privacy.trackingprotection.fingerprinting.enabled": False,
    # ``cookieBehavior = 0`` un-partitions cookies but not the rest of
    # browser state; this un-partitions cache / localStorage / IndexedDB
    # so cross-site supercookie attempts become observable too.
    "privacy.partition.network_state": False,
}

#: Firefox-internal traffic we silence so it does not pollute the capture.
#: Each pref disables a specific outbound chatter source.
NOISE_PREFS: dict[str, Any] = {
    "toolkit.telemetry.enabled": False,
    "toolkit.telemetry.unified": False,
    "datareporting.healthreport.uploadEnabled": False,
    "datareporting.policy.dataSubmissionEnabled": False,
    "app.update.enabled": False,
    "app.update.auto": False,
    "browser.safebrowsing.malware.enabled": False,
    "browser.safebrowsing.phishing.enabled": False,
    "browser.safebrowsing.downloads.enabled": False,
}


class _FirefoxProvisionError(RuntimeError):
    """Firefox is absent and could not be auto-downloaded (offline/blocked)."""


def firefox_available() -> bool:
    """Return ``True`` if Firefox can be launched without a download.

    Asks Selenium Manager to resolve Firefox in **offline** mode, so it
    checks system installations and Selenium's own browser cache but
    never reaches the network. ``False`` means the next launch would
    have to download a private copy. Any resolution error is treated as
    "not available" — the caller then provisions explicitly.
    """
    try:
        out = SeleniumManager().binary_paths(["--browser", "firefox", "--offline"])
        path = out.get("browser_path", "")
        return bool(path) and Path(path).is_file()
    except Exception:
        return False


def _provision_firefox() -> str:
    """Download a private Firefox via Selenium Manager; return its path.

    The browser lands in Selenium's default cache (``~/.cache/selenium``
    on Linux/macOS) — a user-space directory needing no admin rights, so
    a subsequent :func:`firefox_available` probe resolves the cached copy
    and the download runs only once. Raises :class:`_FirefoxProvisionError`
    with operator guidance when the download can't complete.
    """
    try:
        out = SeleniumManager().binary_paths(["--browser", "firefox"])
        path = out.get("browser_path", "")
        if not path or not Path(path).is_file():
            raise ValueError(f"no usable Firefox returned: {path!r}")
        return path
    except Exception as exc:
        raise _FirefoxProvisionError(
            "Firefox is not installed and could not be downloaded "
            f"({exc}). Install Firefox manually, or run on a machine "
            "with network access for the one-time ~80 MB fetch."
        ) from exc


@dataclass
class LaunchedDriver(AbstractContextManager):
    """A running Firefox driver together with its profile lifecycle.

    Use as a context manager — exiting closes the WebDriver and (if the
    profile was created by us) removes the temporary directory.
    """

    driver: Firefox
    profile_path: Path
    profile_is_temporary: bool

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def close(self) -> None:
        """Quit the driver and (if applicable) delete the temp profile."""
        try:
            self.driver.quit()
        finally:
            if self.profile_is_temporary:
                shutil.rmtree(self.profile_path, ignore_errors=True)


def launch_driver(
    profile_path: Path | str | None = None,
    *,
    headless: bool = False,
) -> LaunchedDriver:
    """Launch Firefox with BiDi enabled and capture-friendly prefs.

    ``profile_path``:
      * ``None`` (default) — create a fresh temporary profile directory
        that will be deleted when the returned :class:`LaunchedDriver`
        is closed. Isolates the capture from the developer's history.
      * Path to an existing Firefox profile — used **in place**. The
        browsing session will mutate it (cookies, history, etc.); copy
        the profile beforehand if that is not what you want. The path
        must point to an existing directory.

    ``headless``:
      * ``False`` (default) — visible Firefox window. Required for the
        project's primary use case of recording real human-driven
        browsing sessions.
      * ``True`` — Firefox runs without a visible window. Intended for
        the bulk-tool's already-scripted scan mode so the operator
        doesn't have to watch dozens of windows pop up. BiDi events,
        stealth prefs, and ``get_screenshot_as_png`` all still work.
        Some sites do fingerprint the headless profile differently —
        if you're auditing real visitor exposure, use visible mode.
    """
    profile_is_temporary = profile_path is None
    if profile_is_temporary:
        resolved_profile = Path(tempfile.mkdtemp(prefix="leak_inspector_profile_"))
    else:
        resolved_profile = Path(profile_path)
        if not resolved_profile.is_dir():
            raise FileNotFoundError(
                f"profile path does not exist or is not a directory: {resolved_profile}"
            )

    options = _build_options(resolved_profile, headless=headless)

    # Auto-provision Firefox if it isn't already present. Selenium would
    # download it implicitly inside ``Firefox(options)`` anyway, but doing
    # it explicitly lets us warn the operator before the silent ~80 MB
    # download and turn an offline failure into actionable guidance. The
    # downloaded binary becomes the launch target; geckodriver still
    # auto-provisions via Selenium's own DriverFinder.
    if not firefox_available():
        print(
            "Firefox not found — downloading a private copy for capture "
            "(~80 MB, one-time). This may take a minute…",
            file=sys.stderr,
        )
        options.binary_location = _provision_firefox()

    driver = Firefox(options=options)

    return LaunchedDriver(
        driver=driver,
        profile_path=resolved_profile,
        profile_is_temporary=profile_is_temporary,
    )


def _build_options(profile_path: Path, *, headless: bool = False) -> FirefoxOptions:
    """Construct the :class:`FirefoxOptions` used for a capture session."""
    options = FirefoxOptions()

    # Enable WebDriver BiDi. ``webSocketUrl=True`` is the W3C-standard
    # capability; Selenium >= 4.20 propagates it to geckodriver.
    options.set_capability("webSocketUrl", True)

    # Point Firefox at the chosen profile directory.
    options.add_argument("-profile")
    options.add_argument(str(profile_path))

    if headless:
        # Bulk-mode escape hatch: hide the visible window while still
        # driving a real Firefox. Screenshots, BiDi events, and stealth
        # prefs all continue to work.
        options.add_argument("--headless")

    for key, value in STEALTH_PREFS.items():
        options.set_preference(key, value)
    for key, value in NOISE_PREFS.items():
        options.set_preference(key, value)
    for key, value in EXPOSURE_PREFS.items():
        options.set_preference(key, value)

    return options


__all__ = [
    "EXPOSURE_PREFS",
    "LaunchedDriver",
    "NOISE_PREFS",
    "STEALTH_PREFS",
    "firefox_available",
    "launch_driver",
]
