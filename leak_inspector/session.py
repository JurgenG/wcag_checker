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

"""Orchestrate a live audit session: capture → per-page audit → report.

Wires the reused capture layer to the WCAG audit engines. It opens a
visible Firefox, installs the audit hotkey (see :mod:`.capture.hotkey`),
and on each press audits the page as it is rendered at that instant —
axe-core plus the keyboard/focus checks — accumulating findings across
every page the operator marks. When the window closes, it writes the
report (JSON + text + Markdown + HTML) and the manual-review checklist to
the output directory.

The hotkey is detected by polling: each loop tick runs one
``execute_script`` (via :class:`~.capture.hotkey.HotkeyWatcher`) that both
installs the in-page keydown listener and reads how many times it fired.
Everything — the poll, the audits, the window-close check — runs on the
main thread, so there is no cross-thread state to guard.

The pure output assembly (:func:`write_reports`) and the audit loop
(:func:`_run_audit_loop`, driver-agnostic via injected audit/poll
functions) are unit-tested; the live wiring in :func:`run_session` is
smoke-tested.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from selenium.common.exceptions import WebDriverException

from .capture.driver import launch_driver
from .capture.hotkey import DEFAULT_HOTKEY, HotkeyWatcher
from .wcag import axe_runner, keyboard_nav, manual_checklist, reporter, screenshot
from .wcag.core import Finding

#: Subdirectory of the output directory that per-finding element
#: screenshots are written to.
SCREENSHOT_DIRNAME = "screenshots"

#: How often (seconds) the main loop polls for a closed window / pending
#: audit request when idle.
DEFAULT_POLL_INTERVAL = 0.5

#: Signature of the per-page audit function the loop calls.
AuditFn = Callable[[Any, str], list[Finding]]


@dataclass(frozen=True)
class SessionResult:
    """Outcome of a completed audit session.

    ``audited_urls`` are the pages the operator marked (in first-seen
    order), ``findings`` the accumulated findings across them,
    ``output_dir`` where reports were written, and ``written`` maps each
    report basename to its path.
    """

    audited_urls: tuple[str, ...]
    findings: list[Finding]
    output_dir: Path
    written: dict[str, Path]


def audit_page(
    driver: Any, url: str, screenshot_dir: Path | str | None = None
) -> list[Finding]:
    """Run both audit engines against the driver's current page.

    Combines the axe-core audit (:mod:`.wcag.axe_runner`) and the
    keyboard/focus checks (:mod:`.wcag.keyboard_nav`) into one finding
    list, all labelled with ``url``. When ``screenshot_dir`` is given,
    captures an element-level PNG for each finding into it
    (:mod:`.wcag.screenshot`) while the page is still rendered. Impure:
    drives the live browser and, with ``screenshot_dir``, writes PNGs.
    """
    findings = list(axe_runner.audit(driver, url))
    findings += keyboard_nav.run_all(driver, url)
    if screenshot_dir is not None:
        findings = screenshot.capture_findings(driver, findings, screenshot_dir)
    return findings


def run_session(
    target_url: str,
    output_dir: Path | str,
    *,
    headless: bool = False,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
    on_audit: Callable[[str, int], None] | None = None,
    hotkey: str = DEFAULT_HOTKEY,
) -> SessionResult:
    """Drive a full interactive audit session and write the reports.

    Opens Firefox on ``target_url``, installs the audit ``hotkey`` (default
    :data:`~.capture.hotkey.DEFAULT_HOTKEY`), and audits the live page on
    each press, saving a PNG of every flagged element to
    ``<output_dir>/screenshots/`` as evidence. ``on_audit`` is called after
    each audit with the URL and finding count (the CLI uses it to confirm
    each press). Blocks until the operator closes the window, then writes
    the reports to ``output_dir`` and returns a :class:`SessionResult`.
    ``headless`` runs without a visible window (a real desktop is still
    recommended for accurate focus behaviour).
    """
    findings: list[Finding] = []
    audited_urls: list[str] = []
    screenshot_dir = Path(output_dir) / SCREENSHOT_DIRNAME

    with launch_driver(headless=headless) as launched:
        driver = launched.driver
        watcher = HotkeyWatcher(driver, hotkey=hotkey)
        driver.get(target_url)
        findings, audited_urls = _run_audit_loop(
            driver,
            poll_interval=poll_interval,
            audit_fn=lambda d, u: audit_page(d, u, screenshot_dir),
            poll_fn=watcher.poll,
            on_audit=on_audit,
        )

    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    written = write_reports(output_dir, findings, audited_urls, generated_at=generated_at)
    return SessionResult(
        audited_urls=tuple(audited_urls),
        findings=findings,
        output_dir=Path(output_dir),
        written=written,
    )


def run_once(
    target_url: str,
    output_dir: Path | str,
    *,
    headless: bool = False,
) -> SessionResult:
    """Audit a single page non-interactively and write the reports.

    Opens Firefox on ``target_url``, waits for the page to settle (so a
    client-side redirect cannot leave axe-core injected into a discarded
    document — see :func:`wait_until_settled`), audits that one rendered
    page, writes the reports to ``output_dir``, and returns a
    :class:`SessionResult`. Unlike :func:`run_session` there is no audit
    hotkey and no window-close wait — it audits once and exits, which also
    handles pages that redirect or vanish too fast to press ``Ctrl+Alt+A``
    by hand. ``headless`` runs without a visible window.

    ``SessionResult.audited_urls`` holds the single URL the page settled
    on; when that differs from ``target_url`` a redirect occurred.
    """
    screenshot_dir = Path(output_dir) / SCREENSHOT_DIRNAME
    with launch_driver(headless=headless) as launched:
        driver = launched.driver
        driver.get(target_url)
        audited_url = wait_until_settled(driver)
        findings = audit_page(driver, audited_url, screenshot_dir)

    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    written = write_reports(
        output_dir, findings, [audited_url], generated_at=generated_at
    )
    return SessionResult(
        audited_urls=(audited_url,),
        findings=findings,
        output_dir=Path(output_dir),
        written=written,
    )


def wait_until_settled(
    driver: Any,
    *,
    timeout: float = 15.0,
    quiet: float = 1.5,
    poll: float = 0.25,
) -> str:
    """Block until the page stops navigating and has finished loading.

    A client-side redirect (e.g. language detection) can replace the
    document shortly after ``driver.get`` returns; auditing before that
    settles injects axe-core into a doomed document and ``axe.run`` then
    fails with "axe is not defined". This polls ``driver.current_url`` and
    ``document.readyState`` and returns once the URL has held steady for
    ``quiet`` seconds while ``readyState`` is ``"complete"``, or once
    ``timeout`` seconds elapse (whichever comes first). Returns the URL the
    page settled on — callers treat that as the audited URL, since a
    redirect means it differs from the one requested.
    """
    start = time.monotonic()
    last_url: str | None = None
    stable_since = start
    while True:
        now = time.monotonic()
        try:
            url = driver.current_url
            ready = driver.execute_script(
                "return document.readyState === 'complete';"
            )
        except WebDriverException:
            # Mid-navigation: the context is momentarily unavailable. Treat
            # it as not-yet-settled and keep waiting.
            url, ready = None, False
            last_url = None
        if url is not None:
            if url != last_url:
                last_url, stable_since = url, now
            elif ready and now - stable_since >= quiet:
                return url
        if now - start >= timeout:
            return last_url if last_url is not None else _safe_current_url(driver)
        time.sleep(poll)


def _run_audit_loop(
    driver: Any,
    *,
    poll_interval: float,
    audit_fn: AuditFn,
    poll_fn: Callable[[], int],
    on_audit: Callable[[str, int], None] | None = None,
) -> tuple[list[Finding], list[str]]:
    """Audit whenever the hotkey poll reports presses, until the window closes.

    Runs entirely on the main thread. Each tick calls ``poll_fn`` (which
    installs the in-page hotkey listener if needed and returns the number
    of presses since the last poll); a non-zero result triggers one audit
    of the current page via ``audit_fn``, records the URL once, and calls
    ``on_audit`` with the URL and finding count so the caller can give the
    operator live feedback. Returns the accumulated findings and the
    first-seen-ordered audited URLs.
    """
    findings: list[Finding] = []
    audited_urls: list[str] = []
    while _window_open(driver):
        if poll_fn():
            url = _safe_current_url(driver)
            new_findings = audit_fn(driver, url)
            findings.extend(new_findings)
            if url and url not in audited_urls:
                audited_urls.append(url)
            if on_audit is not None:
                on_audit(url, len(new_findings))
        else:
            time.sleep(poll_interval)
    return findings, audited_urls


def write_reports(
    output_dir: Path | str,
    findings: list[Finding],
    urls: list[str],
    *,
    generated_at: str | None = None,
) -> dict[str, Path]:
    """Render and write every report format to ``output_dir``.

    Builds the report document and the manual-review checklist, then
    writes ``results.json``, ``report.txt``, ``report.md``,
    ``report.html``, and ``manual-checklist.md`` (UTF-8). Creates
    ``output_dir`` if needed. Returns a basename→path map. This is the
    module's pure output seam — no driver, no network.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    document = reporter.build_report(findings, urls=urls, generated_at=generated_at)
    checklist = manual_checklist.build_checklist(urls, generated_at=generated_at)

    payloads = {
        "results.json": reporter.render_json(document),
        "report.txt": reporter.render_text(document),
        "report.md": reporter.render_markdown(document),
        "report.html": reporter.render_html(document),
        "manual-checklist.md": manual_checklist.render_markdown(checklist),
    }
    written: dict[str, Path] = {}
    for name, text in payloads.items():
        path = out / name
        path.write_text(text, encoding="utf-8")
        written[name] = path
    return written


def _window_open(driver: Any) -> bool:
    """Return True while the browser window is still open."""
    try:
        return bool(driver.window_handles)
    except WebDriverException:
        return False


def _safe_current_url(driver: Any) -> str:
    """Return the driver's current URL, or '' if it cannot be read."""
    try:
        return driver.current_url or ""
    except WebDriverException:
        return ""


__all__ = [
    "DEFAULT_POLL_INTERVAL",
    "SCREENSHOT_DIRNAME",
    "SessionResult",
    "audit_page",
    "run_once",
    "run_session",
    "wait_until_settled",
    "write_reports",
]
