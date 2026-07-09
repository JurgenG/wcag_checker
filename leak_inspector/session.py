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
visible Firefox, installs the BiDi ``Ctrl+Alt+A`` hotkey (see
:mod:`.capture.bidi`), and on each keypress audits the page as it is
rendered at that instant — axe-core plus the keyboard/focus checks —
accumulating findings across every page the operator marks. When the
window closes, it writes the report (JSON + text + Markdown + HTML) and
the manual-review checklist to the output directory.

Thread-safety: the hotkey fires on a BiDi background thread, but Selenium
WebDriver is not thread-safe, so the callback only *enqueues* a request.
Every driver command — the audits and the window-close poll — runs on the
main thread, draining that queue. This serializes all WebDriver access.

The pure output assembly (:func:`write_reports`) and the audit loop
(:func:`_run_audit_loop`, driver-agnostic via an injected audit function)
are unit-tested; the live wiring in :func:`run_session` is smoke-tested.
"""

from __future__ import annotations

import queue
import time
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from selenium.common.exceptions import WebDriverException

from .capture.bidi import BiDiCapture
from .capture.driver import launch_driver
from .wcag import axe_runner, keyboard_nav, manual_checklist, reporter
from .wcag.core import Finding

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


def audit_page(driver: Any, url: str) -> list[Finding]:
    """Run both audit engines against the driver's current page.

    Combines the axe-core audit (:mod:`.wcag.axe_runner`) and the
    keyboard/focus checks (:mod:`.wcag.keyboard_nav`) into one finding
    list, all labelled with ``url``. Impure: drives the live browser.
    """
    findings = list(axe_runner.audit(driver, url))
    findings += keyboard_nav.run_all(driver, url)
    return findings


def run_session(
    target_url: str,
    output_dir: Path | str,
    *,
    headless: bool = False,
    poll_interval: float = DEFAULT_POLL_INTERVAL,
) -> SessionResult:
    """Drive a full interactive audit session and write the reports.

    Opens Firefox on ``target_url``, installs the audit hotkey, and audits
    the live page on each ``Ctrl+Alt+A``. Blocks until the operator closes
    the window, then writes the reports to ``output_dir`` and returns a
    :class:`SessionResult`. ``headless`` runs without a visible window
    (a real desktop is still recommended for accurate focus behaviour).
    """
    audit_queue: queue.Queue[str] = queue.Queue()
    findings: list[Finding] = []
    audited_urls: list[str] = []

    with launch_driver(headless=headless) as launched:
        driver = launched.driver
        bidi = BiDiCapture(driver, lambda event: None)
        bidi.audit_requested_callback = audit_queue.put
        bidi.start()
        try:
            driver.get(target_url)
            findings, audited_urls = _run_audit_loop(
                driver, audit_queue, poll_interval=poll_interval, audit_fn=audit_page
            )
        finally:
            with suppress(Exception):
                bidi.stop()

    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    written = write_reports(output_dir, findings, audited_urls, generated_at=generated_at)
    return SessionResult(
        audited_urls=tuple(audited_urls),
        findings=findings,
        output_dir=Path(output_dir),
        written=written,
    )


def _run_audit_loop(
    driver: Any,
    audit_queue: "queue.Queue[str]",
    *,
    poll_interval: float,
    audit_fn: AuditFn,
) -> tuple[list[Finding], list[str]]:
    """Audit on each queued hotkey press until the window closes.

    Runs entirely on the main thread: drains ``audit_queue`` (populated by
    the BiDi callback thread), and for each request audits the current
    page via ``audit_fn`` and records the URL once. Returns the
    accumulated findings and the first-seen-ordered audited URLs.
    """
    findings: list[Finding] = []
    audited_urls: list[str] = []
    while _window_open(driver):
        if _drain(audit_queue):
            url = _safe_current_url(driver)
            findings.extend(audit_fn(driver, url))
            if url and url not in audited_urls:
                audited_urls.append(url)
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


def _drain(audit_queue: "queue.Queue[str]") -> bool:
    """Empty the queue; return True if at least one request was pending."""
    pending = False
    while True:
        try:
            audit_queue.get_nowait()
        except queue.Empty:
            break
        pending = True
    return pending


__all__ = [
    "DEFAULT_POLL_INTERVAL",
    "SessionResult",
    "audit_page",
    "run_session",
    "write_reports",
]
