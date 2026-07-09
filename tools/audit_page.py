"""Single-page WCAG audit runner.

Launches a real Firefox via the capture driver, navigates to a URL, waits
for the page to settle (so a client-side redirect can't leave axe-core
injected into a discarded document), then runs the axe-core audit and the
keyboard/focus checks against the live page and renders the merged
findings grouped by WCAG criterion. Prints the text report; with ``--out``
also writes results.json + report.{txt,md,html} and a ``screenshots/``
directory with an element-level PNG per finding.

This audits a single page's rendered state in one shot; the interactive
``wcag-checker`` command is the full hand-driven, multi-page workflow. The
smoke runner stays as a quick, non-interactive check of one page.

    python tools/audit_page.py https://example.com
    python tools/audit_page.py https://example.com --out reports/
    python tools/audit_page.py https://example.com --headless

A clean run does NOT mean the page conforms — the automated checks decide
only part of a subset of WCAG 2.2, and the manual-review criteria are not
covered here at all.
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from selenium.common.exceptions import WebDriverException

from leak_inspector.capture.driver import launch_driver
from leak_inspector.session import SCREENSHOT_DIRNAME
from leak_inspector.wcag import (
    axe_runner,
    keyboard_nav,
    manual_checklist,
    reporter,
    screenshot,
)


def wait_until_settled(
    driver,
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
    page settled on — which callers should treat as the audited URL, since
    a redirect means it differs from the one requested.
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
            return last_url if last_url is not None else _current_url(driver)
        time.sleep(poll)


def _current_url(driver) -> str:
    """Best-effort read of the driver's current URL, '' if unavailable."""
    try:
        return driver.current_url or ""
    except WebDriverException:
        return ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="URL to audit (include the scheme)")
    parser.add_argument(
        "--headless",
        action="store_true",
        help="run Firefox without a visible window",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="directory to write results.json + report.{txt,md,html} into",
    )
    args = parser.parse_args(argv)

    with launch_driver(headless=args.headless) as launched:
        launched.driver.get(args.url)
        audited_url = wait_until_settled(launched.driver)
        findings = axe_runner.audit(launched.driver, audited_url)
        findings += keyboard_nav.run_all(launched.driver, audited_url)
        if args.out is not None:
            findings = screenshot.capture_findings(
                launched.driver, findings, args.out / SCREENSHOT_DIRNAME
            )

    if audited_url != args.url:
        print(f"Note: {args.url} redirected to {audited_url}; audited that.")

    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    document = reporter.build_report(
        findings, urls=[audited_url], generated_at=generated_at
    )
    checklist = manual_checklist.build_checklist(
        [audited_url], generated_at=generated_at
    )

    print(reporter.render_text(document))

    if args.out is not None:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "results.json").write_text(
            reporter.render_json(document), encoding="utf-8"
        )
        (args.out / "report.txt").write_text(
            reporter.render_text(document), encoding="utf-8"
        )
        (args.out / "report.md").write_text(
            reporter.render_markdown(document), encoding="utf-8"
        )
        (args.out / "report.html").write_text(
            reporter.render_html(document), encoding="utf-8"
        )
        (args.out / "manual-checklist.md").write_text(
            manual_checklist.render_markdown(checklist), encoding="utf-8"
        )
        print(f"Reports written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())