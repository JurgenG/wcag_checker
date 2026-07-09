"""Single-page WCAG audit runner.

Launches a real Firefox via the capture driver, navigates to a URL, runs
the axe-core audit and the keyboard/focus checks against the live page,
and renders the merged findings grouped by WCAG criterion. Prints the
text report; with ``--out`` also writes results.json + report.{txt,md,html}
and a ``screenshots/`` directory with an element-level PNG per finding.

This audits a single page's rendered state in one shot; the interactive
``wcag-checker`` command is the full hand-driven, multi-page workflow. The
smoke runner stays as a quick, non-interactive check of one page.

    python tools/wcag_smoke.py https://example.com
    python tools/wcag_smoke.py https://example.com --out reports/
    python tools/wcag_smoke.py https://example.com --headless

A clean run does NOT mean the page conforms — the automated checks decide
only part of a subset of WCAG 2.2, and the manual-review criteria are not
covered here at all.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from leak_inspector.capture.driver import launch_driver
from leak_inspector.session import SCREENSHOT_DIRNAME
from leak_inspector.wcag import (
    axe_runner,
    keyboard_nav,
    manual_checklist,
    reporter,
    screenshot,
)


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
        findings = axe_runner.audit(launched.driver)
        findings += keyboard_nav.run_all(launched.driver)
        if args.out is not None:
            findings = screenshot.capture_findings(
                launched.driver, findings, args.out / SCREENSHOT_DIRNAME
            )

    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    document = reporter.build_report(
        findings, urls=[args.url], generated_at=generated_at
    )
    checklist = manual_checklist.build_checklist(
        [args.url], generated_at=generated_at
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