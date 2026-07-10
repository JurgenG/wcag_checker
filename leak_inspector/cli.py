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

"""``wcag-checker`` command line.

Thin argument-parsing wrapper over the two session entry points in
:mod:`leak_inspector.session`. By default it runs the interactive session
(:func:`~leak_inspector.session.run_session`): Firefox opens on a starting
URL, the operator browses by hand and presses ``Ctrl+Alt+A`` on each page
to audit, then closes the window to write the reports. With ``--once`` it
runs a one-shot audit (:func:`~leak_inspector.session.run_once`) of a
single page and exits — no hotkey — which is the right choice for a page
that redirects or vanishes too fast to press the hotkey by hand.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from . import session
from .capture.hotkey import DEFAULT_HOTKEY, format_hotkey, hotkey_condition

_DESCRIPTION = (
    "Open Firefox on a URL and audit it for WCAG 2.2 AA issues. By default "
    "you browse by hand and press the audit hotkey on each page to audit; "
    "with --once the given page is audited automatically and the tool exits. "
    "A clean run is not a conformance claim."
)


def build_parser() -> argparse.ArgumentParser:
    """Construct the ``wcag-checker`` argument parser."""
    parser = argparse.ArgumentParser(prog="wcag-checker", description=_DESCRIPTION)
    parser.add_argument("url", help="starting URL to open (include the scheme)")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("reports"),
        help="directory for the reports (default: reports/)",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="run Firefox without a visible window (a real desktop is preferred)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help=(
            "audit the given page once and exit, without the interactive "
            "hotkey (waits for the page to settle first — use this when a "
            "page redirects or closes too fast to press the hotkey)"
        ),
    )
    parser.add_argument(
        "--hotkey",
        default=DEFAULT_HOTKEY,
        metavar="COMBO",
        help=(
            "interactive audit hotkey, e.g. ctrl+alt+shift+a or f9 "
            "(default: %(default)s). Change it if your window manager grabs "
            "the default combo."
        ),
    )
    parser.add_argument(
        "--format",
        default="html",
        metavar="FMT",
        help=(
            "report format(s), comma-separated — choose from "
            + ", ".join(session.FORMAT_CHOICES)
            + " (default: %(default)s). 'jira-tickets' writes one JIRA-style "
            "ticket per issue type into a jira/ subfolder; 'all' writes every "
            "format. The manual-review checklist is always written."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, run the chosen session mode, and print a summary."""
    args = build_parser().parse_args(argv)

    try:
        formats = session.parse_formats(args.format)
    except ValueError as exc:
        print(f"Invalid --format {args.format!r}: {exc}")
        return 2

    if args.once:
        return _run_once(args, formats)

    try:
        hotkey_condition(args.hotkey)  # validate before launching Firefox
    except ValueError as exc:
        print(f"Invalid --hotkey {args.hotkey!r}: {exc}")
        return 2
    return _run_interactive(args, formats)


def _run_interactive(args: argparse.Namespace, formats: tuple[str, ...]) -> int:
    """Run the hand-driven hotkey session and print a short summary."""
    combo = format_hotkey(args.hotkey)
    print(
        f"Opening Firefox. Browse to a page you want checked, click into the "
        f"page (so it has keyboard focus), then press {combo} to audit it. "
        f"Each audit is confirmed below. Close the window when you're done."
    )

    def _confirm(url: str, count: int) -> None:
        print(f"  audited {url} — {count} finding(s)")

    result = session.run_session(
        args.url,
        args.out,
        headless=args.headless,
        on_audit=_confirm,
        hotkey=args.hotkey,
        formats=formats,
    )

    print(
        f"Audited {len(result.audited_urls)} page(s); "
        f"{len(result.findings)} finding(s)."
    )
    print(f"Reports written to {result.output_dir}/")
    print("Reminder: a clean automated run does not imply WCAG 2.2 conformance.")
    return 0


def _run_once(args: argparse.Namespace, formats: tuple[str, ...]) -> int:
    """Run a one-shot single-page audit and print a short summary."""
    print(f"Opening Firefox and auditing {args.url} once...")
    result = session.run_once(
        args.url, args.out, headless=args.headless, formats=formats
    )

    audited = result.audited_urls[0] if result.audited_urls else args.url
    if audited != args.url:
        print(f"Note: {args.url} redirected to {audited}; audited that.")
    print(f"Audited {audited}; {len(result.findings)} finding(s).")
    print(f"Reports written to {result.output_dir}/")
    print("Reminder: a clean automated run does not imply WCAG 2.2 conformance.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
