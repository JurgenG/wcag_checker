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

_DESCRIPTION = (
    "Open Firefox on a URL and audit it for WCAG 2.2 AA issues. By default "
    "you browse by hand and press Ctrl+Alt+A on each page to audit; with "
    "--once the given page is audited automatically and the tool exits. A "
    "clean run is not a conformance claim."
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
            "page redirects or closes too fast to press Ctrl+Alt+A)"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, run the chosen session mode, and print a summary."""
    args = build_parser().parse_args(argv)

    if args.once:
        return _run_once(args)
    return _run_interactive(args)


def _run_interactive(args: argparse.Namespace) -> int:
    """Run the hand-driven hotkey session and print a short summary."""
    print(
        "Opening Firefox. Browse to any page you want checked and press "
        "Ctrl+Alt+A to audit it; close the window when you're done."
    )
    result = session.run_session(args.url, args.out, headless=args.headless)

    print(
        f"Audited {len(result.audited_urls)} page(s); "
        f"{len(result.findings)} finding(s)."
    )
    print(f"Reports written to {result.output_dir}/")
    print("Reminder: a clean automated run does not imply WCAG 2.2 conformance.")
    return 0


def _run_once(args: argparse.Namespace) -> int:
    """Run a one-shot single-page audit and print a short summary."""
    print(f"Opening Firefox and auditing {args.url} once...")
    result = session.run_once(args.url, args.out, headless=args.headless)

    audited = result.audited_urls[0] if result.audited_urls else args.url
    if audited != args.url:
        print(f"Note: {args.url} redirected to {audited}; audited that.")
    print(f"Audited {audited}; {len(result.findings)} finding(s).")
    print(f"Reports written to {result.output_dir}/")
    print("Reminder: a clean automated run does not imply WCAG 2.2 conformance.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
