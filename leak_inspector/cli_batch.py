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

"""``wcag-batch`` command line: audit a list of URLs non-interactively.

Thin argument-parsing wrapper over :func:`leak_inspector.batch.run_batch`.
Reads a plain-text URL list (one per line), audits each into its own
report subdirectory, and writes an aggregate ``summary.{json,md,html}``.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from . import batch, session

_DESCRIPTION = (
    "Audit every URL in a list file for WCAG 2.2 AA issues, one report "
    "directory per site plus an aggregate summary. A clean run is not a "
    "conformance claim."
)


def build_parser() -> argparse.ArgumentParser:
    """Construct the ``wcag-batch`` argument parser."""
    parser = argparse.ArgumentParser(prog="wcag-batch", description=_DESCRIPTION)
    parser.add_argument(
        "urls_file",
        type=Path,
        help="text file with one URL per line (# comments and blanks ignored)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("runs"),
        help="directory for the per-site reports + summary (default: runs/)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="audit only the first N URLs (default: all)",
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help="run Firefox hidden (focus/keyboard checks are less reliable)",
    )
    parser.add_argument(
        "--format",
        default="html",
        metavar="FMT",
        help=(
            "per-site report format(s), comma-separated — choose from "
            + ", ".join(session.FORMAT_CHOICES)
            + " (default: %(default)s). 'jira-tickets' writes one ticket per "
            "issue type per site into that site's jira/ subfolder."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, run the batch, and print a short summary."""
    args = build_parser().parse_args(argv)

    try:
        formats = session.parse_formats(args.format)
    except ValueError as exc:
        print(f"Invalid --format {args.format!r}: {exc}")
        return 2

    urls = batch.read_urls(args.urls_file)
    planned = len(urls) if args.limit is None else min(len(urls), args.limit)
    print(f"Auditing {planned} of {len(urls)} URL(s) from {args.urls_file}...")

    result = batch.run_batch(
        urls,
        args.out,
        headless=args.headless,
        limit=args.limit,
        source=str(args.urls_file),
        formats=formats,
    )

    audited = sum(1 for s in result.sites if s.status == "audited")
    failed = len(result.sites) - audited
    print(f"Done: {audited} audited, {failed} failed.")
    print(f"Summary + per-site reports written to {result.output_dir}/")
    print("Reminder: a clean automated run does not imply WCAG 2.2 conformance.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
