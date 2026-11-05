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
Reads a URL list (one URL per line, or two comma-separated columns with a
name and a URL), audits each into its own report subdirectory, and writes
an aggregate ``summary.{json,md,html}``. ``--lang`` chooses the language
of the reports, the summary, and this command's messages and help.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from . import batch, session
from .cli import REMINDER, add_lang_argument, chosen_lang
from .i18n import DEFAULT_LANG, tr


def build_parser(lang: str = DEFAULT_LANG) -> argparse.ArgumentParser:
    """Construct the ``wcag-batch`` argument parser, with help in ``lang``."""
    parser = argparse.ArgumentParser(
        prog="wcag-batch",
        description=tr(
            lang,
            "Audit every URL in a list file for WCAG 2.2 AA issues, one report "
            "directory per site plus an aggregate summary. A clean run is not "
            "a conformance claim.",
        ),
    )
    parser.add_argument(
        "urls_file",
        type=Path,
        help=tr(
            lang,
            "text file with one URL per line, or name,url pairs (# comments "
            "and blanks ignored)",
        ),
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("runs"),
        help=tr(lang, "directory for the per-site reports + summary (default: runs/)"),
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help=tr(lang, "audit only the first N URLs (default: all)"),
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help=tr(lang, "run Firefox hidden (focus/keyboard checks are less reliable)"),
    )
    parser.add_argument(
        "--width",
        type=int,
        default=None,
        metavar="PX",
        help=tr(
            lang,
            "resize the browser window to this pixel width before auditing "
            "every site, to check responsive/mobile layouts (default: "
            "Firefox's own window width)",
        ),
    )
    parser.add_argument(
        "--format",
        default="html",
        metavar="FMT",
        help=tr(
            lang,
            "per-site report format(s), comma-separated — choose from "
            "{choices} (default: %(default)s). 'jira-tickets' writes one "
            "ticket per issue type per site into that site's jira/ subfolder.",
            choices=", ".join(session.FORMAT_CHOICES),
        ),
    )
    add_lang_argument(parser, lang)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, run the batch, and print a short summary."""
    args = build_parser(chosen_lang(argv)).parse_args(argv)
    lang = args.lang

    try:
        formats = session.parse_formats(args.format)
    except ValueError as exc:
        print(
            tr(
                lang,
                "Invalid --format {value}: {reason}",
                value=repr(args.format),
                reason=exc,
            )
        )
        return 2

    if args.width is not None and args.width <= 0:
        print(
            tr(
                lang,
                "Invalid --width {value}: must be a positive number of pixels",
                value=repr(args.width),
            )
        )
        return 2

    urls = batch.read_urls(args.urls_file)
    planned = len(urls) if args.limit is None else min(len(urls), args.limit)
    print(
        tr(
            lang,
            "Auditing {planned} of {total} URL(s) from {source}...",
            planned=planned,
            total=len(urls),
            source=args.urls_file,
        )
    )

    result = batch.run_batch(
        urls,
        args.out,
        headless=args.headless,
        width=args.width,
        limit=args.limit,
        source=str(args.urls_file),
        formats=formats,
        lang=lang,
    )

    audited = sum(1 for s in result.sites if s.status == "audited")
    failed = len(result.sites) - audited
    print(tr(lang, "Done: {audited} audited, {failed} failed.", audited=audited, failed=failed))
    print(
        tr(
            lang,
            "Summary + per-site reports written to {path}/",
            path=result.output_dir,
        )
    )
    print(tr(lang, REMINDER))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
