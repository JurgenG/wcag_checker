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
URL, the operator browses by hand and presses the audit hotkey (``F9`` by
default) on each page to audit, then closes the window to write the
reports. With ``--once`` it runs a one-shot audit
(:func:`~leak_inspector.session.run_once`) of a single page and exits.

``--lang`` chooses the language of the reports and of this command's own
messages and help (default :data:`~leak_inspector.i18n.DEFAULT_LANG`).
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from . import session
from .capture.hotkey import DEFAULT_HOTKEY, format_hotkey, hotkey_condition
from .i18n import DEFAULT_LANG, LANGUAGES, N_, tr

#: Closing line of every run, translated when printed.
REMINDER = N_("Reminder: a clean automated run does not imply WCAG 2.2 conformance.")


def chosen_lang(argv: Sequence[str] | None) -> str:
    """Return the ``--lang`` value in ``argv`` (or the default), before full parsing.

    Lets the help text itself be built in the chosen language. An
    unsupported value falls back to the default here; the full parser then
    rejects it.
    """
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--lang", default=DEFAULT_LANG)
    known, _ = pre.parse_known_args(argv)
    return known.lang if known.lang in LANGUAGES else DEFAULT_LANG


def add_lang_argument(parser: argparse.ArgumentParser, lang: str) -> None:
    """Add the shared ``--lang`` option to ``parser``, with help in ``lang``."""
    parser.add_argument(
        "--lang",
        default=DEFAULT_LANG,
        choices=LANGUAGES,
        help=tr(
            lang,
            "language of the reports and messages: {choices} (default: %(default)s)",
            choices=", ".join(LANGUAGES),
        ),
    )


def build_parser(lang: str = DEFAULT_LANG) -> argparse.ArgumentParser:
    """Construct the ``wcag-checker`` argument parser, with help in ``lang``."""
    parser = argparse.ArgumentParser(
        prog="wcag-checker",
        description=tr(
            lang,
            "Open Firefox on a URL and audit it for WCAG 2.2 AA issues. By "
            "default you browse by hand and press the audit hotkey on each "
            "page to audit; with --once the given page is audited "
            "automatically and the tool exits. A clean run is not a "
            "conformance claim.",
        ),
    )
    parser.add_argument(
        "url", help=tr(lang, "starting URL to open (include the scheme)")
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("reports"),
        help=tr(lang, "directory for the reports (default: reports/)"),
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help=tr(
            lang,
            "run Firefox without a visible window (a real desktop is preferred)",
        ),
    )
    parser.add_argument(
        "--width",
        type=int,
        default=None,
        metavar="PX",
        help=tr(
            lang,
            "resize the browser window to this pixel width before auditing, "
            "to check a responsive/mobile layout (default: Firefox's own "
            "window width)",
        ),
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help=tr(
            lang,
            "audit the given page once and exit, without the interactive "
            "hotkey (waits for the page to settle first — use this when a "
            "page redirects or closes too fast to press the hotkey)",
        ),
    )
    parser.add_argument(
        "--hotkey",
        default=DEFAULT_HOTKEY,
        metavar="COMBO",
        help=tr(
            lang,
            "interactive audit hotkey, e.g. ctrl+alt+shift+a or f9 "
            "(default: %(default)s). Change it if your window manager grabs "
            "the default combo.",
        ),
    )
    parser.add_argument(
        "--format",
        default="html",
        metavar="FMT",
        help=tr(
            lang,
            "report format(s), comma-separated — choose from {choices} "
            "(default: %(default)s). 'jira-tickets' writes one JIRA-style "
            "ticket per issue type into a jira/ subfolder; 'all' writes every "
            "format. The manual-review checklist is always written.",
            choices=", ".join(session.FORMAT_CHOICES),
        ),
    )
    add_lang_argument(parser, lang)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, run the chosen session mode, and print a summary."""
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

    if args.once:
        return _run_once(args, formats)

    try:
        hotkey_condition(args.hotkey)  # validate before launching Firefox
    except ValueError as exc:
        print(
            tr(
                lang,
                "Invalid --hotkey {value}: {reason}",
                value=repr(args.hotkey),
                reason=exc,
            )
        )
        return 2
    return _run_interactive(args, formats)


def _run_interactive(args: argparse.Namespace, formats: tuple[str, ...]) -> int:
    """Run the hand-driven hotkey session and print a short summary."""
    lang = args.lang
    combo = format_hotkey(args.hotkey)
    print(
        tr(
            lang,
            "Opening Firefox. Browse to a page you want checked, click into "
            "the page (so it has keyboard focus), then press {combo} to audit "
            "it. Each audit is confirmed below. Close the window when you're "
            "done.",
            combo=combo,
        )
    )

    def _confirm(url: str, count: int) -> None:
        print("  " + tr(lang, "audited {url} — {count} finding(s)", url=url, count=count))

    result = session.run_session(
        args.url,
        args.out,
        headless=args.headless,
        width=args.width,
        on_audit=_confirm,
        hotkey=args.hotkey,
        formats=formats,
        lang=lang,
    )

    print(
        tr(
            lang,
            "Audited {pages} page(s); {count} finding(s).",
            pages=len(result.audited_urls),
            count=len(result.findings),
        )
    )
    _print_written(result, lang)
    print(tr(lang, REMINDER))
    return 0


def _run_once(args: argparse.Namespace, formats: tuple[str, ...]) -> int:
    """Run a one-shot single-page audit and print a short summary."""
    lang = args.lang
    print(tr(lang, "Opening Firefox and auditing {url} once...", url=args.url))
    result = session.run_once(
        args.url,
        args.out,
        headless=args.headless,
        width=args.width,
        formats=formats,
        lang=lang,
    )

    audited = result.audited_urls[0] if result.audited_urls else args.url
    if audited != args.url:
        print(
            tr(
                lang,
                "Note: {url} redirected to {target}; audited that.",
                url=args.url,
                target=audited,
            )
        )
    print(
        tr(
            lang,
            "Audited {url}; {count} finding(s).",
            url=audited,
            count=len(result.findings),
        )
    )
    _print_written(result, lang)
    print(tr(lang, REMINDER))
    return 0


def _print_written(result: session.SessionResult, lang: str) -> None:
    """Print the exact report files this run wrote, with their full paths.

    Names the concrete files (not just the directory) so the operator opens
    this run's freshly written, timestamped report rather than a leftover
    from an earlier run in the same domain folder. JIRA tickets live in a
    subfolder, so that folder is summarized once instead of listing every
    ticket.
    """
    print(tr(lang, "Reports written to {path}/", path=result.output_dir))
    jira_dirs: set[str] = set()
    for name, path in result.written.items():
        if "/" in name:
            jira_dirs.add(name.split("/", 1)[0])
        else:
            print(f"  {path}")
    for dirname in sorted(jira_dirs):
        print(f"  {result.output_dir / dirname}/ ({tr(lang, 'JIRA tickets')})")


if __name__ == "__main__":
    raise SystemExit(main())
