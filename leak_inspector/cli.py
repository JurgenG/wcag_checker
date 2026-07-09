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

"""Command-line entry point.

Subcommands:

* ``capture <url> --out <path> [--profile <path>]`` — open Firefox, record
  a session, write a bundle zip.
* ``analyze <bundle> [--format text|json|html|markdown_*] [--no-color]
  [--verbose] [--debug]`` — run tracker modules over a bundle and print a
  report.
* ``update-geoip [--key …]`` — download the MaxMind GeoLite2-Country
  mmdb used by the DNS-posture analyser into the local cache.
* ``--list-modules`` (top-level flag) — print registered detectors.

Heavy dependencies (selenium, tldextract) are imported lazily inside
:func:`_do_capture` so ``analyze`` and ``--list-modules`` work even
when the capture extras are not installed.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .enrichment.artifact import ENRICHMENT_SECTIONS


def main(argv: list[str] | None = None) -> int:
    """Dispatch on the parsed arguments. Returns a process exit code."""
    import sys
    import io
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding='utf-8')
        except AttributeError:
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', newline='')
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.list_modules:
        return _do_list_modules()

    if args.command == "capture":
        return _do_capture(args)
    if args.command == "enrich":
        return _do_enrich(args)
    if args.command == "analyze":
        return _do_analyze(args)
    if args.command == "diff":
        return _do_diff(args)
    if args.command == "update-geoip":
        return _do_update_geoip(args)

    parser.print_help(sys.stderr)
    return 1


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Convenience wrapper for tests — drives the same parser as :func:`main`."""
    return _build_parser().parse_args(argv)


def _build_parser() -> argparse.ArgumentParser:
    """Construct the top-level argument parser and its subparsers."""
    parser = argparse.ArgumentParser(
        prog="leak-inspector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Record a real Firefox browsing session via WebDriver BiDi and\n"
            "analyze the resulting capture bundle for third-party data leaks.\n"
            "\n"
            "Workflow:\n"
            "  1. `capture`  — drive a Firefox window, browse the target site\n"
            "                  manually, and write a self-contained bundle zip\n"
            "                  when the window is closed.\n"
            "  2. `analyze`  — replay the bundle through the registered tracker\n"
            "                  modules and emit a report (text / json / html /\n"
            "                  markdown_summary / markdown_detailed)."
        ),
        epilog=(
            "Examples:\n"
            "  leak-inspector capture https://example.com --out captures/run.zip\n"
            "  leak-inspector analyze captures/run.zip\n"
            "  leak-inspector analyze captures/run.zip --format html > report.html\n"
            "  leak-inspector analyze captures/run.zip --format markdown_detailed > report.md\n"
            "  leak-inspector analyze captures/run.zip --debug --verbose\n"
            "  leak-inspector --list-modules\n"
            "\n"
            "Exit codes:\n"
            "  0   success\n"
            "  1   no subcommand given (usage printed)\n"
            "  2   bundle not found / capture or analysis raised\n"
            "  3   capture-only dependencies missing (run `pip install -e .`)\n"
            "  130 capture interrupted before the bundle was written"
        ),
    )
    parser.add_argument(
        "--list-modules",
        action="store_true",
        help=(
            "print every registered tracker module (id + display name) and "
            "exit. Useful for confirming the active detector set without "
            "running a capture or analysis."
        ),
    )

    sub = parser.add_subparsers(
        dest="command",
        metavar="<command>",
        title="subcommands",
        description="run `<subcommand> --help` for the full per-command help",
    )

    # --- capture ----------------------------------------------------------
    cap = sub.add_parser(
        "capture",
        help="open Firefox and record a session into a bundle zip",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Open a Firefox window, navigate to URL, and record everything\n"
            "the page does — network requests, response bodies (subject to a\n"
            "256 KiB cap), document storage snapshots, and script sources —\n"
            "into a self-contained, schema-versioned bundle zip.\n"
            "\n"
            "Recording is driven entirely by manual human interaction: click\n"
            "around the site as a normal visitor would. The session ends as\n"
            "soon as you close the Firefox window; the bundle is then written\n"
            "to the path given with --out.\n"
            "\n"
            "The browser runs with stealth preferences applied so trackers do\n"
            "not detect the automation. WebDriver-BiDi is used for event\n"
            "subscription; geckodriver and Firefox must be installed."
        ),
        epilog=(
            "Examples:\n"
            "  leak-inspector capture https://example.com \\\n"
            "                 --out captures/example.zip\n"
            "\n"
            "  # Re-use an existing Firefox profile (cookies / consent state\n"
            "  # carried in) — note: the profile is mutated in place.\n"
            "  leak-inspector capture https://example.com \\\n"
            "                 --out captures/example.zip \\\n"
            "                 --profile ~/.mozilla/firefox/leak-inspector\n"
        ),
    )
    cap.add_argument(
        "url",
        help=(
            "URL to open as the starting page. Cross-origin redirects are "
            "followed and the post-redirect landing URL becomes the "
            "first-party context for the analysis."
        ),
    )
    cap.add_argument(
        "--out",
        type=Path,
        required=True,
        metavar="PATH",
        help=(
            "where to write the produced bundle zip. Parent directories must "
            "exist; the file is overwritten if it already exists."
        ),
    )
    cap.add_argument(
        "--profile",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "use an existing Firefox profile directory (default: fresh "
            "temporary profile, discarded on exit). The given profile is "
            "used IN PLACE and will be mutated by the browsing session — "
            "make a copy first if you need to preserve the starting state."
        ),
    )

    # --- enrich -----------------------------------------------------------
    enr = sub.add_parser(
        "enrich",
        help="run the live-network enrichment for an existing bundle",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Run the live-network phase (DNS posture, transport probes,\n"
            "CMS version probe, per-host IP/ASN/geo) for a capture bundle\n"
            "and store the result inside the zip as enrichment.json.\n"
            "\n"
            "Normally this runs automatically right after `capture`, so the\n"
            "stored posture is contemporaneous with the browsing session.\n"
            "Use this subcommand to retrofit bundles captured before the\n"
            "enrichment phase existed, or with --refresh to re-probe after\n"
            "the operator changed their posture (the artifact records its\n"
            "own timestamp; reports display it).\n"
            "\n"
            "--refresh takes an optional section to re-probe just that one\n"
            "(dns, transport, cms-probe, security-txt, hosts); the bundle's\n"
            "other sections and its baseline enriched_at are left untouched,\n"
            "and the re-probed section gets its own timestamp. Bare --refresh\n"
            "re-probes everything."
        ),
        epilog=(
            "Examples:\n"
            "  leak-inspector enrich captures/run.zip\n"
            "  leak-inspector enrich captures/run.zip --refresh\n"
            "  leak-inspector enrich captures/run.zip --refresh cms-probe\n"
        ),
    )
    enr.add_argument(
        "bundle",
        type=Path,
        metavar="BUNDLE",
        help="path to a bundle zip produced by the `capture` subcommand",
    )
    enr.add_argument(
        "--refresh",
        nargs="?",
        const="all",
        choices=["all", *ENRICHMENT_SECTIONS],
        default=None,
        metavar="SECTION",
        help=(
            "re-run the lookups for an existing enrichment. Bare --refresh "
            "re-probes everything and replaces the artifact; --refresh "
            "<section> (one of: "
            + ", ".join(ENRICHMENT_SECTIONS)
            + ") re-probes only that section, keeping the rest and the "
            "baseline timestamp. Without --refresh an already-enriched "
            "bundle is left untouched (no network is contacted)."
        ),
    )

    # --- analyze ----------------------------------------------------------
    ana = sub.add_parser(
        "analyze",
        help="run tracker modules over a previously captured bundle",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Read a bundle zip produced by `capture`, dispatch every\n"
            "recorded request through the registered tracker modules, and\n"
            "write a report to stdout.\n"
            "\n"
            "Repeat hits are deduplicated to one representative per\n"
            "(module, endpoint, parameter-key-set, event-type) tuple before\n"
            "rendering. The raw stream stays available in the JSON output\n"
            "for downstream drill-down.\n"
            "\n"
            "Five output formats are supported (see --format)."
        ),
        epilog=(
            "Examples:\n"
            "  # Plain text on the terminal (ANSI color if TTY).\n"
            "  leak-inspector analyze captures/example.zip\n"
            "\n"
            "  # Single-file HTML report — open the result in a browser.\n"
            "  leak-inspector analyze captures/example.zip \\\n"
            "                 --format html > report.html\n"
            "\n"
            "  # Markdown — collapsed (summary) or fully expanded (detailed).\n"
            "  leak-inspector analyze captures/example.zip \\\n"
            "                 --format markdown_summary  > summary.md\n"
            "  leak-inspector analyze captures/example.zip \\\n"
            "                 --format markdown_detailed > detailed.md\n"
            "\n"
            "  # Add an unclassified-hosts section — useful for spotting\n"
            "  # candidates for new tracker modules.\n"
            "  leak-inspector analyze captures/example.zip --debug\n"
        ),
    )
    ana.add_argument(
        "bundle",
        type=Path,
        metavar="BUNDLE",
        help="path to a bundle zip produced by the `capture` subcommand",
    )
    ana.add_argument(
        "--format",
        choices=("text", "json", "html", "markdown_summary",
                 "markdown_detailed", "pdf"),
        default="text",
        help=(
            "output format (default: text). "
            "`text` is ANSI-coloured prose for terminals; "
            "`json` is a structured payload with both raw and deduplicated "
            "views, suitable for downstream tooling; "
            "`html` is a single self-contained file with fold-open detail "
            "blocks; "
            "`markdown_summary` mirrors the HTML report with every "
            "fold-open block COLLAPSED (executive summary + stat rows + "
            "harvested-field lists only); "
            "`markdown_detailed` mirrors it with every block OPENED "
            "(every representative hit and its full parameter table "
            "rendered inline)."
        ),
    )
    ana.add_argument(
        "--out",
        "-o",
        type=Path,
        metavar="FILE",
        default=None,
        help=(
            "write the report to FILE instead of stdout. For html / "
            "markdown formats, screenshots are written as sibling "
            "lossless-webp files next to FILE (``<stem>.post-load.webp`` "
            "and ``<stem>.shot_<host>_<HHMMSS>.webp``) and referenced by "
            "relative filename. Without --out the report goes to stdout "
            "with screenshots inlined as self-contained data: URIs."
        ),
    )
    ana.add_argument(
        "--no-color",
        action="store_true",
        help=(
            "disable ANSI color in `text` output (color is already off when "
            "stdout is not a TTY; this flag forces it off when it is). "
            "No effect on json / html / markdown formats."
        ),
    )
    ana.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help=(
            "in `text` output, list the source `event_id`s collapsed into "
            "each representative hit so they can be cross-referenced back "
            "to the raw `events.jsonl` inside the bundle. No effect on "
            "other formats."
        ),
    )
    ana.add_argument(
        "--debug",
        action="store_true",
        help=(
            "append a verbose per-unclassified-host block at the end of "
            "the `text` report (sample URLs + observed params) for drafting "
            "new tracker modules. The unclassified-host *list* is always "
            "included by every format via the `unclassified_hosts` array "
            "(JSON) or section (text/markdown/html); this flag only "
            "controls the deeper drill-down."
        ),
    )

    # --- diff -------------------------------------------------------------
    diff = sub.add_parser(
        "diff",
        help="compare two capture bundles (e.g. consent-on vs consent-off)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Compare two capture bundles and surface what changed —\n"
            "trackers that appeared, vendors that no longer fire, new\n"
            "PII fields, new jurisdictions, host deltas, finding deltas.\n"
            "\n"
            "Canonical workflow: capture the same site twice with\n"
            "different consent choices (reject vs accept), then run\n"
            "`leak-inspector diff reject.zip accept.zip` to see exactly\n"
            "what the accept path unlocks. Use --label-a / --label-b to\n"
            "give the two sides readable names in the report."
        ),
        epilog=(
            "Examples:\n"
            "  # html/markdown auto-create <stem_a>_vs_<stem_b>/ with the\n"
            "  # diff + a full single-site report per side.\n"
            "  leak-inspector diff reject.zip accept.zip \\\n"
            "                 --label-a reject --label-b accept --format html\n"
            "\n"
            "  # Pick a specific output directory:\n"
            "  leak-inspector diff before.zip after.zip --format markdown \\\n"
            "                 --out audit/diff/\n"
            "\n"
            "  # Force stdout (skip the auto-directory):\n"
            "  leak-inspector diff a.zip b.zip --format html --stdout > diff.html\n"
        ),
    )
    diff.add_argument(
        "bundle_a", type=Path, metavar="BUNDLE_A",
        help="first bundle zip (the 'A' side — typically the baseline / consent-rejected capture)",
    )
    diff.add_argument(
        "bundle_b", type=Path, metavar="BUNDLE_B",
        help="second bundle zip (the 'B' side — typically the modified / consent-accepted capture)",
    )
    diff.add_argument(
        "--label-a", dest="label_a", default="A",
        help="readable label for the A side in the diff report (default: A)",
    )
    diff.add_argument(
        "--label-b", dest="label_b", default="B",
        help="readable label for the B side in the diff report (default: B)",
    )
    diff.add_argument(
        "--format",
        choices=("text", "json", "html", "markdown"),
        default="text",
        help=(
            "output format (default: text). `markdown` is the detailed "
            "shape — there is no summary/detailed split for diffs."
        ),
    )
    diff.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI color in `text` output.",
    )
    diff.add_argument(
        "--out",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "explicit output directory. Three files are produced: "
            "diff.<ext>, <label_a>.report.<ext>, <label_b>.report.<ext>. "
            "The diff embeds relative links to the two side reports. "
            "When omitted, html and markdown formats auto-derive a "
            "directory name from the bundle filenames "
            "(<stem_a>_vs_<stem_b>/) in the current working directory; "
            "text and json formats still go to stdout by default."
        ),
    )
    diff.add_argument(
        "--stdout",
        action="store_true",
        help=(
            "force stdout output for html/markdown (skipping the "
            "auto-derived output directory). Has no effect for text or "
            "json (those already default to stdout). Mutually exclusive "
            "with --out."
        ),
    )

    # --- update-geoip -----------------------------------------------------
    geoip = sub.add_parser(
        "update-geoip",
        help="download the MaxMind GeoLite2-Country mmdb used by DNS-posture analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Fetch GeoLite2-Country.mmdb from MaxMind and cache it locally so\n"
            "the DNS-posture analyser can label IP addresses with a country.\n"
            "Without the mmdb, ASN attribution still works (via Team Cymru DNS)\n"
            "but the country fields on each IP stay blank.\n"
            "\n"
            "A MaxMind license key is required. Sign up at\n"
            "https://www.maxmind.com/en/geolite2/signup (free) and pass the\n"
            "key via --key or the $MAXMIND_LICENSE_KEY environment variable.\n"
            "\n"
            "The mmdb is written to ~/.cache/leak_inspector/GeoLite2-Country.mmdb\n"
            "by default, or to $LEAK_INSPECTOR_GEOIP_DB if that variable is set.\n"
            "Re-run this command periodically (MaxMind refreshes the data weekly)."
        ),
        epilog=(
            "Examples:\n"
            "  export MAXMIND_LICENSE_KEY=…\n"
            "  leak-inspector update-geoip\n"
            "\n"
            "  leak-inspector update-geoip --key <license-key>\n"
        ),
    )
    geoip.add_argument(
        "--key",
        default=None,
        help=(
            "MaxMind license key. If omitted, $MAXMIND_LICENSE_KEY is used. "
            "Sign up for a free key at maxmind.com/en/geolite2/signup."
        ),
    )

    return parser


# --- subcommand handlers ---------------------------------------------------


def _do_list_modules() -> int:
    """Print one line per registered tracker module."""
    from . import modules  # noqa: F401  -- registers detectors via @register

    for m in modules.all_modules():
        print(f"{m.module_id:15s} {m.module_name}")
    return 0


def _do_capture(args: argparse.Namespace) -> int:
    """Launch Firefox, record a session, write a bundle. Returns an exit code."""
    # Lazy import: only loads selenium + tldextract when actually capturing.
    try:
        from .capture.recorder import Recorder
    except ImportError as exc:
        print(
            f"capture dependencies missing — run `pip install -e .` first ({exc})",
            file=sys.stderr,
        )
        return 3

    print(f"leak-inspector: opening {args.url}", file=sys.stderr)
    print("close the Firefox window when you're done browsing.", file=sys.stderr)

    try:
        result = Recorder(
            args.url,
            args.out,
            profile_path=args.profile,
        ).run()
    except KeyboardInterrupt:
        print("interrupted before bundle was written", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"capture failed: {exc}", file=sys.stderr)
        return 2

    print(f"bundle written: {result.bundle_path}", file=sys.stderr)
    print(f"  session_id: {result.session_id}", file=sys.stderr)
    print(f"  events:     {result.event_count}", file=sys.stderr)
    print(f"  duration:   {result.started_at} -> {result.ended_at}", file=sys.stderr)

    # Enrich immediately so the stored network posture is contemporaneous
    # with the browsing session. Soft-fail: the bundle is already safely
    # on disk, a flaky resolver must never turn the capture into an error.
    _enrich_after_capture(result.bundle_path)
    return 0


def _enrich_bundle(bundle_path, *, refresh: bool = False, sections=None):
    """Lazy-importing seam for :func:`enrichment.producer.enrich_bundle`.

    Module-level so tests can monkeypatch it; lazily imported so the
    CLI keeps its fast no-subcommand startup.
    """
    from .enrichment.producer import enrich_bundle
    return enrich_bundle(bundle_path, refresh=refresh, sections=sections)


def _enrich_after_capture(bundle_path) -> None:
    """Run enrichment right after a capture, soft-failing loudly."""
    print("enriching (DNS posture, transport, host info)…", file=sys.stderr)
    try:
        enrichment, _created = _enrich_bundle(bundle_path)
    except Exception as exc:
        print(
            f"enrichment failed: {exc} — the capture itself is intact; "
            f"run `leak-inspector enrich {bundle_path}` later to add the "
            "network posture.",
            file=sys.stderr,
        )
        return
    _report_enrichment(enrichment, created=True)


def _report_enrichment(enrichment, *, created: bool, sections=None) -> None:
    """One-line operator summary of an enrichment result."""
    if not created:
        print(
            f"already enriched at {enrichment.enriched_at} — use --refresh "
            "to re-run the lookups.",
            file=sys.stderr,
        )
        return
    if sections:
        names = ", ".join(sorted(sections))
        when = next(
            (enrichment.section_timestamps.get(s) for s in sorted(sections)),
            None,
        )
        print(
            f"refreshed {names} at {when}  (baseline enriched_at "
            f"{enrichment.enriched_at} unchanged)",
            file=sys.stderr,
        )
    else:
        summary = [
            ("dns", enrichment.dns_posture),
            ("transport", enrichment.transport_posture),
            ("cms-probe", enrichment.cms_probe),
            ("hosts", enrichment.host_ipinfo or None),
        ]
        state = "  ".join(
            f"{name} {'✓' if value is not None else '–'}"
            for name, value in summary
        )
        print(
            f"enriched at {enrichment.enriched_at}:  {state}", file=sys.stderr,
        )
    for error in enrichment.errors:
        print(f"  warning: {error}", file=sys.stderr)


def _do_enrich(args: argparse.Namespace) -> int:
    """Run the `enrich` subcommand. Returns a process exit code."""
    if not args.bundle.exists():
        print(f"bundle not found: {args.bundle}", file=sys.stderr)
        return 2
    token = args.refresh  # None | "all" | a canonical section id
    refresh = token == "all"
    sections = frozenset({token}) if token not in (None, "all") else None
    try:
        enrichment, created = _enrich_bundle(
            args.bundle, refresh=refresh, sections=sections,
        )
    except Exception as exc:
        print(f"enrichment failed: {exc}", file=sys.stderr)
        return 2
    _report_enrichment(enrichment, created=created, sections=sections)
    return 0


def _do_analyze(args: argparse.Namespace) -> int:
    """Read a bundle, run modules, write a report to stdout."""
    from . import modules  # noqa: F401  -- registers detectors
    from .analysis import analyze_bundle
    from .bundle import BundleReader
    from .report import (
        write_debug_report,
        write_html_report,
        write_json_report,
        write_markdown_detailed,
        write_markdown_summary,
        write_text_report,
    )

    if not args.bundle.exists():
        print(f"bundle not found: {args.bundle}", file=sys.stderr)
        return 2

    try:
        analysis = analyze_bundle(args.bundle)
    except Exception as exc:
        print(f"analysis failed: {exc}", file=sys.stderr)
        return 2

    out_file: Path | None = getattr(args, "out", None)
    can_embed_images = args.format in (
        "html", "markdown_summary", "markdown_detailed"
    )

    # PDF is binary — its own path: require --out, inline screenshots as
    # data: URIs (self-contained file), render via WeasyPrint.
    if args.format == "pdf":
        if out_file is None:
            print(
                "--format pdf requires --out FILE (PDF is binary and "
                "cannot go to stdout)",
                file=sys.stderr,
            )
            return 2
        from .report.pdf import write_pdf_report

        shot, extra_shots, extra_caps = _collect_screenshot_data_uris(
            BundleReader, args.bundle
        )
        try:
            pdf_bytes = write_pdf_report(
                analysis,
                screenshot_filename=shot,
                extra_screenshot_filenames=extra_shots or None,
                extra_screenshot_captions=extra_caps or None,
            )
        except RuntimeError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_bytes(pdf_bytes)
        print(f"wrote {out_file}", file=sys.stderr)
        return 0

    # Screenshot references depend on the output target:
    #  * --out FILE → write PNGs as siblings next to FILE, link relatively.
    #  * stdout     → inline as self-contained data: URIs (the CLI can't
    #                 know where a redirected stdout will land).
    screenshot_src: str | None = None
    extra_screenshot_srcs: list[str] = []
    extra_screenshot_caps: list[str] = []
    if can_embed_images and out_file is not None:
        from .report.screenshots import write_screenshot_sidecars

        out_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            with BundleReader(args.bundle) as bundle:
                screenshot_src, extra_screenshot_srcs, extra_screenshot_caps = (
                    write_screenshot_sidecars(
                        bundle, out_dir=out_file.parent, stem=out_file.stem,
                    )
                )
        except Exception:
            # A bad screenshot section shouldn't sink the whole report.
            screenshot_src, extra_screenshot_srcs, extra_screenshot_caps = (
                None, [], []
            )
    elif can_embed_images:
        screenshot_src, extra_screenshot_srcs, extra_screenshot_caps = (
            _collect_screenshot_data_uris(BundleReader, args.bundle)
        )

    if args.format == "json":
        body = write_json_report(analysis) + "\n"
    elif args.format == "html":
        body = write_html_report(
            analysis,
            screenshot_filename=screenshot_src,
            extra_screenshot_filenames=extra_screenshot_srcs or None,
            extra_screenshot_captions=extra_screenshot_caps or None,
        )
    elif args.format == "markdown_summary":
        body = write_markdown_summary(
            analysis,
            screenshot_filename=screenshot_src,
            extra_screenshot_filenames=extra_screenshot_srcs or None,
            extra_screenshot_captions=extra_screenshot_caps or None,
        )
    elif args.format == "markdown_detailed":
        body = write_markdown_detailed(
            analysis,
            screenshot_filename=screenshot_src,
            extra_screenshot_filenames=extra_screenshot_srcs or None,
            extra_screenshot_captions=extra_screenshot_caps or None,
        )
    else:
        color = (out_file is None and sys.stdout.isatty()) and not args.no_color
        body = write_text_report(analysis, color=color, verbose=args.verbose)
        if args.debug:
            body += "\n" + write_debug_report(analysis)

    if out_file is not None:
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(body, encoding="utf-8")
        n_imgs = (1 if screenshot_src else 0) + len(extra_screenshot_srcs)
        msg = f"wrote {out_file}"
        if n_imgs:
            msg += f" + {n_imgs} screenshot{'s' if n_imgs != 1 else ''}"
        print(msg, file=sys.stderr)
    else:
        sys.stdout.write(body)
    return 0


def _collect_screenshot_data_uris(
    bundle_reader_cls, bundle_path
) -> tuple[str | None, list[str], list[str]]:
    """Pull every screenshot from the bundle as a webp ``data:`` URI.

    Returns ``(canonical_uri_or_None, [extra_uris…], [extra_captions…])``.
    The bundle's archival PNGs are converted to lossless webp first —
    same pixels, ~60-70 % smaller, so the self-contained stdout HTML
    shrinks accordingly. Captions are derived from the original
    filename (``screenshot_<host>_<HHMMSS>.png``) before it's replaced
    by the base64 URI, so the gallery still shows useful labels. The
    HTML and Markdown report writers accept a string (filename OR data
    URI) transparently, so this is what makes the analyze CLI emit a
    self-contained HTML even though it writes to stdout.
    """
    import base64
    from .report.html import _caption_from_extra_screenshot
    from .report.screenshots import png_to_webp

    def to_data_uri(png_bytes: bytes) -> str:
        encoded = base64.b64encode(png_to_webp(png_bytes)).decode("ascii")
        return f"data:image/webp;base64,{encoded}"

    canonical: str | None = None
    extras: list[str] = []
    captions: list[str] = []
    try:
        with bundle_reader_cls(bundle_path) as bundle:
            png = bundle.screenshot_bytes
            if png:
                canonical = to_data_uri(png)
            for name, body in bundle.extra_screenshots():
                extras.append(to_data_uri(body))
                captions.append(_caption_from_extra_screenshot(name))
    except Exception:
        # Don't fail the whole report if the bundle's screenshot section
        # is unreadable — caller still gets a screenshot-less report.
        return None, [], []
    return canonical, extras, captions


def _do_diff(args: argparse.Namespace) -> int:
    """Run the diff subcommand: compare two bundles and write a report.

    By default writes the diff to stdout. When ``--out DIR`` is set,
    writes three files into ``DIR``: the diff report itself plus a
    single-site report for each side, and embeds relative links to
    the per-side reports near the top of the diff.
    """
    from . import modules  # noqa: F401  -- registers detectors
    from .analysis import analyze_bundle
    from .report import (
        write_html_report, write_markdown_detailed, write_text_report,
    )
    from .report.builder import build_report_document
    from .report.diff import build_report_diff
    from .report.diff_renderers import (
        render_diff_html,
        render_diff_json,
        render_diff_markdown,
        render_diff_text,
    )

    for label, path in (("A", args.bundle_a), ("B", args.bundle_b)):
        if not path.exists():
            print(f"bundle {label} not found: {path}", file=sys.stderr)
            return 2

    try:
        analysis_a = analyze_bundle(args.bundle_a)
        analysis_b = analyze_bundle(args.bundle_b)
    except Exception as exc:
        print(f"diff failed: {exc}", file=sys.stderr)
        return 2

    diff = build_report_diff(
        analysis_a, analysis_b,
        label_a=args.label_a, label_b=args.label_b,
    )

    out_dir = getattr(args, "out", None)
    force_stdout = getattr(args, "stdout", False)
    if out_dir is not None and force_stdout:
        print("--out and --stdout are mutually exclusive", file=sys.stderr)
        return 2

    # html / markdown auto-derive an output directory unless --stdout is set;
    # text and json default to stdout because their primary use cases are
    # terminal viewing and piping into other tools respectively.
    if out_dir is None and not force_stdout and args.format in ("html", "markdown"):
        out_dir = _auto_diff_out_dir(args.bundle_a, args.bundle_b)
        print(
            f"writing diff + per-side reports into {out_dir}/  "
            "(use --stdout to write to stdout instead, "
            "or --out DIR for a different location)",
            file=sys.stderr,
        )

    if out_dir is not None:
        return _write_diff_with_side_reports(
            out_dir=out_dir,
            diff=diff,
            analysis_a=analysis_a, analysis_b=analysis_b,
            bundle_a=args.bundle_a, bundle_b=args.bundle_b,
            format_=args.format,
        )

    if args.format == "json":
        sys.stdout.write(render_diff_json(diff))
        sys.stdout.write("\n")
    elif args.format == "html":
        sys.stdout.write(render_diff_html(diff))
    elif args.format == "markdown":
        sys.stdout.write(render_diff_markdown(diff))
    else:
        color = sys.stdout.isatty() and not args.no_color
        sys.stdout.write(render_diff_text(diff, color=color))
    return 0


def _auto_diff_out_dir(bundle_a: Path, bundle_b: Path) -> Path:
    """Derive a default output-directory name from the two bundle filenames.

    ``captures/awel-min.zip`` + ``captures/awel-max.zip`` →
    ``awel-min_vs_awel-max/`` in the current working directory.

    Falls back to ``diff_out/`` when both bundles share a stem (rare —
    e.g. someone diffs ``a/x.zip`` against ``b/x.zip``).
    """
    stem_a = bundle_a.stem
    stem_b = bundle_b.stem
    if stem_a == stem_b:
        return Path("diff_out")
    return Path(f"{stem_a}_vs_{stem_b}")


def _write_diff_with_side_reports(
    *,
    out_dir,
    diff,
    analysis_a,
    analysis_b,
    bundle_a,
    bundle_b,
    format_: str,
) -> int:
    """Write the diff + the two per-side reports into ``out_dir``.

    Side-report filenames are derived from the diff labels: a label
    like ``"reject"`` produces ``reject.report.<ext>``. html/markdown
    side reports get the bundles' screenshots as sibling lossless-webp
    sidecars (the ``analyze -o`` convention) — referenced by relative
    filename, never inlined. JSON-format diffs skip side reports —
    JSON output is for machine consumption and doesn't link.
    """
    import re

    from .report import (
        write_html_report, write_markdown_detailed, write_text_report,
    )
    from .report.diff_renderers import (
        render_diff_html,
        render_diff_json,
        render_diff_markdown,
        render_diff_text,
    )

    out_dir.mkdir(parents=True, exist_ok=True)

    if format_ == "json":
        # Side reports don't fit the JSON shape — just emit the diff.
        (out_dir / "diff.json").write_text(
            render_diff_json(diff) + "\n", encoding="utf-8"
        )
        print(f"wrote {out_dir / 'diff.json'}", file=sys.stderr)
        return 0

    ext = {"html": "html", "markdown": "md", "text": "txt"}.get(format_, "txt")

    def _slug(label: str) -> str:
        s = re.sub(r"[^A-Za-z0-9._-]+", "_", label).strip("_")
        return s or "side"

    slug_a = _slug(diff.label_a)
    slug_b = _slug(diff.label_b)
    # Disambiguate if labels collide after slugification.
    if slug_a == slug_b:
        slug_a, slug_b = f"{slug_a}_a", f"{slug_b}_b"

    side_report_a = f"{slug_a}.report.{ext}"
    side_report_b = f"{slug_b}.report.{ext}"
    diff_path = out_dir / f"diff.{ext}"
    side_path_a = out_dir / side_report_a
    side_path_b = out_dir / side_report_b

    def _sidecars(bundle_zip, stem: str):
        """Write one side's screenshot sidecars; soft-fail to no images."""
        from .bundle.reader import BundleReader
        from .report.screenshots import write_screenshot_sidecars

        try:
            with BundleReader(bundle_zip) as bundle:
                return write_screenshot_sidecars(
                    bundle, out_dir=out_dir, stem=stem,
                )
        except Exception:
            # A bad screenshot section shouldn't sink the side report.
            return None, [], []

    # Render the two per-side reports first so they exist before any
    # diff renderer references them.
    if format_ in ("html", "markdown"):
        shot_a, extras_a, caps_a = _sidecars(bundle_a, f"{slug_a}.report")
        shot_b, extras_b, caps_b = _sidecars(bundle_b, f"{slug_b}.report")
    if format_ == "html":
        side_path_a.write_text(write_html_report(
            analysis_a,
            screenshot_filename=shot_a,
            extra_screenshot_filenames=extras_a or None,
            extra_screenshot_captions=caps_a or None,
        ), encoding="utf-8")
        side_path_b.write_text(write_html_report(
            analysis_b,
            screenshot_filename=shot_b,
            extra_screenshot_filenames=extras_b or None,
            extra_screenshot_captions=caps_b or None,
        ), encoding="utf-8")
        diff_path.write_text(
            render_diff_html(
                diff,
                side_report_a=side_report_a, side_report_b=side_report_b,
            ),
            encoding="utf-8",
        )
    elif format_ == "markdown":
        side_path_a.write_text(write_markdown_detailed(
            analysis_a,
            screenshot_filename=shot_a,
            extra_screenshot_filenames=extras_a or None,
            extra_screenshot_captions=caps_a or None,
        ), encoding="utf-8")
        side_path_b.write_text(write_markdown_detailed(
            analysis_b,
            screenshot_filename=shot_b,
            extra_screenshot_filenames=extras_b or None,
            extra_screenshot_captions=caps_b or None,
        ), encoding="utf-8")
        diff_path.write_text(
            render_diff_markdown(
                diff,
                side_report_a=side_report_a, side_report_b=side_report_b,
            ),
            encoding="utf-8",
        )
    else:  # text (default)
        side_path_a.write_text(write_text_report(analysis_a, color=False), encoding="utf-8")
        side_path_b.write_text(write_text_report(analysis_b, color=False), encoding="utf-8")
        diff_path.write_text(
            render_diff_text(
                diff, color=False,
                side_report_a=side_report_a, side_report_b=side_report_b,
            ),
            encoding="utf-8",
        )

    msg = (
        f"wrote 3 files into {out_dir}:\n"
        f"  {diff_path.name}\n"
        f"  {side_path_a.name}\n"
        f"  {side_path_b.name}"
    )
    if format_ in ("html", "markdown"):
        n_imgs = (
            (1 if shot_a else 0) + len(extras_a)
            + (1 if shot_b else 0) + len(extras_b)
        )
        if n_imgs:
            msg += f"\n  + {n_imgs} screenshot sidecar{'s' if n_imgs != 1 else ''}"
    print(msg, file=sys.stderr)
    return 0


def _do_update_geoip(args: argparse.Namespace) -> int:
    """Download the GeoLite2-Country mmdb and cache it locally."""
    import os

    from .dns_posture.geoip import (
        GeoIPDownloadError,
        cached_db_path,
        download_geoip_db,
    )

    key = args.key or os.environ.get("MAXMIND_LICENSE_KEY", "").strip()
    if not key:
        print(
            "no MaxMind license key provided — pass --key or set "
            "$MAXMIND_LICENSE_KEY (free signup at maxmind.com/en/geolite2/signup)",
            file=sys.stderr,
        )
        return 2

    destination = cached_db_path()
    print(f"downloading GeoLite2-Country.mmdb → {destination}", file=sys.stderr)
    try:
        written = download_geoip_db(key, destination)
    except GeoIPDownloadError as exc:
        print(f"update-geoip failed: {exc}", file=sys.stderr)
        return 2

    size_kb = written.stat().st_size // 1024
    print(f"wrote {written} ({size_kb} KiB)", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover -- module-script form
    sys.exit(main())
