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

"""Zero-interaction bulk capture + HTML-report runner.

Iterates the URLs in ``<dataset>/domains.csv``, captures each one
without manual interaction (page load + a short settle window, then
close the browser), and emits an HTML report per URL into
``<dataset>/reports/<host>.report.html``. Intermediate capture bundles
are kept under ``<dataset>/captures/<host>.zip`` so a run can be
re-analysed without recapturing.

Usage:

    python bulk-tool/run.py bulk-tool/datasets/belgium

The argument must point to a directory containing ``domains.csv``.
That file is either one URL per line (the original form) or a
multi-column CSV with a header naming a ``name`` and a ``website``
column — in which case ``name`` becomes the per-site report title and
``website`` the URL (extra columns are ignored). Blank lines and lines
starting with ``#`` are skipped. Per-URL failures are logged and do not
stop the batch.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

from leak_inspector import modules  # noqa: F401 -- registers detectors
from leak_inspector.analysis import analyze_bundle
from leak_inspector.bundle import BundleReader
from leak_inspector.report.builder import determine_capture_status
from leak_inspector.capture.recorder import Recorder
from leak_inspector.enrichment.producer import enrich_bundle as _enrich_bundle
from leak_inspector.report import (
    write_html_report,
    write_json_report,
    write_markdown_detailed,
)

# Local import; ``bulk-tool`` is run as a script and the hyphen in
# its folder name prevents normal package import, so we add this
# file's directory to sys.path first.
sys.path.insert(0, str(Path(__file__).resolve().parent))
# noinspection PyUnresolvedReferences
from overview import build_overview  # noqa: E402


#: Unattended settle window. ``driver.get`` blocks only until the
#: page-load event, which fires before deferred scripts, framework
#: hydration and consent banners render. So the recorder waits until
#: the BiDi event stream is quiet for ``SETTLE_IDLE_WINDOW_SECONDS``
#: (capped at ``SETTLE_MAX_WAIT_SECONDS``) rather than a fixed sleep —
#: ``WAIT_AFTER_LOAD_SECONDS`` is the minimum floor.
WAIT_AFTER_LOAD_SECONDS = 1.0
SETTLE_IDLE_WINDOW_SECONDS = 2.0
SETTLE_MAX_WAIT_SECONDS = 15.0


def main(argv: list[str] | None = None) -> int:
    """Run the bulk capture pipeline. Returns a process exit code."""
    args = _parse_args(argv)
    dataset_dir: Path = args.dataset_dir.resolve()

    csv_path = dataset_dir / "domains.csv"
    if not csv_path.is_file():
        print(f"domains.csv not found in {dataset_dir}", file=sys.stderr)
        return 2

    captures_dir = dataset_dir / "captures"
    reports_dir = (
        args.out.resolve() if args.out is not None else dataset_dir / "reports"
    )
    captures_dir.mkdir(exist_ok=True)
    reports_dir.mkdir(parents=True, exist_ok=True)

    domains = _read_domains(csv_path)
    if not domains:
        print(f"no URLs in {csv_path}", file=sys.stderr)
        return 0

    print(
        f"bulk-tool: {len(domains)} URL(s) from {csv_path}",
        file=sys.stderr,
    )

    report_ext = _report_ext_for(args.format)

    # PDF needs WeasyPrint (+ native libs). Fail fast — before capturing
    # hundreds of sites — rather than have every per-site render fail.
    if args.format == "pdf":
        from leak_inspector.report.pdf import _import_weasyprint
        try:
            _import_weasyprint()
        except RuntimeError as exc:
            print(f"bulk-tool: {exc}", file=sys.stderr)
            return 2

    failures = 0
    skipped = 0
    re_rendered = 0
    # Per-slug analyses produced while rendering the reports — handed to
    # build_overview so the index doesn't re-run the live analysis.
    analyses: dict = {}
    for index, (url, display_name) in enumerate(domains, start=1):
        slug = _slug_for_url(url)
        bundle_path = captures_dir / f"{slug}.zip"
        report_path = reports_dir / f"{slug}.report.{report_ext}"

        if args.resume and bundle_path.is_file():
            # Reuse an existing capture only if it actually succeeded. A
            # prior failure (HTTP error / unreachable / corrupt bundle) is
            # re-captured — the failure is often transient (e.g. HTTP 429).
            if _prior_capture_failed(bundle_path):
                print(
                    f"[{index}/{len(domains)}] {url} -> {report_path.name} "
                    "[resumed: prior capture failed — re-capturing]",
                    file=sys.stderr,
                )
                # Fall through to the capture block below.
            elif report_path.is_file():
                skipped += 1
                print(
                    f"[{index}/{len(domains)}] {url} -> {report_path.name} "
                    "[resumed: capture + report already present, skipping]",
                    file=sys.stderr,
                )
                continue
            else:
                # Successful capture, but the report in the requested
                # format is missing — common when the first run was
                # --format html and a follow-up wants --format markdown.
                # Re-render only; don't re-capture.
                print(
                    f"[{index}/{len(domains)}] {url} -> {report_path.name} "
                    "[resumed: capture present, rendering report only]",
                    file=sys.stderr,
                )
                try:
                    analyses[slug] = _render_report_from_bundle(
                        bundle_path, report_path, report_format=args.format,
                        display_name=display_name,
                    )
                    re_rendered += 1
                except Exception as exc:
                    failures += 1
                    print(f"  failed: {exc}", file=sys.stderr)
                continue

        print(
            f"[{index}/{len(domains)}] {url} -> {report_path.name}",
            file=sys.stderr,
        )
        try:
            analyses[slug] = _capture_and_report(
                url, bundle_path, report_path,
                headless=args.headless,
                report_format=args.format,
                display_name=display_name,
            )
        except Exception as exc:
            failures += 1
            print(f"  failed: {exc}", file=sys.stderr)

    fresh_captures = len(domains) - failures - skipped - re_rendered
    summary = f"{fresh_captures + re_rendered}/{len(domains)} succeeded"
    parts = []
    if skipped:
        parts.append(f"{skipped} skipped via --resume")
    if re_rendered:
        parts.append(f"{re_rendered} re-rendered from existing capture")
    if parts:
        summary += " (" + "; ".join(parts) + ")"
    print(f"done — {summary}", file=sys.stderr)

    print("building dataset overview…", file=sys.stderr)
    build_overview(
        dataset_dir, reports_dir=reports_dir, analyses=analyses,
        report_format=args.format,
    )

    return 0 if failures == 0 else 2


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Parse the bulk-tool CLI arguments."""
    parser = argparse.ArgumentParser(
        prog="bulk-tool",
        description=(
            "Run leak-inspector against every URL listed in a dataset's "
            "domains.csv and write one HTML report per URL into the "
            "dataset's reports/ folder."
        ),
    )
    parser.add_argument(
        "dataset_dir",
        type=Path,
        help=(
            "path to the dataset folder (must contain domains.csv). "
            "Captures are written into ./captures under this folder; "
            "reports into ./reports unless --out overrides it."
        ),
    )
    parser.add_argument(
        "--out",
        type=Path,
        metavar="DIR",
        default=None,
        help=(
            "write the per-site reports + their webp screenshot sidecars "
            "into DIR instead of <dataset>/reports/. Captures always stay "
            "under <dataset>/captures/ (they are the dataset's artifacts). "
            "DIR is created if missing. Mirrors `analyze -o` / `diff --out`."
        ),
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help=(
            "run Firefox without a visible window. Useful for bulk scans "
            "of many URLs. Screenshots still work; some sites do "
            "fingerprint headless Firefox differently, so for assessments "
            "of real visitor exposure prefer the default visible mode."
        ),
    )
    parser.add_argument(
        "--format",
        choices=("html", "markdown", "pdf", "json"),
        default="html",
        help=(
            "per-site report format. Default 'html' writes "
            "<slug>.report.html (rich layout). "
            "'markdown' writes <slug>.report.md (plain markdown — "
            "usable in git diffs, GitHub previews, or downstream pandoc "
            "pipelines). 'pdf' writes <slug>.report.pdf (branded cover + "
            "TOC + summary, with the detailed report embedded as an "
            "attachment; needs the [pdf] extra). 'json' writes "
            "<slug>.report.json (the full structured document — score, "
            "executive summary, and tracker detail — for downstream "
            "pipelines, with screenshots written beside it and referenced "
            "by relative filename under a `screenshots` key). HTML/Markdown "
            "screenshots "
            "are sibling lossless-webp files (<stem>.post-load.webp, "
            "<stem>.shot_<host>_<HHMMSS>.webp) referenced by relative "
            "filename; PDF inlines them so each file is self-contained."
        ),
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help=(
            "for each URL: skip the Firefox capture when "
            "<slug>.zip already exists, but still render the report in "
            "the requested format if it's missing. A URL is fully "
            "skipped only when both the .zip AND the .report.<ext> are "
            "already on disk. Captures that previously FAILED (HTTP "
            "error / unreachable / corrupt bundle) are re-captured "
            "rather than reused, since such failures are often "
            "transient. Lets a long run pick up after a crash, "
            "and lets a follow-up --format markdown pass complete a "
            "dataset that was originally captured to --format html "
            "without re-running the captures."
        ),
    )
    return parser.parse_args(argv)


def _report_ext_for(report_format: str) -> str:
    """Return the report file extension for a ``--format`` value."""
    return {"markdown": "md", "pdf": "pdf", "json": "json"}.get(
        report_format, "html"
    )


def _read_domains(csv_path: Path) -> list[tuple[str, str | None]]:
    """Return ``(url, display_name)`` pairs from ``domains.csv``.

    Two accepted shapes:

    * **Single column** (the original format) — one URL per line, no
      header. ``display_name`` is ``None`` so the report titles itself
      by host.
    * **Multi-column with a header** — the first non-comment row names
      the columns; a ``name`` column supplies the report title and a
      ``website`` column the URL, matched by title (case-insensitive,
      falling back to positions 0 and 1). Any extra columns are ignored.

    In both shapes, blank rows and ``#`` comment rows are skipped.
    """
    import csv

    def _skip(row: list[str]) -> bool:
        # Drop fully-blank rows and ``#`` comment rows — but keep a row
        # whose first cell is empty if another cell carries data (a blank
        # name with a real website in the headered form).
        if not row or all(not cell.strip() for cell in row):
            return True
        return row[0].lstrip().startswith("#")

    rows = [
        row
        for row in csv.reader(csv_path.read_text(encoding="utf-8").splitlines())
        if not _skip(row)
    ]
    if not rows:
        return []

    # Single-column file → the original URL-per-line format (no header).
    if max(len(row) for row in rows) == 1:
        return [(row[0].strip(), None) for row in rows]

    # Multi-column → the first row is a header; map name/website by title.
    header = [cell.strip().lower() for cell in rows[0]]

    def _column(*titles: str, default: int) -> int:
        for title in titles:
            if title in header:
                return header.index(title)
        return default

    website_idx = _column("website", "url", "domain", default=1)
    name_idx = _column("name", default=0)

    out: list[tuple[str, str | None]] = []
    for row in rows[1:]:
        if website_idx >= len(row):
            continue
        url = row[website_idx].strip()
        if not url:
            continue
        name = row[name_idx].strip() if name_idx < len(row) else ""
        out.append((url, name or None))
    return out


def _prior_capture_failed(bundle_path: Path) -> bool:
    """True when an existing capture bundle didn't land successfully.

    ``--resume`` reuses a bundle only when the capture succeeded; a
    failed one (HTTP 4xx/5xx, or unreachable — DNS/TCP/TLS) is worth
    retrying since the failure is often transient (e.g. an HTTP 429).
    An unreadable / corrupt bundle also counts as failed so it is
    re-captured rather than silently kept.
    """
    try:
        return determine_capture_status(analyze_bundle(bundle_path)).is_failure
    except Exception:
        return True


def _slug_for_url(url: str) -> str:
    """Derive a filesystem-safe per-URL slug.

    Uses the URL's hostname when present; falls back to the raw URL
    string with ``/`` replaced. Strips any leading scheme so the file
    name reads as ``<host>.report.html`` per the spec.
    """
    host = urlparse(url).hostname
    if host:
        return host
    return url.replace("://", "_").replace("/", "_").strip("_")


def _capture_and_report(
    url: str,
    bundle_path: Path,
    report_path: Path,
    *,
    headless: bool = False,
    report_format: str = "html",
    display_name: str | None = None,
):
    """Capture ``url`` into ``bundle_path`` then write its per-site report.

    Thin wrapper: runs the Firefox capture, then hands off to
    :func:`_render_report_from_bundle` for the analyze + render half.
    Returns that helper's analysis so the dataset overview can reuse it.
    ``--resume`` mode calls the render helper directly when a capture
    already exists but the report-in-requested-format is missing.

    ``report_format`` is ``"html"`` (default) or ``"markdown"``.

    When ``headless`` is true, Firefox runs without a visible window —
    the post-load screenshot still works via virtual rendering, but no
    operator is present to press the shortcut so the extras list is
    normally empty.
    """
    result = Recorder(
        url,
        bundle_path,
        auto_close_after_load=WAIT_AFTER_LOAD_SECONDS,
        settle_idle_window=SETTLE_IDLE_WINDOW_SECONDS,
        settle_max_wait=SETTLE_MAX_WAIT_SECONDS,
        headless=headless,
    ).run()
    return _render_report_from_bundle(
        result.bundle_path, report_path, report_format=report_format,
        display_name=display_name,
    )


def _render_report_from_bundle(
    bundle_path: Path,
    report_path: Path,
    *,
    report_format: str = "html",
    display_name: str | None = None,
):
    """Analyse an existing capture bundle, write its report, return the analysis.

    Extracts every PNG the bundle holds to disk next to the report,
    using the same sidecar convention as ``analyze -o FILE`` (the stem
    is the report filename without extension, e.g. ``aalst.be.report``):

    * Canonical post-load shot → ``<stem>.post-load.webp``.
    * Operator-triggered shots → ``<stem>.shot_<host>_<HHMMSS>.webp``.

    Both HTML and Markdown reports reference them by relative filename.

    Used by ``--resume`` when the capture is already on disk but the
    report in the requested format is missing (e.g. the first run was
    ``--format html`` and the second is ``--format markdown``).
    """
    from leak_inspector.report.screenshots import write_screenshot_sidecars

    # Guarantee an enrichment exists before the (strictly offline)
    # analysis: fresh captures enrich here right after the recorder
    # closes; --resume re-renders retrofit pre-enrichment bundles on
    # touch. A no-op when the bundle already carries an artifact.
    # Soft-fail: a dead resolver costs the posture, never the report.
    try:
        _enrich_bundle(bundle_path)
    except Exception as exc:
        print(
            f"  enrichment failed: {exc} — rendering without network "
            "posture (run `leak-inspector enrich` later)",
            file=sys.stderr,
        )

    analysis = analyze_bundle(bundle_path)

    # PDF is binary and self-contained: inline screenshots as data: URIs
    # (no sibling webp files) and render via WeasyPrint.
    if report_format == "pdf":
        from leak_inspector.cli import _collect_screenshot_data_uris
        from leak_inspector.report.pdf import write_pdf_report

        shot, extra_shots, extra_caps = _collect_screenshot_data_uris(
            BundleReader, bundle_path
        )
        report_path.write_bytes(write_pdf_report(
            analysis,
            screenshot_filename=shot,
            extra_screenshot_filenames=extra_shots or None,
            extra_screenshot_captions=extra_caps or None,
            display_name=display_name,
        ))
        return analysis

    with BundleReader(bundle_path) as bundle:
        screenshot_filename, extra_screenshot_filenames, extra_captions = (
            write_screenshot_sidecars(
                bundle, out_dir=report_path.parent, stem=report_path.stem,
            )
        )

    if report_format == "json":
        # The structured document plus the screenshots written beside it,
        # referenced by relative filename (same sidecar convention as the
        # HTML/Markdown reports).
        payload = json.loads(
            write_json_report(analysis, display_name=display_name)
        )
        payload["screenshots"] = {
            "post_load": screenshot_filename,
            "extra": [
                {"path": name, "caption": caption}
                for name, caption in zip(
                    extra_screenshot_filenames, extra_captions
                )
            ],
        }
        report_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8"
        )
        return analysis

    if report_format == "markdown":
        rendered = write_markdown_detailed(
            analysis,
            screenshot_filename=screenshot_filename,
            extra_screenshot_filenames=extra_screenshot_filenames or None,
            extra_screenshot_captions=extra_captions or None,
            display_name=display_name,
        )
    else:
        rendered = write_html_report(
            analysis,
            screenshot_filename=screenshot_filename,
            extra_screenshot_filenames=extra_screenshot_filenames or None,
            extra_screenshot_captions=extra_captions or None,
            display_name=display_name,
        )
    report_path.write_text(rendered, encoding="utf-8")
    # Hand the analysis back so the dataset overview can reuse it
    # instead of re-running the live network analysis per site.
    return analysis


if __name__ == "__main__":  # pragma: no cover -- module-script form
    sys.exit(main())