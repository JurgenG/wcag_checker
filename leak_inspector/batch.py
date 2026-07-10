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

"""Non-interactive batch audit over a list of URLs.

Audits every URL in a plain-text list (one URL per line; ``#`` comments
and blank lines skipped) using the same one-shot flow as
``wcag-checker --once`` — open the page, wait for it to settle, run
axe-core plus the keyboard/focus checks, and capture per-finding element
screenshots. One Firefox is reused across the whole list; a site that
fails (timeout, crash, no axe injection) is recorded and the run
continues.

Each site gets its own subdirectory of the output directory with the full
report set (via :func:`.session.write_reports`); an aggregate
``summary.{json,md,html}`` at the top level carries one row per site with
its finding counts or its failure. The rendering helpers are pure
(``list[SiteResult]`` in, strings out) and unit-tested; :func:`run_batch`
owns the live browser.

Unattended note: batch runs default to a visible browser (accurate focus
behaviour), like the interactive tool — pass ``headless=True`` for a
hidden run, accepting that the focus/keyboard checks are less reliable
without a real display.
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .capture.driver import launch_driver
from .session import SCREENSHOT_DIRNAME, audit_page, wait_until_settled, write_reports
from .wcag import reporter


@dataclass(frozen=True)
class SiteResult:
    """Outcome of auditing one URL in a batch.

    ``status`` is ``"audited"`` or ``"failed"``. For a failed site
    ``error`` holds the exception text and the counts are zero; for an
    audited site ``error`` is ``None`` and the counts summarize its
    findings. ``slug`` is the site's output subdirectory name.
    """

    url: str
    slug: str
    status: str
    error: str | None
    error_count: int
    warning_count: int
    needs_review_count: int
    criteria_with_findings: int


@dataclass(frozen=True)
class BatchResult:
    """Outcome of a batch run: the per-site results plus written files."""

    sites: tuple[SiteResult, ...]
    output_dir: Path
    generated_at: str | None
    source: str | None
    written: dict[str, Path]


def read_urls(path: Path | str) -> list[str]:
    """Read a URL list file: one URL per line, order-preserving, deduplicated.

    Blank lines and ``#`` comments are skipped; surrounding whitespace is
    stripped. Duplicates are dropped, keeping first-seen order.
    """
    seen: dict[str, None] = {}
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        seen.setdefault(line, None)
    return list(seen)


def site_slug(url: str, taken: set[str]) -> str:
    """Return a filesystem-safe, unique subdirectory name for ``url``.

    Derived from the host (path/query dropped); characters outside
    ``[a-z0-9._-]`` become ``-``. If the resulting name is already in
    ``taken``, a ``-2``, ``-3`` … suffix is appended so two URLs never
    share an output directory. The chosen name is added to ``taken``.
    """
    host = (urlparse(url).hostname or "").lower()
    base = "".join(c if (c.isalnum() or c in "._-") else "-" for c in host).strip("-")
    base = base or "site"
    slug = base
    n = 1
    while slug in taken:
        n += 1
        slug = f"{base}-{n}"
    taken.add(slug)
    return slug


def run_batch(
    urls: list[str],
    output_dir: Path | str,
    *,
    headless: bool = False,
    limit: int | None = None,
    source: str | None = None,
) -> BatchResult:
    """Audit each URL into its own subdirectory and write an aggregate summary.

    Reuses one Firefox for the whole list (sequential). Each URL runs the
    one-shot audit flow; any site that raises is recorded as ``"failed"``
    and the run continues. ``limit`` caps how many URLs are audited (the
    first N); ``source`` labels the summary with where the list came from.
    Returns a :class:`BatchResult`; the per-site reports and the
    ``summary.*`` files are written under ``output_dir``.
    """
    out = Path(output_dir)
    selected = urls if limit is None else urls[:limit]
    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    taken: set[str] = set()
    sites: list[SiteResult] = []
    with launch_driver(headless=headless) as launched:
        driver = launched.driver
        for url in selected:
            slug = site_slug(url, taken)
            sites.append(_audit_site(driver, url, slug, out / slug, generated_at))

    written = write_summary(out, sites, generated_at=generated_at, source=source)
    return BatchResult(
        sites=tuple(sites),
        output_dir=out,
        generated_at=generated_at,
        source=source,
        written=written,
    )


def _audit_site(
    driver, url: str, slug: str, site_dir: Path, generated_at: str
) -> SiteResult:
    """Audit one URL into ``site_dir``; never raises — failures are recorded."""
    try:
        driver.get(url)
        audited_url = wait_until_settled(driver)
        findings = audit_page(driver, audited_url, site_dir / SCREENSHOT_DIRNAME)
        write_reports(site_dir, findings, [audited_url], generated_at=generated_at)
        sev = reporter.build_report(findings, urls=[audited_url]).summary
        return SiteResult(
            url=url,
            slug=slug,
            status="audited",
            error=None,
            error_count=sev.findings_by_severity["error"],
            warning_count=sev.findings_by_severity["warning"],
            needs_review_count=sev.findings_by_severity["needs-review"],
            criteria_with_findings=sev.criteria_with_findings,
        )
    except Exception as exc:  # noqa: BLE001 - one bad site must not stop the batch
        return SiteResult(
            url=url,
            slug=slug,
            status="failed",
            error=_short_error(exc),
            error_count=0,
            warning_count=0,
            needs_review_count=0,
            criteria_with_findings=0,
        )


def _short_error(exc: Exception) -> str:
    """Reduce an exception to a single, table-safe line.

    Selenium errors carry a multi-line stacktrace in ``str(exc)``; keep
    only the first line (the message) so the summary's Markdown table and
    HTML rows stay intact, capped to a sensible length.
    """
    first = str(exc).splitlines()[0].strip() if str(exc).strip() else ""
    message = f"{type(exc).__name__}: {first}" if first else type(exc).__name__
    return message if len(message) <= 200 else message[:197] + "..."


#: Repeated in every summary format, mirroring the per-page report disclaimer.
SUMMARY_DISCLAIMER = (
    "A clean automated run does not imply WCAG 2.2 AA conformance. These "
    "per-site totals count only automated findings; every site still needs "
    "the manual-review checklist worked through before any conformance claim."
)


def write_summary(
    output_dir: Path | str,
    sites: list[SiteResult],
    *,
    generated_at: str | None = None,
    source: str | None = None,
) -> dict[str, Path]:
    """Render and write ``summary.{json,md,html}`` to ``output_dir``.

    Pure output seam (no driver, no network); creates ``output_dir`` if
    needed and returns a basename→path map.
    """
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    payloads = {
        "summary.json": render_summary_json(sites, generated_at=generated_at, source=source),
        "summary.md": render_summary_markdown(sites, generated_at=generated_at, source=source),
        "summary.html": render_summary_html(sites, generated_at=generated_at, source=source),
    }
    written: dict[str, Path] = {}
    for name, text in payloads.items():
        path = out / name
        path.write_text(text, encoding="utf-8")
        written[name] = path
    return written


def _counts(sites: list[SiteResult]) -> tuple[int, int]:
    """Return (audited, failed) site counts."""
    audited = sum(1 for s in sites if s.status == "audited")
    return audited, len(sites) - audited


def render_summary_json(
    sites: list[SiteResult], *, generated_at: str | None = None, source: str | None = None
) -> str:
    """Render the canonical ``summary.json`` string."""
    audited, failed = _counts(sites)
    payload = {
        "generated_at": generated_at,
        "source": source,
        "disclaimer": SUMMARY_DISCLAIMER,
        "totals": {"sites": len(sites), "audited": audited, "failed": failed},
        "sites": [
            {
                "url": s.url,
                "slug": s.slug,
                "status": s.status,
                "error": s.error,
                "report": f"{s.slug}/report.html" if s.status == "audited" else None,
                "findings": {
                    "error": s.error_count,
                    "warning": s.warning_count,
                    "needs-review": s.needs_review_count,
                },
                "criteria_with_findings": s.criteria_with_findings,
            }
            for s in sites
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_summary_markdown(
    sites: list[SiteResult], *, generated_at: str | None = None, source: str | None = None
) -> str:
    """Render the aggregate summary as a Markdown table."""
    audited, failed = _counts(sites)
    lines = ["# WCAG 2.2 AA batch audit", ""]
    if generated_at:
        lines.append(f"_Generated: {generated_at}_")
        lines.append("")
    if source:
        lines.append(f"Source: `{source}`")
        lines.append("")
    lines.append(f"{len(sites)} site(s): {audited} audited, {failed} failed.")
    lines.append("")
    lines.append(f"> {SUMMARY_DISCLAIMER}")
    lines.append("")
    lines.append("| Site | Status | Criteria | Error | Warning | Needs-review |")
    lines.append("| --- | --- | ---: | ---: | ---: | ---: |")
    for s in sites:
        if s.status == "audited":
            lines.append(
                f"| [{s.url}]({s.slug}/report.html) | audited "
                f"| {s.criteria_with_findings} | {s.error_count} "
                f"| {s.warning_count} | {s.needs_review_count} |"
            )
        else:
            lines.append(f"| {s.url} | **failed**: {s.error} | – | – | – | – |")
    return "\n".join(lines).rstrip() + "\n"


def render_summary_html(
    sites: list[SiteResult], *, generated_at: str | None = None, source: str | None = None
) -> str:
    """Render a self-contained HTML summary (inline CSS; links to per-site reports)."""
    audited, failed = _counts(sites)
    rows: list[str] = []
    for s in sites:
        if s.status == "audited":
            link = f"<a href='{html.escape(s.slug, quote=True)}/report.html'>{html.escape(s.url)}</a>"
            rows.append(
                "<tr>"
                f"<td>{link}</td><td class='ok'>audited</td>"
                f"<td>{s.criteria_with_findings}</td><td>{s.error_count}</td>"
                f"<td>{s.warning_count}</td><td>{s.needs_review_count}</td></tr>"
            )
        else:
            rows.append(
                "<tr>"
                f"<td>{html.escape(s.url)}</td>"
                f"<td class='fail'>failed: {html.escape(s.error or '')}</td>"
                "<td>–</td><td>–</td><td>–</td><td>–</td></tr>"
            )
    generated = (
        f"<p class='meta'>Generated: {html.escape(generated_at)}</p>" if generated_at else ""
    )
    src = f"<p class='meta'>Source: {html.escape(source)}</p>" if source else ""
    return _SUMMARY_HTML_TEMPLATE.format(
        generated=generated,
        source=src,
        total=len(sites),
        audited=audited,
        failed=failed,
        disclaimer=html.escape(SUMMARY_DISCLAIMER),
        rows="".join(rows),
    )


#: Self-contained page shell for :func:`render_summary_html`. Literal
#: ``{`` / ``}`` in the CSS are doubled so ``str.format`` leaves them be.
_SUMMARY_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WCAG 2.2 AA batch audit</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }}
.meta {{ color: #555; }}
.disclaimer {{ background: #fff8e1; border-left: 4px solid #f0ad4e;
  padding: 0.75rem 1rem; margin: 1rem 0; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
th, td {{ border: 1px solid #ddd; padding: 0.4rem 0.6rem; text-align: left;
  font-size: 0.9rem; }}
th {{ background: #f4f4f4; }}
td.ok {{ color: #0a5; }}
td.fail {{ color: #842029; }}
</style>
</head>
<body>
<h1>WCAG 2.2 AA batch audit</h1>
{generated}
{source}
<p class="disclaimer">{disclaimer}</p>
<p>{total} site(s): {audited} audited, {failed} failed.</p>
<table>
<thead><tr><th>Site</th><th>Status</th><th>Criteria</th><th>Error</th>
<th>Warning</th><th>Needs-review</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</body>
</html>
"""


__all__ = [
    "BatchResult",
    "SiteResult",
    "SUMMARY_DISCLAIMER",
    "read_urls",
    "render_summary_html",
    "render_summary_json",
    "render_summary_markdown",
    "run_batch",
    "site_slug",
    "write_summary",
]
