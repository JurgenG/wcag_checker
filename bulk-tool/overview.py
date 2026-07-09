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

"""Dataset-level summary report.

Walks every ``<dataset>/captures/*.zip`` produced by ``run.py``,
re-analyses each bundle to extract the executive-summary signals
needed for cross-site comparison, then writes a single
``<dataset>/reports/index.html`` overview (or ``index.json`` for a
``--format json`` dataset — see ``report_format``) containing:

* Top-3 cleanest sites.
* Worst-3 sites (most high-severity findings).
* Frequency table of the most common findings across all sites.
* Full list with hyperlinks to each per-site HTML report, ranked by
  composite score (best first; unscored / failed captures last) with
  TOT / RES / SEC / PRIV columns.

Can be invoked standalone (``python bulk-tool/overview.py
<dataset_dir>``) to rebuild the overview without recapturing.
"""

from __future__ import annotations

import argparse
import html
import json
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from leak_inspector import modules  # noqa: F401 -- registers detectors
from leak_inspector.analysis import Analysis, analyze_bundle
from leak_inspector.dns_posture.sovereignty import asn_to_provider
from leak_inspector.dns_posture.types import IPInfo
from leak_inspector.modules.base import (
    MODULE_KIND_GOVERNMENT,
    MODULE_KIND_PARA_GOVERNMENT,
    TrackerModule,
    all_modules,
)
from leak_inspector.report._branding import (
    BELIBRE_HOMEPAGE,
    belibre_logo_svg_inline,
    BRANDING_TITLE_PREFIX,
    INTRO_DISCLAIMER_TEXT,
    INTRO_PARAGRAPHS,
    INTRO_TITLE,
)
from leak_inspector.report.builder import EU_MEMBERS, build_report_document
from leak_inspector.report.document import CaptureStatus, ReportDocument
from leak_inspector.report.score_v2 import ScoreView, format_stars


#: How many entries to surface in the best/worst rollups.
TOP_N = 3
#: How many distinct findings to surface in the "common flaws" table.
COMMON_FLAWS_N = 10
#: How many top hosts to list per public-sector entity row.
PUBLIC_SECTOR_TOP_HOSTS = 5

#: Display order for the government sub-section — geographic / political
#: scope, matching the module registration order in
#: ``leak_inspector/modules/__init__.py``.
_GOV_LEVEL_ORDER: tuple[str, ...] = (
    "european",
    "federal_be",
    "regional_vlaanderen",
    "regional_wallonie",
    "regional_brussels_capital",
)


@dataclass
class SiteSummary:
    """One row in the overview — pre-computed metrics for ranking and display."""

    slug: str                   # host (matches "<slug>.zip" / "<slug>.report.html")
    target_url: str             # what the bundle's manifest said it captured
    landing_url: str            # post-redirect landing page
    report_filename: str        # relative href from index.html
    high_finding_count: int
    medium_finding_count: int
    low_finding_count: int
    total_high_impact_fields: int
    trackers_fired: int
    third_party_hosts_touched: int
    finding_headlines: list[tuple[str, str]]  # (severity, headline) pairs

    # Public-sector third parties this site contacted, grouped for the
    # overview's per-category sections. Each map keys an aggregation
    # bucket (government_level / paragov vendor) to the set of hosts
    # this site actually touched in that bucket.
    gov_hosts_by_level: dict[str, set[str]] = field(default_factory=dict)
    paragov_hosts_by_vendor: dict[str, set[str]] = field(default_factory=dict)

    # First-party hosting at analysis time — the ASN / country of the
    # first IP that the site's ``base_domain`` resolves to. Lets the
    # overview's all-reports table show at a glance which sites sit on
    # which provider / country. ``None`` when DNS resolution failed.
    first_party_ip: IPInfo | None = None

    # Reachability classification of the landing-page load. Captures
    # whose ``is_failure`` is True are excluded from the cleanest /
    # worst-3 rankings but still listed in the all-reports table with
    # their status surfaced inline.
    capture_status: CaptureStatus | None = None

    # CMS / web-platform fingerprint with EOL judgment applied. ``None``
    # when no platform was identified. Drives the "Platform" column in
    # the all-reports table; past-EOL versions get a visible badge.
    cms_fingerprint: object | None = None

    # Composite resilience / security / privacy scorecard from the
    # per-site ReportDocument. ``None`` for hermetic analyses (no DNS
    # posture → no score) and for failed / missing captures. Drives the
    # TOT / RES / SEC / PRIV columns and the all-reports ranking.
    score: ScoreView | None = None

    @property
    def ranking_weight(self) -> float:
        """Higher = worse. Weighted so high-severity findings dominate."""
        return (
            self.high_finding_count * 1000.0
            + self.medium_finding_count * 50.0
            + self.total_high_impact_fields * 5.0
            + self.trackers_fired * 1.0
            + self.third_party_hosts_touched * 0.1
        )


#: Thread-pool width for analyzing bundles whose analysis wasn't handed
#: in by the bulk runner. The work is network-bound (DNS posture,
#: per-host ASN lookups, transport probes), so threads parallelize it
#: well; 8 keeps the resolver load polite while cutting a 497-site
#: standalone rebuild from ~10+ minutes to roughly an eighth of that.
_OVERVIEW_ANALYSIS_WORKERS = 8


def _build_module_metadata() -> dict[str, TrackerModule]:
    """Map every registered module's id to its instance for O(1) lookup."""
    return {m.module_id: m for m in all_modules()}


#: Per-site report extensions the bulk runner can produce, in priority
#: order (first hit wins when both happen to exist for a slug).
_REPORT_EXTENSIONS: tuple[str, ...] = ("html", "md")


def _expected_slugs_from_csv(csv_path: Path) -> set[str]:
    """Read ``domains.csv`` and derive the slug each URL would produce.

    Delegates to the runner's own reader + slug logic so the two stay in
    lock-step — including the multi-column ``name,website`` form. (Parsing
    each line independently here would turn a ``Name,https://host`` row
    into a bogus slug and make every captured site look "missing".)
    """
    # Lazy import: run.py imports build_overview from this module at load
    # time, so importing run at module scope would be circular. Both
    # modules are fully initialised by the time this runs.
    import run

    return {run._slug_for_url(url) for url, _name in run._read_domains(csv_path)}


def _synthetic_missing_capture_summary(slug: str) -> SiteSummary:
    """Stand-in summary for a URL that has no capture file at all.

    ``report_filename`` is empty so the renderer knows to show the slug
    as plain text rather than as a broken link. All ranking-relevant
    numbers stay at zero, and ``capture_status`` is the "didn't complete"
    sentinel that excludes it from best/worst.
    """
    return SiteSummary(
        slug=slug,
        target_url="",
        landing_url="",
        report_filename="",
        high_finding_count=0,
        medium_finding_count=0,
        low_finding_count=0,
        total_high_impact_fields=0,
        trackers_fired=0,
        third_party_hosts_touched=0,
        finding_headlines=[],
        capture_status=CaptureStatus(
            http_status=None,
            reason="Capture didn't complete",
            is_failure=True,
        ),
    )


def _find_report_path(
    reports_dir: Path,
    slug: str,
    extensions: tuple[str, ...] = _REPORT_EXTENSIONS,
) -> Path | None:
    """Return the per-site report path for ``slug`` if one exists.

    ``extensions`` is the search order (first hit wins). It defaults to
    ``<slug>.report.html`` then ``<slug>.report.md``; a ``--format json``
    dataset passes ``("json",)`` so the overview links the structured
    ``<slug>.report.json`` documents. Returns ``None`` when none exists.
    """
    for ext in extensions:
        candidate = reports_dir / f"{slug}.report.{ext}"
        if candidate.is_file():
            return candidate
    return None


def _classify_public_sector(
    analysis: Analysis, meta_by_id: dict[str, TrackerModule]
) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """Group an analysis' hits by public-sector kind.

    Returns ``(gov_by_level, paragov_by_vendor)``. Keys are the
    ``government_level`` and (paragov) ``vendor`` strings respectively;
    values are the set of distinct hosts on this site that the module
    fired on.
    """
    gov: dict[str, set[str]] = {}
    paragov: dict[str, set[str]] = {}
    for hit in analysis.hits:
        meta = meta_by_id.get(hit.module_id)
        if meta is None:
            continue
        if meta.module_kind == MODULE_KIND_GOVERNMENT:
            gov.setdefault(meta.government_level, set()).add(hit.host)
        elif meta.module_kind == MODULE_KIND_PARA_GOVERNMENT:
            paragov.setdefault(meta.vendor or meta.module_name, set()).add(
                hit.host
            )
    return gov, paragov


def _first_party_ip(analysis: Analysis) -> IPInfo | None:
    """Return the first resolvable IP for the analysis' ``base_domain``.

    Prefers IPv4 (more reliable ASN coverage); falls back to IPv6 only
    if no A record was found. ``None`` if no DNS posture is available
    or both record lists are empty.
    """
    posture = analysis.dns_posture
    if posture is None:
        return None
    if posture.a_records:
        return posture.a_records[0]
    if posture.aaaa_records:
        return posture.aaaa_records[0]
    return None


def build_overview(
    dataset_dir: Path,
    reports_dir: Path | None = None,
    analyses: dict[str, Analysis] | None = None,
    report_format: str = "html",
) -> Path | None:
    """Build (or rebuild) the dataset overview. Returns the index path written.

    ``reports_dir`` defaults to ``<dataset>/reports``; the bulk runner
    passes its ``--out`` override so the index (whose per-site links
    are relative) lands next to the reports it links to.

    ``report_format`` selects which per-site reports to link and how the
    overview is emitted. ``"json"`` discovers ``<slug>.report.json``
    documents and writes a machine-readable ``index.json``; any other
    value links ``<slug>.report.html`` / ``.report.md`` and writes the
    human-readable ``index.html``.

    ``analyses`` maps slug → already-computed :class:`Analysis`. The
    bulk runner passes the analyses it just produced while rendering
    the per-site reports, so the overview doesn't re-run the live
    network analysis (DNS posture, per-host ASN enrichment, transport
    probes) a second time for every site. Slugs not in the map — the
    ``--resume``-skipped sites, or everything in a standalone
    ``overview.py`` rebuild — are analyzed here on a thread pool: the
    work is network-bound, so threads cut the wall-clock roughly by
    the worker count.

    Returns ``None`` when there are no analysable bundles yet.
    """
    captures_dir = dataset_dir / "captures"
    if reports_dir is None:
        reports_dir = dataset_dir / "reports"
    if not captures_dir.is_dir():
        print(f"no captures/ in {dataset_dir}", file=sys.stderr)
        return None
    reports_dir.mkdir(parents=True, exist_ok=True)

    bundles = sorted(captures_dir.glob("*.zip"))
    if not bundles:
        print(f"no bundle zips in {captures_dir}", file=sys.stderr)
        return None

    analyses = analyses or {}
    meta_by_id = _build_module_metadata()
    captured_slugs = {bundle.stem for bundle in bundles}

    # A json dataset links the structured per-site documents; every other
    # format links the html / md reports.
    report_exts = ("json",) if report_format == "json" else _REPORT_EXTENSIONS

    # Only bundles with a written report can be linked from the index.
    linkable: list[tuple[str, Path, str]] = []  # (slug, bundle, report name)
    for bundle in bundles:
        report_path = _find_report_path(reports_dir, bundle.stem, report_exts)
        if report_path is None:
            # We can't link to a report that was never written. Skip
            # silently — these are the per-URL failures from run.py.
            continue
        linkable.append((bundle.stem, bundle, report_path.name))

    def _analyze(slug: str, bundle: Path) -> Analysis:
        cached = analyses.get(slug)
        return cached if cached is not None else analyze_bundle(bundle)

    summaries: list[SiteSummary] = []
    done = 0
    with ThreadPoolExecutor(max_workers=_OVERVIEW_ANALYSIS_WORKERS) as pool:
        futures = [
            pool.submit(_analyze, slug, bundle)
            for slug, bundle, _ in linkable
        ]
        # Iterate in submission order so the overview rows stay
        # deterministic regardless of thread completion order.
        for (slug, _bundle, report_filename), future in zip(linkable, futures):
            done += 1
            print(f"  [{done}/{len(linkable)}] {slug}", file=sys.stderr)
            try:
                analysis = future.result()
                doc = build_report_document(analysis)
            except Exception as exc:
                print(f"    skip — analysis failed: {exc}", file=sys.stderr)
                continue
            gov, paragov = _classify_public_sector(analysis, meta_by_id)
            first_party_ip = _first_party_ip(analysis)
            summaries.append(_summarize(
                slug, report_filename, doc, gov, paragov, first_party_ip
            ))

    # Cross-reference domains.csv: any URL listed but with no
    # corresponding capture .zip is a "didn't complete" outcome
    # (typically a Recorder timeout or crash). Surface those as failed
    # captures so the overview reader sees the full picture instead of
    # silently dropping the URL.
    csv_path = dataset_dir / "domains.csv"
    if csv_path.is_file():
        for slug in sorted(_expected_slugs_from_csv(csv_path) - captured_slugs):
            summaries.append(_synthetic_missing_capture_summary(slug))

    if not summaries:
        print("no analysable bundles — overview not written", file=sys.stderr)
        return None

    if report_format == "json":
        index_path = reports_dir / "index.json"
        index_path.write_text(
            _render_overview_json(dataset_dir.name, summaries),
            encoding="utf-8",
        )
    else:
        index_path = reports_dir / "index.html"
        index_path.write_text(
            _render_overview_html(dataset_dir.name, summaries),
            encoding="utf-8",
        )
    print(f"overview: {index_path}", file=sys.stderr)
    return index_path


# --- summarization ---------------------------------------------------------


def _summarize(
    slug: str,
    report_filename: str,
    doc: ReportDocument,
    gov_hosts_by_level: dict[str, set[str]],
    paragov_hosts_by_vendor: dict[str, set[str]],
    first_party_ip: IPInfo | None,
) -> SiteSummary:
    """Reduce a :class:`ReportDocument` to the fields the overview needs."""
    summary = doc.executive_summary
    stats = summary.stats
    findings = summary.findings or []
    by_severity = Counter(f.severity for f in findings)
    high_impact_fields = sum(
        v.total_high_impact_fields for v in summary.high_impact_by_vendor
    )
    return SiteSummary(
        slug=slug,
        target_url=doc.manifest.target_url,
        landing_url=doc.manifest.landing_url or doc.manifest.target_url,
        report_filename=report_filename,
        high_finding_count=by_severity.get("high", 0),
        medium_finding_count=by_severity.get("medium", 0),
        low_finding_count=by_severity.get("low", 0),
        total_high_impact_fields=high_impact_fields,
        trackers_fired=stats.trackers_fired if stats else 0,
        third_party_hosts_touched=(
            stats.third_party_hosts_touched if stats else 0
        ),
        finding_headlines=[(f.severity, f.headline) for f in findings],
        gov_hosts_by_level=gov_hosts_by_level,
        paragov_hosts_by_vendor=paragov_hosts_by_vendor,
        first_party_ip=first_party_ip,
        capture_status=doc.capture_status,
        cms_fingerprint=getattr(doc, "cms_fingerprint", None),
        score=doc.score,
    )


# --- HTML rendering --------------------------------------------------------


_SEVERITY_BADGE = {
    "high": "🔴",
    "medium": "🟡",
    "low": "🟢",
}


def _render_branding_h1(dataset_name: str) -> str:
    """Render the BeLibre-branded H1 for the overview page.

    Matches the per-site reports' shape: logo on the left (linking to
    belibre.be in a new tab), title text "BeLibre Automatic Leak
    Inspector — Bulk overview", and the dataset name as a styled tail.
    """
    home = html.escape(BELIBRE_HOMEPAGE)
    return (
        '<h1 class="report-title">'
        f'<a class="belibre-link" href="{home}" target="_blank" rel="noopener">'
        f"{belibre_logo_svg_inline()}"
        f"</a>"
        f"<span>{html.escape(BRANDING_TITLE_PREFIX)} — Bulk overview: </span>"
        f"<span>{html.escape(dataset_name)}</span>"
        "</h1>"
    )


def _render_overview_intro() -> str:
    """Render the "About this report" intro using the shared template.

    Uses the same prose as the per-site reports (single source in
    ``leak_inspector/report/_branding.py``). Wrapped in the same
    ``<section class="report-intro">`` markup so the CSS rules transfer.
    """
    home = html.escape(BELIBRE_HOMEPAGE)
    belibre_link = (
        f'<a href="{home}" target="_blank" rel="noopener">BeLibre</a>'
    )
    belibre_url = (
        f'<a href="{home}" target="_blank" rel="noopener">belibre.be</a>'
    )
    disclaimer_bold = f"<strong>{html.escape(INTRO_DISCLAIMER_TEXT)}</strong>"

    parts: list[str] = ['<section class="report-intro">']
    parts.append(f"<h2>{html.escape(INTRO_TITLE)}</h2>")
    for paragraph in INTRO_PARAGRAPHS:
        rendered = paragraph.format(
            belibre_link=belibre_link,
            disclaimer_bold=disclaimer_bold,
            belibre_url=belibre_url,
        )
        parts.append(f"<p>{rendered}</p>")
    parts.append("</section>")
    return "\n".join(parts)


def _is_failed_capture(s: SiteSummary) -> bool:
    """True iff this summary's capture didn't reach a successful landing.

    A ``None`` status means the bundle was produced by a build that
    didn't carry capture_status yet — we treat that as healthy so old
    bundles continue to rank normally.
    """
    return s.capture_status is not None and s.capture_status.is_failure


def _capture_status_label(s: SiteSummary) -> str:
    """Compact human label for the all-reports table.

    * Healthy → "OK"
    * HTTP 4xx/5xx → "HTTP 418 — I'm a Teapot"
    * Unreachable → "Unreachable"
    """
    if s.capture_status is None:
        return ""
    cs = s.capture_status
    if not cs.is_failure:
        return "OK"
    if cs.http_status is not None:
        return f"HTTP {cs.http_status} — {cs.reason}"
    return cs.reason or "Unreachable"


def _render_status_cell(s: SiteSummary) -> str:
    """HTML cell for the all-reports Status column.

    Failures get a red badge so they stand out at a glance; healthy
    captures get a muted "OK" so the column doesn't visually scream
    at the reader for every row.
    """
    label = _capture_status_label(s)
    if not label:
        return '<span class="muted">—</span>'
    if _is_failed_capture(s):
        return f'<span class="badge badge--high">{html.escape(label)}</span>'
    return f'<span class="badge">{html.escape(label)}</span>'


def _select_rankings(
    summaries: list[SiteSummary],
) -> tuple[list[SiteSummary], list[SiteSummary]]:
    """Pick the Top-N cleanest and Worst-N sites — by composite score.

    The cards must agree with the all-reports list, which ranks by
    ``score.total``; ranking by anything else makes the cards' ends
    contradict the list's ends. ``ranking_weight`` (the finding-count
    heuristic) survives as the tie-breaker — and as the whole ranking
    for legacy datasets where nothing carries a score.

    Excluded from the cards: failed captures (a site that didn't load
    can't be compared) and, when scores exist, unscored rows.
    """
    rankable = [s for s in summaries if not _is_failed_capture(s)]
    scored = [s for s in rankable if s.score is not None]
    if scored:
        # Cleanest first by the displayed integer, then by the exact
        # (un-ceiled) raw total so sites sharing a rounded score rank by
        # their true value rather than alphabetically; ranking_weight /
        # slug remain the final tie-breakers for a genuine exact tie.
        ordered = sorted(
            scored,
            key=lambda s: (
                -s.score.total, -s.score.raw_total, s.ranking_weight, s.slug,
            ),
        )
    else:
        # Legacy unscored dataset: fall back to the weight heuristic.
        ordered = sorted(rankable, key=lambda s: (s.ranking_weight, s.slug))
    best = ordered[:TOP_N]
    worst = list(reversed(ordered[-TOP_N:]))
    return best, worst


def _render_overview_html(
    dataset_name: str, summaries: list[SiteSummary]
) -> str:
    """Render the full overview page as a self-contained HTML string."""
    # Failed captures (HTTP error / unreachable) are listed in the
    # all-reports table but excluded from best/worst ranking cards —
    # a site that didn't load cleanly can't be meaningfully compared
    # against ones that did.
    rankable = [s for s in summaries if not _is_failed_capture(s)]
    failed_count = len(summaries) - len(rankable)
    best, worst = _select_rankings(summaries)
    common_flaws = _aggregate_common_flaws(summaries)
    # Alphabetical feeds _render_full_list as the tie-break order; the
    # renderer itself re-sorts by composite score (best first).
    alphabetical = sorted(summaries, key=lambda s: s.slug)

    parts: list[str] = []
    parts.append(_HTML_HEAD.format(
        title=html.escape(f"{BRANDING_TITLE_PREFIX} — {dataset_name} overview"),
    ))
    parts.append(_render_branding_h1(dataset_name))
    parts.append(_render_overview_intro())
    meta_extra = ""
    if failed_count:
        meta_extra = (
            f' <span class="failed-note">'
            f'{failed_count} failed capture{"s" if failed_count != 1 else ""}'
            f" excluded from rankings (see the all-reports table).</span>"
        )
    parts.append(
        f'<p class="meta">{len(summaries)} site'
        f'{"s" if len(summaries) != 1 else ""} analysed. '
        "Rankings use the composite score (resilience × security × "
        "privacy, 0–100) — the same ordering as the all-reports list; "
        "ties break on weighted finding counts."
        f"{meta_extra}</p>"
    )

    parts.append(_render_score_distribution(summaries))
    parts.append(_render_hosting_sovereignty(summaries))

    parts.append('<div class="grid">')
    parts.append(_render_ranking_card(
        "🏆 Top 3 cleanest", "best", best, lowest_first=True
    ))
    parts.append(_render_ranking_card(
        "🚨 Worst 3", "worst", worst, lowest_first=False
    ))
    parts.append("</div>")

    parts.append("<h2>Most common findings</h2>")
    parts.append(_render_common_flaws_table(common_flaws, total=len(summaries)))

    meta_by_id = _build_module_metadata()
    gov_html = _render_government_section(summaries, meta_by_id)
    if gov_html:
        parts.append("<h2>Government third parties</h2>")
        parts.append(gov_html)
    paragov_html = _render_paragov_section(summaries, meta_by_id)
    if paragov_html:
        parts.append("<h2>Para-governmental third parties</h2>")
        parts.append(paragov_html)

    parts.append("<h2>All reports</h2>")
    parts.append(_render_full_list(alphabetical))

    parts.append("</body></html>")
    return "".join(parts)


def _aggregate_common_flaws(
    summaries: list[SiteSummary],
) -> list[tuple[str, str, int]]:
    """Return ``(severity, headline, count)`` sorted by count desc."""
    counter: Counter[tuple[str, str]] = Counter()
    for summary in summaries:
        # de-dupe per-site so one finding hitting twice in the same
        # report still counts once toward the cross-site frequency.
        for entry in set(summary.finding_headlines):
            counter[entry] += 1
    return [
        (severity, headline, count)
        for (severity, headline), count in counter.most_common(COMMON_FLAWS_N)
    ]


def _histogram_counts(values: list[int]) -> list[int]:
    """Bin a list of 0–100 scores into per-value counts indexed by value.

    Returns a list whose element ``i`` is the number of values equal to
    ``i``, for ``i`` in ``0..max``. Empty bins in between stay zero so the
    result maps one-to-one onto evenly-spaced bars. An empty input yields
    an empty list.
    """
    if not values:
        return []
    counts = [0] * (max(values) + 1)
    for value in values:
        counts[value] += 1
    return counts


def _score_histogram(summaries: list[SiteSummary]) -> list[int]:
    """Per-value counts of the composite total across scored sites.

    Sites without a score (hermetic analyses, failed captures) are
    excluded; an empty list is returned when no site carries a score.
    """
    return _histogram_counts(
        [s.score.total for s in summaries if s.score is not None]
    )


#: The three scoring dimensions, in report column order, with the getter
#: that pulls each one's 0–100 value off a ScoreView and a display label.
_SCORE_DIMENSIONS: tuple[tuple[str, str], ...] = (
    ("resilience", "🛡️ Resilience"),
    ("security", "🔐 Security"),
    ("privacy", "🕶️ Privacy"),
)


def _dimension_histogram(
    summaries: list[SiteSummary], dimension: str
) -> list[int]:
    """Per-value counts of one scoring dimension across scored sites.

    ``dimension`` is ``"resilience"``, ``"security"`` or ``"privacy"``.
    Same exclusions and shape as :func:`_score_histogram`.
    """
    return _histogram_counts([
        getattr(s.score, dimension).stars
        for s in summaries if s.score is not None
    ])


#: Geometry for the inline score-distribution bar chart (user-space units;
#: the SVG scales to its container via viewBox + width:100%).
_HIST_BAR_W = 9          # px per bar (one bar per integer score)
_HIST_GAP = 2            # px between bars
_HIST_PLOT_H = 180       # px plot height (bars)
_HIST_PAD_L = 40         # left padding for the y-axis labels
_HIST_PAD_B = 28         # bottom padding for the x-axis labels
_HIST_PAD_T = 10         # top padding so the tallest bar isn't clipped


#: Gradient stops for the histogram bars, as ``(offset%, hex)`` along the
#: fixed 0–100 score scale: red (bad) → amber → green (good). Literal hex
#: (not ``var()``) because gradient stops must resolve inside the SVG; the
#: values mirror the report's ``--c-*-bd`` severity tokens. The legend's
#: CSS ``linear-gradient`` swatch is kept in sync with these by hand.
_HIST_GRADIENT_STOPS: tuple[tuple[int, str], ...] = (
    (0, "#d63138"),   # --c-bad-bd
    (50, "#b88d2c"),  # --c-warn-bd
    (100, "#2e8550"),  # --c-good-bd
)
#: id of the gradient ``<def>`` referenced by every bar's fill.
_HIST_GRADIENT_ID = "score-hist-grad"


def _render_score_histogram_svg(
    counts: list[int], *, plot_h: int = _HIST_PLOT_H
) -> str:
    """Render a score distribution as a self-contained inline SVG.

    ``counts`` is the :func:`_score_histogram` / :func:`_dimension_histogram`
    output (element ``i`` = sites scoring ``i``). One bar per integer
    score from 0 to the dataset max; bar height is proportional to the
    count, with the peak count labelled on the y-axis and x-ticks every
    10 points. ``plot_h`` sets the plot (bar) height in user units — the
    composite chart uses the default; the per-dimension minis pass a
    smaller value. Bars are filled from a red→amber→green gradient
    anchored to the fixed 0–100 scale, so a given score keeps the same
    hue across datasets. Returns an empty string when there is nothing to
    plot, so the caller can skip the whole section.
    """
    if not counts:
        return ""
    peak = max(counts)
    if peak == 0:
        return ""
    n = len(counts)  # scores 0..n-1
    step = _HIST_BAR_W + _HIST_GAP
    plot_w = n * step
    width = _HIST_PAD_L + plot_w
    height = _HIST_PAD_T + plot_h + _HIST_PAD_B
    baseline = _HIST_PAD_T + plot_h

    # Gradient spans score 0..100 in user space (not 0..max), so the hue
    # at any bar reflects its absolute score, comparable across datasets.
    grad_x1 = _HIST_PAD_L
    grad_x2 = _HIST_PAD_L + 100 * step
    stops = "".join(
        f'<stop offset="{off}%" stop-color="{color}"/>'
        for off, color in _HIST_GRADIENT_STOPS
    )
    parts: list[str] = [
        f'<svg class="score-hist" viewBox="0 0 {width} {height}" '
        f'role="img" width="100%" '
        f'aria-label="Distribution of composite scores across the dataset">',
        f'<defs><linearGradient id="{_HIST_GRADIENT_ID}" '
        f'gradientUnits="userSpaceOnUse" '
        f'x1="{grad_x1}" y1="0" x2="{grad_x2}" y2="0">{stops}'
        f"</linearGradient></defs>",
    ]
    # y-axis: a baseline rule plus the peak-count tick at the top.
    parts.append(
        f'<line x1="{_HIST_PAD_L}" y1="{baseline}" x2="{width}" '
        f'y2="{baseline}" class="hist-axis"/>'
    )
    parts.append(
        f'<line x1="{_HIST_PAD_L}" y1="{_HIST_PAD_T}" x2="{_HIST_PAD_L}" '
        f'y2="{baseline}" class="hist-axis"/>'
    )
    parts.append(
        f'<text x="{_HIST_PAD_L - 5}" y="{_HIST_PAD_T + 4}" '
        f'class="hist-ylabel">{peak}</text>'
    )
    parts.append(
        f'<text x="{_HIST_PAD_L - 5}" y="{baseline}" '
        f'class="hist-ylabel">0</text>'
    )
    # Bars + x-ticks (every 10 points, plus the final max).
    for score, count in enumerate(counts):
        x = _HIST_PAD_L + score * step
        if count:
            bar_h = count / peak * plot_h
            y = baseline - bar_h
            parts.append(
                f'<rect x="{x}" y="{y:.1f}" width="{_HIST_BAR_W}" '
                f'height="{bar_h:.1f}" fill="url(#{_HIST_GRADIENT_ID})">'
                f"<title>score {score}: {count} site"
                f'{"s" if count != 1 else ""}</title></rect>'
            )
        if score % 10 == 0 or score == n - 1:
            parts.append(
                f'<text x="{x + _HIST_BAR_W / 2:.1f}" y="{baseline + 16}" '
                f'class="hist-xlabel">{score}</text>'
            )
    parts.append("</svg>")
    return "".join(parts)


#: Plot height (user units) for the compact per-dimension mini-charts.
_HIST_DIM_PLOT_H = 96


def _render_score_distribution(summaries: list[SiteSummary]) -> str:
    """Render the "Score distribution" section, or "" when no scores exist.

    Leads with the composite-total chart, then a per-dimension row of
    three minis (resilience / security / privacy) so a reader can see
    which axis pulls the dataset down. Each chart shares the same
    0–100-anchored red→amber→green gradient.
    """
    total_svg = _render_score_histogram_svg(_score_histogram(summaries))
    if not total_svg:
        return ""

    dim_blocks: list[str] = []
    for dimension, label in _SCORE_DIMENSIONS:
        svg = _render_score_histogram_svg(
            _dimension_histogram(summaries, dimension),
            plot_h=_HIST_DIM_PLOT_H,
        )
        if not svg:
            continue
        dim_blocks.append(
            '<div class="hist-dim">'
            f"<h4>{label}</h4>"
            f'<div class="hist-wrap">{svg}</div>'
            "</div>"
        )

    dims_html = ""
    if dim_blocks:
        dims_html = (
            "<h3>By dimension</h3>"
            f'<div class="hist-dims">{"".join(dim_blocks)}</div>'
        )

    return (
        "<h2>Score distribution</h2>"
        '<p class="meta">Number of sites at each composite total score '
        "(0–100), coloured low&#8201;→&#8201;high: "
        '<span class="hist-legend">'
        '<span>0</span><span class="hist-legend-bar"></span><span>100</span>'
        "</span>.</p>"
        f'<div class="hist-wrap">{total_svg}</div>'
        f"{dims_html}"
    )


# --- hosting sovereignty ---------------------------------------------------
#
# Where each site's first-party hosting physically resolves (the
# ``country_code`` of its first IP, MaxMind geolocation) and on whose
# infrastructure (the ASN org, collapsed to a friendly provider label).
# The whole tool is about data sovereignty, so the headline reader wants
# is "how much of this public-sector estate sits outside the EU".


def _provider_label(info: IPInfo) -> str:
    """Friendly provider name for an IP, or "" when the org is unknown.

    Mirrors :func:`_format_first_party_ip` / :func:`_hosting_payload`:
    the AS-org collapsed via :func:`asn_to_provider`, falling back to the
    raw org string.
    """
    if not info.as_org:
        return ""
    return asn_to_provider(info.as_org) or info.as_org


def _hosting_country_counts(
    summaries: list[SiteSummary],
) -> list[tuple[str, int]]:
    """Count sites per first-party hosting country, most-hosted first.

    Only sites whose first IP has a known ``country_code`` are counted;
    ties break alphabetically by country code.
    """
    counter: Counter[str] = Counter()
    for s in summaries:
        ip = s.first_party_ip
        if ip is not None and ip.country_code:
            counter[ip.country_code] += 1
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))


def _hosting_provider_counts(
    summaries: list[SiteSummary],
) -> list[tuple[str, int]]:
    """Count sites per first-party hosting provider, most-hosted first.

    Sites whose first IP carries no AS-org are skipped; ties break
    alphabetically by provider label.
    """
    counter: Counter[str] = Counter()
    for s in summaries:
        ip = s.first_party_ip
        if ip is None:
            continue
        label = _provider_label(ip)
        if label:
            counter[label] += 1
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))


def _hosting_eu_split(summaries: list[SiteSummary]) -> tuple[int, int, int]:
    """Return ``(eu, non_eu, unknown)`` site counts by hosting jurisdiction.

    Classification is by physical ``country_code`` against
    :data:`EU_MEMBERS`. Sites with no first IP or no known country count
    as ``unknown``.
    """
    eu = non_eu = unknown = 0
    for s in summaries:
        ip = s.first_party_ip
        if ip is None or not ip.country_code:
            unknown += 1
        elif ip.country_code in EU_MEMBERS:
            eu += 1
        else:
            non_eu += 1
    return eu, non_eu, unknown


#: How many hosting providers to list before collapsing the tail.
_HOSTING_PROVIDER_TOP_N = 12


def _render_hbar_rows(
    items: list[tuple[str, int]], *, color_class_of=None
) -> str:
    """Render a labelled horizontal-bar list (one ``<div class="hbar">`` per row).

    Bar width is the count as a percentage of the largest count.
    ``color_class_of`` optionally maps a row label to a CSS modifier
    class for the bar fill (used to tint countries by EU membership);
    when ``None`` the neutral bar colour applies.
    """
    if not items:
        return ""
    top = max(count for _, count in items) or 1
    rows: list[str] = []
    for label, count in items:
        width = count / top * 100.0
        modifier = ""
        if color_class_of is not None:
            mod = color_class_of(label)
            modifier = f" hbar-fill--{mod}" if mod else ""
        esc = html.escape(label)
        rows.append(
            '<div class="hbar">'
            f'<span class="hbar-label" title="{esc}">{esc}</span>'
            '<span class="hbar-track">'
            f'<span class="hbar-fill{modifier}" style="width:{width:.1f}%">'
            "</span></span>"
            f'<span class="hbar-num">{count}</span>'
            "</div>"
        )
    return "".join(rows)


def _eu_membership_class(country_code: str) -> str:
    """CSS modifier for a country bar — ``good`` if EU, else ``bad``."""
    return "good" if country_code in EU_MEMBERS else "bad"


def _render_hosting_sovereignty(summaries: list[SiteSummary]) -> str:
    """Render the "Hosting sovereignty" section, or "" when no hosting data.

    A headline EU / non-EU / unknown split, then two horizontal-bar
    lists: sites per hosting country (tinted by EU membership) and sites
    per hosting provider (top N, with the tail collapsed).
    """
    countries = _hosting_country_counts(summaries)
    providers = _hosting_provider_counts(summaries)
    if not countries and not providers:
        return ""

    eu, non_eu, unknown = _hosting_eu_split(summaries)
    known = eu + non_eu
    eu_pct = (eu / known * 100.0) if known else 0.0

    # Collapse the provider tail so the list stays scannable.
    shown = providers[:_HOSTING_PROVIDER_TOP_N]
    tail = providers[_HOSTING_PROVIDER_TOP_N:]
    if tail:
        shown = shown + [("Other", sum(c for _, c in tail))]

    parts = [
        "<h2>Hosting sovereignty</h2>",
        '<p class="meta">Where each site\'s first-party hosting physically '
        "resolves (country / ASN of its first IP). "
        f"<strong>{eu}</strong> of {known} sites with known hosting "
        f"({eu_pct:.0f}%) are in the EU; "
        f"<strong>{non_eu}</strong> are outside it"
        + (f"; {unknown} unknown" if unknown else "")
        + ".</p>",
        "<h3>By country</h3>",
        '<div class="hbars">'
        + _render_hbar_rows(countries, color_class_of=_eu_membership_class)
        + "</div>",
        "<h3>By provider</h3>",
        '<div class="hbars hbars--wide">'
        + _render_hbar_rows(shown)
        + "</div>",
    ]
    return "".join(parts)


def _render_ranking_card(
    title: str,
    css_class: str,
    rows: list[SiteSummary],
    *,
    lowest_first: bool,
) -> str:
    """Render one of the best/worst ranking cards."""
    if not rows:
        return (
            f'<section class="card {css_class}"><h2>{html.escape(title)}</h2>'
            "<p>(none)</p></section>"
        )
    items: list[str] = []
    for rank, row in enumerate(rows, start=1):
        score_bit = (
            f"<strong>{row.score.total}</strong>/100 · "
            if row.score is not None else ""
        )
        items.append(
            "<li>"
            f'<span class="rank">#{rank}</span>'
            f'<a href="{html.escape(row.report_filename)}">'
            f"{html.escape(row.slug)}</a>"
            f'<div class="metrics">'
            f"{score_bit}"
            f"🔴 {row.high_finding_count} high · "
            f"🟡 {row.medium_finding_count} medium · "
            f"{row.trackers_fired} trackers · "
            f"{row.third_party_hosts_touched} 3p hosts"
            "</div>"
            "</li>"
        )
    direction = (
        "composite score, cleanest first"
        if lowest_first else "composite score, worst first"
    )
    return (
        f'<section class="card {css_class}">'
        f"<h2>{html.escape(title)}</h2>"
        f'<ol class="ranking">{"".join(items)}</ol>'
        f'<p class="hint">Sorted by {direction} — same ordering as the '
        "all-reports list.</p>"
        "</section>"
    )


def _render_common_flaws_table(
    flaws: list[tuple[str, str, int]], *, total: int
) -> str:
    """Render the cross-site finding-frequency table."""
    if not flaws:
        return "<p>No findings recorded.</p>"
    rows: list[str] = []
    for severity, headline, count in flaws:
        pct = (count / total * 100.0) if total else 0.0
        rows.append(
            "<tr>"
            f'<td class="sev">{_SEVERITY_BADGE.get(severity, "·")} '
            f"{html.escape(severity)}</td>"
            f"<td>{html.escape(headline)}</td>"
            f'<td class="num">{count}</td>'
            f'<td class="num">{pct:.0f}%</td>'
            "</tr>"
        )
    return (
        '<table class="flaws">'
        "<thead><tr><th>Severity</th><th>Finding</th>"
        "<th>Sites</th><th>%</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
    )


def _government_reach(
    summaries: list[SiteSummary],
) -> tuple[dict[str, set[str]], dict[str, Counter[str]]]:
    """Aggregate government third-party reach across the dataset.

    Returns ``(sites_per_level, hosts_per_level)``: for each
    ``government_level``, the set of site slugs that touched it and a
    ``Counter`` mapping each contacted host to the number of sites that
    reached it. Shared by the HTML and JSON overview renderers.
    """
    sites_per_level: dict[str, set[str]] = {}
    hosts_per_level: dict[str, Counter[str]] = {}
    for summary in summaries:
        for level, hosts in summary.gov_hosts_by_level.items():
            if not hosts:
                continue
            sites_per_level.setdefault(level, set()).add(summary.slug)
            counter = hosts_per_level.setdefault(level, Counter())
            for host in hosts:
                counter[host] += 1
    return sites_per_level, hosts_per_level


def _paragov_reach(
    summaries: list[SiteSummary],
) -> tuple[dict[str, set[str]], dict[str, Counter[str]]]:
    """Aggregate para-governmental reach across the dataset.

    Returns ``(sites_per_vendor, hosts_per_vendor)`` with the same shape
    as :func:`_government_reach`, keyed by vendor. Shared by the HTML and
    JSON overview renderers.
    """
    sites_per_vendor: dict[str, set[str]] = {}
    hosts_per_vendor: dict[str, Counter[str]] = {}
    for summary in summaries:
        for vendor, hosts in summary.paragov_hosts_by_vendor.items():
            if not hosts:
                continue
            sites_per_vendor.setdefault(vendor, set()).add(summary.slug)
            counter = hosts_per_vendor.setdefault(vendor, Counter())
            for host in hosts:
                counter[host] += 1
    return sites_per_vendor, hosts_per_vendor


def _render_government_section(
    summaries: list[SiteSummary], meta_by_id: dict[str, TrackerModule]
) -> str:
    """Render one row per government level showing reach across the dataset.

    Returns an empty string when no government third-party hits were
    seen — the caller skips the whole section so the page isn't padded
    with empty placeholders.
    """
    sites_per_level, hosts_per_level = _government_reach(summaries)
    if not sites_per_level:
        return ""

    level_labels = _level_labels_from_modules(meta_by_id)
    rows: list[str] = []
    for level in _GOV_LEVEL_ORDER:
        sites = sites_per_level.get(level)
        if not sites:
            continue
        label = level_labels.get(level, level)
        host_counter = hosts_per_level.get(level, Counter())
        rows.append(_render_public_sector_row(
            label=label,
            sub_label=level,
            site_count=len(sites),
            hosts=host_counter,
            total_sites=len(summaries),
        ))
    if not rows:
        return ""
    return (
        '<table class="public-sector">'
        "<thead><tr><th>Government level</th><th>Sites</th>"
        "<th>Hosts touched (sites)</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
    )


def _render_paragov_section(
    summaries: list[SiteSummary], meta_by_id: dict[str, TrackerModule]
) -> str:
    """Render one row per para-governmental entity showing reach across the dataset."""
    sites_per_vendor, hosts_per_vendor = _paragov_reach(summaries)
    if not sites_per_vendor:
        return ""

    # Sort vendors by reach (sites) descending — most-impactful first.
    ordered = sorted(
        sites_per_vendor.items(),
        key=lambda kv: (-len(kv[1]), kv[0]),
    )
    rows: list[str] = []
    for vendor, sites in ordered:
        host_counter = hosts_per_vendor[vendor]
        rows.append(_render_public_sector_row(
            label=vendor,
            sub_label="",
            site_count=len(sites),
            hosts=host_counter,
            total_sites=len(summaries),
        ))
    return (
        '<table class="public-sector">'
        "<thead><tr><th>Entity</th><th>Sites</th>"
        "<th>Hosts touched (sites)</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody>"
        "</table>"
    )


def _render_public_sector_row(
    *,
    label: str,
    sub_label: str,
    site_count: int,
    hosts: Counter[str],
    total_sites: int,
) -> str:
    """Render one ``<tr>`` for a gov / paragov entity's reach."""
    top_hosts = hosts.most_common(PUBLIC_SECTOR_TOP_HOSTS)
    rendered_hosts = ", ".join(
        f"<code>{html.escape(host)}</code> ({n})" for host, n in top_hosts
    )
    if len(hosts) > PUBLIC_SECTOR_TOP_HOSTS:
        rendered_hosts += f" + {len(hosts) - PUBLIC_SECTOR_TOP_HOSTS} more"
    pct = (site_count / total_sites * 100.0) if total_sites else 0.0
    sub = (
        f' <span class="sub">{html.escape(sub_label)}</span>'
        if sub_label else ""
    )
    return (
        "<tr>"
        f"<td>{html.escape(label)}{sub}</td>"
        f'<td class="num">{site_count} ({pct:.0f}%)</td>'
        f'<td class="hosts">{rendered_hosts}</td>'
        "</tr>"
    )


def _level_labels_from_modules(
    meta_by_id: dict[str, TrackerModule]
) -> dict[str, str]:
    """Map ``government_level`` → display name pulled from each module's identity."""
    labels: dict[str, str] = {}
    for module in meta_by_id.values():
        if module.module_kind == MODULE_KIND_GOVERNMENT and module.government_level:
            labels[module.government_level] = module.module_name
    return labels


def _score_cells(score: ScoreView | None) -> str:
    """Render the four leading TOT / RES / SEC / PRIV ``<td>`` cells.

    Unscored rows (hermetic analysis, failed capture) get em-dashes
    rather than zeroes — the site has no score, not a score of 0.
    """
    if score is None:
        dash = '<td class="num"><span class="muted">—</span></td>'
        return dash * 4
    return (
        f'<td class="num">{score.total}</td>'
        f'<td class="num">{format_stars(score.resilience.stars)}</td>'
        f'<td class="num">{format_stars(score.security.stars)}</td>'
        f'<td class="num">{format_stars(score.privacy.stars)}</td>'
    )


def _full_list_order(rows: list[SiteSummary]) -> list[SiteSummary]:
    """Rank the site list by composite score (best first).

    Scored rows sort by the displayed total descending, then by the exact
    (un-ceiled) raw total so sites sharing a rounded score order by their
    true value; unscored rows (``score is None`` — hermetic analyses and
    failed captures) sink to the bottom. The sort is stable, so a genuine
    raw-value tie and the unscored block keep the caller's (alphabetical)
    order. Shared by the HTML and JSON overview renderers.
    """
    return sorted(
        rows,
        key=lambda s: (
            (-1, -1.0) if s.score is None
            else (s.score.total, s.score.raw_total)
        ),
        reverse=True,
    )


def _render_full_list(rows: list[SiteSummary]) -> str:
    """Render the full site list, ranked by composite score (best first)."""
    ranked = _full_list_order(rows)
    items: list[str] = []
    for row in ranked:
        failed = _is_failed_capture(row)
        status_cell_html = _render_status_cell(row)
        row_class = ' class="failed"' if failed else ""
        if row.report_filename:
            slug_cell = (
                f'<a href="{html.escape(row.report_filename)}">'
                f"{html.escape(row.slug)}</a>"
            )
        else:
            # Synthetic row — no per-site report exists to link to.
            slug_cell = (
                f'<span title="No capture written">{html.escape(row.slug)}</span>'
            )
        items.append(
            f"<tr{row_class}>"
            f"{_score_cells(row.score)}"
            f"<td>{slug_cell}</td>"
            f"<td>{status_cell_html}</td>"
            f'<td class="hosting">{_format_first_party_ip(row.first_party_ip)}</td>'
            f'<td class="platform">{_format_platform_cell(row.cms_fingerprint)}</td>'
            f'<td class="num">{row.high_finding_count}</td>'
            f'<td class="num">{row.medium_finding_count}</td>'
            f'<td class="num">{row.trackers_fired}</td>'
            f'<td class="num">{row.third_party_hosts_touched}</td>'
            "</tr>"
        )
    return (
        '<table class="full">'
        "<thead><tr>"
        "<th>TOT</th><th>🛡️ RES</th><th>🔐 SEC</th><th>🕶️ PRIV</th>"
        "<th>Site</th><th>Status</th><th>Hosting (ASN / country)</th>"
        "<th>Platform</th>"
        "<th>🔴 high</th><th>🟡 medium</th>"
        "<th>Trackers</th><th>3p hosts</th></tr></thead>"
        f"<tbody>{''.join(items)}</tbody>"
        "</table>"
    )


def _format_platform_cell(fp) -> str:
    """Render the CMS / version / EOL state for one row of the full-list table.

    No fingerprint → em-dash so the column reads consistently. Past-EOL
    versions get a small red ``EOL`` badge so a scanner of the table
    can spot them at a glance.
    """
    if fp is None:
        return '<span class="muted">—</span>'
    name = html.escape(fp.name)
    version = f' <span class="ver">{html.escape(fp.version)}</span>' if fp.version else ""
    eol_badge = ' <span class="badge badge--strong">EOL</span>' if fp.is_eol else ""
    return f"{name}{version}{eol_badge}"


def _format_first_party_ip(info: IPInfo | None) -> str:
    """Render an :class:`IPInfo` as ``AS<n> <provider> (<cc>)``.

    Uses :func:`asn_to_provider` to collapse raw AS-org strings to a
    friendlier label (Cloudflare, AWS, Hetzner Online, …); falls back
    to the raw AS-org when no fingerprint matches. Missing fields are
    dropped rather than rendered as ``?`` — matches the dns_posture
    pattern of staying silent when data is missing.
    """
    if info is None:
        return '<span class="muted">—</span>'
    parts: list[str] = []
    if info.asn is not None:
        parts.append(f"AS{info.asn}")
    if info.as_org:
        parts.append(html.escape(asn_to_provider(info.as_org) or info.as_org))
    if info.country_code:
        parts.append(f"({html.escape(info.country_code)})")
    if not parts:
        return '<span class="muted">—</span>'
    return " ".join(parts)


# --- JSON rendering --------------------------------------------------------


def _pct(part: int, total: int) -> float:
    """Percentage of ``total`` represented by ``part``, rounded to 1 dp."""
    return round(part / total * 100.0, 1) if total else 0.0


def _score_payload(score: ScoreView | None) -> dict[str, int] | None:
    """Serialize a :class:`ScoreView` to its composite + dimension values."""
    if score is None:
        return None
    return {
        "total": score.total,
        "resilience": score.resilience.stars,
        "security": score.security.stars,
        "privacy": score.privacy.stars,
    }


def _hosting_payload(info: IPInfo | None) -> dict[str, object] | None:
    """Serialize first-party hosting as ``{asn, provider, country}``.

    Mirrors :func:`_format_first_party_ip` — the provider is the friendly
    label from :func:`asn_to_provider`, falling back to the raw AS-org.
    """
    if info is None:
        return None
    provider = (
        (asn_to_provider(info.as_org) or info.as_org) if info.as_org else None
    )
    return {
        "asn": info.asn,
        "provider": provider,
        "country": info.country_code or None,
    }


def _platform_payload(fp) -> dict[str, object] | None:
    """Serialize a CMS fingerprint as ``{name, version, is_eol}``."""
    if fp is None:
        return None
    return {
        "name": fp.name,
        "version": fp.version or None,
        "is_eol": bool(fp.is_eol),
    }


def _hosts_payload(hosts: Counter[str]) -> list[dict[str, object]]:
    """Serialize a host→site-count counter, most-reached host first.

    Unlike the HTML table this carries every host (no top-N truncation):
    the JSON overview is machine-readable, so it stays data-complete.
    """
    return [
        {"host": host, "sites": count}
        for host, count in sorted(hosts.items(), key=lambda kv: (-kv[1], kv[0]))
    ]


def _ranking_row_payload(rank: int, row: SiteSummary) -> dict[str, object]:
    """Serialize one best/worst ranking entry."""
    return {
        "rank": rank,
        "slug": row.slug,
        "report": row.report_filename or None,
        "score_total": row.score.total if row.score is not None else None,
        "high_findings": row.high_finding_count,
        "medium_findings": row.medium_finding_count,
        "trackers_fired": row.trackers_fired,
        "third_party_hosts": row.third_party_hosts_touched,
    }


def _site_payload(row: SiteSummary) -> dict[str, object]:
    """Serialize one full-list site row."""
    return {
        "slug": row.slug,
        "report": row.report_filename or None,
        "target_url": row.target_url,
        "landing_url": row.landing_url,
        "score": _score_payload(row.score),
        "status": _capture_status_label(row) or None,
        "is_failure": _is_failed_capture(row),
        "hosting": _hosting_payload(row.first_party_ip),
        "platform": _platform_payload(row.cms_fingerprint),
        "high_findings": row.high_finding_count,
        "medium_findings": row.medium_finding_count,
        "low_findings": row.low_finding_count,
        "trackers_fired": row.trackers_fired,
        "third_party_hosts": row.third_party_hosts_touched,
    }


def _government_payload(
    summaries: list[SiteSummary], meta_by_id: dict[str, TrackerModule]
) -> list[dict[str, object]]:
    """Serialize government third-party reach, ordered by geographic scope."""
    sites_per_level, hosts_per_level = _government_reach(summaries)
    if not sites_per_level:
        return []
    labels = _level_labels_from_modules(meta_by_id)
    total = len(summaries)
    out: list[dict[str, object]] = []
    for level in _GOV_LEVEL_ORDER:
        sites = sites_per_level.get(level)
        if not sites:
            continue
        out.append({
            "level": level,
            "label": labels.get(level, level),
            "sites": len(sites),
            "pct": _pct(len(sites), total),
            "hosts": _hosts_payload(hosts_per_level.get(level, Counter())),
        })
    return out


def _paragov_payload(
    summaries: list[SiteSummary],
) -> list[dict[str, object]]:
    """Serialize para-governmental reach, most-reaching vendor first."""
    sites_per_vendor, hosts_per_vendor = _paragov_reach(summaries)
    if not sites_per_vendor:
        return []
    total = len(summaries)
    ordered = sorted(
        sites_per_vendor.items(), key=lambda kv: (-len(kv[1]), kv[0])
    )
    return [
        {
            "vendor": vendor,
            "sites": len(sites),
            "pct": _pct(len(sites), total),
            "hosts": _hosts_payload(hosts_per_vendor[vendor]),
        }
        for vendor, sites in ordered
    ]


def _render_overview_json(
    dataset_name: str, summaries: list[SiteSummary]
) -> str:
    """Render the dataset overview as a structured ``index.json`` string.

    Carries the same information the HTML overview shows — dataset name,
    site counts, best/worst rankings, cross-site common findings,
    government / para-gov reach, and the full per-site list ordered by
    composite score — but machine-readable for downstream pipelines.
    """
    total = len(summaries)
    rankable = [s for s in summaries if not _is_failed_capture(s)]
    best, worst = _select_rankings(summaries)
    meta_by_id = _build_module_metadata()
    ordered = _full_list_order(sorted(summaries, key=lambda s: s.slug))
    payload = {
        "dataset": dataset_name,
        "site_count": total,
        "failed_capture_count": total - len(rankable),
        "rankings": {
            "cleanest": [
                _ranking_row_payload(rank, row)
                for rank, row in enumerate(best, start=1)
            ],
            "worst": [
                _ranking_row_payload(rank, row)
                for rank, row in enumerate(worst, start=1)
            ],
        },
        "common_findings": [
            {
                "severity": severity,
                "headline": headline,
                "sites": count,
                "pct": _pct(count, total),
            }
            for severity, headline, count in _aggregate_common_flaws(summaries)
        ],
        "government_third_parties": _government_payload(summaries, meta_by_id),
        "paragov_third_parties": _paragov_payload(summaries),
        "sites": [_site_payload(row) for row in ordered],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


_HTML_HEAD = """<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<title>{title}</title>
<style>
  /* Design tokens — kept in sync with leak_inspector/report/html.py so the
     bulk overview shares the per-site report's palette. */
  :root {{
    --c-bad-bg:  #fde2e1; --c-bad-bd:  #d63138; --c-bad-fg:  #842029;
    --c-warn-bg: #fff3cd; --c-warn-bd: #b88d2c; --c-warn-fg: #664d03;
    --c-good-bg: #d1e7dd; --c-good-bd: #2e8550; --c-good-fg: #0f5132;
    --c-info-bg: #cfe2ff; --c-info-bd: #4a90c1; --c-info-fg: #084298;
    --c-muted-fg: #888; --c-chip-bg: #eee;
  }}

  /* Defensive: every <img> in the report stays inside its container. */
  img {{ max-width: 100%; height: auto; }}

  body {{ font-family: -apple-system, system-ui, "Segoe UI", sans-serif;
         margin: 2em auto; max-width: 1100px; padding: 0 1em;
         color: #222; background: #fafafa; line-height: 1.45; }}
  h1 {{ margin-bottom: 0.2em; }}
  h1.report-title {{ display: flex; align-items: center; gap: 0.5em;
                     flex-wrap: wrap; font-size: 1.4em; }}
  h1.report-title a {{ color: inherit; text-decoration: none; }}
  h1.report-title .belibre-link {{ text-decoration: none; }}
  h1.report-title .belibre-logo {{ height: 32px; width: auto;
                                   vertical-align: middle; border: none; }}
  section.report-intro {{ margin: 1em 0 1.5em; padding: 0.85em 1.25em;
                          background: #f0f6fb; border-left: 4px solid var(--c-info-bd);
                          border-radius: 0 3px 3px 0;
                          font-size: 0.92em; line-height: 1.5; }}
  section.report-intro h2 {{ font-size: 1em; margin: 0 0 0.4em;
                             color: var(--c-info-fg); text-transform: uppercase;
                             letter-spacing: 0.5px; border-bottom: none;
                             padding-bottom: 0; }}
  section.report-intro p {{ margin: 0.4em 0; }}
  section.report-intro p:first-of-type {{ margin-top: 0; }}
  section.report-intro p:last-of-type  {{ margin-bottom: 0; }}
  section.report-intro a {{ color: var(--c-info-fg); }}

  /* Shared badge component — same shape as per-site reports. */
  .badge {{ display: inline-block; padding: 1px 7px; border-radius: 3px;
            font-size: 0.72em; font-weight: 700; letter-spacing: 0.3px;
            background: var(--c-chip-bg); color: #555; white-space: nowrap; }}
  .badge--high   {{ background: var(--c-bad-bg);  color: var(--c-bad-fg);  }}
  .badge--medium {{ background: var(--c-warn-bg); color: var(--c-warn-fg); }}
  .badge--low    {{ background: var(--c-good-bg); color: var(--c-good-fg); }}
  .badge--info   {{ background: var(--c-info-bg); color: var(--c-info-fg); }}
  .badge--strong {{ background: var(--c-bad-fg);  color: #fff; }}
  h2 {{ margin-top: 2em; border-bottom: 1px solid #ddd; padding-bottom: 0.2em; }}
  p.meta {{ color: #666; margin-top: 0; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1em;
           margin-top: 1.5em; }}
  .card {{ background: #fff; border: 1px solid #ddd; border-radius: 6px;
           padding: 1em 1.2em; }}
  .card.best {{ border-left: 4px solid #2a8f3c; }}
  .card.worst {{ border-left: 4px solid #c0392b; }}
  ol.ranking {{ list-style: none; padding: 0; margin: 0; }}
  ol.ranking li {{ padding: 0.5em 0; border-bottom: 1px solid #eee; }}
  ol.ranking li:last-child {{ border-bottom: none; }}
  ol.ranking .rank {{ display: inline-block; width: 2.2em;
                      color: #999; font-weight: bold; }}
  ol.ranking .metrics {{ color: #666; font-size: 0.85em;
                         margin-left: 2.2em; margin-top: 0.15em; }}
  .hint {{ color: #888; font-size: 0.8em; margin: 0.6em 0 0 0; }}
  table {{ border-collapse: collapse; width: 100%; background: #fff;
           margin-top: 0.5em; }}
  th, td {{ padding: 0.4em 0.6em; border-bottom: 1px solid #eee;
            text-align: left; vertical-align: top; }}
  th {{ background: #f0f0f0; }}
  td.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
  td.sev {{ white-space: nowrap; }}
  table.flaws td:nth-child(2) {{ width: 100%; }}
  table.full td.hosting {{ font-size: 0.85em; color: #555;
                           white-space: nowrap; }}
  table.full td.platform {{ font-size: 0.88em; color: #333;
                            white-space: nowrap; }}
  table.full td.platform .ver {{ font-family: ui-monospace, monospace;
                                 background: #f0f0f0; padding: 0 0.3em;
                                 border-radius: 2px; color: #444; }}
  table.full tr.failed td:nth-child(n+8) {{ color: #aaa; }}
  /* Capture-status indicator + EOL marker now use the shared .badge
     component (--strong for EOL, default for OK, --high for failure). */
  .failed-note {{ color: var(--c-bad-fg); font-weight: 500; }}
  .muted {{ color: #bbb; }}
  table.public-sector td.hosts {{ font-size: 0.88em; color: #444; }}
  table.public-sector td.hosts code {{ background: #f4f4f4; padding: 0 0.3em;
                                       border-radius: 3px; }}
  .sub {{ display: inline-block; margin-left: 0.5em; color: #888;
          font-size: 0.8em; }}
  /* Score-distribution histogram. The SVG scales to the wrapper, which
     scrolls horizontally on narrow viewports so bars never squash. */
  .hist-wrap {{ overflow-x: auto; background: #fff; border: 1px solid #ddd;
                border-radius: 6px; padding: 0.6em 0.8em; }}
  svg.score-hist {{ display: block; min-width: 480px; }}
  svg.score-hist .hist-axis {{ stroke: #bbb; stroke-width: 1; }}
  svg.score-hist .hist-ylabel {{ fill: #666; font-size: 11px;
                                 text-anchor: end; }}
  svg.score-hist .hist-xlabel {{ fill: #666; font-size: 11px;
                                 text-anchor: middle; }}
  /* Legend: a small gradient swatch matching the bars' red→amber→green
     fill (kept in sync with _HIST_GRADIENT_STOPS by hand). */
  .hist-legend {{ display: inline-flex; align-items: center; gap: 0.4em;
                  vertical-align: middle; }}
  .hist-legend-bar {{ display: inline-block; width: 90px; height: 0.7em;
                      border-radius: 2px;
                      background: linear-gradient(to right,
                        #d63138, #b88d2c, #2e8550); }}
  /* Per-dimension mini-charts: stacked full-width, each captioned. */
  .hist-dims {{ display: flex; flex-direction: column; gap: 0.4em; }}
  .hist-dim h4 {{ margin: 0.6em 0 0.2em; font-size: 0.95em; color: #444; }}
  /* Hosting-sovereignty horizontal bars. */
  .hbars {{ display: flex; flex-direction: column; gap: 0.25em;
            margin-top: 0.4em; }}
  .hbar {{ display: grid; grid-template-columns: 3.5em 1fr 2.5em;
           align-items: center; gap: 0.6em; }}
  /* Provider labels are long AS-org strings — give them a wide, left-
     aligned column so they read on one line instead of wrapping. */
  .hbars--wide .hbar {{ grid-template-columns: 14em 1fr 2.5em; }}
  .hbars--wide .hbar-label {{ text-align: left; white-space: nowrap;
                              overflow: hidden; text-overflow: ellipsis; }}
  .hbar-label {{ font-size: 0.85em; color: #444; text-align: right;
                 font-variant-numeric: tabular-nums; }}
  .hbar-track {{ background: #eee; border-radius: 3px; height: 1.1em; }}
  .hbar-fill {{ display: block; height: 100%; border-radius: 3px;
                background: var(--c-info-bd); min-width: 2px; }}
  .hbar-fill--good {{ background: var(--c-good-bd); }}
  .hbar-fill--bad  {{ background: var(--c-bad-bd); }}
  .hbar-num {{ font-size: 0.85em; color: #666; text-align: right;
               font-variant-numeric: tabular-nums; }}
  a {{ color: #1a5fb4; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  @media (max-width: 720px) {{ .grid {{ grid-template-columns: 1fr; }} }}
</style>
</head><body>
"""


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Parse the standalone overview CLI arguments."""
    parser = argparse.ArgumentParser(
        prog="bulk-tool-overview",
        description=(
            "Rebuild the index.html overview for a bulk-tool dataset by "
            "re-analysing every capture bundle in <dataset>/captures/."
        ),
    )
    parser.add_argument(
        "dataset_dir",
        type=Path,
        help=(
            "path to the dataset folder (must contain captures/ and "
            "reports/ produced by run.py)."
        ),
    )
    parser.add_argument(
        "--format",
        choices=("html", "json"),
        default="html",
        help=(
            "which per-site reports to link and how to emit the overview. "
            "'html' (default) links <slug>.report.html / .report.md and "
            "writes index.html. 'json' links the structured "
            "<slug>.report.json documents and writes a machine-readable "
            "index.json. Must match the --format the dataset was captured "
            "with."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Standalone entry point. Returns a process exit code."""
    args = _parse_args(argv)
    dataset_dir: Path = args.dataset_dir.resolve()
    result = build_overview(dataset_dir, report_format=args.format)
    return 0 if result is not None else 2


if __name__ == "__main__":  # pragma: no cover -- module-script form
    sys.exit(main())
