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

"""Merge findings by WCAG criterion and render them in four formats.

Pure module: it consumes :class:`~.core.Finding` lists plus the criteria
registry (and the optional per-page reading views from :mod:`.text_view`,
embedded as a *Reading view* section) and returns strings. It never
touches the network, the driver, or the filesystem — the CLI/session
layer decides where to write the output.

The flow is build-once, render-many. :func:`build_report` folds the flat
finding list into a :class:`ReportDocument` (findings grouped by
criterion + a registry-derived :class:`CoverageSummary`); the four
``render_*`` functions turn that same document into JSON (the canonical
``results.json``), plain text, Markdown, and a self-contained HTML page.

Honesty (see :mod:`.core`): the report never asserts that a criterion
passed. It shows the automated findings, states how much of WCAG 2.2 AA
is even automatable, and repeats — in every format — that a clean
automated run is not conformance and that every criterion still needs
manual review.
"""

from __future__ import annotations

import html
import json
import textwrap
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Literal

from . import text_view
from .core import CRITERIA_REGISTRY, Finding, WcagCriterion, criterion
from .text_view import PageTextView

#: Per-criterion outcome derived from its findings. A criterion only
#: appears in a report when it has findings, so these are the only two
#: values — never a "pass", which the tool cannot assert.
Status = Literal["fail", "needs-review"]

#: The conformance target this tool audits: WCAG 2.2 levels A and AA.
#: AAA criteria are out of scope and excluded from the coverage counts.
_IN_SCOPE_LEVELS = frozenset({"A", "AA"})

#: Sort order for findings and status ranking (most severe first).
_SEVERITY_ORDER = {"error": 0, "warning": 1, "needs-review": 2}

#: axe impact grades, best (most severe) first — used only to order
#: criteria *within* a priority band, never to set the band itself.
_IMPACT_ORDER = {"critical": 0, "serious": 1, "moderate": 2, "minor": 3}


@dataclass(frozen=True)
class Priority:
    """A remediation-priority band for a criterion's findings.

    ``key`` is the short id (``"P1"`` … ``"P4"``), ``label`` the human
    name, ``rank`` the sort order (1 = most urgent), and ``jira`` the
    matching JIRA priority name. A band is a *fix-order* hint derived from
    finding severity and WCAG level — never a conformance/pass-fail claim.
    """

    key: str
    label: str
    rank: int
    jira: str


#: The four bands. P1: a confirmed (error) failure of a level-A criterion —
#: the most fundamental barriers, and A is a prerequisite for AA. P2: a
#: confirmed failure at AA. P3: a lower-impact definite failure (warning).
#: P4: only unconfirmed needs-review candidates (need human triage first).
P1 = Priority("P1", "Critical", 1, "Highest")
P2 = Priority("P2", "High", 2, "High")
P3 = Priority("P3", "Medium", 3, "Medium")
P4 = Priority("P4", "Review", 4, "Low")
PRIORITY_BANDS: tuple[Priority, ...] = (P1, P2, P3, P4)


def _priority_for(entry: WcagCriterion, findings: Sequence[Finding]) -> Priority:
    """Band a criterion by its worst finding severity and its WCAG level."""
    worst = min(_SEVERITY_ORDER.get(f.severity, 99) for f in findings)
    if worst == _SEVERITY_ORDER["error"]:
        return P1 if entry.level == "A" else P2
    if worst == _SEVERITY_ORDER["warning"]:
        return P3
    return P4


def _impact_rank(findings: Sequence[Finding]) -> int:
    """Best (lowest) axe-impact rank among the findings; ties broken later."""
    ranks = [_IMPACT_ORDER[f.impact] for f in findings if f.impact in _IMPACT_ORDER]
    return min(ranks) if ranks else len(_IMPACT_ORDER)

#: Stated in every rendered format so a clean run is never mistaken for
#: a conformance claim.
DISCLAIMER = (
    "A clean automated run does not imply WCAG 2.2 AA conformance. "
    "Automated tooling decides only part of a subset of the success "
    "criteria; a criterion with no automated finding is not a pass, and "
    "every criterion requires manual review before a conformance claim "
    "can be made."
)


@dataclass(frozen=True)
class CoverageSummary:
    """Registry-derived context for a run's findings.

    ``urls`` are the pages audited. ``total_in_scope`` is the count of
    WCAG 2.2 A + AA success criteria; ``by_tier`` splits those by
    automatability tier (``full`` / ``partial`` / ``manual``).
    ``criteria_with_findings`` is how many criteria this run flagged, and
    ``findings_by_severity`` totals the findings themselves. Together they
    state coverage — what the tool can speak to — without implying
    conformance.
    """

    urls: tuple[str, ...]
    total_in_scope: int
    by_tier: dict[str, int]
    criteria_with_findings: int
    findings_by_severity: dict[str, int]
    by_priority: dict[str, int]


@dataclass(frozen=True)
class CriterionReport:
    """One WCAG criterion together with the findings this run produced.

    ``criterion`` is the registry entry, ``status`` is ``"fail"`` when any
    finding is an error/warning and ``"needs-review"`` when the criterion
    has only unconfirmed (axe-incomplete) findings, and ``priority`` is its
    remediation band (see :class:`Priority`). ``findings`` is ordered
    most-severe first.
    """

    criterion: WcagCriterion
    status: Status
    priority: Priority
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class ReportDocument:
    """The full, format-agnostic audit result.

    ``criteria`` holds one :class:`CriterionReport` per criterion that had
    findings, sorted worst-first by remediation priority (band, then axe
    impact, then occurrence count). ``summary`` is the coverage context,
    ``generated_at`` an optional caller-supplied timestamp (this module
    never reads the clock, to stay pure and deterministic), and ``title``
    an optional site label shown in the heading (e.g. a municipality name).
    ``text_views`` holds the per-page linearized reading views (see
    :mod:`.text_view`), rendered into every format as a *Reading view*
    manual-review section; empty when none were captured.
    """

    summary: CoverageSummary
    criteria: tuple[CriterionReport, ...]
    generated_at: str | None
    title: str | None = None
    text_views: tuple[PageTextView, ...] = ()


def build_report(
    findings: Iterable[Finding],
    *,
    urls: Sequence[str] | None = None,
    generated_at: str | None = None,
    title: str | None = None,
    text_views: Sequence[PageTextView] = (),
) -> ReportDocument:
    """Fold a flat finding list into a grouped, summarized report.

    ``findings`` are grouped by their ``criterion`` id and each group is
    matched to a registry entry (findings whose id is not in the registry
    are dropped — they carry no criterion to report against). ``urls`` is
    the full set of pages audited, so a page that produced no finding is
    still recorded; when omitted it is inferred from the findings.
    ``generated_at`` is passed straight through to the renderers.
    ``text_views`` are the per-page reading views embedded as the report's
    *Reading view* section.
    """
    grouped: dict[str, list[Finding]] = {}
    for finding in findings:
        grouped.setdefault(finding.criterion, []).append(finding)

    criteria: list[CriterionReport] = []
    for criterion_id, group in grouped.items():
        entry = criterion(criterion_id)
        if entry is None:
            continue
        ordered = tuple(sorted(group, key=_finding_sort_key))
        criteria.append(
            CriterionReport(
                criterion=entry,
                status=_status_for(ordered),
                priority=_priority_for(entry, ordered),
                findings=ordered,
            )
        )
    criteria.sort(key=_criterion_priority_key)

    summary = _build_summary(
        criteria,
        audited_urls=_audited_urls(grouped, urls),
    )
    return ReportDocument(
        summary=summary,
        criteria=tuple(criteria),
        generated_at=generated_at,
        title=title,
        text_views=tuple(text_views),
    )


def _status_for(findings: Sequence[Finding]) -> Status:
    """Return ``"fail"`` if any finding is a definite failure, else review."""
    if any(f.severity in ("error", "warning") for f in findings):
        return "fail"
    return "needs-review"


def _build_summary(
    criteria: Sequence[CriterionReport],
    *,
    audited_urls: tuple[str, ...],
) -> CoverageSummary:
    """Compute the registry-derived coverage numbers for a run."""
    in_scope = [c for c in CRITERIA_REGISTRY if c.level in _IN_SCOPE_LEVELS]
    by_tier = {"full": 0, "partial": 0, "manual": 0}
    for crit in in_scope:
        by_tier[crit.automatable] += 1

    by_severity = {"error": 0, "warning": 0, "needs-review": 0}
    by_priority = {band.key: 0 for band in PRIORITY_BANDS}
    for report in criteria:
        by_priority[report.priority.key] += 1
        for finding in report.findings:
            by_severity[finding.severity] += 1

    return CoverageSummary(
        urls=audited_urls,
        total_in_scope=len(in_scope),
        by_tier=by_tier,
        criteria_with_findings=len(criteria),
        findings_by_severity=by_severity,
        by_priority=by_priority,
    )


def _audited_urls(
    grouped: dict[str, list[Finding]], urls: Sequence[str] | None
) -> tuple[str, ...]:
    """Union the explicit audited URLs with those seen in findings."""
    seen = set(urls or ())
    for group in grouped.values():
        seen.update(f.url for f in group)
    return tuple(sorted(seen))


def _finding_sort_key(finding: Finding) -> tuple[int, int, str, str]:
    """Order findings most-severe first, then worst axe impact, URL, selector."""
    return (
        _SEVERITY_ORDER.get(finding.severity, 99),
        _IMPACT_ORDER.get(finding.impact, len(_IMPACT_ORDER)),
        finding.url,
        finding.selector or "",
    )


def _criterion_sort_key(criterion_id: str) -> tuple[int, ...]:
    """Sort criterion ids numerically so ``1.4.10`` follows ``1.4.9``."""
    return tuple(int(part) for part in criterion_id.split("."))


def _criterion_priority_key(report: "CriterionReport") -> tuple:
    """Order criteria worst-first: band, then axe impact, then occurrences."""
    return (
        report.priority.rank,
        _impact_rank(report.findings),
        -len(report.findings),
        _criterion_sort_key(report.criterion.id),
    )


# --- Renderers -------------------------------------------------------------


def render_json(document: ReportDocument) -> str:
    """Render the canonical ``results.json`` string.

    Stable key order, UTF-8 preserved, two-space indent. This is the
    authoritative machine-readable output; the other formats are derived
    views for humans.
    """
    payload = {
        "title": document.title,
        "generated_at": document.generated_at,
        "disclaimer": DISCLAIMER,
        "summary": {
            "urls": list(document.summary.urls),
            "total_in_scope": document.summary.total_in_scope,
            "criteria_with_findings": document.summary.criteria_with_findings,
            "by_tier": document.summary.by_tier,
            "by_priority": document.summary.by_priority,
            "findings_by_severity": document.summary.findings_by_severity,
        },
        "criteria": [
            {
                "id": report.criterion.id,
                "name": report.criterion.name,
                "level": report.criterion.level,
                "automatable": report.criterion.automatable,
                "status": report.status,
                "priority": report.priority.key,
                "priority_label": report.priority.label,
                "findings": [
                    {
                        "severity": f.severity,
                        "impact": f.impact,
                        "message": f.message,
                        "selector": f.selector,
                        "url": f.url,
                        "screenshot": f.screenshot,
                    }
                    for f in report.findings
                ],
            }
            for report in document.criteria
        ],
        "reading_view": text_view.reading_view_payload(document.text_views),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_text(document: ReportDocument) -> str:
    """Render a plain-text report for a terminal or a ``.txt`` sidecar."""
    summary = document.summary
    lines = ["WCAG 2.2 AA audit", "=================", ""]
    if document.title:
        lines.append(f"Site: {document.title}")
    if document.generated_at:
        lines.append(f"Generated: {document.generated_at}")
    lines.append(f"Pages audited ({len(summary.urls)}):")
    lines.extend(f"  - {url}" for url in summary.urls)
    lines.append("")

    lines += ["Coverage summary", "----------------"]
    lines.append(f"WCAG 2.2 A + AA criteria in scope: {summary.total_in_scope}")
    lines.append(f"  automatable (full):    {summary.by_tier['full']}")
    lines.append(f"  automatable (partial): {summary.by_tier['partial']}")
    lines.append(f"  manual only:           {summary.by_tier['manual']}")
    lines.append(f"Criteria with findings: {summary.criteria_with_findings}")
    pri = summary.by_priority
    lines.append(
        f"By priority: {pri['P1']} critical, {pri['P2']} high, "
        f"{pri['P3']} medium, {pri['P4']} needs-review"
    )
    sev = summary.findings_by_severity
    lines.append(
        f"Findings: {sev['error']} error, {sev['warning']} warning, "
        f"{sev['needs-review']} needs-review"
    )
    lines.append("")
    lines.extend(textwrap.wrap(DISCLAIMER, width=76))
    lines.append("")

    lines += ["Findings by priority", "--------------------"]
    if not document.criteria:
        lines.append("No automated findings.")
    for report in document.criteria:
        crit = report.criterion
        lines.append(
            f"[{report.priority.key} {report.priority.label}]  {crit.id}  "
            f"{crit.name}  [{crit.level} · {crit.automatable}]"
        )
        for finding in report.findings:
            lines.append(f"  [{finding.severity}] {finding.selector or '(page)'}")
            lines.append(f"      {finding.message}")
            lines.append(f"      {finding.url}")
            if finding.screenshot:
                lines.append(f"      evidence: {finding.screenshot}")
        lines.append("")

    reading = text_view.render_text_section(document.text_views)
    if reading:
        lines += ["", reading.rstrip()]
    return "\n".join(lines).rstrip() + "\n"


def render_markdown(document: ReportDocument) -> str:
    """Render a Markdown report: a priority overview then band-grouped detail."""
    summary = document.summary
    sev = summary.findings_by_severity
    pri = summary.by_priority
    tier = summary.by_tier
    lines = ["# WCAG 2.2 AA audit", ""]
    if document.title:
        lines.append(f"**{document.title}**")
        lines.append("")
    if document.generated_at:
        lines.append(f"_Generated: {document.generated_at}_")
        lines.append("")
    lines.append(f"> {DISCLAIMER}")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(f"**Pages audited ({len(summary.urls)}):**")
    lines.extend(f"- {url}" for url in summary.urls)
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| A + AA criteria in scope | {summary.total_in_scope} |")
    lines.append(
        f"| Automatable (full / partial / manual) | "
        f"{tier['full']} / {tier['partial']} / {tier['manual']} |"
    )
    lines.append(f"| Criteria with findings | {summary.criteria_with_findings} |")
    lines.append(
        f"| Priority (P1 crit / P2 high / P3 med / P4 review) | "
        f"{pri['P1']} / {pri['P2']} / {pri['P3']} / {pri['P4']} |"
    )
    lines.append(
        f"| Findings | {sev['error']} error / {sev['warning']} warning / "
        f"{sev['needs-review']} needs-review |"
    )
    lines.append("")

    lines.append("## Priority overview")
    lines.append("")
    if not document.criteria:
        lines.append("No automated findings.")
        lines.append("")
    else:
        lines.append("| Priority | Criterion | Level | Occurrences | Worst |")
        lines.append("| --- | --- | --- | ---: | --- |")
        for report in document.criteria:
            crit = report.criterion
            lines.append(
                f"| {report.priority.key} · {report.priority.label} "
                f"| {crit.id} {crit.name} | {crit.level} "
                f"| {len(report.findings)} | {report.findings[0].severity} |"
            )
        lines.append("")

    lines.append("## Findings")
    lines.append("")
    for band in PRIORITY_BANDS:
        band_reports = [r for r in document.criteria if r.priority.key == band.key]
        if not band_reports:
            continue
        lines.append(f"### {band.key} · {band.label}")
        lines.append("")
        for report in band_reports:
            crit = report.criterion
            lines.append(
                f"#### {crit.id} {crit.name} "
                f"({crit.level} · {crit.automatable}) — {report.status.upper()}"
            )
            lines.append("")
            for finding in report.findings:
                evidence = (
                    f" [[evidence]]({finding.screenshot})" if finding.screenshot else ""
                )
                impact = f" _{finding.impact}_" if finding.impact else ""
                lines.append(
                    f"- **{finding.severity}**{impact} "
                    f"`{finding.selector or '(page)'}` — "
                    f"{finding.message} ({finding.url}){evidence}"
                )
            lines.append("")

    reading = text_view.render_markdown_section(document.text_views)
    if reading:
        lines += ["", reading.rstrip()]
    return "\n".join(lines).rstrip() + "\n"


def _evidence_cell(screenshot: str | None) -> str:
    """Render the Evidence table cell: a thumbnail linking to the PNG.

    The path is a report-relative reference to a local file (e.g.
    ``screenshots/<file>.png``); ``None`` renders an em dash. The value is
    HTML-escaped so a hostile selector-derived path cannot break out.
    """
    if not screenshot:
        return "—"
    src = html.escape(screenshot, quote=True)
    return f"<a href='{src}'><img class='evidence' src='{src}' alt='element screenshot'></a>"


def _pri_pill(priority: Priority) -> str:
    """A coloured priority pill, e.g. ``P1 Critical``."""
    return (
        f"<span class='pri {priority.key}'>"
        f"{html.escape(priority.key)} {html.escape(priority.label)}</span>"
    )


def render_html(document: ReportDocument) -> str:
    """Render an HTML page with inline CSS and no external network assets.

    Leads with a priority triage table, then the findings grouped by
    priority band (worst first). The only local references are the
    element-evidence PNGs under ``screenshots/`` (written beside the
    report); the page carries no remote CSS, fonts, or scripts.
    """
    summary = document.summary
    sev = summary.findings_by_severity
    pri = summary.by_priority

    url_items = "".join(f"<li>{html.escape(u)}</li>" for u in summary.urls)
    subtitle = (
        f"<p class='subtitle'>{html.escape(document.title)}</p>"
        if document.title
        else ""
    )
    generated = (
        f"<p class='meta'>Generated: {html.escape(document.generated_at)}</p>"
        if document.generated_at
        else ""
    )

    if document.criteria:
        triage_rows = "".join(
            "<tr>"
            f"<td>{_pri_pill(report.priority)}</td>"
            f"<td><a href='#crit-{html.escape(report.criterion.id, quote=True)}'>"
            f"{html.escape(report.criterion.id)} {html.escape(report.criterion.name)}</a></td>"
            f"<td>{html.escape(report.criterion.level)}</td>"
            f"<td class='num'>{len(report.findings)}</td>"
            f"<td class='sev-{html.escape(report.findings[0].severity)}'>"
            f"{html.escape(report.findings[0].severity)}</td></tr>"
            for report in document.criteria
        )
        triage = (
            "<table class='triage'><thead><tr><th>Priority</th><th>Criterion</th>"
            "<th>Level</th><th>Occurrences</th><th>Worst</th></tr></thead>"
            f"<tbody>{triage_rows}</tbody></table>"
        )
    else:
        triage = "<p>No automated findings.</p>"

    sections: list[str] = []
    for band in PRIORITY_BANDS:
        band_reports = [r for r in document.criteria if r.priority.key == band.key]
        if not band_reports:
            continue
        sections.append(
            f"<h2 class='band'>{_pri_pill(band)} {html.escape(band.label)} priority</h2>"
        )
        for report in band_reports:
            crit = report.criterion
            rows = "".join(
                "<tr class='sev-{sev}'>"
                "<td>{sev}</td><td>{impact}</td><td><code>{sel}</code></td>"
                "<td>{msg}</td><td>{url}</td><td>{evidence}</td></tr>".format(
                    sev=html.escape(f.severity),
                    impact=html.escape(f.impact or "—"),
                    sel=html.escape(f.selector or "(page)"),
                    msg=html.escape(f.message),
                    url=html.escape(f.url),
                    evidence=_evidence_cell(f.screenshot),
                )
                for f in report.findings
            )
            sections.append(
                f"<section id='crit-{html.escape(crit.id, quote=True)}'>"
                f"<h3>{_pri_pill(report.priority)} {html.escape(crit.id)} "
                f"{html.escape(crit.name)} "
                f"<span class='tag'>{html.escape(crit.level)} · "
                f"{html.escape(crit.automatable)}</span> "
                f"<span class='status {report.status}'>"
                f"{html.escape(report.status.upper())}</span></h3>"
                "<table><thead><tr><th>Severity</th><th>Impact</th><th>Element</th>"
                "<th>Message</th><th>URL</th><th>Evidence</th></tr></thead>"
                f"<tbody>{rows}</tbody></table></section>"
            )

    return _HTML_TEMPLATE.format(
        subtitle=subtitle,
        generated=generated,
        url_count=len(summary.urls),
        url_items=url_items,
        total_in_scope=summary.total_in_scope,
        full=summary.by_tier["full"],
        partial=summary.by_tier["partial"],
        manual=summary.by_tier["manual"],
        with_findings=summary.criteria_with_findings,
        p1=pri["P1"],
        p2=pri["P2"],
        p3=pri["P3"],
        p4=pri["P4"],
        errors=sev["error"],
        warnings=sev["warning"],
        review=sev["needs-review"],
        disclaimer=html.escape(DISCLAIMER),
        triage=triage,
        sections="".join(sections),
        reading_view=text_view.render_html_section(document.text_views),
    )


#: Self-contained page shell for :func:`render_html`. Literal ``{`` / ``}``
#: in the CSS are doubled so ``str.format`` leaves them untouched.
_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WCAG 2.2 AA audit</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }}
h1 {{ margin-bottom: 0.25rem; }}
.subtitle {{ font-size: 1.15rem; font-weight: 600; margin: 0 0 0.25rem; }}
.meta {{ color: #555; }}
.disclaimer {{ background: #fff8e1; border-left: 4px solid #f0ad4e;
  padding: 0.75rem 1rem; margin: 1rem 0; }}
table {{ border-collapse: collapse; width: 100%; margin: 0.5rem 0 1.5rem; }}
th, td {{ border: 1px solid #ddd; padding: 0.4rem 0.6rem; text-align: left;
  vertical-align: top; font-size: 0.9rem; }}
th {{ background: #f4f4f4; }}
code {{ font-size: 0.85em; word-break: break-all; }}
td.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
img.evidence {{ max-width: 360px; max-height: 480px; border: 1px solid #ccc;
  display: block; }}
.summary td, .summary th {{ white-space: nowrap; }}
.triage {{ max-width: 100%; }}
.tag {{ font-size: 0.75rem; color: #555; font-weight: normal; }}
.status {{ font-size: 0.75rem; padding: 0.1rem 0.4rem; border-radius: 3px; }}
.status.fail {{ background: #f8d7da; color: #842029; }}
.status.needs-review {{ background: #fff3cd; color: #664d03; }}
.pri {{ display: inline-block; font-size: 0.72rem; font-weight: 700;
  padding: 0.1rem 0.45rem; border-radius: 3px; color: #fff;
  white-space: nowrap; }}
.pri.P1 {{ background: #b4362e; }}
.pri.P2 {{ background: #b5651d; }}
.pri.P3 {{ background: #7a6300; }}
.pri.P4 {{ background: #41607a; }}
.band {{ margin-top: 2rem; border-bottom: 2px solid #ddd;
  padding-bottom: 0.25rem; }}
.sev-error td:first-child {{ color: #842029; font-weight: bold; }}
.sev-warning td:first-child {{ color: #664d03; font-weight: bold; }}
.sev-needs-review td:first-child {{ color: #055160; }}
.rv-note {{ color: #555; font-size: 0.85rem; margin: 0.5rem 0 1rem; }}
details.rv {{ border: 1px solid #ddd; border-radius: 4px; margin: 0.5rem 0;
  padding: 0.4rem 0.75rem; }}
details.rv summary {{ cursor: pointer; font-weight: 600; }}
.rv-url {{ color: #667; font-size: 0.85rem; margin: 0.3rem 0; }}
ul.rv-list {{ list-style: none; margin: 0.5rem 0; padding-left: 0.5rem;
  font-size: 0.88rem; }}
ul.rv-list li {{ padding: 0.05rem 0; }}
ul.rv-list li.rv-text {{ color: #333; }}
ul.rv-list li.rv-heading {{ margin-top: 0.3rem; }}
ul.rv-list li.rv-warn {{ color: #842029; }}
ul.rv-list code {{ background: #f4f4f4; padding: 0 0.2rem; border-radius: 2px; }}
</style>
</head>
<body>
<h1>WCAG 2.2 AA audit</h1>
{subtitle}
{generated}
<p class="disclaimer">{disclaimer}</p>
<h2>Summary</h2>
<p>Pages audited ({url_count}):</p>
<ul>{url_items}</ul>
<table class="summary">
<tr><th>A + AA criteria in scope</th><td>{total_in_scope}</td></tr>
<tr><th>Automatable (full / partial / manual)</th>
  <td>{full} / {partial} / {manual}</td></tr>
<tr><th>Criteria with findings</th><td>{with_findings}</td></tr>
<tr><th>Priority</th><td>{p1} critical / {p2} high / {p3} medium /
  {p4} needs-review</td></tr>
<tr><th>Findings</th><td>{errors} error / {warnings} warning /
  {review} needs-review</td></tr>
</table>
<h2>Priority overview</h2>
{triage}
<h2>Findings</h2>
{sections}
{reading_view}
</body>
</html>
"""


def render_jira_tickets(document: ReportDocument) -> dict[str, str]:
    """Render one JIRA-style ticket (Markdown) per criterion with findings.

    Returns a mapping of relative filename (e.g.
    ``1.4.3-contrast-minimum.md``) to ticket body — one ticket per *type*
    of issue (WCAG criterion), each a self-contained work item with fields,
    the affected elements, and acceptance criteria. Pure: no filesystem;
    the caller writes the files (into a ``jira/`` subfolder).
    """
    tickets: dict[str, str] = {}
    for report in document.criteria:
        name = f"{report.criterion.id}-{_jira_slug(report.criterion.name)}.md"
        tickets[name] = _jira_ticket(report, generated_at=document.generated_at)
    return tickets


def _jira_slug(name: str) -> str:
    """Filesystem-safe lowercase slug of a criterion name."""
    slug = "".join(c.lower() if c.isalnum() else "-" for c in name)
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-") or "criterion"


def _jira_ticket(report: CriterionReport, *, generated_at: str | None) -> str:
    """Render one criterion's findings as a JIRA-style Markdown ticket.

    The title, ``Priority`` field, and labels carry the remediation band so
    the ticket slots into a backlog at the right rank. A ``needs-review``
    criterion is typed as a triage task (a candidate the tool cannot
    confirm), not a confirmed bug. Affected elements are grouped by page.
    """
    crit = report.criterion
    findings = report.findings
    priority = report.priority
    urls: list[str] = []
    for finding in findings:
        if finding.url and finding.url not in urls:
            urls.append(finding.url)
    triage = report.status == "needs-review"

    labels = [
        "accessibility", "wcag", "wcag2.2", f"level-{crit.level}",
        crit.id, f"priority-{priority.key.lower()}",
    ]
    if triage:
        labels.append("needs-triage")

    lines = [
        f"# [{priority.key}] WCAG {crit.id} {crit.name} — "
        f"{len(findings)} occurrence(s)",
        "",
    ]
    lines += ["| Field | Value |", "| --- | --- |"]
    lines.append(
        f"| Type | {'Accessibility review (candidate)' if triage else 'Accessibility bug'} |"
    )
    lines.append(f"| Priority | {priority.jira} ({priority.key} · {priority.label}) |")
    lines.append(f"| WCAG 2.2 criterion | {crit.id} {crit.name} (level {crit.level}) |")
    lines.append(f"| Automatability | {crit.automatable} |")
    lines.append(f"| Occurrences | {len(findings)} on {len(urls)} page(s) |")
    lines.append(f"| Labels | {', '.join(labels)} |")
    lines += ["", "## Description", ""]
    if triage:
        lines.append(
            f"WCAG 2.2 **{crit.id} {crit.name}** (level {crit.level}) needs a "
            f"human decision: the automated audit flagged {len(findings)} "
            f"candidate(s) across {len(urls)} page(s) but cannot confirm this "
            f"criterion on its own. Triage each, then fix or dismiss."
        )
    else:
        lines.append(
            f"WCAG 2.2 success criterion **{crit.id} {crit.name}** (level "
            f"{crit.level}) is not satisfied. The automated audit flagged "
            f"{len(findings)} occurrence(s) across {len(urls)} page(s)."
        )
    lines += ["", "## Affected elements", ""]
    for url in urls:
        lines.append(f"### {url}")
        for finding in findings:
            if finding.url != url:
                continue
            evidence = (
                f" — [evidence]({finding.screenshot})" if finding.screenshot else ""
            )
            impact = f" _(impact: {finding.impact})_" if finding.impact else ""
            lines.append(
                f"- **{finding.severity}**{impact} "
                f"`{finding.selector or '(page)'}` — {finding.message}{evidence}"
            )
        lines.append("")
    lines += ["## Acceptance criteria", ""]
    lines.append(
        f"- [ ] Every element above satisfies WCAG 2.2 {crit.id} {crit.name}."
    )
    lines.append("- [ ] A re-run of the audit reports no findings for this criterion.")
    if triage or crit.automatable != "full":
        lines.append(
            "- [ ] A person has confirmed this criterion — the tool flags "
            "candidates here but cannot decide it on its own."
        )
    lines.append("")
    stamp = f" at {generated_at}" if generated_at else ""
    lines.append(f"> Generated by wcag-checker{stamp}. {DISCLAIMER}")
    return "\n".join(lines).rstrip() + "\n"


__all__ = [
    "CoverageSummary",
    "CriterionReport",
    "DISCLAIMER",
    "PRIORITY_BANDS",
    "Priority",
    "ReportDocument",
    "Status",
    "build_report",
    "render_html",
    "render_jira_tickets",
    "render_json",
    "render_markdown",
    "render_text",
]
