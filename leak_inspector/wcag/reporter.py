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

Language: :func:`build_report` takes a ``lang`` that the document
carries; every renderer writes its labels, the criterion names and the
embedded sections in that language (see :mod:`leak_inspector.i18n`).
Machine-readable values in the JSON (ids, severities, tiers, statuses)
stay language-independent.

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

from ..i18n import N_, SOURCE_LANG, criterion_name, tr
from . import manual_checklist, text_view
from .core import CRITERIA_REGISTRY, Finding, WcagCriterion, criterion
from .text_view import PageTextView

#: Per-criterion outcome derived from its findings. A criterion only
#: appears in a report when it has findings, so these are the only two
#: values — never a "pass", which the tool cannot assert.
Status = Literal["fail", "needs-review"]

#: What the automated run was able to say about a criterion this time, for
#: the coverage table. ``"findings"`` — automated issues were flagged;
#: ``"clean-auto"`` — a ``full``-tier criterion was auto-checked and
#: nothing was flagged (checked, but still *not* a pass); ``"manual"`` —
#: not decided automatically (a ``partial``/``manual`` criterion with no
#: automated finding), so it still needs the manual checklist.
RunStatus = Literal["findings", "clean-auto", "manual"]

#: Human labels for :data:`RunStatus` in the coverage table's "This run"
#: column (the finding count is substituted for ``"findings"``).
RUN_STATUS_LABELS: dict[str, str] = {
    "clean-auto": N_("no automated finding"),
    "manual": N_("needs manual review"),
}

#: Legend shown under the coverage table so its columns are unambiguous —
#: chiefly that neither "no automated finding" nor a missing row is a pass.
COVERAGE_LEGEND = N_(
    "Coverage is how much of a criterion automated tooling can decide: "
    "'full' (a clean automated check is meaningful evidence), 'partial' "
    "(tooling flags candidates, a human confirms), 'manual' (no automated "
    "check — human judgement only). This run: 'N finding(s)' are automated "
    "issues to fix or triage; 'no automated finding' means the automatable "
    "part was checked and nothing was flagged — not a pass; 'needs manual "
    "review' means it was not decided automatically. Work the manual-review "
    "checklist below for every 'partial'/'manual' criterion regardless."
)

#: The conformance target this tool audits: WCAG 2.2 levels A and AA.
#: AAA criteria are out of scope and excluded from the coverage counts.
_IN_SCOPE_LEVELS = frozenset({"A", "AA"})

#: Sort order for findings and status ranking (most severe first).
_SEVERITY_ORDER = {"error": 0, "warning": 1, "needs-review": 2}

#: axe impact grades, best (most severe) first — used only to order
#: criteria *within* a priority band, never to set the band itself.
_IMPACT_ORDER = {"critical": 0, "serious": 1, "moderate": 2, "minor": 3}

#: Display labels for the language-independent values shown in reports.
_SEVERITY_LABELS = {
    "error": N_("error"),
    "warning": N_("warning"),
    "needs-review": N_("needs-review"),
}
_TIER_LABELS = {"full": N_("full"), "partial": N_("partial"), "manual": N_("manual")}
_STATUS_LABELS = {"fail": N_("FAIL"), "needs-review": N_("NEEDS REVIEW")}
_IMPACT_LABELS = {
    "critical": N_("critical"),
    "serious": N_("serious"),
    "moderate": N_("moderate"),
    "minor": N_("minor"),
}


@dataclass(frozen=True)
class Priority:
    """A remediation-priority band for a criterion's findings.

    ``key`` is the short id (``"P1"`` … ``"P4"``), ``label`` the English
    human name (translated when rendered), ``rank`` the sort order (1 = most urgent), and ``jira`` the
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
P1 = Priority("P1", N_("Critical"), 1, "Highest")
P2 = Priority("P2", N_("High"), 2, "High")
P3 = Priority("P3", N_("Medium"), 3, "Medium")
P4 = Priority("P4", N_("Review"), 4, "Low")
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
DISCLAIMER = N_(
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
class CoverageRow:
    """One WCAG 2.2 A+AA criterion's coverage status for this run.

    ``criterion`` is the registry entry, ``run_status`` says what the
    automated run could determine (see :data:`RunStatus`), and
    ``finding_count`` is how many findings it produced (0 unless
    ``run_status`` is ``"findings"``). Present for *every* in-scope
    criterion — including those with no findings — so the report can state
    plainly what was and was not automatically checked.
    """

    criterion: WcagCriterion
    run_status: RunStatus
    finding_count: int


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
    manual-review section; empty when none were captured. ``coverage`` has
    one :class:`CoverageRow` per in-scope A+AA criterion (with or without
    findings), driving the report's explicit *Coverage* table. ``lang`` is
    the language the renderers write in.
    """

    summary: CoverageSummary
    criteria: tuple[CriterionReport, ...]
    generated_at: str | None
    title: str | None = None
    text_views: tuple[PageTextView, ...] = ()
    coverage: tuple[CoverageRow, ...] = ()
    lang: str = SOURCE_LANG


def build_report(
    findings: Iterable[Finding],
    *,
    urls: Sequence[str] | None = None,
    generated_at: str | None = None,
    title: str | None = None,
    text_views: Sequence[PageTextView] = (),
    lang: str = SOURCE_LANG,
) -> ReportDocument:
    """Fold a flat finding list into a grouped, summarized report.

    ``findings`` are grouped by their ``criterion`` id and each group is
    matched to a registry entry (findings whose id is not in the registry
    are dropped — they carry no criterion to report against). ``urls`` is
    the full set of pages audited, so a page that produced no finding is
    still recorded; when omitted it is inferred from the findings.
    ``generated_at`` is passed straight through to the renderers.
    ``text_views`` are the per-page reading views embedded as the report's
    *Reading view* section. ``lang`` is the language the document renders
    in.
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
        coverage=_build_coverage(criteria),
        lang=lang,
    )


def _build_coverage(criteria: Sequence[CriterionReport]) -> tuple[CoverageRow, ...]:
    """Row up every in-scope A+AA criterion with what this run could say.

    A criterion with findings is ``"findings"``; a ``full``-tier criterion
    with none is ``"clean-auto"`` (auto-checked, nothing flagged — not a
    pass); any other (``partial``/``manual`` with no finding) is
    ``"manual"``. Ordered by criterion number so it reads like the WCAG
    2.2 AA list.
    """
    by_id = {report.criterion.id: report for report in criteria}
    rows: list[CoverageRow] = []
    for entry in CRITERIA_REGISTRY:
        if entry.level not in _IN_SCOPE_LEVELS:
            continue
        report = by_id.get(entry.id)
        if report is not None:
            rows.append(CoverageRow(entry, "findings", len(report.findings)))
        elif entry.automatable == "full":
            rows.append(CoverageRow(entry, "clean-auto", 0))
        else:
            rows.append(CoverageRow(entry, "manual", 0))
    rows.sort(key=lambda row: _criterion_sort_key(row.criterion.id))
    return tuple(rows)


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


def _name(lang: str, crit: WcagCriterion) -> str:
    """The criterion's official title in ``lang``."""
    return criterion_name(lang, crit.id, crit.name)


def _sev(lang: str, severity: str) -> str:
    """Display label for a finding severity."""
    return tr(lang, _SEVERITY_LABELS.get(severity, severity))


def _tier(lang: str, tier: str) -> str:
    """Display label for a coverage tier."""
    return tr(lang, _TIER_LABELS.get(tier, tier))


def _impact(lang: str, impact: str) -> str:
    """Display label for an axe impact grade."""
    return tr(lang, _IMPACT_LABELS.get(impact, impact))


def _status(lang: str, status: str) -> str:
    """Display label for a criterion status."""
    return tr(lang, _STATUS_LABELS.get(status, status))


def _page(lang: str) -> str:
    """Placeholder shown for a finding that targets the whole page."""
    return tr(lang, "(page)")


def render_json(document: ReportDocument) -> str:
    """Render the canonical ``results.json`` string.

    Stable key order, UTF-8 preserved, two-space indent. This is the
    authoritative machine-readable output; the other formats are derived
    views for humans. Names, labels, messages and the disclaimer are in
    the document's language; ids, severities, tiers and statuses are not
    translated.
    """
    lang = document.lang
    payload = {
        "lang": lang,
        "title": document.title,
        "generated_at": document.generated_at,
        "disclaimer": tr(lang, DISCLAIMER),
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
                "name": _name(lang, report.criterion),
                "level": report.criterion.level,
                "automatable": report.criterion.automatable,
                "status": report.status,
                "priority": report.priority.key,
                "priority_label": tr(lang, report.priority.label),
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
        "coverage": [
            {
                "id": row.criterion.id,
                "name": _name(lang, row.criterion),
                "level": row.criterion.level,
                "automatable": row.criterion.automatable,
                "run_status": row.run_status,
                "finding_count": row.finding_count,
            }
            for row in document.coverage
        ],
        "reading_view": text_view.reading_view_payload(document.text_views),
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _run_status_text(row: CoverageRow, lang: str) -> str:
    """The 'This run' cell text for a coverage row."""
    if row.run_status == "findings":
        return tr(lang, "{count} finding(s)", count=row.finding_count)
    return tr(lang, RUN_STATUS_LABELS[row.run_status])


def _priority_counts(lang: str, pri: dict[str, int], separator: str) -> str:
    """'N critical / N high / N medium / N needs-review' for the summary."""
    return separator.join(
        (
            tr(lang, "{count} critical", count=pri["P1"]),
            tr(lang, "{count} high", count=pri["P2"]),
            tr(lang, "{count} medium", count=pri["P3"]),
            tr(lang, "{count} needs-review", count=pri["P4"]),
        )
    )


def _severity_counts(lang: str, sev: dict[str, int], separator: str) -> str:
    """'N error / N warning / N needs-review' for the summary."""
    return separator.join(
        (
            tr(lang, "{count} error", count=sev["error"]),
            tr(lang, "{count} warning", count=sev["warning"]),
            tr(lang, "{count} needs-review", count=sev["needs-review"]),
        )
    )


def render_text(document: ReportDocument) -> str:
    """Render a plain-text report for a terminal or a ``.txt`` sidecar."""
    lang = document.lang
    summary = document.summary
    title = tr(lang, "WCAG 2.2 AA audit")
    lines = [title, "=" * len(title), ""]
    if document.title:
        lines.append(tr(lang, "Site: {title}", title=document.title))
    if document.generated_at:
        lines.append(tr(lang, "Generated: {when}", when=document.generated_at))
    lines.append(tr(lang, "Pages audited ({count}):", count=len(summary.urls)))
    lines.extend(f"  - {url}" for url in summary.urls)
    lines.append("")

    heading = tr(lang, "Coverage summary")
    lines += [heading, "-" * len(heading)]
    lines.append(
        tr(lang, "WCAG 2.2 A + AA criteria in scope: {count}", count=summary.total_in_scope)
    )
    lines.append(tr(lang, "  automatable (full):    {count}", count=summary.by_tier["full"]))
    lines.append(
        tr(lang, "  automatable (partial): {count}", count=summary.by_tier["partial"])
    )
    lines.append(tr(lang, "  manual only:           {count}", count=summary.by_tier["manual"]))
    lines.append(
        tr(lang, "Criteria with findings: {count}", count=summary.criteria_with_findings)
    )
    lines.append(
        tr(lang, "By priority: {counts}", counts=_priority_counts(lang, summary.by_priority, ", "))
    )
    lines.append(
        tr(
            lang,
            "Findings: {counts}",
            counts=_severity_counts(lang, summary.findings_by_severity, ", "),
        )
    )
    lines.append("")
    lines.extend(textwrap.wrap(tr(lang, DISCLAIMER), width=76))
    lines.append("")

    heading = tr(lang, "Coverage — all WCAG 2.2 A + AA criteria")
    lines += [heading, "-" * len(heading)]
    lines.extend(textwrap.wrap(tr(lang, COVERAGE_LEGEND), width=76))
    lines.append("")
    for row in document.coverage:
        crit = row.criterion
        lines.append(
            f"  {crit.id:<7} {crit.level:<2} {_tier(lang, crit.automatable):<12} "
            f"{_run_status_text(row, lang):<24} {_name(lang, crit)}"
        )
    lines.append("")

    heading = tr(lang, "Findings by priority")
    lines += [heading, "-" * len(heading)]
    if not document.criteria:
        lines.append(tr(lang, "No automated findings."))
    for report in document.criteria:
        crit = report.criterion
        lines.append(
            f"[{report.priority.key} {tr(lang, report.priority.label)}]  {crit.id}  "
            f"{_name(lang, crit)}  [{crit.level} · {_tier(lang, crit.automatable)}]"
        )
        for finding in report.findings:
            lines.append(
                f"  [{_sev(lang, finding.severity)}] {finding.selector or _page(lang)}"
            )
            lines.append(f"      {finding.message}")
            lines.append(f"      {finding.url}")
            if finding.screenshot:
                lines.append(
                    "      " + tr(lang, "evidence: {path}", path=finding.screenshot)
                )
        lines.append("")

    reading = text_view.render_text_section(document.text_views, lang=lang)
    if reading:
        lines += ["", reading.rstrip()]
    lines += ["", _checklist(document, "text").rstrip()]
    return "\n".join(lines).rstrip() + "\n"


def _checklist(document: ReportDocument, fmt: str) -> str:
    """Render the embedded manual-review checklist section in ``fmt``.

    Builds the checklist from the document's audited URLs, timestamp and
    language and delegates to :mod:`.manual_checklist`; ``fmt`` is
    ``"text"``, ``"markdown"`` or ``"html"``.
    """
    checklist = manual_checklist.build_checklist(
        document.summary.urls, generated_at=document.generated_at, lang=document.lang
    )
    if fmt == "markdown":
        return manual_checklist.render_markdown_section(checklist)
    if fmt == "html":
        return manual_checklist.render_html_section(checklist)
    return manual_checklist.render_text_section(checklist)


def render_markdown(document: ReportDocument) -> str:
    """Render a Markdown report: a priority overview then band-grouped detail."""
    lang = document.lang
    summary = document.summary
    tier = summary.by_tier
    lines = [f"# {tr(lang, 'WCAG 2.2 AA audit')}", ""]
    if document.title:
        lines.append(f"**{document.title}**")
        lines.append("")
    if document.generated_at:
        lines.append(f"_{tr(lang, 'Generated: {when}', when=document.generated_at)}_")
        lines.append("")
    lines.append(f"> {tr(lang, DISCLAIMER)}")
    lines.append("")

    lines.append(f"## {tr(lang, 'Summary')}")
    lines.append("")
    lines.append(f"**{tr(lang, 'Pages audited ({count}):', count=len(summary.urls))}**")
    lines.extend(f"- {url}" for url in summary.urls)
    lines.append("")
    lines.append(f"| {tr(lang, 'Metric')} | {tr(lang, 'Value')} |")
    lines.append("| --- | --- |")
    lines.append(f"| {tr(lang, 'A + AA criteria in scope')} | {summary.total_in_scope} |")
    lines.append(
        f"| {tr(lang, 'Automatable (full / partial / manual)')} | "
        f"{tier['full']} / {tier['partial']} / {tier['manual']} |"
    )
    lines.append(
        f"| {tr(lang, 'Criteria with findings')} | {summary.criteria_with_findings} |"
    )
    lines.append(
        f"| {tr(lang, 'Priority')} | "
        f"{_priority_counts(lang, summary.by_priority, ' / ')} |"
    )
    lines.append(
        f"| {tr(lang, 'Findings')} | "
        f"{_severity_counts(lang, summary.findings_by_severity, ' / ')} |"
    )
    lines.append("")

    lines.append(f"## {tr(lang, 'Coverage — all WCAG 2.2 A + AA criteria')}")
    lines.append("")
    lines.append(f"> {tr(lang, COVERAGE_LEGEND)}")
    lines.append("")
    lines.append(
        f"| {tr(lang, 'Criterion')} | {tr(lang, 'Level')} | "
        f"{tr(lang, 'Coverage')} | {tr(lang, 'This run')} |"
    )
    lines.append("| --- | --- | --- | --- |")
    for row in document.coverage:
        crit = row.criterion
        lines.append(
            f"| {crit.id} {_name(lang, crit)} | {crit.level} | "
            f"{_tier(lang, crit.automatable)} | {_run_status_text(row, lang)} |"
        )
    lines.append("")

    lines.append(f"## {tr(lang, 'Priority overview')}")
    lines.append("")
    if not document.criteria:
        lines.append(tr(lang, "No automated findings."))
        lines.append("")
    else:
        lines.append(
            f"| {tr(lang, 'Priority')} | {tr(lang, 'Criterion')} | {tr(lang, 'Level')} "
            f"| {tr(lang, 'Occurrences')} | {tr(lang, 'Worst')} |"
        )
        lines.append("| --- | --- | --- | ---: | --- |")
        for report in document.criteria:
            crit = report.criterion
            lines.append(
                f"| {report.priority.key} · {tr(lang, report.priority.label)} "
                f"| {crit.id} {_name(lang, crit)} | {crit.level} "
                f"| {len(report.findings)} | {_sev(lang, report.findings[0].severity)} |"
            )
        lines.append("")

    lines.append(f"## {tr(lang, 'Findings')}")
    lines.append("")
    for band in PRIORITY_BANDS:
        band_reports = [r for r in document.criteria if r.priority.key == band.key]
        if not band_reports:
            continue
        lines.append(f"### {band.key} · {tr(lang, band.label)}")
        lines.append("")
        for report in band_reports:
            crit = report.criterion
            lines.append(
                f"#### {crit.id} {_name(lang, crit)} "
                f"({crit.level} · {_tier(lang, crit.automatable)}) — "
                f"{_status(lang, report.status)}"
            )
            lines.append("")
            for finding in report.findings:
                evidence = (
                    f" [[{tr(lang, 'evidence')}]]({finding.screenshot})"
                    if finding.screenshot
                    else ""
                )
                impact = f" _{_impact(lang, finding.impact)}_" if finding.impact else ""
                lines.append(
                    f"- **{_sev(lang, finding.severity)}**{impact} "
                    f"`{finding.selector or _page(lang)}` — "
                    f"{finding.message} ({finding.url}){evidence}"
                )
            lines.append("")

    reading = text_view.render_markdown_section(document.text_views, lang=lang)
    if reading:
        lines += ["", reading.rstrip()]
    lines += ["", _checklist(document, "markdown").rstrip()]
    return "\n".join(lines).rstrip() + "\n"


def _evidence_cell(screenshot: str | None, lang: str) -> str:
    """Render the Evidence table cell: a thumbnail linking to the PNG.

    The path is a report-relative reference to a local file (e.g.
    ``screenshots/<file>.png``); ``None`` renders an em dash. The value is
    HTML-escaped so a hostile selector-derived path cannot break out.
    """
    if not screenshot:
        return "—"
    src = html.escape(screenshot, quote=True)
    alt = html.escape(tr(lang, "element screenshot"), quote=True)
    return f"<a href='{src}'><img class='evidence' src='{src}' alt='{alt}'></a>"


def _coverage_name_cell(row: CoverageRow, lang: str) -> str:
    """Criterion cell for the coverage table; links to its findings anchor."""
    label = f"{html.escape(row.criterion.id)} {html.escape(_name(lang, row.criterion))}"
    if row.run_status == "findings":
        anchor = html.escape(row.criterion.id, quote=True)
        return f"<a href='#crit-{anchor}'>{label}</a>"
    return label


def _pri_pill(priority: Priority, lang: str) -> str:
    """A coloured priority pill, e.g. ``P1 Critical``."""
    return (
        f"<span class='pri {priority.key}'>"
        f"{html.escape(priority.key)} {html.escape(tr(lang, priority.label))}</span>"
    )


def _th(lang: str, *labels: str) -> str:
    """A table header row with translated, escaped labels."""
    cells = "".join(f"<th>{html.escape(tr(lang, label))}</th>" for label in labels)
    return f"<thead><tr>{cells}</tr></thead>"


def render_html(document: ReportDocument) -> str:
    """Render an HTML page with inline CSS and no external network assets.

    Leads with a priority triage table, then the findings grouped by
    priority band (worst first). The only local references are the
    element-evidence PNGs under ``screenshots/`` (written beside the
    report); the page carries no remote CSS, fonts, or scripts. The page's
    ``lang`` attribute is the document's language.
    """
    lang = document.lang
    summary = document.summary
    esc = html.escape

    url_items = "".join(f"<li>{esc(u)}</li>" for u in summary.urls)
    subtitle = (
        f"<p class='subtitle'>{esc(document.title)}</p>" if document.title else ""
    )
    generated = (
        f"<p class='meta'>{esc(tr(lang, 'Generated: {when}', when=document.generated_at))}</p>"
        if document.generated_at
        else ""
    )

    if document.criteria:
        triage_rows = "".join(
            "<tr>"
            f"<td>{_pri_pill(report.priority, lang)}</td>"
            f"<td><a href='#crit-{esc(report.criterion.id, quote=True)}'>"
            f"{esc(report.criterion.id)} {esc(_name(lang, report.criterion))}</a></td>"
            f"<td>{esc(report.criterion.level)}</td>"
            f"<td class='num'>{len(report.findings)}</td>"
            f"<td class='sev-{esc(report.findings[0].severity)}'>"
            f"{esc(_sev(lang, report.findings[0].severity))}</td></tr>"
            for report in document.criteria
        )
        triage = (
            "<table class='triage'>"
            + _th(
                lang,
                N_("Priority"),
                N_("Criterion"),
                N_("Level"),
                N_("Occurrences"),
                N_("Worst"),
            )
            + f"<tbody>{triage_rows}</tbody></table>"
        )
    else:
        triage = f"<p>{esc(tr(lang, 'No automated findings.'))}</p>"

    sections: list[str] = []
    for band in PRIORITY_BANDS:
        band_reports = [r for r in document.criteria if r.priority.key == band.key]
        if not band_reports:
            continue
        band_title = tr(lang, "{label} priority", label=tr(lang, band.label))
        sections.append(
            f"<h2 class='band'>{_pri_pill(band, lang)} {esc(band_title)}</h2>"
        )
        for report in band_reports:
            crit = report.criterion
            rows = "".join(
                "<tr class='sev-{sev_class}'>"
                "<td>{sev}</td><td>{impact}</td><td><code>{sel}</code></td>"
                "<td>{msg}</td><td>{url}</td><td>{evidence}</td></tr>".format(
                    sev_class=esc(f.severity),
                    sev=esc(_sev(lang, f.severity)),
                    impact=esc(_impact(lang, f.impact) if f.impact else "—"),
                    sel=esc(f.selector or _page(lang)),
                    msg=esc(f.message),
                    url=esc(f.url),
                    evidence=_evidence_cell(f.screenshot, lang),
                )
                for f in report.findings
            )
            sections.append(
                f"<section id='crit-{esc(crit.id, quote=True)}'>"
                f"<h3>{_pri_pill(report.priority, lang)} {esc(crit.id)} "
                f"{esc(_name(lang, crit))} "
                f"<span class='tag'>{esc(crit.level)} · "
                f"{esc(_tier(lang, crit.automatable))}</span> "
                f"<span class='status {report.status}'>"
                f"{esc(_status(lang, report.status))}</span></h3>"
                "<table>"
                + _th(
                    lang,
                    N_("Severity"),
                    N_("Impact"),
                    N_("Element"),
                    N_("Message"),
                    N_("URL"),
                    N_("Evidence"),
                )
                + f"<tbody>{rows}</tbody></table></section>"
            )

    coverage_rows = "".join(
        "<tr>"
        f"<td>{_coverage_name_cell(row, lang)}</td>"
        f"<td>{esc(row.criterion.level)}</td>"
        f"<td>{esc(_tier(lang, row.criterion.automatable))}</td>"
        f"<td class='run-{row.run_status}'>{esc(_run_status_text(row, lang))}</td>"
        "</tr>"
        for row in document.coverage
    )
    coverage = (
        f"<p class='cov-legend'>{esc(tr(lang, COVERAGE_LEGEND))}</p>"
        "<table class='coverage'>"
        + _th(lang, N_("Criterion"), N_("Level"), N_("Coverage"), N_("This run"))
        + f"<tbody>{coverage_rows}</tbody></table>"
    )

    def t(text: str, **params: object) -> str:
        return esc(tr(lang, text, **params))

    return _HTML_TEMPLATE.format(
        lang=esc(lang, quote=True),
        title=t("WCAG 2.2 AA audit"),
        subtitle=subtitle,
        generated=generated,
        disclaimer=t(DISCLAIMER),
        h_summary=t("Summary"),
        pages_audited=t("Pages audited ({count}):", count=len(summary.urls)),
        url_items=url_items,
        h_in_scope=t("A + AA criteria in scope"),
        total_in_scope=summary.total_in_scope,
        h_automatable=t("Automatable (full / partial / manual)"),
        full=summary.by_tier["full"],
        partial=summary.by_tier["partial"],
        manual=summary.by_tier["manual"],
        h_with_findings=t("Criteria with findings"),
        with_findings=summary.criteria_with_findings,
        h_priority=t("Priority"),
        priority_counts=esc(_priority_counts(lang, summary.by_priority, " / ")),
        h_findings=t("Findings"),
        severity_counts=esc(_severity_counts(lang, summary.findings_by_severity, " / ")),
        h_coverage=t("Coverage — all WCAG 2.2 A + AA criteria"),
        coverage=coverage,
        h_overview=t("Priority overview"),
        triage=triage,
        sections="".join(sections),
        reading_view=text_view.render_html_section(document.text_views, lang=lang),
        checklist=_checklist(document, "html"),
    )


#: Self-contained page shell for :func:`render_html`. Literal ``{`` / ``}``
#: in the CSS are doubled so ``str.format`` leaves them untouched.
_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="{lang}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
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
.cov-legend {{ color: #555; font-size: 0.85rem; margin: 0.5rem 0 1rem; }}
table.coverage td.run-findings {{ color: #842029; font-weight: 600; }}
table.coverage td.run-clean-auto {{ color: #0a5; }}
table.coverage td.run-manual {{ color: #664d03; }}
.mc-note {{ color: #555; font-size: 0.85rem; margin: 0.5rem 0 1rem; }}
details.mc {{ border: 1px solid #ddd; border-radius: 4px; margin: 0.5rem 0;
  padding: 0.4rem 0.75rem; }}
details.mc summary {{ cursor: pointer; font-weight: 600; }}
.mc-crit {{ margin: 0.6rem 0; }}
ul.mc-list {{ list-style: none; margin: 0.3rem 0 0.6rem; padding-left: 0.5rem;
  font-size: 0.9rem; }}
ul.mc-list li {{ padding: 0.1rem 0; }}
</style>
</head>
<body>
<h1>{title}</h1>
{subtitle}
{generated}
<p class="disclaimer">{disclaimer}</p>
<h2>{h_summary}</h2>
<p>{pages_audited}</p>
<ul>{url_items}</ul>
<table class="summary">
<tr><th>{h_in_scope}</th><td>{total_in_scope}</td></tr>
<tr><th>{h_automatable}</th>
  <td>{full} / {partial} / {manual}</td></tr>
<tr><th>{h_with_findings}</th><td>{with_findings}</td></tr>
<tr><th>{h_priority}</th><td>{priority_counts}</td></tr>
<tr><th>{h_findings}</th><td>{severity_counts}</td></tr>
</table>
<h2>{h_coverage}</h2>
{coverage}
<h2>{h_overview}</h2>
{triage}
<h2>{h_findings}</h2>
{sections}
{reading_view}
{checklist}
</body>
</html>
"""


def render_jira_tickets(document: ReportDocument) -> dict[str, str]:
    """Render one JIRA-style ticket (Markdown) per criterion with findings.

    Returns a mapping of relative filename (e.g.
    ``1.4.3-contrast-minimum.md``) to ticket body — one ticket per *type*
    of issue (WCAG criterion), each a self-contained work item with fields,
    the affected elements, and acceptance criteria, in the document's
    language. Filenames use the English criterion name so they are stable
    across languages. Pure: no filesystem; the caller writes the files
    (into a ``jira/`` subfolder).
    """
    tickets: dict[str, str] = {}
    for report in document.criteria:
        name = f"{report.criterion.id}-{_jira_slug(report.criterion.name)}.md"
        tickets[name] = _jira_ticket(
            report, generated_at=document.generated_at, lang=document.lang
        )
    return tickets


def _jira_slug(name: str) -> str:
    """Filesystem-safe lowercase slug of a criterion name."""
    slug = "".join(c.lower() if c.isalnum() else "-" for c in name)
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug.strip("-") or "criterion"


def _jira_ticket(
    report: CriterionReport, *, generated_at: str | None, lang: str
) -> str:
    """Render one criterion's findings as a JIRA-style Markdown ticket.

    The title, ``Priority`` field, and labels carry the remediation band so
    the ticket slots into a backlog at the right rank. A ``needs-review``
    criterion is typed as a triage task (a candidate the tool cannot
    confirm), not a confirmed bug. Affected elements are grouped by page.
    Labels and the JIRA priority name stay in English (they are JIRA
    field values).
    """
    crit = report.criterion
    name = _name(lang, crit)
    findings = report.findings
    priority = report.priority
    urls: list[str] = []
    for finding in findings:
        if finding.url and finding.url not in urls:
            urls.append(finding.url)
    triage = report.status == "needs-review"
    params = {
        "id": crit.id,
        "name": name,
        "level": crit.level,
        "count": len(findings),
        "pages": len(urls),
    }

    labels = [
        "accessibility", "wcag", "wcag2.2", f"level-{crit.level}",
        crit.id, f"priority-{priority.key.lower()}",
    ]
    if triage:
        labels.append("needs-triage")

    lines = [
        f"# [{priority.key}] WCAG {crit.id} {name} — "
        + tr(lang, "{count} occurrence(s)", count=len(findings)),
        "",
    ]
    lines += [f"| {tr(lang, 'Field')} | {tr(lang, 'Value')} |", "| --- | --- |"]
    ticket_type = (
        tr(lang, "Accessibility review (candidate)")
        if triage
        else tr(lang, "Accessibility bug")
    )
    lines.append(f"| {tr(lang, 'Type')} | {ticket_type} |")
    lines.append(
        f"| {tr(lang, 'Priority')} | {priority.jira} "
        f"({priority.key} · {tr(lang, priority.label)}) |"
    )
    lines.append(
        f"| {tr(lang, 'WCAG 2.2 criterion')} | "
        + tr(lang, "{id} {name} (level {level})", **params)
        + " |"
    )
    lines.append(f"| {tr(lang, 'Automatability')} | {_tier(lang, crit.automatable)} |")
    lines.append(
        f"| {tr(lang, 'Occurrences')} | "
        + tr(lang, "{count} on {pages} page(s)", **params)
        + " |"
    )
    lines.append(f"| {tr(lang, 'Labels')} | {', '.join(labels)} |")
    lines += ["", f"## {tr(lang, 'Description')}", ""]
    if triage:
        lines.append(
            tr(
                lang,
                "WCAG 2.2 **{id} {name}** (level {level}) needs a human "
                "decision: the automated audit flagged {count} candidate(s) "
                "across {pages} page(s) but cannot confirm this criterion on "
                "its own. Triage each, then fix or dismiss.",
                **params,
            )
        )
    else:
        lines.append(
            tr(
                lang,
                "WCAG 2.2 success criterion **{id} {name}** (level {level}) is "
                "not satisfied. The automated audit flagged {count} "
                "occurrence(s) across {pages} page(s).",
                **params,
            )
        )
    lines += ["", f"## {tr(lang, 'Affected elements')}", ""]
    for url in urls:
        lines.append(f"### {url}")
        for finding in findings:
            if finding.url != url:
                continue
            evidence = (
                f" — [{tr(lang, 'evidence')}]({finding.screenshot})"
                if finding.screenshot
                else ""
            )
            impact = (
                " _("
                + tr(lang, "impact: {impact}", impact=_impact(lang, finding.impact))
                + ")_"
                if finding.impact
                else ""
            )
            lines.append(
                f"- **{_sev(lang, finding.severity)}**{impact} "
                f"`{finding.selector or _page(lang)}` — {finding.message}{evidence}"
            )
        lines.append("")
    lines += [f"## {tr(lang, 'Acceptance criteria')}", ""]
    lines.append(
        "- [ ] "
        + tr(lang, "Every element above satisfies WCAG 2.2 {id} {name}.", **params)
    )
    lines.append(
        "- [ ] " + tr(lang, "A re-run of the audit reports no findings for this criterion.")
    )
    if triage or crit.automatable != "full":
        lines.append(
            "- [ ] "
            + tr(
                lang,
                "A person has confirmed this criterion — the tool flags "
                "candidates here but cannot decide it on its own.",
            )
        )
    lines.append("")
    footer = (
        tr(lang, "Generated by wcag-checker at {when}.", when=generated_at)
        if generated_at
        else tr(lang, "Generated by wcag-checker.")
    )
    lines.append(f"> {footer} {tr(lang, DISCLAIMER)}")
    return "\n".join(lines).rstrip() + "\n"


__all__ = [
    "COVERAGE_LEGEND",
    "CoverageRow",
    "CoverageSummary",
    "CriterionReport",
    "DISCLAIMER",
    "PRIORITY_BANDS",
    "Priority",
    "ReportDocument",
    "RunStatus",
    "Status",
    "build_report",
    "render_html",
    "render_jira_tickets",
    "render_json",
    "render_markdown",
    "render_text",
]
