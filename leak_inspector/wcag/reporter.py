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
registry and returns strings. It never touches the network, the driver,
or the filesystem — the CLI/session layer decides where to write the
output.

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

from .core import CRITERIA_REGISTRY, Finding, WcagCriterion, criterion

#: Per-criterion outcome derived from its findings. A criterion only
#: appears in a report when it has findings, so these are the only two
#: values — never a "pass", which the tool cannot assert.
Status = Literal["fail", "needs-review"]

#: The conformance target this tool audits: WCAG 2.2 levels A and AA.
#: AAA criteria are out of scope and excluded from the coverage counts.
_IN_SCOPE_LEVELS = frozenset({"A", "AA"})

#: Sort order for findings and status ranking (most severe first).
_SEVERITY_ORDER = {"error": 0, "warning": 1, "needs-review": 2}

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


@dataclass(frozen=True)
class CriterionReport:
    """One WCAG criterion together with the findings this run produced.

    ``criterion`` is the registry entry, ``status`` is ``"fail"`` when any
    finding is an error/warning and ``"needs-review"`` when the criterion
    has only unconfirmed (axe-incomplete) findings. ``findings`` is
    ordered most-severe first.
    """

    criterion: WcagCriterion
    status: Status
    findings: tuple[Finding, ...]


@dataclass(frozen=True)
class ReportDocument:
    """The full, format-agnostic audit result.

    ``criteria`` holds one :class:`CriterionReport` per criterion that had
    findings, sorted in WCAG numbering order. ``summary`` is the coverage
    context and ``generated_at`` an optional caller-supplied timestamp
    (this module never reads the clock, to stay pure and deterministic).
    """

    summary: CoverageSummary
    criteria: tuple[CriterionReport, ...]
    generated_at: str | None


def build_report(
    findings: Iterable[Finding],
    *,
    urls: Sequence[str] | None = None,
    generated_at: str | None = None,
) -> ReportDocument:
    """Fold a flat finding list into a grouped, summarized report.

    ``findings`` are grouped by their ``criterion`` id and each group is
    matched to a registry entry (findings whose id is not in the registry
    are dropped — they carry no criterion to report against). ``urls`` is
    the full set of pages audited, so a page that produced no finding is
    still recorded; when omitted it is inferred from the findings.
    ``generated_at`` is passed straight through to the renderers.
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
                findings=ordered,
            )
        )
    criteria.sort(key=lambda report: _criterion_sort_key(report.criterion.id))

    summary = _build_summary(
        criteria,
        audited_urls=_audited_urls(grouped, urls),
    )
    return ReportDocument(
        summary=summary,
        criteria=tuple(criteria),
        generated_at=generated_at,
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
    for report in criteria:
        for finding in report.findings:
            by_severity[finding.severity] += 1

    return CoverageSummary(
        urls=audited_urls,
        total_in_scope=len(in_scope),
        by_tier=by_tier,
        criteria_with_findings=len(criteria),
        findings_by_severity=by_severity,
    )


def _audited_urls(
    grouped: dict[str, list[Finding]], urls: Sequence[str] | None
) -> tuple[str, ...]:
    """Union the explicit audited URLs with those seen in findings."""
    seen = set(urls or ())
    for group in grouped.values():
        seen.update(f.url for f in group)
    return tuple(sorted(seen))


def _finding_sort_key(finding: Finding) -> tuple[int, str, str]:
    """Order findings most-severe first, then by URL and selector."""
    return (
        _SEVERITY_ORDER.get(finding.severity, 99),
        finding.url,
        finding.selector or "",
    )


def _criterion_sort_key(criterion_id: str) -> tuple[int, ...]:
    """Sort criterion ids numerically so ``1.4.10`` follows ``1.4.9``."""
    return tuple(int(part) for part in criterion_id.split("."))


# --- Renderers -------------------------------------------------------------


def render_json(document: ReportDocument) -> str:
    """Render the canonical ``results.json`` string.

    Stable key order, UTF-8 preserved, two-space indent. This is the
    authoritative machine-readable output; the other formats are derived
    views for humans.
    """
    payload = {
        "generated_at": document.generated_at,
        "disclaimer": DISCLAIMER,
        "summary": {
            "urls": list(document.summary.urls),
            "total_in_scope": document.summary.total_in_scope,
            "criteria_with_findings": document.summary.criteria_with_findings,
            "by_tier": document.summary.by_tier,
            "findings_by_severity": document.summary.findings_by_severity,
        },
        "criteria": [
            {
                "id": report.criterion.id,
                "name": report.criterion.name,
                "level": report.criterion.level,
                "automatable": report.criterion.automatable,
                "status": report.status,
                "findings": [
                    {
                        "severity": f.severity,
                        "message": f.message,
                        "selector": f.selector,
                        "url": f.url,
                    }
                    for f in report.findings
                ],
            }
            for report in document.criteria
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_text(document: ReportDocument) -> str:
    """Render a plain-text report for a terminal or a ``.txt`` sidecar."""
    summary = document.summary
    lines = ["WCAG 2.2 AA audit", "=================", ""]
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
    sev = summary.findings_by_severity
    lines.append(
        f"Findings: {sev['error']} error, {sev['warning']} warning, "
        f"{sev['needs-review']} needs-review"
    )
    lines.append("")
    lines.extend(textwrap.wrap(DISCLAIMER, width=76))
    lines.append("")

    lines += ["Findings by criterion", "---------------------"]
    if not document.criteria:
        lines.append("No automated findings.")
    for report in document.criteria:
        crit = report.criterion
        lines.append(
            f"{crit.id}  {crit.name}  "
            f"[{crit.level} · {crit.automatable}]  — {report.status.upper()}"
        )
        for finding in report.findings:
            lines.append(f"  [{finding.severity}] {finding.selector or '(page)'}")
            lines.append(f"      {finding.message}")
            lines.append(f"      {finding.url}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_markdown(document: ReportDocument) -> str:
    """Render a Markdown report suitable for a repo or an issue tracker."""
    summary = document.summary
    sev = summary.findings_by_severity
    lines = ["# WCAG 2.2 AA audit", ""]
    if document.generated_at:
        lines.append(f"_Generated: {document.generated_at}_")
        lines.append("")

    lines.append("## Coverage summary")
    lines.append("")
    lines.append(f"**Pages audited ({len(summary.urls)}):**")
    lines.extend(f"- {url}" for url in summary.urls)
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| A + AA criteria in scope | {summary.total_in_scope} |")
    lines.append(f"| Automatable (full) | {summary.by_tier['full']} |")
    lines.append(f"| Automatable (partial) | {summary.by_tier['partial']} |")
    lines.append(f"| Manual only | {summary.by_tier['manual']} |")
    lines.append(f"| Criteria with findings | {summary.criteria_with_findings} |")
    lines.append(
        f"| Findings | {sev['error']} error / {sev['warning']} warning / "
        f"{sev['needs-review']} needs-review |"
    )
    lines.append("")
    lines.append(f"> {DISCLAIMER}")
    lines.append("")

    lines.append("## Findings by criterion")
    lines.append("")
    if not document.criteria:
        lines.append("No automated findings.")
        lines.append("")
    for report in document.criteria:
        crit = report.criterion
        lines.append(
            f"### {crit.id} {crit.name} "
            f"({crit.level} · {crit.automatable}) — {report.status.upper()}"
        )
        lines.append("")
        for finding in report.findings:
            lines.append(
                f"- **{finding.severity}** `{finding.selector or '(page)'}` — "
                f"{finding.message} ({finding.url})"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_html(document: ReportDocument) -> str:
    """Render a self-contained HTML page (inline CSS, no external assets)."""
    summary = document.summary
    sev = summary.findings_by_severity

    url_items = "".join(f"<li>{html.escape(u)}</li>" for u in summary.urls)
    generated = (
        f"<p class='meta'>Generated: {html.escape(document.generated_at)}</p>"
        if document.generated_at
        else ""
    )

    sections: list[str] = []
    if not document.criteria:
        sections.append("<p>No automated findings.</p>")
    for report in document.criteria:
        crit = report.criterion
        rows = "".join(
            "<tr class='sev-{sev}'>"
            "<td>{sev}</td><td><code>{sel}</code></td>"
            "<td>{msg}</td><td>{url}</td></tr>".format(
                sev=html.escape(f.severity),
                sel=html.escape(f.selector or "(page)"),
                msg=html.escape(f.message),
                url=html.escape(f.url),
            )
            for f in report.findings
        )
        sections.append(
            "<section>"
            f"<h3>{html.escape(crit.id)} {html.escape(crit.name)} "
            f"<span class='tag'>{html.escape(crit.level)} · "
            f"{html.escape(crit.automatable)}</span> "
            f"<span class='status {report.status}'>"
            f"{html.escape(report.status.upper())}</span></h3>"
            "<table><thead><tr><th>Severity</th><th>Element</th>"
            "<th>Message</th><th>URL</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></section>"
        )

    return _HTML_TEMPLATE.format(
        generated=generated,
        url_count=len(summary.urls),
        url_items=url_items,
        total_in_scope=summary.total_in_scope,
        full=summary.by_tier["full"],
        partial=summary.by_tier["partial"],
        manual=summary.by_tier["manual"],
        with_findings=summary.criteria_with_findings,
        errors=sev["error"],
        warnings=sev["warning"],
        review=sev["needs-review"],
        disclaimer=html.escape(DISCLAIMER),
        sections="".join(sections),
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
.meta {{ color: #555; }}
.disclaimer {{ background: #fff8e1; border-left: 4px solid #f0ad4e;
  padding: 0.75rem 1rem; margin: 1rem 0; }}
table {{ border-collapse: collapse; width: 100%; margin: 0.5rem 0 1.5rem; }}
th, td {{ border: 1px solid #ddd; padding: 0.4rem 0.6rem; text-align: left;
  vertical-align: top; font-size: 0.9rem; }}
th {{ background: #f4f4f4; }}
code {{ font-size: 0.85em; word-break: break-all; }}
.summary td, .summary th {{ white-space: nowrap; }}
.tag {{ font-size: 0.75rem; color: #555; font-weight: normal; }}
.status {{ font-size: 0.75rem; padding: 0.1rem 0.4rem; border-radius: 3px; }}
.status.fail {{ background: #f8d7da; color: #842029; }}
.status.needs-review {{ background: #fff3cd; color: #664d03; }}
.sev-error td:first-child {{ color: #842029; font-weight: bold; }}
.sev-warning td:first-child {{ color: #664d03; font-weight: bold; }}
.sev-needs-review td:first-child {{ color: #055160; }}
</style>
</head>
<body>
<h1>WCAG 2.2 AA audit</h1>
{generated}
<p class="disclaimer">{disclaimer}</p>
<h2>Coverage summary</h2>
<p>Pages audited ({url_count}):</p>
<ul>{url_items}</ul>
<table class="summary">
<tr><th>A + AA criteria in scope</th><td>{total_in_scope}</td></tr>
<tr><th>Automatable (full)</th><td>{full}</td></tr>
<tr><th>Automatable (partial)</th><td>{partial}</td></tr>
<tr><th>Manual only</th><td>{manual}</td></tr>
<tr><th>Criteria with findings</th><td>{with_findings}</td></tr>
<tr><th>Findings</th><td>{errors} error / {warnings} warning /
  {review} needs-review</td></tr>
</table>
<h2>Findings by criterion</h2>
{sections}
</body>
</html>
"""


__all__ = [
    "CoverageSummary",
    "CriterionReport",
    "DISCLAIMER",
    "ReportDocument",
    "Status",
    "build_report",
    "render_html",
    "render_json",
    "render_markdown",
    "render_text",
]
