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

"""Run the axe-core engine on a live page and normalize its output.

Wraps ``axe-selenium-python`` (which bundles axe-core) and turns its
``violations`` and ``incomplete`` results into :class:`~.core.Finding`
objects addressed to WCAG 2.2 success criteria.

Coverage honesty (see :mod:`.core`): axe-core tags every result with the
criteria it implicates (e.g. ``wcag111`` → 1.1.1). This module maps those
tags onto the registry and emits nothing axe-core cannot decide. Results
carrying no ``wcag*`` criterion tag — axe "best-practice" rules and other
non-WCAG heuristics — are dropped rather than mislabelled as a WCAG
finding. axe ``incomplete`` results (axe could not decide on its own)
become ``"needs-review"`` findings, never passes.

Single owner per criterion: 2.5.8 Target Size (Minimum) is measured by
this tool's dedicated :func:`.keyboard_nav.check_target_size`, so any axe
result mapping to 2.5.8 is dropped here (see
:data:`_CRITERIA_OWNED_ELSEWHERE`) to avoid reporting the same criterion
from two engines. axe-core 4.10.2 ships its ``target-size`` rule disabled
by default, so this is latent today, but the drop keeps it from
surfacing if a future axe release enables that rule.

Boundary: takes a live driver from the caller and runs against it. It
never launches, configures, or closes the browser session — that belongs
to the capture/session layer.
"""

from __future__ import annotations

from typing import Any

from .core import CRITERIA_BY_ID, Finding, Severity

#: The WCAG 2.2 AA tag set passed to axe-core's ``runOnly`` filter, so a
#: run reports only the criteria this tool audits (levels A and AA across
#: WCAG 2.0, 2.1, and 2.2) instead of axe's full rule set including AAA
#: and best-practice heuristics.
AA_TAG_SET: tuple[str, ...] = (
    "wcag2a",
    "wcag2aa",
    "wcag21a",
    "wcag21aa",
    "wcag22aa",
)

#: axe impact levels that count as a definite failure worth an ``"error"``;
#: lower-impact violations are still definite failures but reported as
#: ``"warning"`` (see :data:`~.core.Severity`).
_ERROR_IMPACTS = frozenset({"critical", "serious"})

#: Criteria that a dedicated :mod:`.keyboard_nav` check owns end to end;
#: axe results mapping to them are dropped so the criterion is reported
#: by exactly one engine. 2.5.8 Target Size (Minimum) is measured by
#: :func:`.keyboard_nav.check_target_size` (24×24 CSS-px with the inline
#: exception); axe's own ``target-size`` rule (tagged ``wcag258``) would
#: otherwise double-report it if enabled.
_CRITERIA_OWNED_ELSEWHERE = frozenset({"2.5.8"})


def audit(driver: Any, url: str | None = None) -> list[Finding]:
    """Inject axe-core, run the AA rule set, and normalize the results.

    ``driver`` is a live Selenium WebDriver on the page to audit; the
    caller owns its lifecycle. ``url`` labels the findings; when omitted
    it is read from ``driver.current_url``.

    Side effect: injects and executes axe-core JavaScript in the current
    browsing context. Returns the findings (possibly empty); an empty
    list means no automatable defect was detected, never that the page
    conforms.
    """
    page_url = url if url is not None else driver.current_url
    results = run_axe(driver)
    return normalize_results(results, page_url)


def run_axe(driver: Any) -> dict[str, Any]:
    """Inject axe-core into ``driver`` and return its raw results dict.

    Restricts the run to :data:`AA_TAG_SET`. Imports
    ``axe-selenium-python`` lazily so the pure normalization helpers in
    this module stay importable — and testable — without a browser stack
    installed. Side effect: executes JavaScript on the live driver.
    """
    from axe_selenium_python import Axe

    axe = Axe(driver)
    axe.inject()
    return axe.run(options={"runOnly": {"type": "tag", "values": list(AA_TAG_SET)}})


def normalize_results(results: dict[str, Any], url: str) -> list[Finding]:
    """Convert a raw axe results dict into a flat list of findings.

    Pure. ``results`` is the structure returned by ``Axe.run`` (with
    ``"violations"`` and ``"incomplete"`` lists). Violations map to
    ``"error"``/``"warning"`` by axe impact; incomplete results map to
    ``"needs-review"``. Each result is expanded to one finding per
    offending node per WCAG criterion its tags implicate; results whose
    tags map to no registered criterion are skipped.
    """
    findings: list[Finding] = []
    for result in results.get("violations", ()):
        findings.extend(_findings_for_result(result, url, incomplete=False))
    for result in results.get("incomplete", ()):
        findings.extend(_findings_for_result(result, url, incomplete=True))
    return findings


def _findings_for_result(
    result: dict[str, Any], url: str, *, incomplete: bool
) -> list[Finding]:
    """Expand one axe result into findings, one per node per criterion."""
    criteria = [
        c
        for c in criteria_from_tags(result.get("tags", ()))
        if c not in _CRITERIA_OWNED_ELSEWHERE
    ]
    if not criteria:
        return []

    impact = result.get("impact")
    severity: Severity = (
        "needs-review" if incomplete else _impact_to_severity(impact)
    )
    nodes = result.get("nodes") or ({},)
    findings: list[Finding] = []
    for node in nodes:
        message = _build_message(result, node, incomplete=incomplete)
        selector = _node_selector(node)
        for criterion_id in criteria:
            findings.append(
                Finding(
                    criterion=criterion_id,
                    severity=severity,
                    message=message,
                    selector=selector,
                    url=url,
                    impact=impact if isinstance(impact, str) else None,
                )
            )
    return findings


def criteria_from_tags(tags: object) -> list[str]:
    """Return the registered WCAG criterion ids implied by axe ``tags``.

    Preserves tag order and drops duplicates and any tag that does not
    resolve to a criterion in the registry (level tags like ``wcag2aa``,
    best-practice tags, categories like ``cat.color``).
    """
    seen: dict[str, None] = {}
    for tag in tags if isinstance(tags, (list, tuple)) else ():
        criterion_id = _tag_to_criterion_id(tag)
        if criterion_id is not None:
            seen.setdefault(criterion_id, None)
    return list(seen)


def _tag_to_criterion_id(tag: object) -> str | None:
    """Map an axe ``wcag<digits>`` tag to a dotted criterion id, or None.

    axe encodes a criterion as ``wcag`` followed by the principle digit,
    the guideline digit, and the criterion number (one or two digits):
    ``wcag111`` → ``1.1.1``, ``wcag1410`` → ``1.4.10``. Level tags such
    as ``wcag2aa`` contain letters and are rejected. The result is
    returned only if it names a criterion in the registry.
    """
    if not isinstance(tag, str) or not tag.startswith("wcag"):
        return None
    digits = tag[len("wcag"):]
    if len(digits) < 3 or not digits.isdigit():
        return None
    criterion_id = f"{digits[0]}.{digits[1]}.{digits[2:]}"
    return criterion_id if criterion_id in CRITERIA_BY_ID else None


def _impact_to_severity(impact: object) -> Severity:
    """Map an axe violation ``impact`` string to a finding severity."""
    return "error" if impact in _ERROR_IMPACTS else "warning"


def _node_selector(node: dict[str, Any]) -> str | None:
    """Return a CSS selector for an axe node's ``target``, or None.

    axe's ``target`` is a list of selectors that descend through nested
    frames; they are joined so the finding points at the element even
    across a frame boundary.
    """
    target = node.get("target")
    if isinstance(target, (list, tuple)) and target:
        return " ".join(str(part) for part in target)
    return None


def _build_message(
    result: dict[str, Any], node: dict[str, Any], *, incomplete: bool
) -> str:
    """Compose a human-readable message from an axe result and node.

    Folds the source rule id, axe's help text, the per-node failure
    summary, and the help URL into one string so the finding carries its
    provenance without the caller re-reading the raw axe output.
    """
    rule_id = result.get("id", "unknown")
    prefix = "needs review" if incomplete else "violation"
    parts = [f"[{rule_id}] {prefix}: {result.get('help', '').strip()}"]

    summary = (node.get("failureSummary") or "").strip()
    if summary:
        parts.append(summary)

    help_url = (result.get("helpUrl") or "").strip()
    if help_url:
        parts.append(f"See {help_url}")

    return " — ".join(parts)


__all__ = [
    "AA_TAG_SET",
    "audit",
    "criteria_from_tags",
    "normalize_results",
    "run_axe",
]