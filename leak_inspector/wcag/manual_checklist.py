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

"""Generate the human-review checklist for what tooling cannot decide.

The automated engines (:mod:`.axe_runner`, :mod:`.keyboard_nav`) cover
only the ``full``-tier substance of a subset of WCAG 2.2 AA. This module
enumerates the criteria that still need a person — every ``manual``-tier
criterion (no automated assertion is possible) and every ``partial``-tier
criterion (the tool flags candidates but a human must confirm) within the
level A + AA conformance target — and pre-fills them per audited route.

Pure and build-once/render-many, mirroring :mod:`.reporter`:
:func:`build_checklist` selects the criteria from the registry and pairs
them with the audited URLs; :func:`render_markdown` and
:func:`render_json` turn that into a ``manual-checklist.md`` (checkboxes,
grouped per page) and a machine-readable form. It is **not** a test
runner — it emits review tasks, never pass/fail results.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass

from .core import CRITERIA_REGISTRY, WcagCriterion

#: The conformance target: WCAG 2.2 levels A and AA (AAA is out of scope).
_IN_SCOPE_LEVELS = frozenset({"A", "AA"})

#: Tiers that require human review — everything the automated pass cannot
#: settle on its own. ``full``-tier criteria are excluded (axe decides
#: their automatable substance).
_REVIEW_TIERS = frozenset({"manual", "partial"})

#: Explains the checklist's standing, carried into every rendered format.
NOTE = (
    "These success criteria cannot be decided automatically. Confirm each "
    "one by hand on every page below. 'manual' criteria need human "
    "judgement outright; 'partial' criteria may also have candidate "
    "findings in the automated report — cross-check those. Completing this "
    "checklist is necessary, but on its own still not a conformance claim."
)


@dataclass(frozen=True)
class ManualChecklist:
    """The set of review criteria paired with the routes to check them on.

    ``criteria`` are the in-scope ``manual``/``partial`` success criteria
    in WCAG numbering order; ``urls`` are the audited routes each must be
    confirmed against. ``generated_at`` is an optional caller-supplied
    timestamp (this module never reads the clock, to stay deterministic).
    The criteria×routes matrix is left implicit here and expanded by the
    renderers, so the data model stays free of duplication.
    """

    criteria: tuple[WcagCriterion, ...]
    urls: tuple[str, ...]
    generated_at: str | None


def build_checklist(
    urls: Sequence[str],
    *,
    generated_at: str | None = None,
) -> ManualChecklist:
    """Select the review criteria and pair them with the audited routes.

    ``urls`` is the set of pages audited (deduplicated and sorted).
    Returns a :class:`ManualChecklist` holding every in-scope
    ``manual``/``partial`` criterion in WCAG numbering order.
    """
    criteria = tuple(
        c
        for c in CRITERIA_REGISTRY
        if c.level in _IN_SCOPE_LEVELS and c.automatable in _REVIEW_TIERS
    )
    return ManualChecklist(
        criteria=criteria,
        urls=tuple(sorted(set(urls))),
        generated_at=generated_at,
    )


def _by_tier(
    criteria: Sequence[WcagCriterion], tier: str
) -> list[WcagCriterion]:
    """Return the criteria of one automatability tier, in registry order."""
    return [c for c in criteria if c.automatable == tier]


def render_markdown(checklist: ManualChecklist) -> str:
    """Render the checklist as ``manual-checklist.md`` (checkboxes per page).

    Each audited route gets a section with two groups — criteria needing
    human judgement (``manual``) and criteria whose automated candidates
    must be confirmed (``partial``) — as unchecked task-list items.
    """
    manual = _by_tier(checklist.criteria, "manual")
    partial = _by_tier(checklist.criteria, "partial")

    lines = ["# WCAG 2.2 AA manual-review checklist", ""]
    if checklist.generated_at:
        lines.append(f"_Generated: {checklist.generated_at}_")
        lines.append("")
    lines.append(NOTE)
    lines.append("")
    lines.append(
        f"{len(checklist.criteria)} criteria to review "
        f"({len(manual)} manual, {len(partial)} partial) "
        f"across {len(checklist.urls)} page(s)."
    )
    lines.append("")

    if not checklist.urls:
        lines.append("_No pages were recorded to review._")
        return "\n".join(lines).rstrip() + "\n"

    for url in checklist.urls:
        lines.append(f"## {url}")
        lines.append("")
        lines.append("### Needs human judgement (manual)")
        lines.extend(_checkbox(c) for c in manual)
        lines.append("")
        lines.append("### Confirm automated candidates (partial)")
        lines.extend(_checkbox(c) for c in partial)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _checkbox(criterion: WcagCriterion) -> str:
    """Format one criterion as an unchecked Markdown task-list item."""
    return f"- [ ] {criterion.id} {criterion.name} ({criterion.level})"


def render_json(checklist: ManualChecklist) -> str:
    """Render the checklist as a machine-readable JSON string.

    Stable key order, two-space indent. Stores the criteria and routes
    once each; the review matrix is their product.
    """
    payload = {
        "generated_at": checklist.generated_at,
        "note": NOTE,
        "urls": list(checklist.urls),
        "criteria": [
            {
                "id": c.id,
                "name": c.name,
                "level": c.level,
                "tier": c.automatable,
            }
            for c in checklist.criteria
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


__all__ = [
    "ManualChecklist",
    "NOTE",
    "build_checklist",
    "render_json",
    "render_markdown",
]