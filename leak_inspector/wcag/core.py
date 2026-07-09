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

"""Driver-free WCAG data model and the WCAG 2.2 criteria registry.

This module is the shared vocabulary for the whole ``wcag`` package and
imports nothing browser- or driver-specific, so it stays reusable by
report tooling, tests, and any downstream consumer.

Two dataclasses:

* :class:`WcagCriterion` — one WCAG 2.2 success criterion, tagged with
  the level (A / AA / AAA) and the *automatability tier* that says how
  much of it a tool can decide on its own.
* :class:`Finding` — one accessibility issue produced by a check
  (axe-core or a keyboard-navigation probe), addressed to a criterion.

:data:`CRITERIA_REGISTRY` is the authoritative list of all 87 WCAG 2.2
success criteria. The ``automatable`` tier on each entry is the single
source of truth for coverage reporting — downstream code and reports
label their output from it instead of re-deriving what is and isn't
automatable.

Automatability tiers
--------------------
* ``"full"`` — a tool can decide the automatable substance of the
  criterion on its own (e.g. colour contrast, ``lang`` presence,
  name/role/value). A machine pass is meaningful evidence.
* ``"partial"`` — a tool can flag *candidates* but a human must
  confirm (e.g. link-text quality, reflow, target size, focus order).
* ``"manual"`` — needs human judgement; no assertion is emitted, only
  a checklist item (e.g. meaningful-vs-present alt text, error-message
  quality, plain language, media alternatives).

The tiers reflect what axe-core 4.10 plus this tool's
:mod:`.keyboard_nav` checks can actually determine; they describe
coverage, never conformance. A criterion marked ``"full"`` that passes
automatically is not proof of conformance — only that the automatable
part found no defect.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

#: WCAG conformance level of a success criterion.
Level = Literal["A", "AA", "AAA"]

#: How much of a criterion a tool can decide on its own — see the module
#: docstring for the meaning of each tier.
Automatable = Literal["full", "partial", "manual"]

#: Severity of a :class:`Finding`. ``"error"`` is a definite failure,
#: ``"warning"`` a lower-impact definite failure, and ``"needs-review"``
#: a candidate the tool cannot confirm on its own (axe "incomplete"
#: results and partial-tier keyboard checks land here).
Severity = Literal["error", "warning", "needs-review"]


@dataclass(frozen=True)
class WcagCriterion:
    """One WCAG 2.2 success criterion.

    ``id`` is the dotted number (e.g. ``"1.4.3"``), ``name`` its
    official title, ``level`` the conformance level, and ``automatable``
    the coverage tier (see the module docstring). Frozen because the
    registry is reference data that must not be mutated at runtime.
    """

    id: str
    name: str
    level: Level
    automatable: Automatable


@dataclass
class Finding:
    """One accessibility issue produced by an automated check.

    ``criterion`` is the WCAG 2.2 success-criterion id the issue maps to
    (e.g. ``"1.1.1"``), matching a :attr:`WcagCriterion.id` in the
    registry. ``severity`` is one of :data:`Severity`. ``message`` is a
    human-readable description (checks fold the source rule id and any
    help URL into it). ``selector`` is a CSS selector for the offending
    element when one applies, else ``None``. ``url`` is the page the
    finding was observed on.

    Checks return ``list[Finding]`` and never raise merely because they
    found issues — an empty list means "no issue detected", never
    "criterion satisfied".
    """

    criterion: str
    severity: Severity
    message: str
    selector: str | None
    url: str


# --- WCAG 2.2 success-criteria registry ------------------------------------
#
# All 87 WCAG 2.2 success criteria, in specification order. The
# ``automatable`` tier on each is the coverage claim this tool stands
# behind; keep it conservative — when unsure, prefer "manual" over
# over-claiming "full" (a false green is worse than an honest checklist
# item). See the module docstring for tier definitions.

CRITERIA_REGISTRY: tuple[WcagCriterion, ...] = (
    # -- Principle 1: Perceivable -------------------------------------------
    WcagCriterion("1.1.1", "Non-text Content", "A", "full"),
    WcagCriterion("1.2.1", "Audio-only and Video-only (Prerecorded)", "A", "manual"),
    WcagCriterion("1.2.2", "Captions (Prerecorded)", "A", "manual"),
    WcagCriterion("1.2.3", "Audio Description or Media Alternative (Prerecorded)", "A", "manual"),
    WcagCriterion("1.2.4", "Captions (Live)", "AA", "manual"),
    WcagCriterion("1.2.5", "Audio Description (Prerecorded)", "AA", "manual"),
    WcagCriterion("1.2.6", "Sign Language (Prerecorded)", "AAA", "manual"),
    WcagCriterion("1.2.7", "Extended Audio Description (Prerecorded)", "AAA", "manual"),
    WcagCriterion("1.2.8", "Media Alternative (Prerecorded)", "AAA", "manual"),
    WcagCriterion("1.2.9", "Audio-only (Live)", "AAA", "manual"),
    WcagCriterion("1.3.1", "Info and Relationships", "A", "full"),
    WcagCriterion("1.3.2", "Meaningful Sequence", "A", "partial"),
    WcagCriterion("1.3.3", "Sensory Characteristics", "A", "manual"),
    WcagCriterion("1.3.4", "Orientation", "AA", "full"),
    WcagCriterion("1.3.5", "Identify Input Purpose", "AA", "full"),
    WcagCriterion("1.3.6", "Identify Purpose", "AAA", "manual"),
    WcagCriterion("1.4.1", "Use of Color", "A", "partial"),
    WcagCriterion("1.4.2", "Audio Control", "A", "manual"),
    WcagCriterion("1.4.3", "Contrast (Minimum)", "AA", "full"),
    WcagCriterion("1.4.4", "Resize Text", "AA", "partial"),
    WcagCriterion("1.4.5", "Images of Text", "AA", "manual"),
    WcagCriterion("1.4.6", "Contrast (Enhanced)", "AAA", "full"),
    WcagCriterion("1.4.7", "Low or No Background Audio", "AAA", "manual"),
    WcagCriterion("1.4.8", "Visual Presentation", "AAA", "manual"),
    WcagCriterion("1.4.9", "Images of Text (No Exception)", "AAA", "manual"),
    WcagCriterion("1.4.10", "Reflow", "AA", "partial"),
    WcagCriterion("1.4.11", "Non-text Contrast", "AA", "partial"),
    WcagCriterion("1.4.12", "Text Spacing", "AA", "partial"),
    WcagCriterion("1.4.13", "Content on Hover or Focus", "AA", "manual"),
    # -- Principle 2: Operable ----------------------------------------------
    WcagCriterion("2.1.1", "Keyboard", "A", "manual"),
    WcagCriterion("2.1.2", "No Keyboard Trap", "A", "partial"),
    WcagCriterion("2.1.3", "Keyboard (No Exception)", "AAA", "manual"),
    WcagCriterion("2.1.4", "Character Key Shortcuts", "A", "manual"),
    WcagCriterion("2.2.1", "Timing Adjustable", "A", "partial"),
    WcagCriterion("2.2.2", "Pause, Stop, Hide", "A", "partial"),
    WcagCriterion("2.2.3", "No Timing", "AAA", "manual"),
    WcagCriterion("2.2.4", "Interruptions", "AAA", "manual"),
    WcagCriterion("2.2.5", "Re-authenticating", "AAA", "manual"),
    WcagCriterion("2.2.6", "Timeouts", "AAA", "manual"),
    WcagCriterion("2.3.1", "Three Flashes or Below Threshold", "A", "manual"),
    WcagCriterion("2.3.2", "Three Flashes", "AAA", "manual"),
    WcagCriterion("2.3.3", "Animation from Interactions", "AAA", "manual"),
    WcagCriterion("2.4.1", "Bypass Blocks", "A", "full"),
    WcagCriterion("2.4.2", "Page Titled", "A", "full"),
    WcagCriterion("2.4.3", "Focus Order", "A", "partial"),
    WcagCriterion("2.4.4", "Link Purpose (In Context)", "A", "partial"),
    WcagCriterion("2.4.5", "Multiple Ways", "AA", "manual"),
    WcagCriterion("2.4.6", "Headings and Labels", "AA", "partial"),
    WcagCriterion("2.4.7", "Focus Visible", "AA", "partial"),
    WcagCriterion("2.4.8", "Location", "AAA", "manual"),
    WcagCriterion("2.4.9", "Link Purpose (Link Only)", "AAA", "partial"),
    WcagCriterion("2.4.10", "Section Headings", "AAA", "manual"),
    WcagCriterion("2.4.11", "Focus Not Obscured (Minimum)", "AA", "partial"),
    WcagCriterion("2.4.12", "Focus Not Obscured (Enhanced)", "AAA", "manual"),
    WcagCriterion("2.4.13", "Focus Appearance", "AAA", "manual"),
    WcagCriterion("2.5.1", "Pointer Gestures", "A", "manual"),
    WcagCriterion("2.5.2", "Pointer Cancellation", "A", "manual"),
    WcagCriterion("2.5.3", "Label in Name", "A", "partial"),
    WcagCriterion("2.5.4", "Motion Actuation", "A", "manual"),
    WcagCriterion("2.5.5", "Target Size (Enhanced)", "AAA", "partial"),
    WcagCriterion("2.5.6", "Concurrent Input Mechanisms", "AAA", "manual"),
    WcagCriterion("2.5.7", "Dragging Movements", "AA", "manual"),
    WcagCriterion("2.5.8", "Target Size (Minimum)", "AA", "partial"),
    # -- Principle 3: Understandable ----------------------------------------
    WcagCriterion("3.1.1", "Language of Page", "A", "full"),
    WcagCriterion("3.1.2", "Language of Parts", "AA", "partial"),
    WcagCriterion("3.1.3", "Unusual Words", "AAA", "manual"),
    WcagCriterion("3.1.4", "Abbreviations", "AAA", "manual"),
    WcagCriterion("3.1.5", "Reading Level", "AAA", "manual"),
    WcagCriterion("3.1.6", "Pronunciation", "AAA", "manual"),
    WcagCriterion("3.2.1", "On Focus", "A", "manual"),
    WcagCriterion("3.2.2", "On Input", "A", "manual"),
    WcagCriterion("3.2.3", "Consistent Navigation", "AA", "manual"),
    WcagCriterion("3.2.4", "Consistent Identification", "AA", "manual"),
    WcagCriterion("3.2.5", "Change on Request", "AAA", "manual"),
    WcagCriterion("3.2.6", "Consistent Help", "A", "manual"),
    WcagCriterion("3.3.1", "Error Identification", "A", "manual"),
    WcagCriterion("3.3.2", "Labels or Instructions", "A", "partial"),
    WcagCriterion("3.3.3", "Error Suggestion", "AA", "manual"),
    WcagCriterion("3.3.4", "Error Prevention (Legal, Financial, Data)", "AA", "manual"),
    WcagCriterion("3.3.5", "Help", "AAA", "manual"),
    WcagCriterion("3.3.6", "Error Prevention (All)", "AAA", "manual"),
    WcagCriterion("3.3.7", "Redundant Entry", "A", "manual"),
    WcagCriterion("3.3.8", "Accessible Authentication (Minimum)", "AA", "manual"),
    WcagCriterion("3.3.9", "Accessible Authentication (Enhanced)", "AAA", "manual"),
    # -- Principle 4: Robust ------------------------------------------------
    WcagCriterion("4.1.1", "Parsing", "A", "full"),
    WcagCriterion("4.1.2", "Name, Role, Value", "A", "full"),
    WcagCriterion("4.1.3", "Status Messages", "AA", "partial"),
)

#: The WCAG 2.2 recommendation defines exactly this many success criteria.
#: A registry test pins the count so an accidental add/drop is caught.
WCAG_22_CRITERIA_COUNT = 87

#: Registry indexed by criterion id for O(1) lookup.
CRITERIA_BY_ID: dict[str, WcagCriterion] = {c.id: c for c in CRITERIA_REGISTRY}


def criterion(criterion_id: str) -> WcagCriterion | None:
    """Return the :class:`WcagCriterion` for ``criterion_id``, or ``None``.

    ``None`` means the id is not a recognised WCAG 2.2 success criterion
    (e.g. a finding tagged with a best-practice rule that maps to no
    single criterion) — callers decide how to present such findings.
    """
    return CRITERIA_BY_ID.get(criterion_id)


__all__ = [
    "Automatable",
    "CRITERIA_BY_ID",
    "CRITERIA_REGISTRY",
    "Finding",
    "Level",
    "Severity",
    "WCAG_22_CRITERIA_COUNT",
    "WcagCriterion",
    "criterion",
]