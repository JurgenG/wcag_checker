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

Each criterion carries a short, ordered list of concrete review
questions (:data:`QUESTIONS`) so the checklist walks a person step by
step through *how* to check it, not merely *which* criteria remain. A
question that starts with an applicability gate ("If not, mark N/A.")
lets the reviewer skip criteria that do not apply to the page.

Pure and build-once/render-many, mirroring :mod:`.reporter`:
:func:`build_checklist` selects the criteria from the registry and pairs
them with the audited URLs; :func:`render_markdown` and
:func:`render_json` turn that into a ``manual-checklist.md`` (each
criterion a heading with its questions as checkboxes, per page) and a
machine-readable form. It is **not** a test runner — it emits review
tasks, never pass/fail results.
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

#: Ordered, concrete review questions per success criterion, keyed by
#: criterion id. Each list walks a reviewer through *how* to check that
#: criterion on the page; where a criterion only applies conditionally,
#: the first question gates it ("If not, mark N/A."). A companion test
#: pins that every in-scope manual/partial criterion has an entry and
#: that no entry names a criterion outside that set, so the data cannot
#: drift from the registry.
QUESTIONS: dict[str, tuple[str, ...]] = {
    "1.2.1": (
        "Does the page contain prerecorded audio-only or video-only media? (If not, mark N/A.)",
        "For audio-only, is an equivalent text transcript provided?",
        "For video-only, is a text or audio description of the visual content provided?",
    ),
    "1.2.2": (
        "Does the page contain prerecorded video with audio? (If not, mark N/A.)",
        "Are synchronized captions provided for all dialogue and important sounds?",
    ),
    "1.2.3": (
        "Does the page contain prerecorded video with audio? (If not, mark N/A.)",
        "Is an audio description of the important visual detail, or a full text alternative, provided?",
    ),
    "1.2.4": (
        "Does the page stream live audio content? (If not, mark N/A.)",
        "Are real-time captions provided for that live audio?",
    ),
    "1.2.5": (
        "Does the page contain prerecorded video with audio? (If not, mark N/A.)",
        "Is a synchronized audio description track provided for visual information the soundtrack does not convey?",
    ),
    "1.3.2": (
        "Linearize the page (disable CSS): does the content still read in a meaningful order?",
        "Does the DOM order match the intended reading order assistive tech would follow?",
    ),
    "1.3.3": (
        "Do any instructions rely only on shape, size, or position (e.g. 'the round button', 'the box on the right')?",
        "Do any instructions rely only on colour or sound? (cross-check 1.4.1)",
        "Is every such instruction also given in a form that does not require seeing the layout?",
    ),
    "1.4.1": (
        "Is colour ever the only means of conveying information (required fields, links, error/success states)?",
        "Are in-text links distinguishable from surrounding text without relying on colour alone?",
        "Is each colour-coded state also signalled by text, icon, or shape?",
    ),
    "1.4.2": (
        "Does any audio play automatically for more than 3 seconds? (If none, mark N/A.)",
        "Is there a control to pause, stop, or mute it independently of the system volume?",
    ),
    "1.4.4": (
        "Zoom text to 200% (browser zoom): is all text still fully readable?",
        "Is any content or functionality clipped, overlapped, or lost at 200%?",
    ),
    "1.4.5": (
        "Are there images that render text, other than logos/wordmarks? (If none, mark N/A.)",
        "Could that text be presented as real, styleable text instead? If so, it should be.",
    ),
    "1.4.10": (
        "At 320 CSS px width (or 400% zoom), does content reflow to one column with no horizontal scrolling?",
        "Is any information or functionality lost when reflowed? (Data tables and maps are exempt.)",
    ),
    "1.4.11": (
        "Do UI component boundaries (button edges, field borders, focus indicators) meet 3:1 contrast against their surroundings?",
        "Do meaningful graphical objects (icons, chart segments) meet 3:1 contrast?",
    ),
    "1.4.12": (
        "Apply the WCAG text-spacing overrides (line 1.5×, paragraph 2×, letter 0.12em, word 0.16em): does any text clip or overlap?",
        "Is all content and functionality still available after the spacing change?",
    ),
    "1.4.13": (
        "Does hovering or focusing reveal extra content (tooltips, popovers, menus)? (If none, mark N/A.)",
        "Can it be dismissed without moving the pointer or focus (e.g. pressing Esc)?",
        "Does it stay visible while hovered/focused and remain until dismissed?",
    ),
    "2.1.1": (
        "Can you operate every interactive control using the keyboard alone?",
        "Is any action available only by mouse/pointer (hover-only, drag-only)?",
    ),
    "2.1.2": (
        "Tab through the whole page: can focus always move away from every component with the keyboard alone?",
        "Do modals and embedded widgets let you leave via keyboard (Esc or Tab)? (cross-check the automated finding)",
    ),
    "2.1.4": (
        "Are there single-character key shortcuts (letter, number, or punctuation)? (If none, mark N/A.)",
        "Can they be turned off, remapped, or made active only when the relevant control has focus?",
    ),
    "2.2.1": (
        "Does the page impose any time limit (session timeout, auto-advance, countdown)? (If none, mark N/A.)",
        "Can the user turn off, adjust, or extend the limit before it expires?",
    ),
    "2.2.2": (
        "Is there moving, blinking, scrolling, or auto-updating content lasting more than 5 seconds? (If none, mark N/A.)",
        "Can the user pause, stop, or hide it?",
    ),
    "2.3.1": (
        "Does any content flash more than three times in one second? (If none, mark N/A.)",
        "If it flashes, is the flashing area small and below the general and red-flash thresholds?",
    ),
    "2.4.3": (
        "Tab through the page: does focus move in an order that preserves meaning and operability?",
        "After opening a menu or modal, does focus move into it and return sensibly? (cross-check the automated finding)",
    ),
    "2.4.4": (
        "For each link, is its purpose clear from the link text alone or with its surrounding context?",
        "Are there ambiguous links ('click here', 'read more') whose destination is unclear in context?",
    ),
    "2.4.5": (
        "Is there more than one way to locate this page in the site (search, sitemap, nav menu, A–Z index)? (Exempt if it is a step in a process.)",
        "Do those ways actually lead to this page?",
    ),
    "2.4.6": (
        "Does each heading describe the topic or purpose of the section it introduces?",
        "Does each form label describe the purpose of its control? (cross-check the automated finding)",
    ),
    "2.4.7": (
        "Tab through the page: is the keyboard focus indicator visible on every focused element?",
        "Is there any control where the focus indicator disappears? (cross-check the automated finding)",
    ),
    "2.4.11": (
        "When an element receives focus, is it at least partially visible (not fully hidden behind sticky headers, footers, or overlays)?",
        "Check components near the viewport edges especially. (cross-check the automated finding)",
    ),
    "2.5.1": (
        "Does any function require a multipoint or path-based gesture (pinch, two-finger, swipe along a path)? (If none, mark N/A.)",
        "Is there a single-pointer alternative (e.g. a button) for that function?",
    ),
    "2.5.2": (
        "For single-pointer actions, does activation happen on the up-event rather than the down-event?",
        "Can the user abort by moving away before releasing, or undo the action afterwards?",
    ),
    "2.5.3": (
        "For controls with a visible text label, does the accessible name contain that visible text?",
        "Could a speech-input user activate the control by speaking its visible label? (cross-check the automated finding)",
    ),
    "2.5.4": (
        "Is any function triggered by device or user motion (shake, tilt)? (If none, mark N/A.)",
        "Is there a conventional control alternative, and can the motion actuation be disabled?",
    ),
    "2.5.7": (
        "Does any function require a dragging movement (sliders, drag-and-drop, reordering)? (If none, mark N/A.)",
        "Is there a single-tap or click alternative that does not require dragging?",
    ),
    "2.5.8": (
        "Are pointer targets at least 24×24 CSS px, or spaced so a 24px circle over one does not overlap a neighbour? (cross-check the automated finding)",
        "For any under-size target, does an exception apply (inline in a sentence, essential, or browser-default styling)?",
    ),
    "3.1.2": (
        "Are there passages or phrases in a language different from the page's main language? (If none, mark N/A.)",
        "Does each such passage carry a correct lang attribute?",
    ),
    "3.2.1": (
        "Tab onto each control: does merely focusing it change context (open a window, move focus, submit a form)?",
        "Focusing a control should not, on its own, cause such a change.",
    ),
    "3.2.2": (
        "Change each form control's value (type, select, toggle): does that alone change context (auto-submit, navigate)?",
        "If a change of context does occur on input, were users warned beforehand?",
    ),
    "3.2.3": (
        "Do navigation components that repeat across pages appear in the same relative order each time?",
        "Compare this page against the other audited pages.",
    ),
    "3.2.4": (
        "Are components with the same function identified consistently (same name, icon, and label) across pages?",
        "Compare this page against the other audited pages.",
    ),
    "3.2.6": (
        "If a help mechanism exists (contact details, help link, chat), does it appear in the same relative order on every page that offers it?",
    ),
    "3.3.1": (
        "Trigger a form validation error: is the field in error identified and the problem described in text?",
        "Is the error conveyed by more than colour alone?",
    ),
    "3.3.2": (
        "Does every form field have a visible label or instruction explaining what to enter? (cross-check the automated finding)",
        "Are required fields and any expected format or example indicated?",
    ),
    "3.3.3": (
        "When a validation error is detected and a correction is known, is a suggestion offered to the user?",
        "(Exempt where suggesting a correction would jeopardise security or purpose.)",
    ),
    "3.3.4": (
        "Does the page create a legal commitment, complete a financial transaction, or modify/delete user data? (If not, mark N/A.)",
        "Is the submission reversible, checked for errors, or confirmable before it is finalised?",
    ),
    "3.3.7": (
        "In a multi-step process, is information the user already entered auto-populated or selectable rather than re-typed?",
        "(Exempt when re-entry is essential, e.g. confirming a password.)",
    ),
    "3.3.8": (
        "Does login require a cognitive function test (recalling a password, solving a puzzle, transcribing a text CAPTCHA)? (If none, mark N/A.)",
        "Is an accessible alternative provided (password-manager paste allowed, email link, biometric, or object-recognition CAPTCHA)?",
    ),
    "4.1.3": (
        "Do status messages (e.g. 'saved', result counts, form errors) appear without moving keyboard focus?",
        "Are they exposed via an appropriate role or aria-live region so assistive tech announces them? (cross-check the automated finding)",
    ),
}


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


def questions_for(criterion_id: str) -> tuple[str, ...]:
    """Return the review questions for a criterion, or an empty tuple.

    An empty tuple means no questions are authored for that id — which the
    completeness test forbids for any in-scope criterion, so in practice
    every criterion the checklist carries has at least one question.
    """
    return QUESTIONS.get(criterion_id, ())


def _tier_counts(criteria: Sequence[WcagCriterion]) -> tuple[int, int]:
    """Return the (manual, partial) criterion counts."""
    manual = sum(1 for c in criteria if c.automatable == "manual")
    return manual, len(criteria) - manual


def render_markdown(checklist: ManualChecklist) -> str:
    """Render the checklist as ``manual-checklist.md``.

    Each audited route gets a section; under it, every review criterion is
    a heading (id, name, level, tier) followed by its concrete review
    questions as unchecked task-list items, so a reviewer works through
    the questions page by page.
    """
    manual, partial = _tier_counts(checklist.criteria)

    lines = ["# WCAG 2.2 AA manual-review checklist", ""]
    if checklist.generated_at:
        lines.append(f"_Generated: {checklist.generated_at}_")
        lines.append("")
    lines.append(NOTE)
    lines.append("")
    lines.append(
        f"{len(checklist.criteria)} criteria to review "
        f"({manual} manual, {partial} partial) "
        f"across {len(checklist.urls)} page(s). Work through the questions "
        f"under each criterion for every page."
    )
    lines.append("")

    if not checklist.urls:
        lines.append("_No pages were recorded to review._")
        return "\n".join(lines).rstrip() + "\n"

    for url in checklist.urls:
        lines.append(f"## {url}")
        lines.append("")
        for criterion in checklist.criteria:
            lines.append(
                f"### {criterion.id} {criterion.name} "
                f"({criterion.level} · {criterion.automatable})"
            )
            lines.extend(f"- [ ] {q}" for q in questions_for(criterion.id))
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


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
                "questions": list(questions_for(c.id)),
            }
            for c in checklist.criteria
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


__all__ = [
    "ManualChecklist",
    "NOTE",
    "QUESTIONS",
    "build_checklist",
    "questions_for",
    "render_json",
    "render_markdown",
]