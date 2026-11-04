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

"""Reflow check at a 320 CSS-px viewport (**1.4.10 Reflow**).

WCAG 1.4.10 requires that content reflow to a single column at a viewport
width of 320 CSS px (equivalent to 400% zoom on a 1280px screen) without
the user having to scroll horizontally — except for parts that genuinely
need a two-dimensional layout (data tables, maps, toolbars, etc.).

The reliably automatable signal is exactly that horizontal scroll: at a
320px viewport, does the document's ``scrollWidth`` exceed its
``clientWidth``? If so, something is not reflowing. This module sets a
true 320px viewport via WebDriver BiDi
(``browsing_context.set_viewport`` — which reaches 320px even though a
Firefox *window* cannot go below ~500px), measures the overflow, and then
**restores** the operator's original viewport so an interactive session
continues undisturbed.

``1.4.10`` is a ``partial`` criterion (see :mod:`.core`): a positive
result is a strong candidate, but whether information or functionality is
actually *lost* — and whether an exempt 2-D component is the cause —
needs a human, so the finding is ``needs-review``. If BiDi viewport
control is unavailable, the check reports nothing rather than guessing
(the criterion still stands in the coverage table and manual checklist).

Design mirrors :mod:`.keyboard_nav`: an impure gatherer
(:func:`check_reflow`, which drives the live driver and mutates then
restores the viewport) and a pure evaluator (:func:`evaluate_reflow`) that
the hermetic tests exercise. Boundary: takes a live driver from the
caller; never launches or closes it.
"""

from __future__ import annotations

from contextlib import suppress
from typing import Any

from .core import Finding

#: The WCAG 1.4.10 reflow width in CSS pixels.
REFLOW_WIDTH = 320

#: Viewport height used while measuring — irrelevant to horizontal reflow,
#: but a value is required; tall enough not to force odd layouts.
_REFLOW_HEIGHT = 800

#: Ignore sub-pixel / scrollbar rounding: only treat the page as
#: horizontally scrolling when it overflows by more than this many pixels.
_OVERFLOW_TOLERANCE_PX = 1

_OVERFLOW_JS = (
    "return {scrollWidth: document.documentElement.scrollWidth, "
    "clientWidth: document.documentElement.clientWidth};"
)


def check_reflow(
    driver: Any, url: str | None = None, *, width: int = REFLOW_WIDTH
) -> list[Finding]:
    """Flag horizontal scrolling at a ``width``px viewport (1.4.10).

    ``driver`` is a live Selenium WebDriver on the page to test; the caller
    owns its lifecycle. ``url`` labels the finding; when omitted it is read
    from ``driver.current_url``. Side effect: briefly sets the viewport to
    ``width`` px (via BiDi) to measure, then restores the original
    viewport. Returns a single ``needs-review`` finding when the page
    scrolls horizontally at that width, else an empty list — which also
    covers the case where BiDi viewport control is unavailable.
    """
    page_url = url if url is not None else driver.current_url
    record = _measure_reflow(driver, width)
    if record is None:
        return []
    return evaluate_reflow(record, page_url, width=width)


def _measure_reflow(driver: Any, width: int) -> dict[str, int] | None:
    """Measure document width at a ``width``px viewport, then restore it.

    Returns ``{"scroll_width", "client_width"}`` or ``None`` when the
    viewport cannot be controlled (BiDi absent / call failed) — the audit
    must not break just because reflow could not be measured.
    """
    try:
        context = driver.current_window_handle
        before = driver.execute_script(
            "return {w: window.innerWidth, h: window.innerHeight};"
        )
        set_viewport = driver.browsing_context.set_viewport
    except Exception:
        return None

    try:
        set_viewport(
            context=context, viewport={"width": width, "height": _REFLOW_HEIGHT}
        )
        measured = driver.execute_script(_OVERFLOW_JS)
        return {
            "scroll_width": int(measured.get("scrollWidth", 0)),
            "client_width": int(measured.get("clientWidth", width)),
        }
    except Exception:
        return None
    finally:
        with suppress(Exception):
            set_viewport(
                context=context,
                viewport={"width": int(before["w"]), "height": int(before["h"])},
            )


def evaluate_reflow(
    record: dict[str, int], url: str, *, width: int = REFLOW_WIDTH
) -> list[Finding]:
    """Turn a reflow measurement into a 1.4.10 finding (pure).

    ``record`` has ``scroll_width`` and ``client_width`` (CSS px, measured
    at a ``width``px viewport). When the content is wider than the viewport
    by more than :data:`_OVERFLOW_TOLERANCE_PX`, the page scrolls
    horizontally at 320px — a reflow candidate reported ``needs-review``
    (the loss-of-content and 2-D-exemption judgements stay manual).
    """
    scroll_width = record.get("scroll_width", 0)
    client_width = record.get("client_width", width)
    if scroll_width <= client_width + _OVERFLOW_TOLERANCE_PX:
        return []
    return [
        Finding(
            criterion="1.4.10",
            severity="needs-review",
            message=(
                f"At a {width} CSS-px viewport the page content is "
                f"{scroll_width}px wide and scrolls horizontally (viewport "
                f"{client_width}px). WCAG 1.4.10 requires content to reflow to "
                "one column with no horizontal scrolling at 320px. Confirm — "
                "content that genuinely needs a two-dimensional layout (data "
                "tables, maps) is exempt."
            ),
            selector=None,
            url=url,
        )
    ]


__all__ = ["REFLOW_WIDTH", "check_reflow", "evaluate_reflow"]
