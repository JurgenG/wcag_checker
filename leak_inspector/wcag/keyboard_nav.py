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

"""Focus and keyboard-flow checks that axe-core deliberately skips.

Covers four success criteria that need a live, interactive browser —
things a static rule engine cannot decide:

* :func:`check_focus_visible` — **2.4.7 Focus Visible** and
  **2.4.11 Focus Not Obscured (Minimum)**.
* :func:`check_no_keyboard_trap` — **2.1.2 No Keyboard Trap**.
* :func:`check_tab_order` — **2.4.3 Focus Order**.
* :func:`check_target_size` — **2.5.8 Target Size (Minimum)**.

Every criterion here is a ``partial``-tier one (see :mod:`.core`): the
check surfaces *candidates* — an undersized target, a missing focus ring,
a positive ``tabindex``, focus that will not advance — and emits them as
``needs-review`` findings for a human to confirm. It never asserts a
pass, and it never reports a candidate as a definite failure.

Design: each check is split into an impure gatherer (``check_*``, which
drives the caller's live driver) and a pure evaluator (``evaluate_*``,
which turns the gathered data into findings). The evaluators are what the
hermetic tests exercise, with a known-good and known-bad fixture each.

Boundary (see the package docstring): these checks take a live driver
from the caller and run against it. They never launch, configure, or
close the browser. A check returns ``list[Finding]`` and only raises for
a real execution error (the page crashed, a script failed) — never
because it found an issue.
"""

from __future__ import annotations

from typing import Any

from .core import Finding

#: WCAG 2.2 minimum target size in CSS pixels (2.5.8).
MIN_TARGET_PX = 24

#: Computed-style properties compared before/after focus to decide whether
#: any visible focus indicator appeared (2.4.7).
_FOCUS_STYLE_KEYS = (
    "outlineStyle",
    "outlineWidth",
    "outlineColor",
    "boxShadow",
    "borderTopWidth",
    "borderTopColor",
    "backgroundColor",
    "textDecorationLine",
)

#: A page element focused this many times in a row while tabbing is
#: treated as a candidate keyboard trap (2.1.2) — focus is not advancing.
_STUCK_REPEAT = 3

#: Caps to keep a check bounded on pathological pages.
_MAX_ELEMENTS = 400
_MAX_TAB_PRESSES = 60

# --- Shared browser-side helpers -------------------------------------------
#
# Prepended to every injected script: a focusable-element selector, a
# visibility test, and a compact CSS-path builder so findings carry a
# selector that matches the one axe-core-style tooling would report.

_JS_HELPERS = r"""
const FOCUSABLE = 'a[href],area[href],button:not([disabled]),' +
  'input:not([disabled]):not([type=hidden]),select:not([disabled]),' +
  'textarea:not([disabled]),[tabindex]:not([tabindex="-1"]),' +
  '[contenteditable="true"],audio[controls],video[controls]';
function isVisible(el){
  if(!el.getClientRects().length) return false;
  const s=getComputedStyle(el);
  return s.visibility!=='hidden' && s.display!=='none';
}
function cssPath(el){
  if(!el || el.nodeType!==1) return null;
  if(el.id) return '#'+CSS.escape(el.id);
  const parts=[];
  while(el && el.nodeType===1 && el!==document.documentElement){
    let sel=el.tagName.toLowerCase();
    if(el.classList.length){
      sel += '.'+Array.from(el.classList).slice(0,2)
        .map(c=>CSS.escape(c)).join('.');
    }
    const parent=el.parentNode;
    if(parent){
      const sibs=Array.from(parent.children).filter(c=>c.tagName===el.tagName);
      if(sibs.length>1) sel += ':nth-of-type('+(sibs.indexOf(el)+1)+')';
    }
    parts.unshift(sel);
    el=parent;
  }
  return parts.join(' > ');
}
function focusable(){
  return Array.from(document.querySelectorAll(FOCUSABLE))
    .filter(isVisible).slice(0, %d);
}
""" % _MAX_ELEMENTS


# --- 2.4.7 Focus Visible / 2.4.11 Focus Not Obscured -----------------------

_FOCUS_VISIBLE_JS = _JS_HELPERS + r"""
function snap(el){
  const s=getComputedStyle(el);
  return {outlineStyle:s.outlineStyle,outlineWidth:s.outlineWidth,
    outlineColor:s.outlineColor,boxShadow:s.boxShadow,
    borderTopWidth:s.borderTopWidth,borderTopColor:s.borderTopColor,
    backgroundColor:s.backgroundColor,textDecorationLine:s.textDecorationLine};
}
const out=[];
for(const el of focusable()){
  const before=snap(el);
  try{ el.focus({preventScroll:true}); }catch(e){}
  const gotFocus=document.activeElement===el;
  const after=snap(el);
  let obscured=false;
  if(gotFocus){
    const r=el.getBoundingClientRect();
    const cx=r.left+r.width/2, cy=r.top+r.height/2;
    if(cx>=0 && cy>=0 && cx<=innerWidth && cy<=innerHeight){
      const top=document.elementFromPoint(cx,cy);
      obscured=!!(top && el!==top && !el.contains(top) && !top.contains(el));
    }
  }
  try{ el.blur(); }catch(e){}
  out.push({selector:cssPath(el), gotFocus:gotFocus,
    stylesBefore:before, stylesAfter:after, obscured:obscured});
}
return out;
"""


def check_focus_visible(driver: Any, url: str | None = None) -> list[Finding]:
    """Flag focusable elements with no focus indicator or obscured focus.

    Supports **2.4.7 Focus Visible** and **2.4.11 Focus Not Obscured
    (Minimum)**. Focuses each visible focusable element, compares its
    computed style before/after focus, and checks whether the focused
    element is covered by other content. Side effect: momentarily moves
    focus across the page's focusable elements.
    """
    page_url = url if url is not None else driver.current_url
    records = driver.execute_script(_FOCUS_VISIBLE_JS)
    return evaluate_focus_visible(records, page_url)


def evaluate_focus_visible(records: list[dict[str, Any]], url: str) -> list[Finding]:
    """Turn focus-probe records into 2.4.7 / 2.4.11 findings (pure).

    A record has ``gotFocus``, ``stylesBefore``/``stylesAfter`` (computed
    style subsets), and ``obscured``. An element that received focus but
    showed no style change is a 2.4.7 candidate; one obscured while
    focused is a 2.4.11 candidate. Elements that could not take focus are
    skipped — the check cannot assess what it could not focus.
    """
    findings: list[Finding] = []
    for record in records:
        if not record.get("gotFocus"):
            continue
        selector = record.get("selector")
        if not _indicator_changed(
            record.get("stylesBefore", {}), record.get("stylesAfter", {})
        ):
            findings.append(
                Finding(
                    criterion="2.4.7",
                    severity="needs-review",
                    message=(
                        "No computed-style change detected when this element "
                        "received keyboard focus — it may lack a visible focus "
                        "indicator. Confirm a focus indicator is perceivable."
                    ),
                    selector=selector,
                    url=url,
                )
            )
        if record.get("obscured"):
            findings.append(
                Finding(
                    criterion="2.4.11",
                    severity="needs-review",
                    message=(
                        "The focused element is covered by other content at its "
                        "centre point — focus may be hidden (e.g. behind a sticky "
                        "header). Confirm the focused element stays visible."
                    ),
                    selector=selector,
                    url=url,
                )
            )
    return findings


def _indicator_changed(before: dict[str, Any], after: dict[str, Any]) -> bool:
    """Return True if any tracked focus-indicator style differs on focus."""
    return any(before.get(k) != after.get(k) for k in _FOCUS_STYLE_KEYS)


# --- 2.5.8 Target Size (Minimum) -------------------------------------------

_TARGET_SIZE_JS = _JS_HELPERS + r"""
const out=[];
for(const el of focusable()){
  const r=el.getBoundingClientRect();
  out.push({selector:cssPath(el), width:r.width, height:r.height,
    inline:getComputedStyle(el).display==='inline'});
}
return out;
"""


def check_target_size(driver: Any, url: str | None = None) -> list[Finding]:
    """Flag interactive targets smaller than the 24×24 CSS-px minimum.

    Supports **2.5.8 Target Size (Minimum)**. Measures each visible
    focusable element's rendered box. Inline targets (the criterion's
    in-sentence exception) are not flagged. Read-only: measures only.
    """
    page_url = url if url is not None else driver.current_url
    records = driver.execute_script(_TARGET_SIZE_JS)
    return evaluate_target_size(records, page_url)


def evaluate_target_size(records: list[dict[str, Any]], url: str) -> list[Finding]:
    """Turn target measurements into 2.5.8 findings (pure).

    A record has ``width``/``height`` (CSS px) and ``inline``. A rendered
    target narrower or shorter than :data:`MIN_TARGET_PX` and not inline
    is a candidate; the spacing/essential/equivalent exceptions cannot be
    decided automatically, so it is reported ``needs-review``. Zero-size
    boxes are skipped (not rendered).
    """
    findings: list[Finding] = []
    for record in records:
        width = record.get("width") or 0
        height = record.get("height") or 0
        if width <= 0 or height <= 0 or record.get("inline"):
            continue
        if width < MIN_TARGET_PX or height < MIN_TARGET_PX:
            findings.append(
                Finding(
                    criterion="2.5.8",
                    severity="needs-review",
                    message=(
                        f"Target renders at {round(width)}×{round(height)} CSS px, "
                        f"below the {MIN_TARGET_PX}×{MIN_TARGET_PX} minimum. Confirm "
                        "no spacing, inline, or equivalent-control exception applies."
                    ),
                    selector=record.get("selector"),
                    url=url,
                )
            )
    return findings


# --- 2.4.3 Focus Order -----------------------------------------------------

_TAB_ORDER_JS = _JS_HELPERS + r"""
const out=[];
for(const el of focusable()){
  const attr=el.getAttribute('tabindex');
  out.push({selector:cssPath(el), tabindex: attr===null ? null : parseInt(attr,10)});
}
return out;
"""


def check_tab_order(driver: Any, url: str | None = None) -> list[Finding]:
    """Flag positive ``tabindex`` values that override natural focus order.

    Supports **2.4.3 Focus Order**. A positive ``tabindex`` forces an
    element ahead of the document order and is the one focus-order
    anti-pattern that can be detected statically; whether the resulting
    order is *meaningful* remains a manual judgement. Read-only.
    """
    page_url = url if url is not None else driver.current_url
    records = driver.execute_script(_TAB_ORDER_JS)
    return evaluate_tab_order(records, page_url)


def evaluate_tab_order(records: list[dict[str, Any]], url: str) -> list[Finding]:
    """Turn tabindex records into 2.4.3 findings (pure).

    Each record has a ``tabindex`` (int, or ``None`` when the attribute is
    absent). A value greater than zero is flagged as a candidate: it makes
    the focus order diverge from the DOM order, which usually — but not
    always — harms the focus sequence.
    """
    findings: list[Finding] = []
    for record in records:
        tabindex = record.get("tabindex")
        if isinstance(tabindex, int) and tabindex > 0:
            findings.append(
                Finding(
                    criterion="2.4.3",
                    severity="needs-review",
                    message=(
                        f"Positive tabindex ({tabindex}) forces this element ahead "
                        "of the document order. Confirm the resulting focus order is "
                        "still meaningful; prefer tabindex 0 and DOM order."
                    ),
                    selector=record.get("selector"),
                    url=url,
                )
            )
    return findings


# --- 2.1.2 No Keyboard Trap ------------------------------------------------

_FOCUSABLE_COUNT_JS = _JS_HELPERS + "return focusable().length;"

_ACTIVE_SELECTOR_JS = _JS_HELPERS + r"""
const el=document.activeElement;
if(!el || el===document.body || el===document.documentElement) return null;
return cssPath(el);
"""


def check_no_keyboard_trap(driver: Any, url: str | None = None) -> list[Finding]:
    """Detect focus that will not advance past an element via the keyboard.

    Supports **2.1.2 No Keyboard Trap**. Presses Tab repeatedly and
    records the focused element after each press; an element that keeps
    the focus for several presses in a row is a candidate trap. Side
    effect: sends Tab keystrokes and moves focus. Does nothing when the
    page has no focusable elements.
    """
    from selenium.webdriver.common.action_chains import ActionChains
    from selenium.webdriver.common.keys import Keys

    page_url = url if url is not None else driver.current_url
    count = driver.execute_script(_FOCUSABLE_COUNT_JS) or 0
    if count <= 0:
        return []

    driver.execute_script(
        "if(document.activeElement) document.activeElement.blur();"
    )
    presses = min(count * 2 + 5, _MAX_TAB_PRESSES)
    sequence: list[str | None] = []
    for _ in range(presses):
        ActionChains(driver).send_keys(Keys.TAB).perform()
        sequence.append(driver.execute_script(_ACTIVE_SELECTOR_JS))
    return evaluate_no_keyboard_trap(sequence, page_url)


def evaluate_no_keyboard_trap(
    sequence: list[str | None], url: str
) -> list[Finding]:
    """Turn an observed tab-focus sequence into 2.1.2 findings (pure).

    ``sequence`` is the element selector focused after each Tab press
    (``None`` when focus left the page content). Any element focused
    :data:`_STUCK_REPEAT` or more times consecutively is reported once as
    a candidate keyboard trap — focus was not advancing. The criterion
    permits traps escapable by other keys, so this is ``needs-review``.
    """
    findings: list[Finding] = []
    reported: set[str] = set()
    run_value: str | None = None
    run_length = 0
    for selector in sequence:
        if selector is not None and selector == run_value:
            run_length += 1
        else:
            run_value = selector
            run_length = 1
        if (
            run_value is not None
            and run_length >= _STUCK_REPEAT
            and run_value not in reported
        ):
            reported.add(run_value)
            findings.append(
                Finding(
                    criterion="2.1.2",
                    severity="needs-review",
                    message=(
                        "Keyboard focus stayed on this element for "
                        f"{_STUCK_REPEAT}+ consecutive Tab presses — focus may be "
                        "trapped. Confirm focus can move away using the keyboard "
                        "alone (Tab or documented keys)."
                    ),
                    selector=run_value,
                    url=url,
                )
            )
    return findings


# --- Aggregate -------------------------------------------------------------


def run_all(driver: Any, url: str | None = None) -> list[Finding]:
    """Run every keyboard/focus check and return the combined findings.

    Convenience for the session layer. Order: focus visibility/obscuring,
    target size, focus order, keyboard trap (the trap check moves focus,
    so it runs last).
    """
    page_url = url if url is not None else driver.current_url
    findings: list[Finding] = []
    findings += check_focus_visible(driver, page_url)
    findings += check_target_size(driver, page_url)
    findings += check_tab_order(driver, page_url)
    findings += check_no_keyboard_trap(driver, page_url)
    return findings


__all__ = [
    "MIN_TARGET_PX",
    "check_focus_visible",
    "check_no_keyboard_trap",
    "check_tab_order",
    "check_target_size",
    "evaluate_focus_visible",
    "evaluate_no_keyboard_trap",
    "evaluate_tab_order",
    "evaluate_target_size",
    "run_all",
]