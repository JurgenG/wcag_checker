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

"""Capture cropped screenshot evidence for findings.

For every finding that points at an element (has a CSS selector), draw a
rectangle around that element in the live page and save a screenshot
**cropped to the element plus surrounding context** — the element's
bounding box expanded by its own width to the left and right and its own
height above and below (so a 50×70 element yields a 150×210 region). The
width is capped at the browser window's width; the height is bounded only
by the page (it may extend past the visible window). This shows the
flagged element in local context rather than as a speck on the whole page.
Findings with no element (page-level findings) keep ``screenshot=None``.

The rectangle is drawn by injecting a temporary absolutely-positioned
overlay at the element's page coordinates (removed again right after the
shot), so it lines up exactly with the rendered element and needs no
image library. The crop uses WebDriver BiDi
``browsingContext.captureScreenshot`` with a document-origin box clip, so
the returned PNG is exactly the expanded region — no image post-processing.

Because the shot is of the page as rendered at audit time, this runs on
the live driver immediately after a page's findings are gathered, before
the operator navigates away. Boundary (see :mod:`.axe_runner`): it takes
a live driver from the caller and never launches, configures, or closes
the session.

Robustness: locating and shooting an element touches the live DOM, which
can fail benignly — the selector may no longer match, the element may not
be rendered (zero-size), or the browser may refuse the capture. Such a
finding simply keeps ``screenshot=None`` rather than aborting the audit.
Distinct ``(url, selector)`` pairs are shot once and shared, so an element
failing several criteria yields one PNG.
"""

from __future__ import annotations

import base64
import hashlib
from contextlib import suppress
from dataclasses import replace
from pathlib import Path
from typing import Any

from selenium.common.exceptions import WebDriverException

from .core import Finding

#: Injected to locate the element, draw the highlight box, and report the
#: geometry the crop needs. ``arguments[0]`` is the CSS selector. Returns
#: ``None`` when the selector matches nothing or the element has no rendered
#: size; otherwise draws the overlay and returns the element's page-relative
#: position and size (``x``/``y``/``w``/``h``, CSS px) plus the window width
#: (``winW``) and full page height (``pageH``) so the caller can cap the
#: crop's width to the window and its height to the page. The overlay is
#: absolutely positioned at the
#: element's page coordinates with a high z-index so it shows over any
#: stacking context, and tagged so :data:`_UNHIGHLIGHT_JS` can remove it.
_LOCATE_AND_HIGHLIGHT_JS = r"""
var selector = arguments[0];
var el;
try { el = document.querySelector(selector); } catch (e) { return null; }
if (!el) return null;
var r = el.getBoundingClientRect();
if (r.width <= 0 || r.height <= 0) return null;
var box = document.createElement('div');
box.setAttribute('data-wcag-evidence-box', '1');
var s = box.style;
s.position = 'absolute';
s.left = (r.left + window.scrollX) + 'px';
s.top = (r.top + window.scrollY) + 'px';
s.width = Math.max(r.width, 3) + 'px';
s.height = Math.max(r.height, 3) + 'px';
s.border = '3px solid #ff2d55';
s.outline = '2px solid rgba(255,255,255,0.95)';
s.outlineOffset = '0px';
s.background = 'rgba(255,45,85,0.10)';
s.boxSizing = 'border-box';
s.margin = '0';
s.padding = '0';
s.borderRadius = '0';
s.zIndex = '2147483647';
s.pointerEvents = 'none';
document.documentElement.appendChild(box);
var d = document.documentElement;
return {
  x: r.left + window.scrollX,
  y: r.top + window.scrollY,
  w: r.width,
  h: r.height,
  winW: d.clientWidth,
  pageH: Math.max(d.scrollHeight, d.clientHeight)
};
"""

#: Removes every highlight box the capture added.
_UNHIGHLIGHT_JS = r"""
var boxes = document.querySelectorAll('[data-wcag-evidence-box]');
for (var i = 0; i < boxes.length; i++) boxes[i].remove();
"""


def capture_findings(
    driver: Any, findings: list[Finding], screenshot_dir: Path | str
) -> list[Finding]:
    """Capture cropped evidence and return findings with ``screenshot`` set.

    For each finding with a selector, boxes the matching element and saves
    a PNG cropped to the element's expanded surrounding region (see
    :func:`_expanded_box`) into ``screenshot_dir``, returning a copy of the
    finding carrying the PNG's path (relative to ``screenshot_dir``'s
    parent, e.g. ``screenshots/<file>.png``) in ``screenshot``; findings
    without a selector, or whose element cannot be located/shot, are
    returned unchanged. Side effects: reads and briefly mutates the live
    DOM (the overlay is removed after each shot) and writes PNG files
    (creating ``screenshot_dir`` on first capture). Input findings are not
    mutated.
    """
    out = Path(screenshot_dir)
    shot: dict[tuple[str, str], str | None] = {}
    updated: list[Finding] = []
    for finding in findings:
        name = _evidence_for(driver, finding, out, shot)
        updated.append(replace(finding, screenshot=name) if name else finding)
    return updated


def _evidence_for(
    driver: Any,
    finding: Finding,
    out: Path,
    shot: dict[tuple[str, str], str | None],
) -> str | None:
    """Return the evidence path for a finding, shooting once per element.

    The returned path is relative to ``out``'s parent (e.g.
    ``screenshots/<file>.png``), so it links directly from a report
    written alongside the screenshot directory.
    """
    if not finding.selector:
        return None
    key = (finding.url, finding.selector)
    if key not in shot:
        name = _evidence_name(finding.url, finding.selector)
        ok = _capture_element(driver, finding.selector, out, name)
        shot[key] = f"{out.name}/{name}" if ok else None
    return shot[key]


def _expanded_box(
    x: float, y: float, w: float, h: float, win_w: float, page_h: float
) -> dict[str, float]:
    """Expand an element box by its own size, capped to window/page (pure).

    Given the element's page-relative position (``x``, ``y``) and size
    (``w``, ``h``), returns the crop rectangle ``{x, y, width, height}``
    grown by ``w`` to the left and right and ``h`` above and below — a
    ``3w × 3h`` region centred on the element (a 50×70 element → 150×210).
    The width is capped to the browser window (``0`` to ``win_w``); the
    height is capped only to the page (``0`` to ``page_h``), so a tall crop
    may extend past the visible window but never past the document. Capping
    near an edge trims that side, so the crop can be smaller than
    ``3w × 3h``.
    """
    left = max(0.0, x - w)
    top = max(0.0, y - h)
    right = min(win_w, x + 2 * w)
    bottom = min(page_h, y + 2 * h)
    return {"x": left, "y": top, "width": right - left, "height": bottom - top}


def _capture_element(driver: Any, selector: str, out: Path, name: str) -> bool:
    """Box the element matching ``selector`` and save a cropped PNG.

    Returns True when a screenshot was written, False when the element
    cannot be found/rendered or the browser declines the capture. The
    highlight overlay is always removed again when one was drawn, even if
    the capture fails.
    """
    try:
        geom = driver.execute_script(_LOCATE_AND_HIGHLIGHT_JS, selector)
    except WebDriverException:
        return False
    if not geom:
        return False
    try:
        clip = _expanded_box(
            float(geom["x"]),
            float(geom["y"]),
            float(geom["w"]),
            float(geom["h"]),
            float(geom["winW"]),
            float(geom["pageH"]),
        )
        png = _capture_clip(driver, clip)
        out.mkdir(parents=True, exist_ok=True)
        (out / name).write_bytes(png)
        return True
    except (WebDriverException, KeyError, ValueError, TypeError):
        return False
    finally:
        with suppress(WebDriverException):
            driver.execute_script(_UNHIGHLIGHT_JS)


def _capture_clip(driver: Any, clip: dict[str, float]) -> bytes:
    """Capture the ``clip`` region of the current page as PNG bytes.

    Uses WebDriver BiDi ``browsingContext.captureScreenshot`` with a
    document-origin box clip (``clip`` carries CSS-px ``x``/``y``/``width``/
    ``height`` in page coordinates) and decodes the base64 result. Raises
    :class:`~selenium.common.exceptions.WebDriverException` (or a decode
    error) if the capture fails; the caller treats that as "no screenshot".
    """
    data = driver.browsing_context.capture_screenshot(
        context=driver.current_window_handle,
        origin="document",
        clip={
            "type": "box",
            "x": clip["x"],
            "y": clip["y"],
            "width": clip["width"],
            "height": clip["height"],
        },
    )
    return base64.b64decode(data)


def _evidence_name(url: str, selector: str) -> str:
    """Return a stable, collision-resistant PNG filename for an element.

    Derived from the page URL and selector so the same element yields the
    same name across a run (enabling dedup) and elements on different pages
    never collide, without leaking a long selector into the filesystem.
    """
    digest = hashlib.sha1(f"{url}\n{selector}".encode("utf-8")).hexdigest()
    return f"{digest[:12]}.png"


__all__ = ["capture_findings"]
