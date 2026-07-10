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

"""Capture full-page screenshot evidence for findings.

For every finding that points at an element (has a CSS selector), draw a
rectangle around that element in the live page and save a **full-page**
screenshot — the whole rendered page, so the flagged element is shown in
context rather than cropped to a contextless sliver. Findings with no
element (page-level findings) keep ``screenshot=None``.

The rectangle is drawn by injecting a temporary absolutely-positioned
overlay at the element's page coordinates (removed again right after the
shot), so it lines up exactly with the rendered element and needs no
image library. The capture uses Firefox's full-page screenshot, which
spans the entire scrollable document, not just the viewport.

Because the shot is of the page as rendered at audit time, this runs on
the live driver immediately after a page's findings are gathered, before
the operator navigates away. Boundary (see :mod:`.axe_runner`): it takes
a live driver from the caller and never launches, configures, or closes
the session.

Robustness: locating and shooting an element touches the live DOM, which
can fail benignly — the selector may no longer match, or the browser may
refuse a screenshot. Such a finding simply keeps ``screenshot=None``
rather than aborting the audit. Distinct ``(url, selector)`` pairs are
shot once and shared, so an element failing several criteria yields one
PNG.
"""

from __future__ import annotations

import hashlib
from contextlib import suppress
from dataclasses import replace
from pathlib import Path
from typing import Any

from selenium.common.exceptions import WebDriverException

from .core import Finding

#: Injected to draw the highlight box. ``arguments[0]`` is the CSS
#: selector. Returns ``True`` if the element was found and boxed, else
#: ``False``. The overlay is absolutely positioned at the element's page
#: coordinates with a high z-index so it shows over any stacking context,
#: and tagged so :data:`_UNHIGHLIGHT_JS` can remove it.
_HIGHLIGHT_JS = r"""
var selector = arguments[0];
var el;
try { el = document.querySelector(selector); } catch (e) { return false; }
if (!el) return false;
var r = el.getBoundingClientRect();
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
return true;
"""

#: Removes every highlight box the capture added.
_UNHIGHLIGHT_JS = r"""
var boxes = document.querySelectorAll('[data-wcag-evidence-box]');
for (var i = 0; i < boxes.length; i++) boxes[i].remove();
"""


def capture_findings(
    driver: Any, findings: list[Finding], screenshot_dir: Path | str
) -> list[Finding]:
    """Capture full-page evidence and return findings with ``screenshot`` set.

    For each finding with a selector, boxes the matching element and saves
    a full-page PNG into ``screenshot_dir``, returning a copy of the
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


def _capture_element(driver: Any, selector: str, out: Path, name: str) -> bool:
    """Box the element matching ``selector`` and save a full-page PNG.

    Returns True when a screenshot was written, False when the element
    cannot be found or the browser declines the screenshot. The highlight
    overlay is always removed again, even if the screenshot fails.
    """
    try:
        highlighted = driver.execute_script(_HIGHLIGHT_JS, selector)
    except WebDriverException:
        return False
    if not highlighted:
        return False
    out.mkdir(parents=True, exist_ok=True)
    try:
        png = driver.get_full_page_screenshot_as_png()
        (out / name).write_bytes(png)
        return True
    except WebDriverException:
        return False
    finally:
        with suppress(WebDriverException):
            driver.execute_script(_UNHIGHLIGHT_JS)


def _evidence_name(url: str, selector: str) -> str:
    """Return a stable, collision-resistant PNG filename for an element.

    Derived from the page URL and selector so the same element yields the
    same name across a run (enabling dedup) and elements on different pages
    never collide, without leaking a long selector into the filesystem.
    """
    digest = hashlib.sha1(f"{url}\n{selector}".encode("utf-8")).hexdigest()
    return f"{digest[:12]}.png"


__all__ = ["capture_findings"]
