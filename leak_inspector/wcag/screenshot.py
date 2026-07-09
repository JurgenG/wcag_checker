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

"""Capture element-level screenshot evidence for findings.

For every finding that points at an element (has a CSS selector), locate
that element on the live page and save a PNG of *just that element* — the
snippet with the issue — as evidence beside the report. Findings that
have no element (page-level findings) keep ``screenshot=None``.

Because the shot is of the page as rendered at audit time, this runs on
the live driver immediately after a page's findings are gathered, before
the operator navigates away. Boundary (see :mod:`.axe_runner`): it takes
a live driver from the caller and never launches, configures, or closes
the session.

Robustness: locating and shooting an element touches the live DOM, which
can fail benignly — the selector may no longer match, or the element may
be zero-sized or off-screen. Such a finding simply keeps
``screenshot=None`` rather than aborting the audit; only the caller's own
driver errors propagate. Distinct ``(url, selector)`` pairs are shot once
and shared, so an element failing several criteria yields one PNG.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Any

from selenium.common.exceptions import WebDriverException
from selenium.webdriver.common.by import By

from .core import Finding


def capture_findings(
    driver: Any, findings: list[Finding], screenshot_dir: Path | str
) -> list[Finding]:
    """Capture element evidence and return findings with ``screenshot`` set.

    For each finding with a selector, saves a PNG of the matching element
    into ``screenshot_dir`` and returns a copy of the finding carrying the
    PNG's path (relative to ``screenshot_dir``'s parent, e.g.
    ``screenshots/<file>.png``) in ``screenshot``; findings without a
    selector, or whose element cannot be located/rendered, are returned
    unchanged. Side
    effects: reads the live DOM and writes PNG files (creating
    ``screenshot_dir`` on first capture). Input findings are not mutated.
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
    """Save a PNG of the element matching ``selector`` into ``out/name``.

    Returns True when a screenshot was written, False when the element
    cannot be found or the driver declines to shoot it (e.g. zero-sized or
    unrendered). Scrolls the element into view as a side effect.
    """
    try:
        element = driver.find_element(By.CSS_SELECTOR, selector)
    except WebDriverException:
        return False
    out.mkdir(parents=True, exist_ok=True)
    try:
        return bool(element.screenshot(str(out / name)))
    except WebDriverException:
        return False


def _evidence_name(url: str, selector: str) -> str:
    """Return a stable, collision-resistant PNG filename for an element.

    Derived from the page URL and selector so the same element yields the
    same name across a run (enabling dedup) and elements on different pages
    never collide, without leaking a long selector into the filesystem.
    """
    digest = hashlib.sha1(f"{url}\n{selector}".encode("utf-8")).hexdigest()
    return f"{digest[:12]}.png"


__all__ = ["capture_findings"]
