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

"""Time-based-media presence checks that axe-core does not cover.

axe-core already flags two media criteria and this tool maps them
straight through (see :mod:`.axe_runner`): **1.2.2 Captions** (its
``video-caption`` rule) and **1.4.2 Audio Control** (its
``no-autoplay-audio`` rule). This module fills the two remaining
prerecorded-media criteria axe does *not* decide:

* **1.2.1 Audio-only and Video-only (Prerecorded)** — a native
  ``<audio>`` element is present; if it is prerecorded audio-only it needs
  an equivalent text transcript. (axe's ``audio-caption`` rule is
  deprecated and does not run.)
* **1.2.3 Audio Description or Media Alternative (Prerecorded)** — a
  native ``<video>`` element is present; visual information it conveys
  needs an audio description or a full text alternative.

Both are inherently ``partial`` (see :mod:`.core`): the check can tell you
a media element *exists* — a reliable applicability signal — but not
whether a transcript or audio description has been provided elsewhere on
the page, whether the media is prerecorded rather than live, or what is
inside a cross-origin ``<iframe>`` embed (YouTube/Vimeo etc., which this
does not see). So every finding is ``needs-review``: a candidate for a
human to confirm, never a pass and never a definite failure.

Design mirrors :mod:`.keyboard_nav`: an impure gatherer (:func:`check_media`,
one ``execute_script`` over the live DOM) and a pure evaluator
(:func:`evaluate_media`) that the hermetic tests drive with canned data.
Boundary: takes a live driver from the caller; never launches or closes it.
"""

from __future__ import annotations

from typing import Any

from .core import Finding

#: Cap on how many media elements one page is inspected for, so a
#: pathological page cannot produce an unbounded number of findings.
_MAX_MEDIA = 100

#: Injected gatherer: inventory every native ``<audio>``/``<video>`` with
#: the facts the evaluator needs. Read-only. ``arguments[0]`` is the cap.
_MEDIA_JS = r"""
const MAX = arguments[0];
function cssPath(el){
  if(!el || el.nodeType!==1) return null;
  if(el.id) return '#'+CSS.escape(el.id);
  const parts=[];
  while(el && el.nodeType===1 && el!==document.documentElement){
    let sel=el.tagName.toLowerCase();
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
const out=[];
const media=Array.from(document.querySelectorAll('audio,video')).slice(0, MAX);
for(const el of media){
  out.push({tag: el.tagName.toLowerCase(), selector: cssPath(el)});
}
return out;
"""


def check_media(driver: Any, url: str | None = None) -> list[Finding]:
    """Inventory native media elements and flag 1.2.1 / 1.2.3 candidates.

    ``driver`` is a live Selenium WebDriver on the page to inspect; the
    caller owns its lifecycle. ``url`` labels the findings; when omitted it
    is read from ``driver.current_url``. Read-only: one ``execute_script``
    that reads the DOM and mutates nothing. Returns ``needs-review``
    findings (possibly empty); an empty list means no native media was
    found, never that the criteria pass.
    """
    page_url = url if url is not None else driver.current_url
    records = driver.execute_script(_MEDIA_JS, _MAX_MEDIA)
    return evaluate_media(records, page_url)


def evaluate_media(records: list[dict[str, Any]], url: str) -> list[Finding]:
    """Turn a media inventory into 1.2.1 / 1.2.3 findings (pure).

    Each record has ``tag`` (``"audio"`` / ``"video"``) and ``selector``.
    An ``<audio>`` yields a 1.2.1 transcript candidate; a ``<video>``
    yields a 1.2.3 audio-description/alternative candidate. All findings
    are ``needs-review`` — the presence is certain, the remedy is not.
    """
    findings: list[Finding] = []
    for record in records:
        tag = record.get("tag")
        selector = record.get("selector")
        if tag == "audio":
            findings.append(
                Finding(
                    criterion="1.2.1",
                    severity="needs-review",
                    message=(
                        "An <audio> element is present. If it is prerecorded "
                        "audio-only, WCAG 1.2.1 requires an equivalent text "
                        "transcript — confirm one is provided (this tool cannot "
                        "detect a transcript elsewhere on the page)."
                    ),
                    selector=selector,
                    url=url,
                )
            )
        elif tag == "video":
            findings.append(
                Finding(
                    criterion="1.2.3",
                    severity="needs-review",
                    message=(
                        "A <video> element is present. WCAG 1.2.3 requires an "
                        "audio description or a full text alternative for "
                        "information the video conveys visually — confirm one is "
                        "provided. (Captions, 1.2.2, are checked separately.)"
                    ),
                    selector=selector,
                    url=url,
                )
            )
    return findings


__all__ = ["check_media", "evaluate_media"]
