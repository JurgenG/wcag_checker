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

"""Descriptive-text heuristics for content axe-core does not judge.

Two success criteria turn on whether *visible text does its job* — which a
rule engine cannot decide in general, but whose worst cases are reliably
detectable:

* **2.4.4 Link Purpose (In Context)** — :func:`check_link_purpose` flags
  links whose text is a generic filler phrase ("click here", "read more",
  …) that does not describe the destination out of context. axe's
  ``link-name`` rule already covers links with *no* accessible name; this
  covers links that have a name but an unhelpful one.
* **2.4.6 Headings and Labels** — :func:`check_empty_headings` flags
  headings with no text at all. A heading that describes nothing is the
  objective slice of 2.4.6; whether a non-empty heading is *descriptive*
  stays a human judgement.

Both criteria are ``partial`` (see :mod:`.core`): these are candidates a
human confirms, reported ``needs-review`` — never a definite failure and
never a pass. axe's ``empty-heading`` rule is tagged *best-practice* (so
this tool drops it) and it makes no 2.4.4 phrase judgement, which is why
these live here rather than coming from axe.

Design mirrors :mod:`.keyboard_nav`: impure gatherers (``check_*``, one
``execute_script`` each, read-only) and pure evaluators (``evaluate_*``)
that the hermetic tests drive with canned data. Boundary: the checks take
a live driver from the caller; they never launch or close it. Every
public function takes a keyword-only ``lang`` for its messages (see
:mod:`leak_inspector.i18n`).
"""

from __future__ import annotations

import re
from typing import Any

from ..i18n import SOURCE_LANG, tr
from .core import Finding

#: Normalised link phrases that do not describe a destination on their own.
#: Compared against the link's accessible name after :func:`_normalize`
#: (lowercased, surrounding punctuation/arrows stripped, spaces collapsed),
#: so "Read more »", "READ MORE", and "read more!" all match "read more".
VAGUE_LINK_PHRASES = frozenset(
    {
        "click here",
        "click",
        "here",
        "read more",
        "more",
        "read",
        "learn more",
        "more details",
        "details",
        "link",
        "this",
        "this link",
        "more info",
        "info",
        "continue",
        "go",
        "download",
        "read on",
    }
)

#: Compact CSS-path builder shared by the injected gatherers, so findings
#: carry a selector comparable to axe's.
_CSS_PATH_JS = r"""
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
"""

_LINK_JS = _CSS_PATH_JS + r"""
const out=[];
for(const a of Array.from(document.querySelectorAll('a[href]')).slice(0, 500)){
  let name=(a.getAttribute('aria-label')||'').trim();
  if(!name) name=(a.textContent||'').replace(/\s+/g,' ').trim();
  out.push({selector: cssPath(a), name: name});
}
return out;
"""

_HEADING_JS = _CSS_PATH_JS + r"""
const out=[];
const sel='h1,h2,h3,h4,h5,h6,[role="heading"]';
for(const h of Array.from(document.querySelectorAll(sel)).slice(0, 300)){
  let name=(h.getAttribute('aria-label')||'').trim()
    || (h.textContent||'').replace(/\s+/g,' ').trim();
  if(!name){
    const im=h.querySelector('img[alt]');
    if(im) name=(im.getAttribute('alt')||'').trim();
  }
  out.push({selector: cssPath(h), empty: name===''});
}
return out;
"""


def _normalize(text: str) -> str:
    """Lowercase, strip surrounding non-alphanumerics, collapse spaces."""
    lowered = text.strip().lower()
    stripped = re.sub(r"^[^a-z0-9]+|[^a-z0-9]+$", "", lowered)
    return re.sub(r"\s+", " ", stripped)


def check_link_purpose(
    driver: Any, url: str | None = None, *, lang: str = SOURCE_LANG
) -> list[Finding]:
    """Flag links whose accessible name is a generic filler phrase (2.4.4).

    ``driver`` is a live Selenium WebDriver; the caller owns its lifecycle.
    ``url`` labels the findings (defaults to ``driver.current_url``).
    Read-only: one ``execute_script`` over the page's links.
    """
    page_url = url if url is not None else driver.current_url
    records = driver.execute_script(_LINK_JS)
    return evaluate_link_purpose(records, page_url, lang=lang)


def evaluate_link_purpose(
    records: list[dict[str, Any]], url: str, *, lang: str = SOURCE_LANG
) -> list[Finding]:
    """Turn link records into 2.4.4 findings (pure).

    Each record has ``name`` (accessible name) and ``selector``. A link
    whose normalised name is in :data:`VAGUE_LINK_PHRASES` is a candidate;
    links with an empty name are left to axe's ``link-name`` rule (2.4.4 /
    4.1.2) and not re-reported here.
    """
    findings: list[Finding] = []
    for record in records:
        name = (record.get("name") or "").strip()
        if not name or _normalize(name) not in VAGUE_LINK_PHRASES:
            continue
        findings.append(
            Finding(
                criterion="2.4.4",
                severity="needs-review",
                message=tr(
                    lang,
                    "Link text {name} may not describe the link's purpose out "
                    "of context (WCAG 2.4.4). Confirm the destination is clear "
                    "from the link text alone, or make the text more specific.",
                    name=repr(name),
                ),
                selector=record.get("selector"),
                url=url,
            )
        )
    return findings


def check_empty_headings(
    driver: Any, url: str | None = None, *, lang: str = SOURCE_LANG
) -> list[Finding]:
    """Flag headings that have no text content (2.4.6).

    ``driver`` is a live Selenium WebDriver; the caller owns its lifecycle.
    ``url`` labels the findings (defaults to ``driver.current_url``).
    Read-only: one ``execute_script`` over the page's headings.
    """
    page_url = url if url is not None else driver.current_url
    records = driver.execute_script(_HEADING_JS)
    return evaluate_empty_headings(records, page_url, lang=lang)


def evaluate_empty_headings(
    records: list[dict[str, Any]], url: str, *, lang: str = SOURCE_LANG
) -> list[Finding]:
    """Turn heading records into 2.4.6 findings (pure).

    Each record has ``empty`` (no accessible text — no child text, no
    ``aria-label``, no image ``alt``) and ``selector``. An empty heading
    describes nothing, so it is reported ``needs-review`` against 2.4.6;
    whether a non-empty heading is adequately *descriptive* stays manual.
    """
    findings: list[Finding] = []
    for record in records:
        if not record.get("empty"):
            continue
        findings.append(
            Finding(
                criterion="2.4.6",
                severity="needs-review",
                message=tr(
                    lang,
                    "This heading has no text content — a heading must describe "
                    "the section it introduces (WCAG 2.4.6). Give it descriptive "
                    "text or remove it if it is not a real heading.",
                ),
                selector=record.get("selector"),
                url=url,
            )
        )
    return findings


def run_all(
    driver: Any, url: str | None = None, *, lang: str = SOURCE_LANG
) -> list[Finding]:
    """Run every content heuristic; messages in ``lang``."""
    page_url = url if url is not None else driver.current_url
    findings: list[Finding] = []
    findings += check_link_purpose(driver, page_url, lang=lang)
    findings += check_empty_headings(driver, page_url, lang=lang)
    return findings


__all__ = [
    "VAGUE_LINK_PHRASES",
    "check_empty_headings",
    "check_link_purpose",
    "evaluate_empty_headings",
    "evaluate_link_purpose",
    "run_all",
]
