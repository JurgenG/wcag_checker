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
``video-caption`` rule, for native ``<video>``) and **1.4.2 Audio
Control** (its ``no-autoplay-audio`` rule). This module inventories the
page's time-based media and makes explicit, per element, both *what it
found* and *what it could not audit*:

* **Native ``<audio>`` / ``<video>``** — reported present, and for each
  the caption / subtitle / description ``<track>`` elements it declares
  are stated explicitly. Audio-only needs a transcript (**1.2.1**); video
  needs an audio description or full text alternative (**1.2.3**). Whether
  a transcript / description actually exists still needs a human, so these
  stay ``needs-review``.
* **YouTube / Vimeo ``<iframe>`` embeds** — reported present but *not
  auditable*: the captions and audio description live inside a
  cross-origin frame this tool cannot read. Flagged ``needs-review`` for
  captions (**1.2.2**) and audio description (**1.2.3**) so a human
  verifies them.
* **Any other ``<iframe>``** — reported as embedded content that could not
  be audited: if it hosts time-based media the 1.2.x criteria apply, so it
  is flagged ``needs-review`` (**1.2.1**) for a human to classify (or mark
  N/A).

Every finding carries the element's CSS selector, so the report captures a
screenshot of it (see :mod:`.screenshot`). Nothing here is ever a pass or
a definite failure — only a candidate a person confirms.

Design mirrors :mod:`.keyboard_nav`: an impure gatherer (:func:`check_media`,
one ``execute_script`` over the live DOM) and a pure evaluator
(:func:`evaluate_media`) that the hermetic tests drive with canned data.
Boundary: takes a live driver from the caller; never launches or closes it.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from .core import Finding

#: Cap on how many media/iframe elements one page is inspected for, so a
#: pathological page cannot produce an unbounded number of findings.
_MAX_MEDIA = 100

#: ``<track>`` ``kind`` values that matter for the media criteria.
_CAPTIONS_KIND = "captions"
_SUBTITLES_KIND = "subtitles"
_DESCRIPTIONS_KIND = "descriptions"

#: Injected gatherer: inventory native ``<audio>``/``<video>`` (with their
#: ``<track>`` kinds) and every ``<iframe>`` (with its ``src``/``title``).
#: Read-only. ``arguments[0]`` is the cap on total elements collected.
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
function tracks(el){
  return Array.from(el.querySelectorAll('track')).map(function(t){
    return {
      kind: (t.getAttribute('kind')||'').toLowerCase(),
      label: t.getAttribute('label')||'',
      srclang: t.getAttribute('srclang')||''
    };
  });
}
const out=[];
const media=document.querySelectorAll('audio,video');
for(let i=0;i<media.length && out.length<MAX;i++){
  const el=media[i];
  out.push({type:'media', tag: el.tagName.toLowerCase(),
            selector: cssPath(el), tracks: tracks(el)});
}
const frames=document.querySelectorAll('iframe');
for(let i=0;i<frames.length && out.length<MAX;i++){
  const el=frames[i];
  out.push({type:'iframe', selector: cssPath(el),
            src: el.getAttribute('src')||'', title: el.getAttribute('title')||''});
}
return out;
"""


def check_media(driver: Any, url: str | None = None) -> list[Finding]:
    """Inventory media/embeds and flag 1.2.x candidates.

    ``driver`` is a live Selenium WebDriver on the page to inspect; the
    caller owns its lifecycle. ``url`` labels the findings; when omitted it
    is read from ``driver.current_url``. Read-only: one ``execute_script``
    that reads the DOM and mutates nothing. Returns ``needs-review``
    findings (possibly empty); an empty list means no media or iframe was
    found, never that the criteria pass.
    """
    page_url = url if url is not None else driver.current_url
    records = driver.execute_script(_MEDIA_JS, _MAX_MEDIA)
    return evaluate_media(records, page_url)


def evaluate_media(records: list[dict[str, Any]], url: str) -> list[Finding]:
    """Turn a media/iframe inventory into 1.2.x findings (pure).

    Each record is either a native-media record (``type`` ``"media"``,
    ``tag`` ``"audio"``/``"video"``, plus a ``tracks`` list) or an iframe
    record (``type`` ``"iframe"``, plus ``src``/``title``). Native media
    yields an explicit transcript (1.2.1) or audio-description (1.2.3)
    candidate stating the caption/subtitle/description tracks found;
    YouTube/Vimeo embeds yield captions (1.2.2) + audio-description (1.2.3)
    candidates flagged as un-auditable; any other iframe yields a 1.2.1
    "review this embed" candidate. All findings are ``needs-review``.
    """
    findings: list[Finding] = []
    for record in records:
        if record.get("type") == "iframe" or "src" in record:
            findings.extend(_iframe_findings(record, url))
            continue
        tag = record.get("tag")
        if tag == "video":
            findings.append(_video_finding(record, url))
        elif tag == "audio":
            findings.append(_audio_finding(record, url))
    return findings


def _track_kinds(record: dict[str, Any]) -> list[str]:
    """Return the lowercased ``kind`` of each ``<track>`` on a media record."""
    return [
        (t.get("kind") or "").strip().lower()
        for t in (record.get("tracks") or [])
        if isinstance(t, dict)
    ]


def _yn(present: bool) -> str:
    """Render a detected/absent flag as ``yes``/``no`` for a message."""
    return "yes" if present else "no"


def _video_finding(record: dict[str, Any], url: str) -> Finding:
    """Build the 1.2.3 candidate for a native ``<video>`` (states its tracks)."""
    kinds = _track_kinds(record)
    detected = (
        f"captions: {_yn(_CAPTIONS_KIND in kinds)}, "
        f"subtitles: {_yn(_SUBTITLES_KIND in kinds)}, "
        f"descriptions: {_yn(_DESCRIPTIONS_KIND in kinds)}"
    )
    return Finding(
        criterion="1.2.3",
        severity="needs-review",
        message=(
            f"A <video> element is present. Detected text tracks — {detected}. "
            "WCAG 1.2.3 needs an audio description or a full text alternative "
            "for information conveyed visually — confirm one is provided (it "
            "may be a described version or transcript, not a <track>, so a "
            "human must check). Captions (1.2.2) are evaluated separately."
        ),
        selector=record.get("selector"),
        url=url,
    )


def _audio_finding(record: dict[str, Any], url: str) -> Finding:
    """Build the 1.2.1 transcript candidate for a native ``<audio>``."""
    kinds = [k for k in _track_kinds(record) if k]
    extra = (
        f" (It also declares text track(s): {', '.join(sorted(set(kinds)))}.)"
        if kinds
        else ""
    )
    return Finding(
        criterion="1.2.1",
        severity="needs-review",
        message=(
            "An <audio> element is present. If it is prerecorded audio-only, "
            "WCAG 1.2.1 requires an equivalent text transcript — confirm one is "
            "provided (a transcript elsewhere on the page cannot be detected "
            "automatically)." + extra
        ),
        selector=record.get("selector"),
        url=url,
    )


def _provider(src: str) -> str | None:
    """Return ``"YouTube"``/``"Vimeo"`` for a known video-embed ``src``, else None."""
    host = (urlparse(src).hostname or "").lower()
    if host.endswith(("youtube.com", "youtube-nocookie.com")) or host == "youtu.be":
        return "YouTube"
    if host == "vimeo.com" or host.endswith(".vimeo.com"):
        return "Vimeo"
    return None


def _iframe_findings(record: dict[str, Any], url: str) -> list[Finding]:
    """Build the un-auditable-embed candidate(s) for an ``<iframe>``.

    A recognized YouTube/Vimeo embed yields two candidates (captions 1.2.2
    and audio description 1.2.3), both stating the contents could not be
    inspected. Any other iframe yields one 1.2.1 candidate asking a human to
    classify the embed (or mark N/A if it is not time-based media).
    """
    src = record.get("src") or ""
    title = (record.get("title") or "").strip()
    selector = record.get("selector")
    provider = _provider(src)
    if provider is not None:
        lead = (
            f"A {provider} video embed is present, but its contents cannot be "
            "inspected automatically (cross-origin <iframe>)."
        )
        return [
            Finding(
                criterion="1.2.2",
                severity="needs-review",
                message=lead + " Confirm synchronized captions are available (WCAG 1.2.2).",
                selector=selector,
                url=url,
            ),
            Finding(
                criterion="1.2.3",
                severity="needs-review",
                message=(
                    lead + " Confirm an audio description or full text "
                    "alternative is available (WCAG 1.2.3)."
                ),
                selector=selector,
                url=url,
            ),
        ]
    host = (urlparse(src).hostname or "").lower()
    where = f"from {host}" if host else "with no external src"
    label = f", title “{title}”" if title else ""
    return [
        Finding(
            criterion="1.2.1",
            severity="needs-review",
            message=(
                f"An <iframe> embed ({where}{label}) could not be audited "
                "automatically. If it presents time-based media (audio or "
                "video), WCAG 1.2.1–1.2.5 apply — review it manually; if it "
                "is not media (e.g. a map, form, or advert), mark N/A."
            ),
            selector=selector,
            url=url,
        )
    ]


__all__ = ["check_media", "evaluate_media"]