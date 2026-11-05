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

"""Point a manual reviewer at the concrete elements a criterion hinges on.

Several WCAG criteria cannot be *decided* automatically, but the specific
page elements they turn on *can* be located — so instead of a generic
"does the page do X?" question, this surfaces the exact element to check.
Each detection is emitted as a ``needs-review`` :class:`~.core.Finding`
carrying the element's selector (so the report screenshots it); nothing
here is ever a pass or a definite failure.

Criteria covered (all ``manual`` tier — these are review pointers, not
decisions):

* **4.1.3 Status Messages** — locate ARIA live regions
  (``role=status``/``alert``/``log``, ``aria-live``); point at each to
  confirm status messages are routed through it, or note when none exists.
* **3.3.8 Accessible Authentication (Minimum)** — locate password fields
  (a login step) and CAPTCHA widgets (reCAPTCHA / hCaptcha / Turnstile);
  point at each to confirm no un-assisted cognitive test is required.
* **2.4.5 Multiple Ways** — locate the page's location mechanisms (a
  search field, site navigation, a sitemap link) and report which were
  found, so the reviewer confirms at least two lead here.
* **3.2.6 Consistent Help** — locate help/contact mechanisms, so the
  reviewer confirms they appear in the same relative order across pages.

Design mirrors :mod:`.media`: one impure gatherer (:func:`check_pointers`,
a single read-only ``execute_script``) and a pure evaluator
(:func:`evaluate_pointers`) the hermetic tests drive with canned data.
Boundary: takes a live driver from the caller; never launches or closes it.
Messages are written in the ``lang`` passed to :func:`check_pointers` /
:func:`evaluate_pointers` (see :mod:`leak_inspector.i18n`).
"""

from __future__ import annotations

from typing import Any

from ..i18n import SOURCE_LANG, tr
from .core import Finding

#: Cap on how many elements of each kind one page is inspected for, so a
#: pathological page cannot produce an unbounded number of findings.
_MAX_PER_KIND = 25

#: Injected gatherer: locate the elements each covered criterion hinges on
#: and return them grouped by kind. Read-only. ``arguments[0]`` is the cap.
_POINTERS_JS = r"""
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
function txt(el){ return (el.textContent||'').trim().replace(/\s+/g,' ').slice(0,80); }
function take(sel){
  const out=[]; const nodes=document.querySelectorAll(sel);
  for(let i=0;i<nodes.length && out.length<MAX;i++) out.push(nodes[i]);
  return out;
}

const live=[];
for(const el of take('[role=status],[role=alert],[role=log],[aria-live]')){
  const al=(el.getAttribute('aria-live')||'').toLowerCase();
  if(al==='off') continue;
  live.push({selector:cssPath(el), role:(el.getAttribute('role')||'').toLowerCase(), ariaLive:al});
}

const passwords=take('input[type=password]').map(el=>({selector:cssPath(el)}));

const captchas=[]; const seen=new Set();
for(const [kind,sel] of [
  ['reCAPTCHA','.g-recaptcha, iframe[src*="recaptcha"], [data-sitekey]'],
  ['hCaptcha','.h-captcha, iframe[src*="hcaptcha"]'],
  ['Cloudflare Turnstile','.cf-turnstile, iframe[src*="challenges.cloudflare.com"]']]){
  for(const el of take(sel)){
    const s=cssPath(el);
    if(seen.has(s)) continue; seen.add(s);
    captchas.push({selector:s, kind});
  }
}

const search=take('input[type=search], [role=search]').map(el=>({selector:cssPath(el)}));
const navs=take('nav, [role=navigation]').map(el=>({selector:cssPath(el)}));

const sitemap=[];
for(const el of take('a[href]')){
  const href=(el.getAttribute('href')||'').toLowerCase();
  if(href.includes('sitemap') || /\bsite ?map\b/i.test(txt(el))){
    sitemap.push({selector:cssPath(el), text:txt(el)});
    if(sitemap.length>=MAX) break;
  }
}

const help=[]; const helpRe=/\b(help|contact|support|faq)\b/i;
for(const el of take('a[href]')){
  const href=(el.getAttribute('href')||'').toLowerCase();
  if(helpRe.test(href) || helpRe.test(txt(el))){
    help.push({selector:cssPath(el), text:txt(el)});
    if(help.length>=MAX) break;
  }
}

return {live, passwords, captchas, search, navs, sitemap, help};
"""


def check_pointers(
    driver: Any, url: str | None = None, *, lang: str = SOURCE_LANG
) -> list[Finding]:
    """Locate the review-pointer elements on the live page and flag them.

    ``driver`` is a live Selenium WebDriver on the page to inspect; the
    caller owns its lifecycle. ``url`` labels the findings; when omitted it
    is read from ``driver.current_url``. Read-only: one ``execute_script``
    that reads the DOM and mutates nothing. Returns ``needs-review``
    findings (possibly empty), with messages in ``lang``.
    """
    page_url = url if url is not None else driver.current_url
    data = driver.execute_script(_POINTERS_JS, _MAX_PER_KIND)
    return evaluate_pointers(data, page_url, lang=lang)


def evaluate_pointers(
    data: dict[str, Any], url: str, *, lang: str = SOURCE_LANG
) -> list[Finding]:
    """Turn the located elements into review-pointer findings (pure).

    ``data`` groups the located elements by kind (``live``, ``passwords``,
    ``captchas``, ``search``, ``navs``, ``sitemap``, ``help``). Emits
    ``needs-review`` findings for 4.1.3, 3.3.8, 2.4.5, and 3.2.6, each
    pointing at the specific element(s) a reviewer must verify, with
    messages in ``lang``.
    """
    findings: list[Finding] = []
    findings += _status_findings(data.get("live") or [], url, lang)
    findings += _auth_findings(
        data.get("passwords") or [], data.get("captchas") or [], url, lang
    )
    findings += _ways_findings(
        data.get("search") or [],
        data.get("navs") or [],
        data.get("sitemap") or [],
        url,
        lang,
    )
    findings += _help_findings(data.get("help") or [], url, lang)
    return findings


def _status_findings(
    live: list[dict[str, Any]], url: str, lang: str
) -> list[Finding]:
    """4.1.3 — point at each live region, or note that none was found."""
    if not live:
        return [
            Finding(
                criterion="4.1.3",
                severity="needs-review",
                message=tr(
                    lang,
                    "No ARIA live region (role=status/alert/log or aria-live) was "
                    "found. If the page shows status messages without reloading "
                    "(form errors, 'saved', result counts, cart updates), they are "
                    "probably not announced to screen readers — check WCAG 4.1.3.",
                ),
                selector=None,
                url=url,
            )
        ]
    out: list[Finding] = []
    for region in live:
        role = region.get("role")
        live_val = region.get("ariaLive")
        where = role or (
            f"aria-live={live_val}" if live_val else tr(lang, "live region")
        )
        out.append(
            Finding(
                criterion="4.1.3",
                severity="needs-review",
                message=tr(
                    lang,
                    "A live region ({where}) was found. Confirm the page routes "
                    "its status messages (errors, 'saved', result counts) through "
                    "it so they are announced without moving focus (WCAG 4.1.3).",
                    where=where,
                ),
                selector=region.get("selector"),
                url=url,
            )
        )
    return out


def _auth_findings(
    passwords: list[dict[str, Any]],
    captchas: list[dict[str, Any]],
    url: str,
    lang: str,
) -> list[Finding]:
    """3.3.8 — point at login password fields and CAPTCHA widgets."""
    out: list[Finding] = []
    for field in passwords:
        out.append(
            Finding(
                criterion="3.3.8",
                severity="needs-review",
                message=tr(
                    lang,
                    "A password field was found (a login/authentication step). "
                    "Confirm it does not rely on a cognitive function test: the "
                    "browser and password managers must be able to fill or paste "
                    "it, and no un-assisted memorisation or transcription is "
                    "required (WCAG 3.3.8).",
                ),
                selector=field.get("selector"),
                url=url,
            )
        )
    for widget in captchas:
        kind = widget.get("kind") or "CAPTCHA"
        out.append(
            Finding(
                criterion="3.3.8",
                severity="needs-review",
                message=tr(
                    lang,
                    "A {kind} was found. Confirm an accessible alternative to the "
                    "cognitive test exists (e.g. an audio challenge, an email/link "
                    "sign-in, or object recognition) (WCAG 3.3.8).",
                    kind=kind,
                ),
                selector=widget.get("selector"),
                url=url,
            )
        )
    return out


def _ways_findings(
    search: list[dict[str, Any]],
    navs: list[dict[str, Any]],
    sitemap: list[dict[str, Any]],
    url: str,
    lang: str,
) -> list[Finding]:
    """2.4.5 — report which location mechanisms were found (one finding)."""
    mechanisms: list[str] = []
    if search:
        mechanisms.append(tr(lang, "a search field"))
    if navs:
        mechanisms.append(tr(lang, "site navigation"))
    if sitemap:
        mechanisms.append(tr(lang, "a sitemap link"))
    primary = search or navs or sitemap
    selector = primary[0].get("selector") if primary else None

    if not mechanisms:
        message = tr(
            lang,
            "No obvious way to locate this page was detected (no search field, "
            "site navigation, or sitemap link). WCAG 2.4.5 needs at least two "
            "independent ways to find a page — verify manually (exempt if this "
            "page is a step within a process).",
        )
    elif len(mechanisms) >= 2:
        message = tr(
            lang,
            "Ways to locate this page detected: {found}. WCAG 2.4.5 needs at "
            "least two independent ways that lead here — confirm there are two "
            "or more and each actually leads here (exempt if this page is a "
            "step within a process).",
            found=", ".join(mechanisms),
        )
    else:
        message = tr(
            lang,
            "Ways to locate this page detected: {found}. WCAG 2.4.5 needs at "
            "least two independent ways that lead here — confirm at least one "
            "more independent way exists (exempt if this page is a step within "
            "a process).",
            found=", ".join(mechanisms),
        )
    return [
        Finding(
            criterion="2.4.5",
            severity="needs-review",
            message=message,
            selector=selector,
            url=url,
        )
    ]


def _help_findings(
    help_links: list[dict[str, Any]], url: str, lang: str
) -> list[Finding]:
    """3.2.6 — point at help/contact mechanisms (one summary finding)."""
    if not help_links:
        return []
    labels: list[str] = []
    for link in help_links:
        text = (link.get("text") or "").strip()
        if text and text not in labels:
            labels.append(text)
        if len(labels) >= 3:
            break
    examples = (
        ", ".join(f"“{label}”" for label in labels)
        if labels
        else tr(lang, "a help/contact link")
    )
    return [
        Finding(
            criterion="3.2.6",
            severity="needs-review",
            message=tr(
                lang,
                "Help/contact mechanism(s) found ({examples}). WCAG 3.2.6 needs "
                "help that is offered to appear in the same relative order on every "
                "page that has it — compare its placement across the audited pages.",
                examples=examples,
            ),
            selector=help_links[0].get("selector"),
            url=url,
        )
    ]


__all__ = ["check_pointers", "evaluate_pointers"]