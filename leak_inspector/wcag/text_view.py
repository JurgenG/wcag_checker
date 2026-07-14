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

"""Produce an approximate *linearized reading view* of a live page.

Walks the rendered DOM in source order and emits, for each heading, link,
button, image, form field and landmark, a simplified accessible name —
roughly what a screen reader or a text-only browser encounters as it
reads down the page. The result is embedded as a *Reading view* section
in the audit report (every format), via the ``render_*_section`` helpers
that :mod:`.reporter` calls.

**This is a review aid, not a test.** It deliberately makes *no* pass/fail
claim (see ``CLAUDE.md``: never assert coverage the engine cannot decide).
It cannot judge whether an accessible name is *meaningful*, whether the
source order matches the *visual* order (CSS can reorder content), or how
any specific assistive technology actually announces the page — those stay
manual. All it does is surface the accessible-name tree the way a linear
reader would traverse it, and mark elements that have *no* accessible name
(``named=False``) so a reviewer can check them by hand. The name
computation is a pragmatic approximation of the ARIA accessible-name
algorithm (aria-labelledby → aria-label → associated ``<label>`` / ``alt``
→ text content → ``title`` / ``value``), not a conformant implementation.

Structure mirrors the other engines' pure/impure split:

* :func:`extract` takes a live driver from the caller and runs one DOM
  walk in the page (impure; it never launches or closes the browser —
  same boundary as :mod:`.axe_runner` and :mod:`.screenshot`).
* the ``render_*_section`` functions and :func:`reading_view_payload` are
  pure — :class:`PageTextView` values in, strings/data out — so they are
  unit-tested against canned data.
"""

from __future__ import annotations

import html
import textwrap
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

#: Default cap on how many elements one page walk emits. A page with more
#: is truncated (and :attr:`PageTextView.truncated` is set) so a runaway
#: DOM cannot produce an unbounded artifact; the render notes the cut so
#: the limit is never silent.
DEFAULT_MAX_NODES = 4000

#: Explains the artifact's standing; carried into the rendered document so
#: the reading view is never mistaken for a screen-reader test result.
NOTE = (
    "This is an approximate *linearized reading view*: the page walked in "
    "DOM source order with a simplified accessible name for each heading, "
    "link, button, image, form field and landmark — broadly what a screen "
    "reader or text-only browser encounters reading top to bottom. It is a "
    "manual-review aid, NOT a screen-reader test and NOT a conformance "
    "check. It cannot tell you whether a name is *meaningful*, whether this "
    "order matches the *visual* layout (CSS can reorder content), or how any "
    "assistive technology actually announces the page. ⚠ marks an "
    "element that has no accessible name for you to check by hand."
)


@dataclass(frozen=True)
class TextNode:
    """One element in the linearized reading order.

    ``role`` is the reader-facing kind — ``"heading"``, ``"link"``,
    ``"button"``, ``"image"``, ``"field"``, ``"landmark"``, ``"frame"`` or
    ``"text"`` (a run of body text). ``name`` is the computed accessible
    name or text (may be empty). ``named`` is ``False`` when an element
    that needs an accessible name has none — the reviewer's cue. ``level``
    is the heading level (1–6) for headings; ``field_type`` the control
    type for fields; ``landmark`` the landmark role for landmarks;
    ``note`` a short caveat (e.g. ``"no alt attribute"``,
    ``"name from placeholder only"``, ``"decorative (empty alt)"``).
    """

    role: str
    name: str
    named: bool = True
    level: int | None = None
    field_type: str | None = None
    landmark: str | None = None
    note: str | None = None


@dataclass(frozen=True)
class PageTextView:
    """The linearized reading view of one audited page.

    ``url`` and ``title`` identify the page; ``nodes`` is the reading-order
    sequence; ``truncated`` is ``True`` when the walk hit
    :data:`DEFAULT_MAX_NODES` and stopped early.
    """

    url: str
    title: str
    nodes: tuple[TextNode, ...]
    truncated: bool = False


#: In-page DOM walker. Returns ``{title, nodes, truncated}``; each node is
#: a plain object mirroring :class:`TextNode`. Interactive/heading/image
#: elements are "consumed" (their subtree is not descended for text, since
#: their text is already folded into the name), so nothing is
#: double-counted; landmarks and plain containers are descended into.
#: Accessible-name computation is the simplified approximation documented
#: in the module docstring. ``arguments[0]`` is the node cap.
_WALK_JS = r"""
var MAX = arguments[0] || 4000;
var out = [];
var state = {truncated: false};
var SKIP = {SCRIPT: 1, STYLE: 1, NOSCRIPT: 1, TEMPLATE: 1};

function textOf(el) {
  return (el.textContent || '').replace(/\s+/g, ' ').trim();
}

function refNames(ids) {
  var parts = [];
  ids.split(/\s+/).forEach(function (id) {
    if (!id) return;
    var r = document.getElementById(id);
    if (r) parts.push(textOf(r));
  });
  return parts.join(' ').trim();
}

function ariaName(el) {
  var lb = el.getAttribute('aria-labelledby');
  if (lb) { var n = refNames(lb); if (n) return n; }
  var al = el.getAttribute('aria-label');
  if (al && al.trim()) return al.trim();
  return '';
}

function controlName(el) {
  var a = ariaName(el);
  if (a) return a;
  var t = textOf(el);
  if (t) return t;
  var im = el.querySelector('img[alt]');
  if (im) { var alt = (im.getAttribute('alt') || '').trim(); if (alt) return alt; }
  var val = el.getAttribute('value');
  if (val && val.trim()) return val.trim();
  var altAttr = el.getAttribute('alt');
  if (altAttr && altAttr.trim()) return altAttr.trim();
  var title = el.getAttribute('title');
  if (title && title.trim()) return title.trim();
  return '';
}

function fieldName(el) {
  var a = ariaName(el);
  if (a) return {name: a, source: 'aria'};
  var id = el.getAttribute('id');
  if (id && window.CSS && CSS.escape) {
    var lab = document.querySelector('label[for="' + CSS.escape(id) + '"]');
    if (lab) { var t = textOf(lab); if (t) return {name: t, source: 'label'}; }
  }
  var wrap = el.closest ? el.closest('label') : null;
  if (wrap) { var w = textOf(wrap); if (w) return {name: w, source: 'label'}; }
  var title = el.getAttribute('title');
  if (title && title.trim()) return {name: title.trim(), source: 'title'};
  var ph = el.getAttribute('placeholder');
  if (ph && ph.trim()) return {name: ph.trim(), source: 'placeholder'};
  return {name: '', source: 'none'};
}

function landmarkType(el, tag, role) {
  var roles = {banner: 1, navigation: 1, main: 1, contentinfo: 1,
    complementary: 1, search: 1, form: 1, region: 1};
  if (role && roles[role]) return role;
  if (tag === 'NAV') return 'navigation';
  if (tag === 'MAIN') return 'main';
  if (tag === 'HEADER') return 'banner';
  if (tag === 'FOOTER') return 'contentinfo';
  if (tag === 'ASIDE') return 'complementary';
  if (tag === 'FORM') return 'form';
  return null;
}

function classify(el) {
  var tag = el.tagName;
  var role = (el.getAttribute('role') || '').toLowerCase();
  if (role === 'presentation' || role === 'none') return {kind: 'container'};
  if (/^H[1-6]$/.test(tag)) return {kind: 'heading', level: parseInt(tag[1], 10)};
  if (role === 'heading') {
    return {kind: 'heading', level: parseInt(el.getAttribute('aria-level') || '2', 10)};
  }
  if (tag === 'A' && el.hasAttribute('href')) return {kind: 'link'};
  if (role === 'link') return {kind: 'link'};
  if (tag === 'BUTTON' || role === 'button') return {kind: 'button'};
  if (tag === 'INPUT') {
    var t = (el.getAttribute('type') || 'text').toLowerCase();
    if (t === 'hidden') return {kind: 'skip'};
    if (t === 'button' || t === 'submit' || t === 'reset' || t === 'image') {
      return {kind: 'button'};
    }
    return {kind: 'field', fieldType: t};
  }
  if (tag === 'TEXTAREA') return {kind: 'field', fieldType: 'textarea'};
  if (tag === 'SELECT') return {kind: 'field', fieldType: 'select'};
  if (tag === 'IMG' || role === 'img') return {kind: 'image'};
  if (tag === 'SVG' || tag === 'svg') return {kind: 'image', svg: true};
  var landmark = landmarkType(el, tag, role);
  if (landmark) return {kind: 'landmark', landmark: landmark};
  if (tag === 'IFRAME') return {kind: 'frame'};
  return {kind: 'container'};
}

function visible(el) {
  if (el.hasAttribute('hidden')) return false;
  if (el.getAttribute('aria-hidden') === 'true') return false;
  var cs = window.getComputedStyle(el);
  if (cs && (cs.display === 'none' || cs.visibility === 'hidden')) return false;
  return true;
}

function push(node) {
  if (out.length >= MAX) { state.truncated = true; return false; }
  if (node.role === 'text') {
    var last = out[out.length - 1];
    if (last && last.role === 'text') {
      last.name = (last.name + ' ' + node.name).trim();
      return true;
    }
  }
  out.push(node);
  return true;
}

function emitImage(el, isSvg) {
  if (isSvg) {
    var t = el.querySelector('title');
    var n = ariaName(el) || (t ? textOf(t) : '');
    if (n) push({role: 'image', name: n, named: true});
    return;  // an unnamed inline SVG is treated as decorative
  }
  var a = ariaName(el);
  if (a) { push({role: 'image', name: a, named: true}); return; }
  if (!el.hasAttribute('alt')) {
    push({role: 'image', name: '', named: false, note: 'no alt attribute'});
    return;
  }
  var alt = el.getAttribute('alt');
  if (alt.trim() === '') {
    push({role: 'image', name: '', named: true, note: 'decorative (empty alt)'});
    return;
  }
  push({role: 'image', name: alt.trim(), named: true});
}

function walk(el) {
  var kids = el.childNodes;
  for (var i = 0; i < kids.length; i++) {
    if (out.length >= MAX) { state.truncated = true; return; }
    var child = kids[i];
    if (child.nodeType === 3) {
      var t = (child.textContent || '').replace(/\s+/g, ' ').trim();
      if (t) push({role: 'text', name: t});
      continue;
    }
    if (child.nodeType !== 1) continue;
    if (SKIP[child.tagName]) continue;
    if (!visible(child)) continue;
    var c = classify(child);
    if (c.kind === 'skip' || c.kind === 'container') {
      if (c.kind === 'container') walk(child);
      continue;
    }
    if (c.kind === 'heading') {
      var hn = controlName(child);
      push({role: 'heading', level: c.level, name: hn, named: hn !== ''});
    } else if (c.kind === 'link' || c.kind === 'button') {
      var cn = controlName(child);
      push({role: c.kind, name: cn, named: cn !== ''});
    } else if (c.kind === 'field') {
      var f = fieldName(child);
      var note = null;
      if (f.source === 'placeholder') note = 'name from placeholder only';
      else if (f.source === 'title') note = 'name from title attribute';
      else if (f.source === 'none') note = 'no label';
      push({role: 'field', fieldType: c.fieldType, name: f.name,
        named: f.name !== '', note: note});
    } else if (c.kind === 'image') {
      emitImage(child, !!c.svg);
    } else if (c.kind === 'landmark') {
      push({role: 'landmark', landmark: c.landmark, name: ariaName(child),
        named: true});
      walk(child);
    } else if (c.kind === 'frame') {
      var ft = child.getAttribute('title');
      push({role: 'frame', name: (ft || child.getAttribute('src') || '').trim(),
        named: !!(ft && ft.trim()),
        note: (ft && ft.trim()) ? null : 'iframe has no title'});
    }
  }
}

if (document.body) walk(document.body);
return {title: document.title || '', nodes: out, truncated: state.truncated};
"""


def extract(
    driver: Any, url: str | None = None, *, max_nodes: int = DEFAULT_MAX_NODES
) -> PageTextView:
    """Walk the driver's current page into a :class:`PageTextView`.

    ``driver`` is a live Selenium WebDriver on the page to read; the caller
    owns its lifecycle (this never launches or closes it). ``url`` labels
    the view; when omitted it is read from ``driver.current_url``.
    ``max_nodes`` caps the walk (see :data:`DEFAULT_MAX_NODES`).

    Side effect: executes one JavaScript DOM walk in the current browsing
    context. Returns the reading view; it makes no pass/fail judgement.
    """
    page_url = url if url is not None else driver.current_url
    raw = driver.execute_script(_WALK_JS, max_nodes)
    return _to_page_view(raw, page_url)


def _to_page_view(raw: Any, url: str) -> PageTextView:
    """Convert the walker's raw dict into a :class:`PageTextView`. Pure."""
    data = raw or {}
    nodes = tuple(_to_node(n) for n in (data.get("nodes") or ()))
    return PageTextView(
        url=url,
        title=str(data.get("title") or "").strip(),
        nodes=nodes,
        truncated=bool(data.get("truncated")),
    )


def _to_node(data: dict[str, Any]) -> TextNode:
    """Convert one raw walker node into a :class:`TextNode`. Pure."""
    level = data.get("level")
    return TextNode(
        role=str(data.get("role") or "text"),
        name=str(data.get("name") or ""),
        named=bool(data.get("named", True)),
        level=int(level) if isinstance(level, (int, float)) else None,
        field_type=data.get("fieldType") or None,
        landmark=data.get("landmark") or None,
        note=data.get("note") or None,
    )


#: Title of the report's embedded reading-view section, shared across the
#: Markdown / text / HTML renderings so the section reads the same
#: everywhere.
SECTION_HEADING = "Reading view (manual-review aid)"


def render_markdown_section(views: Sequence[PageTextView]) -> str:
    """Render the reading view as a Markdown ``## Reading view`` section.

    Pure. Each page gets a sub-section with a heading/landmark/link/image/
    field tally and its reading-order list; elements with no accessible
    name are flagged with ``⚠``. Leads with :data:`NOTE` so the section is
    not read as a screen-reader test result. Returns ``""`` when there are
    no views, so a report with nothing captured gets no empty section.
    """
    if not views:
        return ""
    lines = [f"## {SECTION_HEADING}", "", NOTE, ""]
    for view in views:
        lines.append(f"### {view.title or view.url}")
        if view.title:
            lines.append(f"<{view.url}>")
        lines.append("")
        lines.append(_summary_line(view))
        lines.append("")
        if not view.nodes:
            lines += ["_No visible content was extracted from this page._", ""]
            continue
        lines += [f"- {_format_node(node)}" for node in view.nodes]
        if view.truncated:
            lines += ["", _truncation_note(view)]
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_text_section(views: Sequence[PageTextView]) -> str:
    """Render the reading view as a plain-text report section.

    Pure. Mirrors :func:`render_markdown_section` for the ``.txt`` report;
    returns ``""`` when there are no views.
    """
    if not views:
        return ""
    lines = [SECTION_HEADING, "-" * len(SECTION_HEADING), ""]
    lines += textwrap.wrap(NOTE, width=76)
    lines.append("")
    for view in views:
        lines.append(view.title or view.url)
        if view.title:
            lines.append(f"  {view.url}")
        lines.append(f"  {_summary_line(view)}")
        if not view.nodes:
            lines += ["  (no visible content was extracted from this page)", ""]
            continue
        lines += [f"  {_format_node(node)}" for node in view.nodes]
        if view.truncated:
            lines.append(f"  {_truncation_note(view)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_html_section(views: Sequence[PageTextView]) -> str:
    """Render the reading view as an HTML fragment for the report body.

    Pure. Each page is a collapsed ``<details>`` (title + tally in the
    summary) holding the reading-order list, so the section never dominates
    the report until expanded. Every value is HTML-escaped. Returns ``""``
    when there are no views (the report then shows no reading-view section).
    """
    if not views:
        return ""
    parts = [
        f"<h2>{html.escape(SECTION_HEADING)}</h2>",
        f"<p class='rv-note'>{html.escape(NOTE)}</p>",
    ]
    for view in views:
        heading = html.escape(view.title or view.url)
        parts.append("<details class='rv'>")
        parts.append(
            f"<summary>{heading} — {html.escape(_summary_line(view))}</summary>"
        )
        if view.title:
            parts.append(f"<p class='rv-url'>{html.escape(view.url)}</p>")
        if not view.nodes:
            parts.append(
                "<p><em>No visible content was extracted from this page.</em></p>"
            )
        else:
            items = "".join(_node_html(node) for node in view.nodes)
            parts.append(f"<ul class='rv-list'>{items}</ul>")
            if view.truncated:
                parts.append(f"<p><em>{html.escape(_truncation_note(view))}</em></p>")
        parts.append("</details>")
    return "".join(parts)


def reading_view_payload(views: Sequence[PageTextView]) -> list[dict[str, Any]]:
    """Return the reading view as JSON-ready data for ``results.json``. Pure."""
    return [
        {
            "url": view.url,
            "title": view.title,
            "truncated": view.truncated,
            "nodes": [
                {
                    "role": node.role,
                    "name": node.name,
                    "named": node.named,
                    "level": node.level,
                    "field_type": node.field_type,
                    "landmark": node.landmark,
                    "note": node.note,
                }
                for node in view.nodes
            ],
        }
        for view in views
    ]


def _truncation_note(view: PageTextView) -> str:
    """Sentence stating the walk was capped, so the cut is never silent."""
    return (
        f"Reading view truncated at {len(view.nodes)} elements; the page has more."
    )


def _summary_line(view: PageTextView) -> str:
    """One-line tally of the page's landmarks, headings, and controls."""
    nodes = view.nodes
    images = [n for n in nodes if n.role == "image"]
    fields = [n for n in nodes if n.role == "field"]
    return (
        f"{_count(nodes, 'heading')} heading(s), "
        f"{_count(nodes, 'landmark')} landmark(s), "
        f"{_count(nodes, 'link')} link(s), "
        f"{_count(nodes, 'button')} button(s), "
        f"{len(images)} image(s) ({sum(1 for n in images if not n.named)} "
        "without a name), "
        f"{len(fields)} form field(s) ({sum(1 for n in fields if not n.named)} "
        "without a label)."
    )


def _count(nodes: Sequence[TextNode], role: str) -> int:
    """Number of nodes with the given role."""
    return sum(1 for n in nodes if n.role == role)


def _format_node(node: TextNode) -> str:
    """Format one node as the body of a Markdown list item."""
    if node.role == "heading":
        return f"**H{node.level or '?'}** " + (
            node.name if node.named else "⚠ (empty heading)"
        )
    if node.role == "text":
        return node.name
    tag = _role_tag(node)
    if not node.named:
        return f"`{tag}` ⚠ {node.note or 'no accessible name'}"
    body = f'"{node.name}"' if node.name else "(unnamed)"
    return f"`{tag}` {body}" + (f" — {node.note}" if node.note else "")


def _role_tag(node: TextNode) -> str:
    """Backtick tag for a node: role plus its field type / landmark role."""
    if node.role == "field" and node.field_type:
        return f"field:{node.field_type}"
    if node.role == "landmark" and node.landmark:
        return f"landmark:{node.landmark}"
    return node.role


def _node_html(node: TextNode) -> str:
    """Format one node as an escaped ``<li>`` for the HTML reading view."""
    if node.role == "heading":
        label = html.escape(node.name) if node.named else "⚠ (empty heading)"
        return f"<li class='rv-heading'><strong>H{node.level or '?'}</strong> {label}</li>"
    if node.role == "text":
        return f"<li class='rv-text'>{html.escape(node.name)}</li>"
    tag = f"<code>{html.escape(_role_tag(node))}</code>"
    if not node.named:
        return f"<li class='rv-warn'>{tag} ⚠ {html.escape(node.note or 'no accessible name')}</li>"
    body = f'"{html.escape(node.name)}"' if node.name else "(unnamed)"
    note = f" — {html.escape(node.note)}" if node.note else ""
    return f"<li>{tag} {body}{note}</li>"


__all__ = [
    "DEFAULT_MAX_NODES",
    "NOTE",
    "SECTION_HEADING",
    "PageTextView",
    "TextNode",
    "extract",
    "reading_view_payload",
    "render_html_section",
    "render_markdown_section",
    "render_text_section",
]
