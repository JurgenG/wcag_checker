# leak_inspector — record what data a website leaks during a real
# human-driven browsing session.
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

"""PDF report export.

A PDF is the existing HTML report (:mod:`leak_inspector.report.html`)
rendered through **WeasyPrint** (HTML→PDF), with:

* a branded **cover page** — BeLibre logo, the site URL, the project
  source link, the capture date, and the disclaimer;
* a **table of contents** page (printed, with page numbers) plus a PDF
  **bookmark outline** for navigation;
* the report body. By default the body is the **summary** (per-hit
  parameter tables omitted), and the **full detailed** report is
  embedded as a PDF *file attachment* — so a reader gets a tight
  printable summary while the exhaustive drill-down travels in the same
  file.

WeasyPrint shows ``<details>`` content regardless of open-state (the
collapse is a browser-only affordance), so the summary is produced by
stripping the per-hit detail tables, keeping each section's summary
line.

WeasyPrint is an **optional** dependency (heavy native libs — cairo /
pango / gdk-pixbuf), imported lazily: :func:`render_pdf_document`
raises a clear, install-pointing :class:`RuntimeError` when it (or its
native libs) are missing. The cover / TOC / HTML-assembly helpers are
pure and need no WeasyPrint.
"""

from __future__ import annotations

import re
from html import escape

from ._branding import (
    BELIBRE_HOMEPAGE,
    BRANDING_TITLE_PREFIX,
    PROJECT_SOURCE_URL,
    belibre_logo_svg_inline,
    title_host_label,
)
from .builder import build_report_document
from .document import ManifestView, ReportDocument

from .html import render_html_document

#: Print CSS, appended after the report's own ``<style>`` (later rules
#: win). A4 + margins; the cover and the TOC each own a page; PDF
#: bookmarks come from ``bookmark-level`` on the section headings; the
#: TOC's page numbers come from ``target-counter``.
_PDF_CSS = """
@page { size: A4; margin: 18mm 16mm; }

/* PDF outline (the navigation bookmark tree). The report's own header
   <h1> stays top-level (level 1); every section <h2> nests under it at
   level 2 — matching the printed TOC. */
.pdf-cover h1 { bookmark-level: 1; bookmark-label: "Cover"; }
.pdf-toc .pdf-toc-title { bookmark-level: 1; bookmark-label: "Contents"; }
h2 { bookmark-level: 2; }

.pdf-cover {
  page-break-after: always;
  display: flex; flex-direction: column; min-height: 86vh;
}
.pdf-cover .belibre-logo { height: 48px; width: auto; }
.pdf-cover h1 { margin: 24px 0 4px; font-size: 22px; }
.pdf-cover .pdf-cover-host { font-size: 15px; color: #444; }
.pdf-cover .pdf-cover-meta { margin-top: 28px; line-height: 1.7; }
.pdf-cover .pdf-cover-meta dt {
  font-weight: bold; color: #555; font-size: 11px;
  text-transform: uppercase; letter-spacing: .04em; margin-top: 12px;
}
.pdf-cover .pdf-cover-meta dd { margin: 0; word-break: break-all; }
.pdf-cover .pdf-cover-disclaimer {
  margin-top: auto; padding-top: 24px; color: #666; font-style: italic;
}

/* Printed table of contents */
.pdf-toc { page-break-after: always; }
.pdf-toc .pdf-toc-title { font-size: 18px; margin: 0 0 16px; }
.pdf-toc ol { list-style: none; padding: 0; margin: 0; }
.pdf-toc li { margin: 7px 0; border-bottom: 1px dotted #ccc; }
.pdf-toc a { text-decoration: none; color: #1a1a1a; }
.pdf-toc a::after {
  content: target-counter(attr(href), page); float: right; color: #666;
}

/* Summary-mode note where the per-hit tables were omitted */
.pdf-detail-ref { color: #666; font-style: italic; margin: 4px 0 0; }

/* Colour emoji + flags. WeasyPrint cannot colour-render emoji glyphs at
   the ~16px body size, so each is replaced (see _wrap_emoji) by inline
   SVG extracted from the bundled Twemoji font — sized here to ride the
   text like a character. */
svg.emoji { height: 1em; width: auto; vertical-align: -0.15em; }
"""

#: One colour-emoji grapheme: a regional-indicator **flag pair** (kept
#: whole), or a pictographic glyph (astral emoji planes plus the three
#: BMP emoji the reports use — ⚠ ✅ ❌) with an optional trailing
#: variation selector. Deliberately excludes text-presentation symbols
#: the reports render as plain glyphs (✓ ✗ → ► − √ ≥ ∞, CJK names).
_EMOJI_RE = re.compile(
    "(?:[\U0001F1E6-\U0001F1FF]{2}"                          # flag pair
    "|[\U0001F000-\U0001FAFF⚠✅❌]️?)"     # pictograph +VS16
)


def _wrap_emoji(html: str) -> str:
    """Replace each colour emoji with inline Twemoji SVG so WeasyPrint
    renders it in colour at any size. Emoji the font can't represent are
    left as the raw character."""
    from .emoji_svg import emoji_to_svg
    return _EMOJI_RE.sub(
        lambda m: emoji_to_svg(m.group(0)) or m.group(0), html,
    )

#: A ``<details>…</details>`` block (per-hit drill-down). Non-nested in
#: the report, so a non-greedy match per block is safe. Group 1 is the
#: ``<summary>`` to keep when omitting the detail tables.
_DETAILS_RE = re.compile(
    r"<details[^>]*>\s*(<summary>.*?</summary>).*?</details>", re.S,
)

#: An ``<h2>`` section heading. Group 1 = existing attributes, group 2 =
#: inner markup (flag emoji, module-id spans, …).
_H2_RE = re.compile(r"<h2([^>]*)>(.*?)</h2>", re.S)


def _strip_detail_tables(html: str) -> str:
    """Replace each per-hit ``<details>`` body with a pointer note,
    keeping the section's ``<summary>`` line — the summary view."""
    def repl(m: re.Match) -> str:
        return (
            f"<details open>{m.group(1)}"
            '<p class="pdf-detail-ref">Full per-hit detail is in the '
            "attached detailed report.</p></details>"
        )
    return _DETAILS_RE.sub(repl, html)


def _add_section_ids(html: str) -> tuple[str, list[tuple[str, str]]]:
    """Give each ``<h2>`` a stable id and collect ``(id, label)`` for the
    TOC. Headings that already carry an id are left as-is."""
    entries: list[tuple[str, str]] = []
    counter = [0]

    def repl(m: re.Match) -> str:
        attrs, inner = m.group(1), m.group(2)
        if "id=" in attrs:
            return m.group(0)
        sid = f"sec-{counter[0]}"
        counter[0] += 1
        label = re.sub(r"<[^>]+>", "", inner).strip()
        entries.append((sid, label))
        return f'<h2 id="{sid}"{attrs}>{inner}</h2>'

    return _H2_RE.sub(repl, html), entries


def _toc_html(entries: list[tuple[str, str]]) -> str:
    """Build the printed table-of-contents ``<nav>`` (page numbers are
    filled by WeasyPrint via ``target-counter`` in the CSS)."""
    items = "\n".join(
        f'<li><a href="#{sid}">{escape(label)}</a></li>'
        for sid, label in entries
    )
    return (
        '<nav class="pdf-toc">\n'
        '<h2 class="pdf-toc-title">Contents</h2>\n'
        f"<ol>\n{items}\n</ol>\n</nav>\n"
    )


def _cover_html(manifest: ManifestView) -> str:
    """Build the cover-page ``<section>`` (pure; no WeasyPrint).

    Carries the BeLibre logo, the report title + site host, and a
    metadata list: the site URL, the capture date (from the manifest —
    deterministic, not the wall clock), the project source repository,
    the project homepage, and the auto-generation disclaimer.
    """
    host = escape(title_host_label(manifest))
    target = escape(manifest.target_url or "")
    captured = escape((manifest.ended_at or manifest.started_at or "")[:10])
    return f"""<section class="pdf-cover">
  {belibre_logo_svg_inline()}
  <h1>{escape(BRANDING_TITLE_PREFIX)}</h1>
  <div class="pdf-cover-host">{host}</div>
  <dl class="pdf-cover-meta">
    <dt>Website</dt><dd><a href="{target}">{target}</a></dd>
    <dt>Captured</dt><dd>{captured}</dd>
    <dt>Tool source</dt>
    <dd><a href="{PROJECT_SOURCE_URL}">{escape(PROJECT_SOURCE_URL)}</a></dd>
    <dt>Project</dt>
    <dd><a href="{BELIBRE_HOMEPAGE}">{escape(BELIBRE_HOMEPAGE)}</a></dd>
  </dl>
  <p class="pdf-cover-disclaimer">This report is automatically generated.</p>
</section>
"""


def build_pdf_html(
    document: ReportDocument,
    *,
    detailed: bool = False,
    screenshot_filename: str | None = None,
    extra_screenshot_filenames: list[str] | None = None,
    extra_screenshot_captions: list[str] | None = None,
) -> str:
    """Assemble print-ready HTML: cover + TOC + report.

    ``detailed=False`` (default) omits the per-hit parameter tables (the
    summary view); ``detailed=True`` keeps them. Pure — no WeasyPrint —
    so it is fully testable. The cover precedes a printed table of
    contents; both precede the report body. Section headings get ids so
    the TOC can link to them; the PDF bookmark outline is produced from
    ``bookmark-level`` CSS at render time.
    """
    html = render_html_document(
        document,
        screenshot_filename=screenshot_filename,
        extra_screenshot_filenames=extra_screenshot_filenames,
        extra_screenshot_captions=extra_screenshot_captions,
    )
    if not detailed:
        html = _strip_detail_tables(html)
    html, entries = _add_section_ids(html)
    html = html.replace("</head>", f"<style>{_PDF_CSS}</style>\n</head>", 1)
    front = _cover_html(document.manifest) + _toc_html(entries)
    html = html.replace("<body>\n", "<body>\n" + front, 1)
    # Wrap emoji last, so the cover, the TOC labels and the body all get
    # the colour font (no emoji appear in the <head>/<style>).
    return _wrap_emoji(html)


def _import_weasyprint():
    """Return the WeasyPrint ``HTML`` / ``Attachment``; raise a clear,
    install-pointing error when the package or its native libs are
    missing."""
    try:
        from weasyprint import HTML, Attachment
    except (ImportError, OSError) as exc:  # pragma: no cover
        # ImportError: package absent. OSError: package present but its
        # native libraries (cairo / pango / gdk-pixbuf) are missing.
        raise RuntimeError(
            "PDF export needs WeasyPrint and its native libraries "
            "(cairo, pango, gdk-pixbuf). Install with: "
            "pip install 'leak-inspector[pdf]' (or pip install weasyprint), "
            f"and the native libs per WeasyPrint's install docs. ({exc})"
        ) from exc
    return HTML, Attachment


def render_pdf_document(
    document: ReportDocument,
    *,
    detailed: bool = False,
    attach_detailed: bool = True,
    screenshot_filename: str | None = None,
    extra_screenshot_filenames: list[str] | None = None,
    extra_screenshot_captions: list[str] | None = None,
) -> bytes:
    """Render a :class:`ReportDocument` to PDF bytes via WeasyPrint.

    By default the body is the **summary** and the **full detailed**
    report is embedded as a PDF file attachment (``attach_detailed``);
    pass ``detailed=True`` to make the body itself the detailed report
    (and no attachment). Raises :class:`RuntimeError` when WeasyPrint is
    unavailable.
    """
    HTML, Attachment = _import_weasyprint()
    shots = dict(
        screenshot_filename=screenshot_filename,
        extra_screenshot_filenames=extra_screenshot_filenames,
        extra_screenshot_captions=extra_screenshot_captions,
    )

    attachments = []
    if attach_detailed and not detailed:
        detailed_pdf = render_pdf_document(
            document, detailed=True, attach_detailed=False, **shots,
        )
        host = title_host_label(document.manifest)
        attachments.append(Attachment(
            string=detailed_pdf,
            name=f"{host}-detailed-report.pdf",
            description="Full detailed report (per-hit parameter tables)",
        ))

    html = build_pdf_html(document, detailed=detailed, **shots)
    return HTML(string=html).write_pdf(attachments=attachments or None)


def write_pdf_report(
    analysis,
    *,
    detailed: bool = False,
    attach_detailed: bool = True,
    screenshot_filename: str | None = None,
    extra_screenshot_filenames: list[str] | None = None,
    extra_screenshot_captions: list[str] | None = None,
    display_name: str | None = None,
) -> bytes:
    """Build the document from ``analysis`` and render it to PDF bytes.

    ``display_name`` (optional) overrides the report's title label
    (the host is used when None).
    """
    return render_pdf_document(
        build_report_document(analysis, display_name=display_name),
        detailed=detailed,
        attach_detailed=attach_detailed,
        screenshot_filename=screenshot_filename,
        extra_screenshot_filenames=extra_screenshot_filenames,
        extra_screenshot_captions=extra_screenshot_captions,
    )


__all__ = [
    "build_pdf_html",
    "render_pdf_document",
    "write_pdf_report",
]
