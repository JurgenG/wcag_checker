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

"""HTML reporter — walks a :class:`~.document.ReportDocument` and
emits a standalone HTML document.

Structure mirrors the text + markdown reporters:

* Header banner from the manifest.
* Executive summary — KEY FINDINGS → RECOMMENDED ACTIONS →
  DETAILED FINDINGS (cname cloaks, vendor rollup, jurisdictions,
  volume stats).
* Unclassified third-party hosts table.
* One ``<section class="tracker">`` per fired module, with a
  ``<details>`` block holding each representative hit's classified
  parameter table.

Format-specific affordances stay here: CSS classes, ``title=""``
tooltips, expandable ``<details>``, severity color-coding. The data
itself comes pre-shaped from the document — this file does no
derivation.
"""

from __future__ import annotations

from html import escape as _h
from io import StringIO
from urllib.parse import urlparse

from ._branding import (
    BELIBRE_HOMEPAGE,
    belibre_logo_svg_inline,
    BRANDING_TITLE_PREFIX,
    INTRO_DISCLAIMER_TEXT,
    INTRO_PARAGRAPHS,
    INTRO_TITLE,
    title_host_label,
)

from ..analysis import Analysis
from ..modules.base import (
    CATEGORIES,
    IMPACT_HIGH,
    IMPACT_LOW,
    IMPACT_MEDIUM,
)
from .builder import build_report_document
from .score_v2 import DEFAULT_P50, DEFAULT_S, EXPLAINER_THRESHOLD, format_stars
from .document import (
    DNSPosture,
    ExecutiveSummary,
    ManifestView,
    ModuleSection,
    ParamRow,
    RepresentativeHit,
    ReportDocument,
    UnclassifiedHost,
)


_CSS = """
/* ---------------------------------------------------------------------------
 * Design tokens — change a tone palette here and every section / badge / chip
 * picks it up. Severity-tinted triplets follow a (bg / border / fg) shape.
 * ------------------------------------------------------------------------- */
:root {
  color-scheme: light dark;

  /* Severity badge backgrounds (saturated) + foregrounds */
  --c-bad-bg:  #fde2e1; --c-bad-bd:  #d63138; --c-bad-fg:  #842029;
  --c-warn-bg: #fff3cd; --c-warn-bd: #b88d2c; --c-warn-fg: #664d03;
  --c-good-bg: #d1e7dd; --c-good-bd: #2e8550; --c-good-fg: #0f5132;
  --c-info-bg: #cfe2ff; --c-info-bd: #4a90c1; --c-info-fg: #084298;

  /* Section background tints (paler — sit behind the saturated badges) */
  --c-bad-tint:  #fef6f6;
  --c-warn-tint: #fdf8ee;
  --c-good-tint: #f3faf6;
  --c-info-tint: #f0f6fb;

  /* Neutral */
  --c-muted-fg: #888;
  --c-rule:     #eee;
  --c-chip-bg:  #eee;
}

/* ---------------------------------------------------------------------------
 * Base
 * ------------------------------------------------------------------------- */
body {
  font-family: ui-sans-serif, system-ui, sans-serif;
  max-width: 1200px; margin: 0 auto; padding: 1em 1.5em;
  color: #222; background: #fff; line-height: 1.4;
}
/* Universal image cap — every <img> in the report stays inside its container. */
img { max-width: 100%; height: auto; }

header { border-bottom: 2px solid #333; padding-bottom: 0.5em; margin-bottom: 1em; }
header h1 { margin: 0; font-size: 1.4em; display: flex; align-items: center; gap: 0.5em; flex-wrap: wrap; }
header h1 a { color: inherit; text-decoration: none; }
header h1 a:hover { text-decoration: underline; }
header h1 .belibre-link { text-decoration: none; }
header h1 .belibre-logo { height: 32px; width: auto; vertical-align: middle; border: none; }
header .meta { color: #666; font-size: 0.9em; margin-top: 0.3em; }
header .meta code { background: #f4f4f4; padding: 0 0.3em; border-radius: 2px; }
header .meta div { margin: 0.1em 0; }

h2 { font-size: 1.15em; margin: 0; }
h3 { font-size: 0.95em; margin: 0.9em 0 0.35em; color: #444; text-transform: uppercase; letter-spacing: 0.5px; }

figure.screenshot, figure.screenshot-extra { margin: 1em 0; padding: 0; }
figure.screenshot img, figure.screenshot-extra img { border: 1px solid #ddd; border-radius: 3px; display: block; }
figure.screenshot figcaption, figure.screenshot-extra figcaption { font-size: 0.85em; color: #666; margin-top: 0.25em; }
section.screenshot-gallery { margin-top: 2em; padding-top: 1em; border-top: 1px solid #ddd; }
section.screenshot-gallery h2 { margin-bottom: 0.5em; }

/* Verdict — single dense plain-language paragraph above the exec summary.
   Distinct visual language from the analytical sections below it. */
section.verdict {
  margin: 1em 0 1.5em; padding: 1em 1.25em;
  background: #fafafa; border-left: 4px solid #444;
  border-radius: 0 3px 3px 0;
}
section.verdict h2 { font-size: 0.85em; margin: 0 0 0.4em; color: #555;
                     text-transform: uppercase; letter-spacing: 0.6px;
                     border-bottom: none; padding-bottom: 0; }
section.verdict p  { margin: 0; font-size: 1.02em; line-height: 1.5; color: #222; }

/* The intro + the exec summary keep their distinct visual language. */
section.report-intro {
  margin: 1em 0 1.5em; padding: 0.85em 1.25em;
  background: var(--c-info-tint); border-left: 4px solid var(--c-info-bd);
  border-radius: 0 3px 3px 0; font-size: 0.92em; line-height: 1.5;
}

/* Capture-status banner reuses the bad-tone palette. */
.capture-status.failure {
  margin: 1em 0 1.5em; padding: 0.85em 1.25em;
  background: var(--c-bad-tint); border-left: 4px solid var(--c-bad-bd);
  border-radius: 0 3px 3px 0; font-size: 0.95em; line-height: 1.5;
  color: var(--c-bad-fg);
}
.capture-status.failure strong { color: var(--c-bad-fg); }
.capture-status.failure code {
  background: var(--c-bad-bg); color: var(--c-bad-fg);
  padding: 1px 6px; border-radius: 3px; font-weight: 600;
}

/* ---------------------------------------------------------------------------
 * Shared report-section component — every analyser section uses the same
 * shape; tone modifiers swap the palette via the design tokens above.
 * ------------------------------------------------------------------------- */
section.report-section {
  margin: 1.5em 0; padding: 1em 1.25em;
  background: var(--c-info-tint);
  border-left: 4px solid var(--c-info-bd);
  border-radius: 3px;
}
section.report-section h2 {
  font-size: 1.05em; margin: 0 0 0.4em;
  border-bottom: none; padding-bottom: 0; color: var(--c-info-fg);
}
section.report-section h2 .count { color: var(--c-muted-fg); font-weight: 400; font-size: 0.9em; }
section.report-section p.hint    { color: var(--c-muted-fg); font-size: 0.85em; margin: 0.4em 0 0.8em; }
section.report-section p.note    { color: #555; font-size: 0.85em; margin: 0.4em 0 0; }

section.report-section--bad  { background: var(--c-bad-tint);  border-left-color: var(--c-bad-bd); }
section.report-section--bad  h2 { color: var(--c-bad-fg); }
section.report-section--warn { background: var(--c-warn-tint); border-left-color: var(--c-warn-bd); }
section.report-section--warn h2 { color: var(--c-warn-fg); }
section.report-section--good { background: var(--c-good-tint); border-left-color: var(--c-good-bd); }
section.report-section--good h2 { color: var(--c-good-fg); }

/* A bad-tone callout reused inside CMS section to highlight the EOL note. */
.callout--bad {
  margin: 0.5em 0 0; padding: 0.5em 0.7em;
  background: var(--c-bad-bg); color: var(--c-bad-fg);
  border-radius: 3px; font-size: 0.9em;
}

/* ---------------------------------------------------------------------------
 * Shared data table — every report section's table is a .data-table.
 * ------------------------------------------------------------------------- */
table.data-table { border-collapse: collapse; width: 100%; font-size: 0.85em; }
table.data-table th, table.data-table td {
  padding: 4px 8px; text-align: left; vertical-align: top;
  border-bottom: 1px solid var(--c-rule);
}
table.data-table th {
  background: #f5f5f5; font-weight: 600; font-size: 0.78em;
  text-transform: uppercase; letter-spacing: 0.5px; color: #555;
}
table.data-table td.num   { text-align: right; font-variant-numeric: tabular-nums; }
table.data-table td.mono  { font-family: ui-monospace, monospace; white-space: nowrap; color: #555; }
table.data-table td.muted { color: var(--c-muted-fg); }
table.data-table td.ok    { color: var(--c-good-fg); font-weight: 600; }
table.data-table td.bad   { color: var(--c-bad-fg);  font-weight: 600; }
table.data-table code     { background: transparent; color: #225; font-weight: 600; }
table.data-table .host    { color: #888; font-family: ui-monospace, monospace; font-size: 0.85em; }

/* ---------------------------------------------------------------------------
 * Shared badge — small inline severity tag. Replaces .party-badge,
 * .kind-badge, .eol-tag, .impact, .capture-status-badge.
 * ------------------------------------------------------------------------- */
.badge {
  display: inline-block; padding: 1px 7px; border-radius: 3px;
  font-size: 0.72em; font-weight: 700; letter-spacing: 0.3px;
  background: var(--c-chip-bg); color: #555;
}
.badge--high   { background: var(--c-bad-bg);  color: var(--c-bad-fg);  }
.badge--medium { background: var(--c-warn-bg); color: var(--c-warn-fg); }
.badge--low    { background: var(--c-good-bg); color: var(--c-good-fg); }
.badge--info   { background: var(--c-info-bg); color: var(--c-info-fg); }
.badge--strong { background: var(--c-bad-fg);  color: #fff; }

/* ---------------------------------------------------------------------------
 * Shared chip — smaller, multi-per-row inline labels. Replaces .cookie-chip.
 * ------------------------------------------------------------------------- */
.chip {
  display: inline-block; padding: 1px 6px; margin: 1px 2px 1px 0;
  border-radius: 3px; font-size: 0.72em; font-weight: 600;
  background: var(--c-chip-bg); color: #555;
}
.chip--good { background: var(--c-good-bg); color: var(--c-good-fg); }
.chip--warn { background: var(--c-warn-bg); color: var(--c-warn-fg); }
.chip--bad  { background: var(--c-bad-bg);  color: var(--c-bad-fg);  }
.chip--info { background: var(--c-info-bg); color: var(--c-info-fg); }
section.report-intro h2 {
  font-size: 1em; margin: 0 0 0.4em;
  color: #1b4a72; text-transform: uppercase;
  letter-spacing: 0.5px;
}
section.report-intro p { margin: 0.4em 0; }
section.report-intro p:first-of-type { margin-top: 0; }
section.report-intro p:last-of-type  { margin-bottom: 0; }
section.report-intro a { color: #1b4a72; }

.exec {
  background: #f7f8f9; border: 1px solid #e0e0e0; border-radius: 4px;
  padding: 0.85em 1.25em 1em; margin-bottom: 1.5em;
}
.exec ul { margin: 0.5em 0 0; padding: 0; list-style: none; }
.exec li { padding: 0.15em 0; font-size: 0.92em; }
.exec li b { display: inline-block; width: 12em; color: #555; }
.exec ul.high-fields { margin: 0.4em 0 0.5em 12em; padding: 0; }
.exec ul.high-fields li { padding: 0.1em 0; font-size: 0.88em; }
.exec ul.high-fields li b { width: auto; display: inline; color: inherit; }
.exec ul.high-fields code { background: #f0e6d6; padding: 1px 4px; border-radius: 2px;
                            font-size: 0.92em; }

/* KEY FINDINGS + RECOMMENDED ACTIONS */
ul.key-findings { list-style: none; margin: 0; padding: 0; }
ul.key-findings .finding {
  padding: 0.45em 0.7em; margin: 0.3em 0;
  border-left: 3px solid #e9ecef; background: #fbfbfd;
  border-radius: 0 3px 3px 0;
}
ul.key-findings .finding.sev-high   { border-left-color: #d63138; background: #fef6f6; }
ul.key-findings .finding.sev-medium { border-left-color: #b88d2c; background: #fdf8ee; }
ul.key-findings .finding.sev-low    { border-left-color: #0f5132; background: #f3faf6; }
ul.key-findings .sev-badge {
  display: inline-block; width: 1.4em; text-align: center;
  vertical-align: middle; margin-right: 0.2em;
}
/* Detail now flows inline after the headline rather than dropping to
 * a new line — one finding, one row. Slightly smaller and muted so
 * the headline still leads the eye. */
ul.key-findings .finding-detail {
  font-weight: normal; color: #555; font-size: 0.92em;
}
ul.key-findings .action-meta {
  font-weight: normal; color: var(--c-muted-fg); font-size: 0.85em;
  font-style: italic;
}
ol.actions { margin: 0.2em 0 0.6em 1.5em; padding: 0; font-size: 0.92em; }
ol.actions li { padding: 0.2em 0; }

/* Uniform category label across all categories — same width, same
 * background, same color. Lets the eye land on the field names. */
.cat-label {
  display: inline-block;
  padding: 1px 7px;
  border-radius: 3px;
  font-size: 0.72em;
  font-weight: 600;
  letter-spacing: 0.5px;
  text-transform: uppercase;
  margin-right: 0.4em;
  min-width: 5.5em;
  text-align: center;
  background: #e9ecef;
  color: #495057;
}

/* Unknowns + storage + cookies + cms + transport sections now share
   the .report-section component above; tone modifiers and .data-table
   handle the per-section character without one-off rules. */

.tracker {
  border: 1px solid #ddd;
  border-radius: 5px;
  margin: 1.25em 0;
  background: #fff;
  box-shadow: 0 1px 2px rgba(0,0,0,0.03);
}
.tracker-head { padding: 0.85em 1em; border-bottom: 1px solid #eee; }
.tracker-head .vendor { color: #666; font-size: 0.85em; margin-top: 0.3em; }
.tracker-head .note { color: #888; font-style: italic; font-size: 0.82em;
                      margin-top: 0.25em; }

/* Per-tracker jurisdiction tag — same shape as .badge but a tracker-
   specific marker (kept distinct so the per-tracker drill-down stays
   recognisable). Tones map to the design tokens. */
.jurisdiction {
  display: inline-block; padding: 1px 7px; border-radius: 3px;
  background: var(--c-chip-bg); color: #444;
  font-size: 0.72em; font-weight: 600;
  margin-left: 0.4em; vertical-align: middle; letter-spacing: 0.5px;
}
.jurisdiction.jur-bg-high-risk     { background: var(--c-bad-bg);  color: var(--c-bad-fg);  }
.jurisdiction.jur-bg-eu            { background: var(--c-good-bg); color: var(--c-good-fg); }
.jurisdiction.jur-bg-uk            { background: var(--c-warn-bg); color: var(--c-warn-fg); }
.jurisdiction.jur-bg-other-western { background: var(--c-info-bg); color: var(--c-info-fg); }

.stats {
  display: flex;
  flex-wrap: wrap;
  padding: 0.5em 1em;
  gap: 0.85em 1.25em;
  border-bottom: 1px solid #eee;
}
.stats .stat { font-size: 0.85em; min-width: 8em; }
.stats .stat .label { color: #888; text-transform: uppercase;
                      letter-spacing: 0.5px; font-size: 0.78em; }
.stats .stat .value { font-size: 1.4em; font-weight: 600; }
.stats .stat .value.has-pii   { color: #c00; }
.stats .stat .value.has-ident { color: #a55; }
.stats .stat .value.zero      { color: #999; font-weight: 400; }

.fields-summary { padding: 0.85em 1em; font-size: 0.88em; color: #555; }
.fields-summary .label { color: #666; font-weight: 600; margin-right: 0.4em; }
.fields-summary .fld { display: inline-block; padding: 1px 6px; margin: 1px;
                       background: #f0e6d6; border-radius: 2px; }
.fields-summary .fld.pii      { background: #fde2e1; color: #842029; }
.fields-summary .fld.ident    { background: #fff3cd; color: #664d03; }

summary {
  cursor: pointer;
  padding: 0.6em 1em;
  background: #eef0f3;
  font-size: 0.88em;
  color: #555;
  font-weight: 500;
  outline: none;
  user-select: none;
  border-radius: 0 0 4px 4px;
}
summary:hover { background: #e3e6ea; }
details[open] summary { background: #dde1e6; }

.hit { padding: 0.85em 1em; border-top: 1px dashed #eee; }
.hit .url { font-family: ui-monospace, monospace; font-size: 0.85em;
            color: #444; word-break: break-all; }
.hit .url b { color: #225; }
.hit .hit-meta { color: #888; font-size: 0.78em; margin: 0.3em 0 0.5em; }
.hit .body-label { color: #888; font-weight: 600; font-size: 0.75em;
                   text-transform: uppercase; letter-spacing: 0.5px;
                   margin-top: 0.4em; }
.hit pre.body { background: #f9f6f0; padding: 0.5em 0.7em; border-radius: 3px;
                font-size: 0.82em; white-space: pre-wrap; word-break: break-all;
                max-height: 24em; overflow: auto; }

table.params { border-collapse: collapse; width: 100%; font-size: 0.82em;
               margin-top: 0.5em; }
table.params th, table.params td { padding: 4px 8px; text-align: left;
                                   border-bottom: 1px solid #f0f0f0;
                                   vertical-align: top; }
table.params th { background: #f7f7f7; font-weight: 600; font-size: 0.78em;
                  color: #444; text-transform: uppercase; letter-spacing: 0.5px; }
table.params td.key  { font-family: ui-monospace, monospace; width: 14em;
                       word-break: break-all; }
table.params td.cat  { color: #888; font-size: 0.85em; width: 7em; }
table.params td.imp  { width: 4.5em; }
table.params td.val  { font-family: ui-monospace, monospace; word-break: break-all; }
table.params td.mean { color: #666; font-style: italic; font-size: 0.92em; }

/* .impact replaced by the shared .badge component (--high/--medium/--low). */

footer { color: #aaa; font-size: 0.8em; text-align: center; margin-top: 3em;
         border-top: 1px solid #eee; padding-top: 1em; }

/* DNS-posture internals — the outer box is handled by .report-section.
   Internal rules (per-record-type subheadings + signal grid) keep their
   own visual language because each record type has bespoke structure. */
.dns-posture h3 { font-size: 0.78em; color: var(--c-info-bd); margin: 0.8em 0 0.25em;
                  text-transform: uppercase; letter-spacing: 0.6px; }
.dns-posture table { border-collapse: collapse; width: 100%; font-size: 0.85em;
                     margin: 0.25em 0 0.5em; }
.dns-posture th, .dns-posture td { padding: 3px 8px; text-align: left;
                                   border-bottom: 1px solid #d8e2eb;
                                   vertical-align: top; }
.dns-posture th { background: #dceaf3; color: var(--c-info-fg); font-weight: 600;
                  font-size: 0.78em; text-transform: uppercase;
                  letter-spacing: 0.5px; }
.dns-posture td.num { text-align: right; font-variant-numeric: tabular-nums; }
.dns-posture code { font-family: ui-monospace, monospace; font-size: 0.92em; }
.dns-posture .signal { display: grid; grid-template-columns: 7em 1fr;
                       gap: 0.25em 1em; font-size: 0.88em; }
.dns-posture .signal .label { color: #4a6a86; font-weight: 600; }
.dns-posture .signal .value { color: #2a3a48; }
.dns-posture .ok       { color: var(--c-good-fg); font-weight: 600; }
.dns-posture .bad      { color: var(--c-bad-fg);  font-weight: 600; }
.dns-posture .neutral  { color: #6c757d; }
.dns-posture .errors   { color: #888; font-size: 0.82em; font-style: italic;
                         margin-top: 0.6em; }
"""


# --- entry points ----------------------------------------------------------


def write_html_report(
    analysis: Analysis,
    *,
    screenshot_filename: str | None = None,
    extra_screenshot_filenames: list[str] | None = None,
    extra_screenshot_captions: list[str] | None = None,
    display_name: str | None = None,
) -> str:
    """Render ``analysis`` as a standalone HTML document.

    When ``screenshot_filename`` is provided, the report embeds an
    ``<img>`` near the top referencing that exact filename via a
    relative path. The caller is responsible for ensuring the PNG
    actually exists at that path on disk.

    ``extra_screenshot_filenames`` (optional) is the list of
    operator-triggered screenshots — they render below the canonical
    post-load image as a small gallery. ``extra_screenshot_captions``
    (optional, parallel list) supplies an explicit caption per entry;
    any empty entry (or omitting the list) falls back to deriving the
    caption from the filename — useful when the "filename" is actually
    a ``data:`` URI that carries no host/timestamp info.

    ``display_name`` (optional) overrides the report's title label
    (the host is used when None).
    """
    return render_html_document(
        build_report_document(analysis, display_name=display_name),
        screenshot_filename=screenshot_filename,
        extra_screenshot_filenames=extra_screenshot_filenames,
        extra_screenshot_captions=extra_screenshot_captions,
    )


def render_html_document(
    document: ReportDocument,
    *,
    screenshot_filename: str | None = None,
    extra_screenshot_filenames: list[str] | None = None,
    extra_screenshot_captions: list[str] | None = None,
) -> str:
    """Render an already-built :class:`ReportDocument` as HTML."""
    out = StringIO()
    out.write("<!doctype html>\n")
    out.write('<html lang="en">\n<head>\n<meta charset="utf-8">\n')
    host_label = _title_host_label(document.manifest)
    out.write(
        f"<title>{_BRANDING_TITLE_PREFIX} : {_h(host_label)}</title>\n"
    )
    out.write(f"<style>{_CSS}</style>\n</head>\n<body>\n")

    _render_header(out, document.manifest)
    _render_score(out, document.score)
    _render_consent(out, document.consent)
    _render_intro(out)
    _render_capture_status_banner(out, document.capture_status)
    if screenshot_filename:
        out.write(
            f'<figure class="screenshot">'
            f'<img src="{_h(screenshot_filename)}" '
            f'alt="Captured page as the visitor first saw it">'
            f"<figcaption>Captured page (post-load)</figcaption>"
            f"</figure>\n"
        )
    _render_verdict(out, document.verdict)
    _render_executive_summary(out, document.executive_summary)
    _render_cms(out, document.cms_fingerprint)
    _render_transport_posture(
        out, document.transport_posture, document.security_txt,
        document.tls_posture,
    )
    _render_security_headers(out, document.security_headers)
    _render_dns_posture(out, document.dns_posture)
    _render_cyberfundamentals(out, document.cyberfundamentals)
    _render_cookies(out, document.cookies, document.forwarded_cookie_keys)
    _render_storage(out, document.storage)
    _render_unknown_hosts(out, document.unclassified_hosts)

    if not document.trackers:
        out.write("<p style='color:#888'>No tracker hits found in this capture.</p>\n")
    else:
        for section in document.trackers:
            _render_tracker(out, section)

    if extra_screenshot_filenames:
        out.write('<section class="screenshot-gallery">\n')
        out.write("<h2>Operator-triggered screenshots</h2>\n")
        captions = extra_screenshot_captions or []
        for idx, name in enumerate(extra_screenshot_filenames):
            explicit = captions[idx] if idx < len(captions) else ""
            caption = explicit or _caption_from_extra_screenshot(name)
            out.write(
                f'<figure class="screenshot-extra">'
                f'<img src="{_h(name)}" alt="Operator screenshot {_h(caption)}">'
                f"<figcaption>{_h(caption)}</figcaption>"
                f"</figure>\n"
            )
        out.write("</section>\n")

    _render_score_calculation(out, document.score)

    out.write(
        "<footer>Generated by leak_inspector — "
        f"bundle {_h(document.manifest.session_id)}</footer>\n"
    )
    out.write("</body>\n</html>\n")
    return out.getvalue()


# --- helpers ---------------------------------------------------------------


def _truncate(text: str | None, limit: int) -> str:
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _stat(label: str, value: int, css_class: str = "") -> str:
    css = f' class="value {css_class}"' if css_class else ' class="value"'
    return (
        '<div class="stat">'
        f'<div class="label">{_h(label)}</div>'
        f'<div{css}>{value}</div>'
        "</div>"
    )


# --- sections --------------------------------------------------------------


def _caption_from_extra_screenshot(filename: str) -> str:
    """Derive a human caption from an extra-screenshot filename.

    The recorder writes ``screenshot_<host>_<HHMMSS>.png``; the CLI
    re-prefixes it as ``<slug>.report_<host>_<HHMMSS>.png``. Either
    way the trailing ``_<host>_<HHMMSS>`` is what's interesting —
    extract it for the caption.
    """
    stem = filename.rsplit("/", 1)[-1]
    if stem.endswith(".png"):
        stem = stem[: -len(".png")]
    # Prefer the trailing segment of form _<host>_<HHMMSS>; fall back
    # to the bare filename if the shape doesn't match.
    parts = stem.split("_")
    if len(parts) >= 3 and parts[-1].isdigit() and len(parts[-1]) == 6:
        host = parts[-2]
        hhmmss = parts[-1]
        return f"{host} @ {hhmmss[:2]}:{hhmmss[2:4]}:{hhmmss[4:6]}"
    return stem


#: Backward-compat aliases for the markdown and text reporters that
#: import these names. The single source lives in ``_branding``; these
#: re-exports avoid churn on existing call sites.
_BRANDING_TITLE_PREFIX = BRANDING_TITLE_PREFIX
_BELIBRE_HOMEPAGE = BELIBRE_HOMEPAGE
_title_host_label = title_host_label


def _safe_href(url: str) -> str:
    """Return ``url`` only when its scheme is ``http`` / ``https``, else ``""``.

    Manifest fields like ``target_url`` come from the bundle, which is
    untrusted (bundles get shared between teammates). Letting a
    ``javascript:`` URL reach an ``href`` would mean a viewer clicking
    the report's site link executes JS in the report's tab.
    :func:`html.escape` alone does not stop this — it escapes
    characters but doesn't validate the scheme.

    :func:`urllib.parse.urlparse` already lowercases the scheme and
    strips the leading whitespace / control characters that browsers
    also strip before scheme parsing, so a single ``in {"http",
    "https"}`` check is sufficient.
    """
    if not url:
        return ""
    if urlparse(url).scheme in ("http", "https"):
        return url
    return ""


def _render_header(out: StringIO, m: ManifestView) -> None:
    host_label = _title_host_label(m)
    target_href = _safe_href(m.target_url or "")
    out.write("<header>\n")
    out.write('<h1 class="report-title">\n')
    # Logo on the LEFT, linking to the BeLibre homepage in a new tab.
    # The SVG is inlined (not fetched from belibre.be) so reports render
    # offline and aren't blocked by belibre.be's strict CORP header.
    out.write(
        f'<a class="belibre-link" href="{_h(_BELIBRE_HOMEPAGE)}" '
        f'target="_blank" rel="noopener">'
        f"{belibre_logo_svg_inline()}"
        f"</a>\n"
    )
    out.write(f"<span>{_h(_BRANDING_TITLE_PREFIX)} : </span>")
    # Host clickable in a new tab. Use rel=noopener so the new tab can't
    # navigate the report tab.
    if target_href:
        out.write(
            f'<a class="target-link" href="{_h(target_href)}" '
            f'target="_blank" rel="noopener">{_h(host_label)}</a>\n'
        )
    else:
        out.write(f"<span>{_h(host_label)}</span>\n")
    out.write("</h1>\n")
    out.write('<div class="meta">\n')
    out.write(f"<div>session: <code>{_h(m.session_id)}</code></div>\n")
    out.write(f"<div>captured: {_h(m.started_at)} → {_h(m.ended_at)}</div>\n")
    out.write(f"<div>profile: {_h(m.profile)}</div>\n")
    if m.landing_url and m.landing_url != m.target_url:
        out.write(f"<div>landed at: <code>{_h(m.landing_url)}</code></div>\n")
    out.write("</div>\n</header>\n")


def _render_score(out: StringIO, score) -> None:
    """Render the composite scorecard. Silent when score is None.

    Total leads, dimensions follow. Avoids the ``×`` form because the
    total is the geometric mean of the dimensions, not their product.
    """
    if score is None:
        return
    out.write('<section class="score-card">\n')
    out.write(
        f'<div class="score-headline">'
        f'<span class="score-total">Total: '
        f'{score.total} / {score.max_total}</span>'
        f'<span class="score-sep">  ·  </span>'
        f'<span class="score-dims">'
        f'🛡️ {format_stars(score.resilience.stars)}  '
        f'🔐 {format_stars(score.security.stars)}  '
        f'🕶️ {format_stars(score.privacy.stars)}'
        f"</span>"
        f"</div>\n"
    )
    out.write('<div class="score-dimensions">\n')
    out.write(
        f'<div class="score-dim score-res">'
        f'<strong>🛡️ resilience</strong> '
        f"<span>{format_stars(score.resilience.stars)}/{score.resilience.max_stars}</span> "
        f"<em>{_h(score.resilience.rationale)}</em>"
        f"</div>\n"
    )
    out.write(
        f'<div class="score-dim score-sec">'
        f'<strong>🔐 security</strong> '
        f"<span>{format_stars(score.security.stars)}/{score.security.max_stars}</span> "
        f"<em>{_h(score.security.rationale)}</em>"
        f"</div>\n"
    )
    out.write(
        f'<div class="score-dim score-priv">'
        f'<strong>🕶️ privacy</strong> '
        f"<span>{format_stars(score.privacy.stars)}/{score.privacy.max_stars}</span> "
        f"<em>{_h(score.privacy.rationale)}</em>"
        f"</div>\n"
    )
    out.write("</div>\n")
    if score.top_action:
        out.write(
            f'<div class="score-action">'
            f"<strong>Biggest win:</strong> {_h(score.top_action)}"
            f"</div>\n"
        )
    _render_score_breakdown(out, score)
    out.write("</section>\n")


def _render_score_breakdown(out: StringIO, score) -> None:
    """List what cost each dimension points — each contributor with its
    impact nested beneath it (not a running ``−`` column; the impacts do
    not subtract one-for-one — see "How the score is calculated")."""
    dims = (
        ("🛡️", "resilience", score.resilience),
        ("🔐", "security", score.security),
        ("🕶️", "privacy", score.privacy),
    )
    if not any(d.deductions for _, _, d in dims):
        return
    out.write('<div class="score-breakdown">\n')
    out.write("<strong>What lowered each dimension</strong>\n")
    for emoji, label, dim in dims:
        if not dim.deductions:
            continue
        out.write(
            f"<p class=\"score-breakdown-dim\">{emoji} {label} "
            f"<span>{format_stars(dim.stars)}/{dim.max_stars}</span></p>\n"
        )
        out.write("<ul>\n")
        for line in dim.deductions:
            extra = ""
            if line.explainer and line.amount > EXPLAINER_THRESHOLD:
                extra = f" — {_h(line.explainer)}"
            out.write(
                f"<li>{_h(line.label)}<br>"
                f"<small>impact {line.amount:g}{extra}</small></li>\n"
            )
        out.write("</ul>\n")
    out.write("</div>\n")


def _render_score_calculation(out: StringIO, score) -> None:
    """Write out the arithmetic behind the score, step by step (impacts
    summed per dimension → logistic curve → cube-root total)."""
    if score is None:
        return
    dims = (
        ("🛡️", "resilience", score.resilience),
        ("🔐", "security", score.security),
        ("🕶️", "privacy", score.privacy),
    )
    out.write('<section class="report-section score-calc">\n')
    out.write("<h2>How the score is calculated</h2>\n")
    out.write(
        '<p class="hint">Each tracker and posture signal adds an impact '
        "penalty (0–5) per dimension. The penalties are summed (P), then "
        "mapped through a logistic curve — steep in the middle, flattening "
        "toward 0 and 100 — so they do <strong>not</strong> subtract "
        "one-for-one. The same curve scores all three dimensions:</p>\n"
    )
    out.write(
        f'<p class="score-formula"><code>score(P) = 100 / (1 + '
        f"e^((P − {DEFAULT_P50:g}) / {DEFAULT_S:g}))</code></p>\n"
    )
    out.write(
        '<p class="hint">The total is the cube root (geometric mean) of the '
        "three dimension scores; scores are shown ceil-rounded (printed "
        "range 1–99).</p>\n"
    )
    out.write("<ul>\n")
    for emoji, label, dim in dims:
        amounts = [f"{line.amount:g}" for line in dim.deductions]
        sum_expr = " + ".join(amounts) if amounts else "0"
        out.write(
            f"<li>{emoji} <strong>{label}</strong>: penalties "
            f"{_h(sum_expr)} = {dim.penalty:g} → curve = {dim.raw_score:.1f} "
            f"→ shown as {format_stars(dim.stars)}/100</li>\n"
        )
    out.write("</ul>\n")
    r, s, pv = score.resilience, score.security, score.privacy
    out.write(
        f"<p><strong>Total</strong> = ³√({r.raw_score:.1f} × "
        f"{s.raw_score:.1f} × {pv.raw_score:.1f}) → "
        f"{score.total}/100</p>\n"
    )
    out.write("</section>\n")


def _render_consent(out: StringIO, consent) -> None:
    """Render the one-line consent-state summary (all states, including
    ``unknown``). Single wording source: :func:`.text._consent_line`."""
    from .text import _consent_line

    line = _consent_line(consent)
    if line is None:
        return
    out.write(f'<div class="consent-line">{_h(line)}</div>\n')


def _render_intro(out: StringIO) -> None:
    """Three-paragraph context block.

    Prose lives in :mod:`._branding`; this function fills the
    HTML-specific markup placeholders (``<a target="_blank">`` for
    links, ``<strong>`` for the disclaimer) so the wording stays in
    sync with the markdown and text reporters by construction.
    """
    homepage = _h(BELIBRE_HOMEPAGE)
    belibre_link = (
        f'<a href="{homepage}" target="_blank" rel="noopener">BeLibre</a>'
    )
    belibre_url = (
        f'<a href="{homepage}" target="_blank" rel="noopener">belibre.be</a>'
    )
    disclaimer_bold = f"<strong>{_h(INTRO_DISCLAIMER_TEXT)}</strong>"

    out.write('<section class="report-intro">\n')
    out.write(f"<h2>{_h(INTRO_TITLE)}</h2>\n")
    for paragraph in INTRO_PARAGRAPHS:
        rendered = paragraph.format(
            belibre_link=belibre_link,
            disclaimer_bold=disclaimer_bold,
            belibre_url=belibre_url,
        )
        out.write(f"<p>{rendered}</p>\n")
    out.write("</section>\n")


def _render_capture_status_banner(out: StringIO, status) -> None:
    """Render the failure-status banner when the landing-page load failed.

    No-op for healthy captures — keeps the report layout unchanged for
    the common case. Failures get a red callout with the HTTP code +
    reason phrase ("HTTP 418 — I'm a Teapot") or a simple "Unreachable"
    line for DNS / connection failures.
    """
    if status is None or not status.is_failure:
        return
    if status.http_status is not None:
        label = f"HTTP {status.http_status} — {status.reason}"
    else:
        label = status.reason or "Unreachable"
    out.write(
        '<div class="capture-status failure">\n'
        '<strong>Capture failed.</strong> '
        f"The landing page returned <code>{_h(label)}</code>. "
        "Findings below reflect what loaded before the failure — usually "
        "very little. Verify the URL, the site's availability, and any "
        "regional-blocking before drawing conclusions.\n"
        "</div>\n"
    )


def _render_verdict(out: StringIO, verdict) -> None:
    """Render the manager-facing verdict above the executive summary.

    Renders the three-or-four sentence top verdict as a single dense
    paragraph. The partial-coverage clause (when present) appends as
    the same paragraph so the verdict reads as one continuous
    statement, not a list of disconnected bullets.
    """
    if verdict is None or not verdict.top_sentences:
        return
    out.write('<section class="verdict">\n')
    out.write("<h2>Verdict</h2>\n")
    paragraph = " ".join(_h(s) for s in verdict.top_sentences)
    out.write(f"<p>{paragraph}</p>\n")
    out.write("</section>\n")


def _render_executive_summary(out: StringIO, summary: ExecutiveSummary) -> None:
    out.write('<div class="exec">\n')
    out.write("<h2>Executive summary</h2>\n")

    # KEY FINDINGS — headline + detail joined into one row, headline
    # bold, detail rendered as a muted continuation.
    if summary.findings:
        from .verdict_action_metadata import metadata_for

        def _render_findings_group(label: str, items: list) -> None:
            if not items:
                return
            out.write(f"<h3>{label}</h3>\n")
            out.write('<ul class="key-findings">\n')
            for finding in items:
                out.write(
                    f'<li class="finding sev-{_h(finding.severity)}">'
                    f'<span class="sev-badge">{finding.badge}</span> '
                    f'<b>{_h(finding.headline)}</b>'
                )
                if finding.detail:
                    out.write(
                        f'<span class="finding-detail">. {_h(finding.detail)}</span>'
                    )
                meta = metadata_for(finding.kind)
                if meta is not None:
                    out.write(
                        f' <span class="action-meta">(owner: {_h(meta.owner)}'
                        f' · effort: {_h(meta.effort)})</span>'
                    )
                out.write("</li>\n")
            out.write("</ul>\n")

        # Source split: any DNS finding present → both groups get their
        # labelled headings (the absent group's heading is suppressed by
        # the empty-list guard inside ``_render_findings_group``). No
        # DNS findings at all → fall back to the historical single
        # "Key findings" heading.
        capture_findings = [f for f in summary.findings if f.source != "dns"]
        dns_findings = [f for f in summary.findings if f.source == "dns"]
        if dns_findings:
            _render_findings_group("Key findings — Website", capture_findings)
            _render_findings_group("Key findings — Back-office", dns_findings)
        else:
            _render_findings_group("Key findings", capture_findings)

    # RECOMMENDED ACTIONS
    if summary.actions:
        out.write('<h3>Recommended actions</h3>\n<ol class="actions">\n')
        for action in summary.actions:
            out.write(f"<li>{_h(action)}</li>\n")
        out.write("</ol>\n")

    # DETAILED FINDINGS
    out.write('<h3>Detailed findings</h3>\n<ul>\n')

    # CNAME-cloaked trackers
    if summary.cname_cloaks:
        cloak_title = _h(summary.cname_cloak_tooltip)
        out.write(
            f'<li title="{cloak_title}"><b>⚠ CNAME-cloaked trackers</b> — '
            f'{len(summary.cname_cloaks)} '
            f'alias{"es" if len(summary.cname_cloaks) != 1 else ""} '
            'resolve to known vendors<ul class="cname-cloaks">\n'
        )
        for cloak in summary.cname_cloaks[:6]:
            out.write(
                f'<li title="{cloak_title}">'
                f"<code>{_h(cloak.alias)}</code> → "
                f"<code>{_h(cloak.canonical)}</code> "
                f"[{_h(cloak.vendor_module_name)}]</li>\n"
            )
        if len(summary.cname_cloaks) > 6:
            out.write(
                f"<li>+ {len(summary.cname_cloaks) - 6} more "
                "(see per-tracker sections)</li>\n"
            )
        out.write("</ul></li>\n")

    # HIGH-impact tracking by vendor — with tooltips on vendor names, modules,
    # category labels, and field codes.
    if summary.high_impact_by_vendor:
        out.write(
            '<li><b>HIGH-impact tracking by vendor</b>'
            '<ul class="high-fields">\n'
        )
        for rollup in summary.high_impact_by_vendor[:6]:
            # Bracket with per-module tooltips
            bracket_items: list[str] = []
            for mod in rollup.modules[:3]:
                if mod.tooltip:
                    bracket_items.append(
                        f'<span title="{_h(mod.tooltip)}">{_h(mod.name)}</span>'
                    )
                else:
                    bracket_items.append(_h(mod.name))
            mod_list = ", ".join(bracket_items)
            if len(rollup.modules) > 3:
                mod_list += f" +{len(rollup.modules) - 3}"

            vendor_tag = (
                f'<b title="{_h(rollup.vendor_tooltip)}">{_h(rollup.vendor_label)}</b>'
                if rollup.vendor_tooltip
                else f"<b>{_h(rollup.vendor_label)}</b>"
            )
            out.write(
                f"<li>{vendor_tag} "
                f'<span class="vendor-modules">[{mod_list}]</span><ul>\n'
            )
            for cat in rollup.categories:
                field_items: list[str] = []
                for f in cat.fields[:5]:
                    if f.meaning:
                        field_items.append(
                            f'<code title="{_h(f.meaning)}">{_h(f.key)}</code>'
                        )
                    else:
                        field_items.append(f"<code>{_h(f.key)}</code>")
                shown = ", ".join(field_items)
                if len(cat.fields) > 5:
                    shown += f", +{len(cat.fields) - 5} more"
                cat_label = (
                    f'<span class="cat-label cat-{_h(cat.category)}"'
                    f' title="{_h(cat.description)}">{_h(cat.category)}</span>'
                )
                out.write(f"<li>{cat_label} {shown}</li>\n")
            out.write("</ul></li>\n")
        if len(summary.high_impact_by_vendor) > 6:
            out.write(
                f"<li>+ {len(summary.high_impact_by_vendor) - 6} more vendor(s) "
                "with HIGH-impact fields</li>\n"
            )
        out.write("</ul></li>\n")

    # Vendor jurisdictions tally
    if summary.jurisdictions:
        parts: list[str] = []
        for j in summary.jurisdictions:
            sample = ", ".join(_h(v) for v in j.vendors[:2])
            if len(j.vendors) > 2:
                sample += f", +{len(j.vendors) - 2} more"
            flag_prefix = f"{j.flag} " if j.flag else ""
            bg_class = f" jur-bg-{j.background_class}" if j.background_class else ""
            parts.append(
                f'<span class="jurisdiction jur-{_h(j.code)}{bg_class}">'
                f'{flag_prefix}{_h(j.code)}</span> '
                f'{j.module_count} ({sample})'
            )
        out.write(
            f"<li><b>Vendor jurisdictions</b>{' · '.join(parts)}</li>\n"
        )

    # Volume stats
    stats = summary.stats
    if stats is not None:
        out.write(
            f"<li><b>Trackers fired</b>{stats.trackers_fired} modules · "
            f"{stats.total_requests} requests "
            f"({stats.unique_requests} unique after dedup)</li>\n"
        )
        out.write(
            f"<li><b>Third-party hosts</b>{stats.third_party_hosts_touched} touched · "
            f"{stats.third_party_hosts_claimed} claimed, "
            f"{stats.third_party_hosts_unclassified} unclassified</li>\n"
        )
        if stats.top_by_impact:
            top_parts = [
                f"{_h(e.module_name)} "
                f"({e.high_impact_field_count}H/{e.medium_impact_field_count}M/{e.hit_count}×)"
                for e in stats.top_by_impact
            ]
            out.write(
                f"<li><b>Top by impact</b>{', '.join(top_parts)}</li>\n"
            )

    out.write("</ul>\n</div>\n")


def _render_dns_posture(out: StringIO, posture: DNSPosture | None) -> None:
    if posture is None:
        return
    out.write('<section class="dns-posture">\n')
    out.write(f"<h2>DNS posture — <code>{_h(posture.domain)}</code></h2>\n")

    # Hosting (A + AAAA)
    ips = posture.a_records + posture.aaaa_records
    if ips:
        out.write("<h3>Hosting</h3>\n")
        out.write(
            "<table><thead><tr><th>Address</th><th>AS</th>"
            "<th>Org</th><th>Country</th></tr></thead><tbody>\n"
        )
        for ip in ips:
            asn = f"AS{ip.asn}" if ip.asn is not None else "—"
            out.write(
                "<tr>"
                f"<td><code>{_h(ip.address)}</code></td>"
                f"<td>{_h(asn)}</td>"
                f"<td>{_h(ip.as_org) or '—'}</td>"
                f"<td>{_h(ip.country_code) or '—'}</td>"
                "</tr>\n"
            )
        out.write("</tbody></table>\n")

    # Authoritative DNS
    if posture.nameservers:
        out.write("<h3>Authoritative DNS</h3>\n<ul>\n")
        for ns in posture.nameservers:
            provider = f" — <b>{_h(ns.provider)}</b>" if ns.provider else ""
            jurisdictions = sorted({ip.country_code for ip in ns.ips if ip.country_code})
            jur = f' <span class="neutral">({_h(", ".join(jurisdictions))})</span>' if jurisdictions else ""
            out.write(f"<li><code>{_h(ns.name)}</code>{provider}{jur}</li>\n")
        out.write("</ul>\n")

    # MX
    if posture.mx:
        out.write("<h3>Mail (MX)</h3>\n")
        out.write(
            '<table><thead><tr><th class="num">Pref</th><th>Host</th>'
            "<th>AS / org</th><th>Country</th></tr></thead><tbody>\n"
        )
        for mx in posture.mx:
            jurisdictions = sorted({ip.country_code for ip in mx.ips if ip.country_code})
            orgs = sorted({ip.as_org for ip in mx.ips if ip.as_org})
            out.write(
                "<tr>"
                f'<td class="num">{mx.priority if mx.priority is not None else "—"}</td>'
                f"<td><code>{_h(mx.name)}</code></td>"
                f"<td>{_h(', '.join(orgs)) or '—'}</td>"
                f"<td>{_h(', '.join(jurisdictions)) or '—'}</td>"
                "</tr>\n"
            )
        out.write("</tbody></table>\n")

    # Compact signal grid (DNSSEC / CAA / HTTPS / SPF / DMARC / DKIM / BIMI /
    # MTA-STS / TLS-RPT). Each pair is one row in the .signal grid.
    rows: list[tuple[str, str]] = []
    if posture.dnssec is not None:
        signed = posture.dnssec.parent_has_ds and posture.dnssec.zone_has_dnskey
        rows.append((
            "DNSSEC",
            f'<span class="{"ok" if signed else "bad"}">'
            f'{"signed" if signed else "not signed"}</span> '
            f'<span class="neutral">— {_h(posture.dnssec.summary)}</span>',
        ))
    if posture.caa is not None:
        cas = ", ".join(f"<code>{_h(c)}</code>" for c in posture.caa.issue_cas)
        rows.append(("CAA", cas or '<span class="neutral">(no issue records)</span>'))
    if posture.https is not None:
        parts: list[str] = []
        if posture.https.alpn:
            parts.append("ALPN " + "/".join(_h(a) for a in posture.https.alpn))
        if posture.https.has_ech:
            parts.append('<span class="ok">ECH advertised</span>')
        rows.append(("HTTPS", " · ".join(parts) or '<span class="neutral">(present)</span>'))
    if posture.spf is not None:
        senders = ", ".join(_h(v) for v in posture.spf.sender_vendors[:5])
        if len(posture.spf.sender_vendors) > 5:
            senders += f", +{len(posture.spf.sender_vendors) - 5}"
        bits = [f'<code>{_h(posture.spf.final_qualifier or "?")}</code>']
        if senders:
            bits.append(f"senders: {senders}")
        rows.append(("SPF", " · ".join(bits)))
    else:
        rows.append(("SPF", '<span class="bad">not published</span>'))
    if posture.dmarc is not None:
        bits = [f"p=<code>{_h(posture.dmarc.policy or 'unset')}</code>"]
        if posture.dmarc.pct != 100:
            bits.append(f"pct={posture.dmarc.pct}")
        if posture.dmarc.report_processors:
            bits.append("reports → " + ", ".join(_h(p) for p in posture.dmarc.report_processors))
        rows.append(("DMARC", " · ".join(bits)))
    else:
        rows.append(("DMARC", '<span class="bad">not published</span>'))
    if posture.dkim:
        rows.append((
            "DKIM",
            f"{len(posture.dkim)} selector(s): "
            + ", ".join(f"<code>{_h(d.selector)}</code>" for d in posture.dkim),
        ))
    if posture.bimi is not None and posture.bimi.present:
        rows.append(("BIMI", '<span class="ok">present</span>'))
    if posture.mta_sts is not None and posture.mta_sts.txt_present:
        rows.append((
            "MTA-STS",
            f'<span class="ok">present</span> id <code>{_h(posture.mta_sts.txt_id)}</code>',
        ))
    if posture.tls_rpt is not None and posture.tls_rpt.txt_present:
        rua = ", ".join(_h(r) for r in posture.tls_rpt.rua) or "present"
        rows.append(("TLS-RPT", rua))
    if rows:
        out.write('<h3>Security signals</h3>\n<div class="signal">\n')
        for label, value in rows:
            out.write(
                f'<div class="label">{_h(label)}</div>'
                f'<div class="value">{value}</div>\n'
            )
        out.write("</div>\n")

    # TXT verifications
    if posture.txt_verifications:
        out.write("<h3>Self-disclosed SaaS (via TXT verifications)</h3>\n")
        out.write(
            "<table><thead><tr><th>Vendor</th><th>Purpose</th>"
            "<th>Jurisdiction</th></tr></thead><tbody>\n"
        )
        for txt in posture.txt_verifications:
            out.write(
                "<tr>"
                f"<td><b>{_h(txt.vendor)}</b></td>"
                f"<td>{_h(txt.purpose)}</td>"
                f"<td>{_h(txt.jurisdiction) or '—'}</td>"
                "</tr>\n"
            )
        out.write("</tbody></table>\n")

    if posture.errors:
        out.write(
            f'<div class="errors">'
            f'{len(posture.errors)} lookup error(s) — see JSON output for details.'
            "</div>\n"
        )

    out.write("</section>\n")


def _render_cookies(
    out: StringIO,
    cookies: list,
    forwarded_keys: list[tuple[str, str]] = (),
) -> None:
    """Render the per-capture cookie overview section.

    Lists every ``Set-Cookie`` observed during the session — name,
    issuing host, vendor (module-name or bare host), 1P/3P badge,
    lifetime label, and security-flag chips. ``None``/empty list →
    section is omitted entirely so reports stay tight when no cookies
    were observed (typical for offline / blocked captures).
    ``forwarded_keys`` — ``(name, host)`` of first-party cookies whose
    vendor forwards/cloaks here; those rows get a
    "via first-party proxy" note next to the honest 1P badge.
    """
    if not cookies:
        return
    forwarded = set(forwarded_keys or ())
    out.write('<section class="report-section report-section--warn">\n')
    out.write(f"<h2>Cookies set during this capture <span class=\"count\">"
              f"({len(cookies)})</span></h2>\n")
    out.write('<p class="hint">Every <code>Set-Cookie</code> response '
              "header observed. The visitor pseudonym itself is "
              "redacted; only metadata (lifetime + security flags + "
              "issuing party) is surfaced.</p>\n")
    out.write('<table class="data-table">\n')
    out.write(
        "<thead><tr>"
        "<th>Cookie</th><th>Issued by</th><th>Party</th>"
        "<th>Lifetime</th><th>Flags</th><th>Impact</th>"
        "</tr></thead>\n<tbody>\n"
    )
    for c in cookies:
        party_badge = (
            '<span class="badge badge--low">1P</span>'
            if c.is_first_party
            else '<span class="badge badge--high">3P</span>'
        )
        if (c.name, c.host) in forwarded:
            party_badge += (
                '<br><span class="host">via first-party proxy</span>'
            )
        flags = _cookie_flag_chips(c)
        impact_badge = (
            f'<span class="badge badge--{_h(c.privacy_impact)}">'
            f"{_h(c.privacy_impact)}</span>"
        )
        out.write(
            "<tr>"
            f"<td><code>{_h(c.name)}</code></td>"
            f"<td>{_h(c.vendor)}<br>"
            f"<span class=\"host\">{_h(c.host)}</span></td>"
            f"<td>{party_badge}</td>"
            f"<td class=\"mono\">{_h(c.lifetime_human)}</td>"
            f"<td>{flags}</td>"
            f"<td>{impact_badge}</td>"
            "</tr>\n"
        )
    out.write("</tbody></table>\n</section>\n")


def _cookie_flag_chips(c) -> str:
    """Render the cookie's security attributes as a row of shared .chip badges.

    Tone mapping reflects the privacy implication:
    * SameSite=None → bad (cross-site cookie)
    * SameSite=Lax → warn (default browser behaviour)
    * SameSite=Strict → good (most restrictive)
    * Secure / HttpOnly → good (well-configured)
    * Partitioned → info (CHIPS opt-in; modern but mostly neutral)
    """
    chips: list[str] = []
    samesite = (c.same_site or "(unset)").lower()
    samesite_tone = {
        "none": "chip--bad", "lax": "chip--warn", "strict": "chip--good",
    }.get(samesite, "")
    chips.append(
        f'<span class="chip {samesite_tone}">SameSite={_h(samesite)}</span>'
    )
    if c.secure:
        chips.append('<span class="chip chip--good">Secure</span>')
    if c.http_only:
        chips.append('<span class="chip chip--good">HttpOnly</span>')
    if c.partitioned:
        chips.append('<span class="chip chip--info">Partitioned</span>')
    return " ".join(chips)


def _render_transport_posture(
    out: StringIO, posture, security_txt=None, tls=None,
) -> None:
    """Render the HTTP/HTTPS posture of the captured host(s).

    Deliberately renders even when every probe is green — "yes I
    checked, all ✓" is more useful than silent omission for a
    security audit. This is a conscious divergence from the
    cookies/storage sections, which collapse to nothing when empty.
    Appends the TLS-quality lines and the RFC 9116 ``security.txt``
    status line (single wording source in :mod:`.text`) when those
    probes ran.
    """
    if posture is None:
        return
    out.write('<section class="report-section">\n')
    out.write("<h2>Transport posture</h2>\n")
    out.write('<table class="data-table">\n')
    out.write(
        "<thead><tr><th>Host</th><th>HTTP</th><th>HTTPS</th>"
        "<th>HTTP→HTTPS</th></tr></thead>\n<tbody>\n"
    )
    for hp in _transport_rows(posture):
        out.write(_transport_row_html(hp))
    out.write("</tbody></table>\n")
    from .text import _security_txt_line, _tls_lines

    for tls_line in _tls_lines(tls) or []:
        out.write(f'<p class="hint">{_h(tls_line.strip())}</p>\n')
    line = _security_txt_line(security_txt)
    if line:
        out.write(f'<p class="hint">{_h(line)}</p>\n')
    out.write("</section>\n")


def _render_security_headers(out: StringIO, checks) -> None:
    """Render the main document's security-response-header posture.

    ``checks`` is the evaluated list (or ``None`` when no document
    response was observed — the section is omitted then). Uses the
    shared ``.data-table`` ok/bad cell modifiers."""
    if not checks:
        return
    out.write('<section class="report-section">\n')
    out.write("<h2>Security headers</h2>\n")
    out.write('<table class="data-table">\n')
    out.write(
        "<thead><tr><th>Header</th><th>Present</th><th>Value</th>"
        "</tr></thead>\n<tbody>\n"
    )
    for c in checks:
        if c.ok:
            present = '<td class="ok">✓</td>'
            value = f"<td><code>{_h(c.value)}</code></td>" if c.value \
                else '<td class="muted">—</td>'
        else:
            present = '<td class="bad">✗</td>'
            value = '<td class="muted">—</td>'
        out.write(
            f"<tr><td>{_h(c.label)}</td>{present}{value}</tr>\n"
        )
    out.write("</tbody></table>\n")
    out.write("</section>\n")


#: Per-status cell: (data-table class, glyph, trailing label).
_CF_STATUS_CELL = {
    "ok": ("ok", "✓", ""),
    "fail": ("bad", "✗", "fail"),
    "not_deployed": ("muted", "○", "not deployed"),
    "not_assessed": ("muted", "–", "not assessed"),
}


def _render_cyberfundamentals(out: StringIO, view) -> None:
    """Render the NIS2 / CyberFundamentals baseline, one table per area.

    Renders nothing when ``view`` is ``None`` (un-enriched bundle). Uses
    the shared ``.data-table`` ok/bad/muted cell modifiers."""
    if view is None:
        return
    out.write('<section class="report-section">\n')
    out.write("<h2>NIS2 / CyberFundamentals baseline</h2>\n")
    out.write(
        '<p class="muted">Observable technical controls only — an '
        "indicator, not a conformity assessment. "
        f"{view.passed}/{view.assessed} controls passed.</p>\n"
    )
    for area in view.areas:
        out.write(
            f"<h3>{_h(area.name)} "
            f'<small class="muted">{_h(area.nis2)}</small></h3>\n'
        )
        out.write('<table class="data-table">\n')
        out.write(
            "<thead><tr><th>Control</th><th>Status</th><th>Note</th>"
            "</tr></thead>\n<tbody>\n"
        )
        for c in area.checks:
            cls, glyph, label = _CF_STATUS_CELL.get(
                c.status, ("muted", "?", c.status))
            status = f"{glyph} {label}".strip()
            note = f"<td>{_h(c.detail)}</td>" if c.detail \
                else '<td class="muted">—</td>'
            out.write(
                f"<tr><td>{_h(c.label)}</td>"
                f'<td class="{cls}">{_h(status)}</td>{note}</tr>\n'
            )
        out.write("</tbody></table>\n")
    out.write("</section>\n")


def _transport_rows(posture) -> list:
    rows = [posture.primary]
    if posture.alternate is not None:
        rows.append(posture.alternate)
    return rows


def _transport_row_html(hp) -> str:
    """Render one HostProbe as a row in the transport-posture table.

    Uses the shared .data-table ok/bad/muted cell modifiers.
    """
    def cell(responded: bool, status: int | None) -> str:
        if not responded:
            return '<td class="bad">✗</td>'
        label = str(status) if status is not None else "—"
        return f'<td class="ok">✓ <small>{label}</small></td>'
    if hp.http_redirects_to_https:
        upgrade = '<td class="ok">✓</td>'
    elif hp.http_responded:
        upgrade = '<td class="bad">✗</td>'
    else:
        upgrade = '<td class="muted">—</td>'
    return (
        f"<tr><td><code>{_h(hp.host)}</code></td>"
        f"{cell(hp.http_responded, hp.http_status)}"
        f"{cell(hp.https_responded, hp.https_status)}"
        f"{upgrade}</tr>\n"
    )


def _render_cms(out: StringIO, fp) -> None:
    """Render the detected platform + version + EOL status as a banner.

    Empty / ``None`` fingerprint → section omitted. Past-EOL platforms
    get the ``.eol`` modifier class so CSS can colour the banner red
    and add a visible "END-OF-LIFE" tag.
    """
    if fp is None:
        return
    tone = "report-section--bad" if fp.is_eol else "report-section--good"
    out.write(f'<section class="report-section {tone}">\n')
    eol_tag = '<span class="badge badge--strong">END-OF-LIFE</span>' if fp.is_eol else ""
    version_html = (
        f' <code>{_h(fp.version)}</code>' if fp.version else ""
    )
    heading_label = (
        "Platform end-of-life" if fp.is_eol else "Web platform"
    )
    out.write(
        f"<h2>{heading_label}: "
        f"<strong>{_h(fp.name)}</strong>"
        f"{version_html} {eol_tag}</h2>\n"
    )
    if fp.is_eol and fp.eol_note:
        out.write(f'<p class="callout--bad">{_h(fp.eol_note)}</p>\n')
    if fp.evidence:
        out.write(f'<p class="note">Detected via: {_h(fp.evidence)}</p>\n')
    out.write("</section>\n")


def _render_storage(out: StringIO, storage: list) -> None:
    """Render the ``localStorage`` / ``sessionStorage`` overview.

    Lists every key that survived to end-of-session, with its kind
    (local/session), origin, and value size. The values themselves are
    deliberately not rendered — they frequently contain identifiers,
    tokens, or PII; the report's job is to show *what* is stored, not
    leak it. Empty list → section is omitted entirely.
    """
    if not storage:
        return
    out.write('<section class="report-section">\n')
    out.write(f"<h2>Browser storage during this capture <span class=\"count\">"
              f"({len(storage)})</span></h2>\n")
    out.write('<p class="hint">Keys observed in <code>localStorage</code> and '
              "<code>sessionStorage</code> at session end. Values are "
              "redacted; only the byte size is surfaced.</p>\n")
    out.write('<table class="data-table">\n')
    out.write(
        "<thead><tr>"
        "<th>Key</th><th>Kind</th><th>Origin</th><th>Size</th>"
        "</tr></thead>\n<tbody>\n"
    )
    for e in storage:
        kind_badge = (
            f'<span class="badge badge--info">{_h(e.kind)}</span>'
        )
        out.write(
            "<tr>"
            f"<td><code>{_h(e.key)}</code></td>"
            f"<td>{kind_badge}</td>"
            f"<td class=\"host\">{_h(e.origin)}</td>"
            f"<td class=\"num mono\">{e.value_bytes}&nbsp;B</td>"
            "</tr>\n"
        )
    out.write("</tbody></table>\n</section>\n")


def _render_unknown_hosts(
    out: StringIO, unclassified: list[UnclassifiedHost]
) -> None:
    if not unclassified:
        return
    out.write('<section class="report-section report-section--warn">\n')
    out.write(
        f'<h2>Unclassified third-party hosts '
        f'<span class="count">({len(unclassified)})</span></h2>\n'
    )
    out.write(
        '<p class="hint">'
        "Third-party domains the visited page contacted that no registered "
        "tracker module recognized. May include untracked trackers, asset "
        "CDNs, vendor infrastructure, or partner content."
        '</p>\n'
    )
    out.write('<table class="data-table">\n')
    out.write(
        '<thead><tr>'
        '<th class="num">Hits</th><th>Host</th><th>Via (CDN/edge)</th>'
        '<th>Methods</th><th>Sample request</th>'
        '</tr></thead>\n<tbody>\n'
    )
    for host in unclassified:
        methods = ", ".join(
            f"{_h(m)} × {n}" for m, n in host.methods.items()
        )
        sample = ""
        if host.sample_urls:
            s = host.sample_urls[0]
            sample = f"<code>{_h(s.method)} {_h(_truncate(s.url, 90))}</code>"
        if host.cdn_provider is not None:
            p = host.cdn_provider
            via = (
                f'<span class="muted">{_h(p.name)} '
                f"({_h(p.jurisdiction)})</span>"
            )
        else:
            via = '<span class="muted">—</span>'
        out.write(
            "<tr>"
            f'<td class="num">{host.count}</td>'
            f'<td><code>{_h(host.host)}</code></td>'
            f'<td>{via}</td>'
            f'<td>{methods}</td>'
            f'<td>{sample}</td>'
            "</tr>\n"
        )
    out.write("</tbody></table>\n</section>\n")


def _render_tracker(out: StringIO, section: ModuleSection) -> None:
    meta = section.vendor_meta
    out.write('<section class="tracker">\n')

    # Header — name + jurisdiction badge + vendor/sovereignty notes
    out.write('<div class="tracker-head">\n')
    jurisdiction_html = ""
    if meta.legal_jurisdiction:
        flag_prefix = f"{meta.flag} " if meta.flag else ""
        bg_class = ""  # background hint isn't computed per-tracker yet
        jurisdiction_html = (
            f'<span class="jurisdiction jur-{_h(meta.legal_jurisdiction)}'
            f'{bg_class}">{flag_prefix}{_h(meta.legal_jurisdiction)}</span>'
        )
    out.write(
        f"<h2>{_h(section.module_name)} "
        f"<code>({_h(section.module_id)})</code>{jurisdiction_html}</h2>\n"
    )
    if meta.vendor or meta.data_residency:
        vendor_line = f"<b>{_h(meta.vendor or '—')}</b>"
        if meta.data_residency:
            vendor_line += f" — {_h(meta.data_residency)}"
        out.write(f'<div class="vendor">{vendor_line}</div>\n')
    if meta.sovereignty_notes:
        out.write(f'<div class="note">{_h(meta.sovereignty_notes)}</div>\n')
    out.write("</div>\n")

    # Stat cards
    pii_count = section.category_counts.get("pii", 0)
    ident_count = section.category_counts.get("identifier", 0)
    out.write('<div class="stats">\n')
    out.write(_stat("Total hits", section.total_hits))
    out.write(_stat("Representatives", section.representative_count))
    out.write(_stat("Unique fields", section.unique_param_keys))
    out.write(_stat(
        "PII fields", pii_count, css_class="has-pii" if pii_count else "zero"
    ))
    out.write(_stat(
        "Identifier fields", ident_count,
        css_class="has-ident" if ident_count else "zero",
    ))
    out.write("</div>\n")

    # Harvested-fields summary
    if section.harvested_fields:
        out.write('<div class="fields-summary">\n')
        out.write('<span class="label">Harvested fields:</span> ')
        rendered: list[str] = []
        for hf in section.harvested_fields[:15]:
            cls = ""
            if hf.category == "pii":
                cls = " pii"
            elif hf.category == "identifier":
                cls = " ident"
            rendered.append(f'<span class="fld{cls}">{_h(hf.key)}</span>')
        out.write(" ".join(rendered))
        if len(section.harvested_fields) > 15:
            out.write(
                f' <span style="color:#999">+ {len(section.harvested_fields) - 15} more</span>'
            )
        out.write("\n</div>\n")

    # Fold-open representative-hit detail
    reps = section.representative_hits
    out.write(
        f'<details>\n<summary>{len(reps)} representative hit(s) — '
        "click to expand</summary>\n"
    )
    for rep in reps:
        _render_hit(out, rep)
    out.write("</details>\n")

    out.write("</section>\n")


def _render_hit(out: StringIO, rep: RepresentativeHit) -> None:
    status = "—" if rep.response_status is None else str(rep.response_status)
    out.write('<div class="hit">\n')
    out.write(
        f'<div class="url"><b>{_h(rep.method)}</b> {_h(rep.url)}</div>\n'
    )
    out.write(
        f'<div class="hit-meta">HTTP {_h(status)} · '
        f'collapsed events: {rep.collapsed_event_count}</div>\n'
    )
    if rep.request_body:
        out.write('<div class="body-label">Request body</div>\n')
        out.write(f'<pre class="body">{_h(_truncate(rep.request_body, 1500))}</pre>\n')
    if rep.response_body and not rep.params and not rep.request_body:
        out.write('<div class="body-label">Response body</div>\n')
        out.write(f'<pre class="body">{_h(_truncate(rep.response_body, 1500))}</pre>\n')
    if rep.params:
        _render_params_table(out, rep.params)
    out.write("</div>\n")


def _render_params_table(out: StringIO, params: list[ParamRow]) -> None:
    impact_order = {IMPACT_HIGH: 0, IMPACT_MEDIUM: 1, IMPACT_LOW: 2}
    category_order = {cat: i for i, cat in enumerate(CATEGORIES)}
    sorted_params = sorted(
        params,
        key=lambda x: (
            impact_order.get(x.privacy_impact, 99),
            category_order.get(x.category, 99),
            x.key,
        ),
    )
    out.write('<table class="params">\n')
    out.write(
        "<thead><tr>"
        "<th>Field</th><th>Category</th><th>Impact</th><th>Value</th><th>Meaning</th>"
        "</tr></thead>\n<tbody>\n"
    )
    for p in sorted_params:
        impact_cls = {
            IMPACT_HIGH: "high",
            IMPACT_MEDIUM: "medium",
            IMPACT_LOW: "low",
        }.get(p.privacy_impact, "low")
        out.write(
            f'<tr class="row-{_h(p.category)}">'
            f'<td class="key">{_h(p.key)}</td>'
            f'<td class="cat">{_h(p.category)}</td>'
            f'<td class="imp"><span class="badge badge--{impact_cls}">'
            f'{_h(p.privacy_impact.upper())}</span></td>'
            f'<td class="val">{_h(_truncate(p.value, 80))}</td>'
            f'<td class="mean">{_h(p.meaning)}</td>'
            "</tr>\n"
        )
    out.write("</tbody></table>\n")


__all__ = ["render_html_document", "write_html_report"]
