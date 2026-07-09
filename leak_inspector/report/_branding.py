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

"""Shared branding strings + intro prose for every report format.

Single source of truth for:

* The title prefix ("BeLibre Automatic Leak Inspector").
* The BeLibre homepage / logo URLs.
* The host-label derivation from the manifest.
* The "About this report" intro section's prose.

The intro paragraphs carry ``{belibre_link}`` / ``{disclaimer_bold}`` /
``{belibre_url}`` placeholders that each reporter (HTML, Markdown, Text)
fills in with format-specific markup. Editing the prose in this module
updates every output format simultaneously — no per-format duplication.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse


# --- title / link constants ------------------------------------------------


#: Title prefix shared by every report format.
BRANDING_TITLE_PREFIX = "BeLibre Automatic Leak Inspector"

#: BeLibre homepage. Used by the logo link and the in-intro hyperlink.
BELIBRE_HOMEPAGE = "https://belibre.be"

#: Public source repository (Codeberg). Surfaced on the PDF cover page
#: so a reader can find and audit the tool that produced the report.
PROJECT_SOURCE_URL = "https://codeberg.org/BeLibre/Leak_Detector"

#: Bundled BeLibre logo SVG. Inlined into HTML so reports render
#: offline and aren't subject to the ``Cross-Origin-Resource-Policy:
#: same-origin`` header that belibre.be ships, which silently blocks
#: ``<img src=…>`` embedding from any other origin.
_BELIBRE_LOGO_PATH = Path(__file__).parent / "assets" / "belibre_logo.svg"

#: Cached inline-ready SVG markup. Built lazily on first call.
_inline_svg_cache: str | None = None


def belibre_logo_svg_inline() -> str:
    """Return the BeLibre logo SVG ready to drop into HTML.

    Strips the XML prolog / Inkscape comments, removes the explicit
    physical ``width``/``height`` attributes (so CSS controls the size
    via the ``.belibre-logo`` class), and adds ARIA metadata so screen
    readers announce it correctly. The result is cached for the
    lifetime of the process — the file is small but is referenced
    from every HTML report on the page.
    """
    global _inline_svg_cache
    if _inline_svg_cache is not None:
        return _inline_svg_cache
    raw = _BELIBRE_LOGO_PATH.read_text(encoding="utf-8")
    # Drop the XML declaration and the top-of-file comments — both are
    # valid in standalone SVG but illegal when inlined inside HTML.
    raw = re.sub(r"<\?xml[^?]*\?>", "", raw, count=1)
    raw = re.sub(r"<!--.*?-->", "", raw, count=1, flags=re.DOTALL)
    # Strip the physical-unit width/height (220mm × 220mm). The viewBox
    # is preserved, so CSS ``height: 32px`` produces the correct render.
    raw = re.sub(r'\s+width="220mm"', "", raw, count=1)
    raw = re.sub(r'\s+height="220mm"', "", raw, count=1)
    # Strip the Inkscape-generated ``id="…"`` attributes. They are not
    # referenced internally (no ``url(#…)`` / ``href="#…"``), so dropping
    # them changes nothing visually — but it prevents "anchor defined
    # twice" collisions when the logo is inlined more than once on a page
    # (e.g. the PDF cover *and* the report header).
    raw = re.sub(r'\s+id="[^"]*"', "", raw)
    # Tag the root <svg> with our CSS hook + ARIA metadata. The
    # original element starts ``<svg`` with no class attribute, so
    # injecting once is unambiguous.
    raw = raw.replace(
        "<svg",
        '<svg class="belibre-logo" role="img" aria-label="BeLibre"',
        1,
    )
    _inline_svg_cache = raw.strip()
    return _inline_svg_cache


def title_host_label(manifest) -> str:
    """Best-effort label for the report title.

    An explicit ``display_name`` (e.g. a site's name supplied by the
    bulk runner from a ``domains.csv`` ``name`` column) wins outright.
    Otherwise prefer the parsed host of ``target_url`` (what the operator
    typed and what reads naturally for a per-site report); fall back to
    ``base_domain`` and finally to the raw ``target_url`` so a
    misshapen capture still renders a sensible title.
    """
    display_name = getattr(manifest, "display_name", None)
    if display_name:
        return display_name
    host = urlparse(manifest.target_url).hostname if manifest.target_url else ""
    if host:
        return host
    return manifest.base_domain or manifest.target_url or "(no target)"


# --- "About this report" intro --------------------------------------------


#: Section heading rendered above the intro prose.
INTRO_TITLE = "About this report"

#: Bold line in paragraph #2 that warns the reader the report is
#: automatically produced. Each format wraps this in its own
#: bold/strong markup.
INTRO_DISCLAIMER_TEXT = "This report is automatically generated."

#: Three intro paragraphs. Each carries a single placeholder filled in
#: by the renderer:
#:
#: * paragraph[0] uses ``{belibre_link}``  — the inline "BeLibre" link.
#: * paragraph[1] uses ``{disclaimer_bold}`` — the bolded warning.
#: * paragraph[2] uses ``{belibre_url}``   — the homepage URL,
#:   formatted as a hyperlink in HTML/Markdown and as plain text in
#:   the terminal report.
INTRO_PARAGRAPHS: tuple[str, ...] = (
    "{belibre_link} is a non-profit promoting digital sovereignty for European "
    "organisations — free / open-source / EU-based infrastructure that keeps "
    "data and decisions under European jurisdiction.",

    "{disclaimer_bold} The technical findings are accurate, but their privacy "
    "and sovereignty implications depend on context the tool can't see: what "
    "the site actually does, what consent was collected, the operator's threat "
    "model, and current legal interpretation (Schrems II, GDPR, DMA). Treat it "
    "as a starting point — not a verdict — and read it together with someone "
    "who knows the legal and technical landscape.",

    "BeLibre can put you in touch with practitioners who can help interpret "
    "these findings, build a remediation roadmap, and advise on EU-sovereign "
    "alternatives. See {belibre_url}.",
)


__all__ = [
    "BELIBRE_HOMEPAGE",
    "BRANDING_TITLE_PREFIX",
    "INTRO_DISCLAIMER_TEXT",
    "INTRO_PARAGRAPHS",
    "INTRO_TITLE",
    "PROJECT_SOURCE_URL",
    "belibre_logo_svg_inline",
    "title_host_label",
]