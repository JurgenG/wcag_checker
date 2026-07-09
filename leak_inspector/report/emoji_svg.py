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

"""Colour emoji as inline SVG, extracted from the bundled Twemoji font.

WeasyPrint cannot paint *scaled inline* colour-glyphs (its COLR text
renderer drops or mis-positions them below ~20px), so the PDF path can't
rely on the emoji font directly. It can, however, render inline ``<svg>``
flawlessly at any size (the same way the report's logo is embedded).

This module bridges the two: it reads the bundled **Twemoji**
(``TwemojiMozilla.ttf`` — a COLRv0 / CPAL colour font, Firefox's own
emoji set, with real flag glyphs) and converts a single emoji grapheme
to inline SVG markup — each COLR layer becomes a ``<path>`` filled with
its CPAL palette colour. Flags (regional-indicator pairs) are resolved
to their ligature glyph via the font's GSUB table.

Pure and offline: only :mod:`fontTools` (already required by WeasyPrint)
is used — no new dependency and no network. :func:`emoji_to_svg` returns
``None`` for anything the font can't represent, so callers can fall back
to the raw character.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from fontTools.pens.boundsPen import BoundsPen
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.ttLib import TTFont

#: The bundled Twemoji colour font (COLRv0 / CPAL, vector — scales to any
#: size). Read here for its glyph outlines + palette; never registered as
#: a text font (WeasyPrint can't colour-render it inline).
_TWEMOJI_PATH = Path(__file__).parent / "assets" / "TwemojiMozilla.ttf"

#: COLR "use the current text colour" sentinel (spec: palette index
#: 0xFFFF). Twemoji rarely uses it; render it as black if it appears.
_FOREGROUND = 0xFFFF


@lru_cache(maxsize=1)
def _font() -> TTFont:
    """Load (and cache) the bundled Twemoji font."""
    return TTFont(_TWEMOJI_PATH)


@lru_cache(maxsize=1)
def _ligatures() -> dict[tuple[str, ...], str]:
    """Map a component-glyph sequence to its ligature glyph, read from
    GSUB ligature substitutions — this is how a regional-indicator pair
    (e.g. the two halves of 🇪🇺) resolves to a single flag glyph."""
    out: dict[tuple[str, ...], str] = {}
    gsub = _font().get("GSUB")
    if gsub is None:
        return out
    for lookup in gsub.table.LookupList.Lookup:
        for sub in lookup.SubTable:
            ligatures = getattr(sub, "ligatures", None) or {}
            for first, ligset in ligatures.items():
                for lig in ligset:
                    out[(first, *lig.Component)] = lig.LigGlyph
    return out


def _resolve_glyph(text: str) -> str | None:
    """Return the font glyph name for an emoji grapheme, or ``None``.

    Variation selectors (U+FE0F) are ignored; a single codepoint maps via
    the cmap, a two-codepoint regional-indicator pair maps via the GSUB
    ligature table (a flag).
    """
    font = _font()
    cmap = font.getBestCmap()
    codepoints = [ord(ch) for ch in text if ord(ch) != 0xFE0F]
    if len(codepoints) == 1:
        return cmap.get(codepoints[0])
    if len(codepoints) == 2:
        parts = [cmap.get(cp) for cp in codepoints]
        if all(parts):
            return _ligatures().get(tuple(parts))
    return None


def _fill(color) -> tuple[str, float]:
    """Return ``(#rrggbb, opacity)`` for a CPAL colour record."""
    return f"#{color.red:02x}{color.green:02x}{color.blue:02x}", color.alpha / 255


def _glyph_svg(glyph_name: str) -> str | None:
    """Render a COLRv0 glyph to inline SVG markup, or ``None`` if it has
    no colour layers (not a colour glyph)."""
    font = _font()
    layers = font["COLR"].ColorLayers.get(glyph_name)
    if not layers:
        return None
    palette = font["CPAL"].palettes[0]
    glyph_set = font.getGlyphSet()

    paths: list[str] = []
    bounds = BoundsPen(glyph_set)
    for layer in layers:
        pen = SVGPathPen(glyph_set)
        glyph_set[layer.name].draw(pen)
        d = pen.getCommands()
        if not d:
            continue
        glyph_set[layer.name].draw(bounds)
        if layer.colorID == _FOREGROUND:
            fill, opacity = "#000000", 1.0
        else:
            fill, opacity = _fill(palette[layer.colorID])
        attr = f' fill-opacity="{opacity:g}"' if opacity < 1 else ""
        paths.append(f'<path fill="{fill}"{attr} d="{d}"/>')

    if bounds.bounds is None or not paths:
        return None
    x_min, y_min, x_max, y_max = bounds.bounds
    width, height = x_max - x_min, y_max - y_min
    # Font coordinates are y-up; SVG is y-down. Flip with scale(1,-1) and
    # frame the viewBox on the glyph's own ink bounds (so it sits tight
    # and never clips). class="emoji" lets the PDF CSS size it like text.
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" class="emoji" '
        f'viewBox="{x_min:g} {-y_max:g} {width:g} {height:g}" '
        'preserveAspectRatio="xMidYMid meet">'
        f'<g transform="scale(1,-1)">{"".join(paths)}</g></svg>'
    )


@lru_cache(maxsize=512)
def emoji_to_svg(text: str) -> str | None:
    """Return inline ``<svg>`` markup for an emoji grapheme, or ``None``.

    ``None`` means the bundled font has no colour glyph for it — the
    caller should keep the raw character. Results are cached per grapheme.
    """
    glyph = _resolve_glyph(text)
    if glyph is None:
        return None
    return _glyph_svg(glyph)


__all__ = ["emoji_to_svg"]
