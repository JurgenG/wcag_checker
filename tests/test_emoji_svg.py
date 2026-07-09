"""Tests for the Twemoji → inline-SVG converter.

The converter reads the bundled Twemoji COLRv0/CPAL font and turns one
emoji grapheme into inline ``<svg>`` markup (each colour layer a filled
``<path>``). It is pure and offline (fontTools only). These tests assert
the data the converter produces — not how it renders.
"""

from __future__ import annotations

from leak_inspector.report import emoji_svg


def test_bundled_twemoji_font_is_present() -> None:
    """The COLR/CPAL colour font ships with the package (packaged via
    ``report/assets/*.ttf``)."""
    assert emoji_svg._TWEMOJI_PATH.is_file()
    assert emoji_svg._TWEMOJI_PATH.suffix == ".ttf"


def test_single_codepoint_emoji_becomes_coloured_svg() -> None:
    """A pictographic emoji renders as an svg with colour-filled paths."""
    svg = emoji_svg.emoji_to_svg("\U0001F6E1️")  # 🛡️ shield
    assert svg is not None
    assert svg.startswith("<svg")
    assert 'class="emoji"' in svg
    assert "viewBox=" in svg
    assert svg.count("<path") >= 1
    assert 'fill="#' in svg                     # real palette colour, not mono


def test_variation_selector_is_ignored() -> None:
    """The U+FE0F emoji-presentation selector doesn't change the glyph."""
    assert emoji_svg.emoji_to_svg("\U0001F6E1️") == emoji_svg.emoji_to_svg("\U0001F6E1")


def test_regional_indicator_pair_becomes_one_flag_svg() -> None:
    """🇪🇺 (two regional indicators) resolves via the font's GSUB ligature
    to a single flag glyph — one svg, multiple colour layers."""
    svg = emoji_svg.emoji_to_svg("\U0001F1EA\U0001F1FA")  # 🇪🇺
    assert svg is not None
    assert svg.count("<svg") == 1
    assert svg.count("<path") >= 2              # a flag has several layers


def test_unrepresentable_text_returns_none() -> None:
    """Plain text / text-presentation symbols have no colour glyph, so the
    converter returns None and the caller keeps the raw character."""
    assert emoji_svg.emoji_to_svg("A") is None
    assert emoji_svg.emoji_to_svg("→") is None   # → arrow (text)
    assert emoji_svg.emoji_to_svg("✓") is None   # ✓ check mark (text)
