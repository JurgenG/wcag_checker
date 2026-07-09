"""Tests for the PDF report export.

PDF is produced by rendering the existing HTML report through WeasyPrint
(HTML→PDF), with a branded cover page prepended. WeasyPrint is an
optional dependency (heavy native libs), so the actual render is tested
only when it's importable; the cover-page and HTML-assembly logic —
the part this module authors — is pure and always tested.
"""

from __future__ import annotations

import importlib.util

import pytest

from leak_inspector import modules  # noqa: F401  (registers detectors)
from leak_inspector.analysis.runner import analyze_bundle
from leak_inspector.report.builder import build_report_document
from leak_inspector.report import pdf as pdf_mod
from tests.fixtures.bundles import path as bundle_path

_WEASYPRINT = importlib.util.find_spec("weasyprint") is not None


@pytest.fixture(scope="module")
def document():
    return build_report_document(analyze_bundle(bundle_path("aalst.zip")))


# --- the cover page (pure, no WeasyPrint) ------------------------------------


def test_cover_carries_the_required_elements(document) -> None:
    """The task spec: cover shows BeLibre branding, the site URL, the
    project source link, the date, and the disclaimer."""
    from leak_inspector.report._branding import PROJECT_SOURCE_URL

    cover = pdf_mod._cover_html(document.manifest)
    assert "belibre-logo" in cover                       # BeLibre branding
    assert document.manifest.target_url in cover         # the website URL
    assert PROJECT_SOURCE_URL in cover                   # codeberg source
    assert "automatically generated" in cover.lower()    # disclaimer
    # the capture date (deterministic, from the manifest — not now())
    assert document.manifest.ended_at[:10] in cover


def test_cover_escapes_the_target_url() -> None:
    """A hostile target URL must not inject markup into the cover."""
    from leak_inspector.report.document import ManifestView

    m = ManifestView(
        target_url="https://x.be/?q=<script>alert(1)</script>",
        landing_url="https://x.be/", base_domain="x.be",
        session_id="s", started_at="2026-06-13T00:00:00Z",
        ended_at="2026-06-13T00:01:00Z", profile="p",
        browser_name="firefox", browser_version="151",
    )
    cover = pdf_mod._cover_html(m)
    assert "<script>alert(1)</script>" not in cover
    assert "&lt;script&gt;" in cover


# --- full HTML assembly (pure) -----------------------------------------------


def test_pdf_html_prepends_cover_then_toc_before_the_report(document) -> None:
    html = pdf_mod.build_pdf_html(document)
    assert html.count("<!doctype html>") == 1           # one document
    assert "pdf-cover" in html
    assert "pdf-toc" in html
    # cover, then TOC, then the report body (scorecard / calculation)
    assert (html.index("pdf-cover") < html.index("pdf-toc")
            < html.index("How the score is calculated"))


def test_pdf_html_includes_the_scorecard_sections(document) -> None:
    """Even the summary body keeps the breakdown + calculation."""
    html = pdf_mod.build_pdf_html(document)
    assert "How the score is calculated" in html         # the calculation
    assert "What lowered each dimension" in html          # the breakdown
    assert "Executive summary" in html


def test_summary_body_omits_per_hit_tables_detailed_keeps_them(document) -> None:
    """The default (summary) body strips the per-hit <details> tables and
    leaves a pointer note; detailed=True keeps the full tables."""
    summary = pdf_mod.build_pdf_html(document, detailed=False)
    detailed = pdf_mod.build_pdf_html(document, detailed=True)
    assert "attached detailed report" in summary          # the pointer note
    assert "attached detailed report" not in detailed
    # the detailed HTML is materially larger (the param tables are back)
    assert len(detailed) > len(summary)


def test_toc_links_every_section_heading(document) -> None:
    """The TOC has one anchor per <h2> section, linking to its id."""
    html = pdf_mod.build_pdf_html(document)
    toc = html[html.index('<nav class="pdf-toc"'):html.index("</nav>")]
    # the report's sections each appear as a TOC link
    assert 'href="#sec-0"' in toc
    assert "Executive summary" in toc
    assert "How the score is calculated" in toc


def test_pdf_html_declares_bookmarks_and_page_breaks(document) -> None:
    html = pdf_mod.build_pdf_html(document)
    assert "bookmark-level" in html                       # PDF outline
    assert "target-counter" in html                       # TOC page numbers
    assert "page-break-after" in html


# --- colour-emoji handling (pure) --------------------------------------------
#
# WeasyPrint cannot colour-render emoji glyphs at the report's small body
# size, so the PDF path replaces each emoji with inline SVG extracted from
# the bundled Twemoji font (see leak_inspector.report.emoji_svg). The
# replacement must catch the pictographic/flag emoji the report uses and
# leave the text-presentation glyphs (✓ ✗ → − …) untouched.


def test_wrap_emoji_replaces_colour_emoji_with_svg() -> None:
    """The scorecard / severity / flag emoji each become an inline
    ``<svg class="emoji">`` — including a variation-selector glyph and a
    regional-indicator flag pair (one svg for the pair)."""
    out = pdf_mod._wrap_emoji("🛡️ 47 🔐 50 🔴 🇪🇺 ⚠ ✅ ❌")
    # seven emoji (🛡️ 🔐 🔴 🇪🇺 ⚠ ✅ ❌) → seven inline svgs
    assert out.count('<svg ') == 7
    assert out.count('class="emoji"') == 7
    # the raw emoji characters are gone (replaced by their svg)
    assert "🛡" not in out and "🇪🇺" not in out
    # the svgs carry colour fills (the whole point)
    assert "fill=" in out


def test_wrap_emoji_leaves_text_glyphs_untouched() -> None:
    """Text-presentation symbols the report uses as plain glyphs must not
    be replaced (they render fine as text and are CSS-styled)."""
    text = "ok ✓ no ✗ a → b − c ► d √ ≥ ∞ 百度统计"
    assert pdf_mod._wrap_emoji(text) == text


def test_pdf_html_inlines_emoji_as_svg(document) -> None:
    """The assembled PDF HTML carries the report's emoji as inline svg
    (no @font-face, no raw emoji characters left to render)."""
    html = pdf_mod.build_pdf_html(document)
    assert "@font-face" not in html              # not a text-font approach
    assert 'class="emoji"' in html and "<svg" in html  # emoji inlined as svg
    assert "🛡" not in html                       # raw glyphs replaced


# --- the WeasyPrint render ---------------------------------------------------


@pytest.mark.skipif(not _WEASYPRINT, reason="WeasyPrint not installed")
def test_render_produces_a_pdf(document) -> None:
    out = pdf_mod.render_pdf_document(document)
    assert isinstance(out, bytes)
    assert out[:5] == b"%PDF-"


@pytest.mark.skipif(not _WEASYPRINT, reason="WeasyPrint not installed")
def test_render_embeds_the_detailed_report_as_attachment(document) -> None:
    """The default render carries the detailed report as an embedded
    PDF file attachment (the filename is PDF-encoded, so we assert the
    embedding markers, not the literal name)."""
    out = pdf_mod.render_pdf_document(document)  # attach_detailed default
    assert b"EmbeddedFile" in out


@pytest.mark.skipif(not _WEASYPRINT, reason="WeasyPrint not installed")
def test_detailed_render_has_no_attachment(document) -> None:
    """A detailed-body PDF does not attach a second copy of itself."""
    out = pdf_mod.render_pdf_document(document, detailed=True)
    assert b"EmbeddedFile" not in out


@pytest.mark.skipif(_WEASYPRINT, reason="WeasyPrint IS installed")
def test_render_without_weasyprint_raises_a_clear_error(document) -> None:
    with pytest.raises(RuntimeError) as exc:
        pdf_mod.render_pdf_document(document)
    msg = str(exc.value).lower()
    assert "weasyprint" in msg and "pip" in msg
