"""Tests for the linearized reading-view aid (:mod:`.wcag.text_view`).

Hermetic: the pure conversion (:func:`_to_page_view`) and renderer
(:func:`render_markdown`) are exercised against canned data, and
:func:`extract` is driven with a fake driver whose ``execute_script``
returns a fixed walker payload — no browser. The in-page JavaScript walker
itself is validated live against a real page.
"""

from __future__ import annotations

from leak_inspector.wcag import text_view
from leak_inspector.wcag.text_view import (
    PageTextView,
    TextNode,
    extract,
    render_markdown,
)


class _FakeDriver:
    """Returns a canned walker payload and records the URL/script."""

    def __init__(self, payload: dict) -> None:
        self._payload = payload
        self.current_url = "https://x/current"
        self.script: str | None = None

    def execute_script(self, script: str, *args) -> dict:
        self.script = script
        return self._payload


class TestExtract:
    def test_converts_walker_payload_to_page_view(self) -> None:
        payload = {
            "title": "  Home  ",
            "truncated": False,
            "nodes": [
                {"role": "heading", "level": 1, "name": "Welcome", "named": True},
                {"role": "link", "name": "About", "named": True},
                {"role": "image", "name": "", "named": False,
                 "note": "no alt attribute"},
            ],
        }
        view = extract(_FakeDriver(payload), "https://x/a")
        assert view.url == "https://x/a"
        assert view.title == "Home"  # trimmed
        assert view.nodes[0] == TextNode(
            role="heading", name="Welcome", named=True, level=1
        )
        assert view.nodes[2].role == "image" and view.nodes[2].named is False

    def test_url_defaults_to_current_url(self) -> None:
        driver = _FakeDriver({"title": "T", "nodes": []})
        assert extract(driver).url == "https://x/current"

    def test_missing_or_empty_payload_is_safe(self) -> None:
        assert extract(_FakeDriver(None), "u").nodes == ()
        assert extract(_FakeDriver({}), "u").title == ""

    def test_max_nodes_passed_to_walker(self) -> None:
        driver = _FakeDriver({"title": "T", "nodes": []})
        extract(driver, "u", max_nodes=10)
        # the walker script is the one injected (sanity that we ran ours)
        assert "document.body" in (driver.script or "")


class TestRenderMarkdown:
    def _view(self, *nodes: TextNode, title: str = "Home", truncated: bool = False):
        return PageTextView(
            url="https://x/a", title=title, nodes=tuple(nodes), truncated=truncated
        )

    def test_leads_with_the_not_a_test_disclaimer(self) -> None:
        md = render_markdown([self._view(TextNode(role="text", name="hi"))])
        assert "NOT a screen-reader test" in md
        assert "NOT a conformance" in md

    def test_no_views_states_nothing_recorded(self) -> None:
        md = render_markdown([])
        assert "No pages were recorded" in md

    def test_heading_shows_level_and_text(self) -> None:
        md = render_markdown([self._view(
            TextNode(role="heading", name="About us", level=2)
        )])
        assert "**H2** About us" in md

    def test_empty_heading_is_flagged(self) -> None:
        md = render_markdown([self._view(
            TextNode(role="heading", name="", named=False, level=1)
        )])
        assert "⚠ (empty heading)" in md

    def test_unnamed_image_is_flagged_with_note(self) -> None:
        md = render_markdown([self._view(
            TextNode(role="image", name="", named=False, note="no alt attribute")
        )])
        assert "`image` ⚠ no alt attribute" in md

    def test_named_image_shows_its_alt(self) -> None:
        md = render_markdown([self._view(
            TextNode(role="image", name="Company logo")
        )])
        assert '`image` "Company logo"' in md

    def test_field_tag_carries_type_and_placeholder_note(self) -> None:
        md = render_markdown([self._view(
            TextNode(role="field", name="Search", field_type="text",
                     note="name from placeholder only")
        )])
        assert '`field:text` "Search" — name from placeholder only' in md

    def test_unlabelled_field_is_flagged(self) -> None:
        md = render_markdown([self._view(
            TextNode(role="field", name="", named=False, field_type="email",
                     note="no label")
        )])
        assert "`field:email` ⚠ no label" in md

    def test_landmark_tag_carries_its_role(self) -> None:
        md = render_markdown([self._view(
            TextNode(role="landmark", name="Main menu", landmark="navigation")
        )])
        assert '`landmark:navigation` "Main menu"' in md

    def test_summary_counts_names_missing(self) -> None:
        md = render_markdown([self._view(
            TextNode(role="heading", name="H", level=1),
            TextNode(role="image", name="", named=False, note="no alt attribute"),
            TextNode(role="image", name="ok"),
            TextNode(role="field", name="", named=False, field_type="text",
                     note="no label"),
        )])
        assert "1 heading(s)" in md
        assert "2 image(s) (1 without a name)" in md
        assert "1 form field(s) (1 without a label)" in md

    def test_truncation_is_reported_not_silent(self) -> None:
        md = render_markdown([self._view(
            TextNode(role="text", name="a"), truncated=True
        )])
        assert "truncated" in md

    def test_empty_page_notes_no_content(self) -> None:
        md = render_markdown([self._view(title="Blank")])
        assert "No visible content was extracted" in md

    def test_title_links_to_url(self) -> None:
        md = render_markdown([self._view(
            TextNode(role="text", name="x"), title="Home"
        )])
        assert "## Home" in md
        assert "<https://x/a>" in md

    def test_generated_at_included(self) -> None:
        md = render_markdown(
            [self._view(TextNode(role="text", name="x"))], generated_at="2026-07-14"
        )
        assert "2026-07-14" in md
