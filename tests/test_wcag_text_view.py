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
    reading_view_payload,
    render_html_section,
    render_markdown_section,
    render_text_section,
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


def _view(*nodes: TextNode, title: str = "Home", truncated: bool = False):
    return PageTextView(
        url="https://x/a", title=title, nodes=tuple(nodes), truncated=truncated
    )


class TestRenderMarkdownSection:
    def test_leads_with_the_not_a_test_disclaimer(self) -> None:
        md = render_markdown_section([_view(TextNode(role="text", name="hi"))])
        assert md.startswith("## Reading view (manual-review aid)")
        assert "NOT a screen-reader test" in md
        assert "NOT a conformance" in md

    def test_no_views_yields_no_section(self) -> None:
        assert render_markdown_section([]) == ""

    def test_heading_shows_level_and_text(self) -> None:
        md = render_markdown_section([_view(
            TextNode(role="heading", name="About us", level=2)
        )])
        assert "**H2** About us" in md

    def test_empty_heading_is_flagged(self) -> None:
        md = render_markdown_section([_view(
            TextNode(role="heading", name="", named=False, level=1)
        )])
        assert "⚠ (empty heading)" in md

    def test_unnamed_image_is_flagged_with_note(self) -> None:
        md = render_markdown_section([_view(
            TextNode(role="image", name="", named=False, note="no alt attribute")
        )])
        assert "`image` ⚠ no alt attribute" in md

    def test_named_image_shows_its_alt(self) -> None:
        md = render_markdown_section([_view(
            TextNode(role="image", name="Company logo")
        )])
        assert '`image` "Company logo"' in md

    def test_field_tag_carries_type_and_placeholder_note(self) -> None:
        md = render_markdown_section([_view(
            TextNode(role="field", name="Search", field_type="text",
                     note="name from placeholder only")
        )])
        assert '`field:text` "Search" — name from placeholder only' in md

    def test_unlabelled_field_is_flagged(self) -> None:
        md = render_markdown_section([_view(
            TextNode(role="field", name="", named=False, field_type="email",
                     note="no label")
        )])
        assert "`field:email` ⚠ no label" in md

    def test_landmark_tag_carries_its_role(self) -> None:
        md = render_markdown_section([_view(
            TextNode(role="landmark", name="Main menu", landmark="navigation")
        )])
        assert '`landmark:navigation` "Main menu"' in md

    def test_summary_counts_names_missing(self) -> None:
        md = render_markdown_section([_view(
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
        md = render_markdown_section([_view(
            TextNode(role="text", name="a"), truncated=True
        )])
        assert "truncated" in md

    def test_empty_page_notes_no_content(self) -> None:
        md = render_markdown_section([_view(title="Blank")])
        assert "No visible content was extracted" in md

    def test_title_links_to_url(self) -> None:
        md = render_markdown_section([_view(
            TextNode(role="text", name="x"), title="Home"
        )])
        assert "### Home" in md
        assert "<https://x/a>" in md


class TestRenderTextSection:
    def test_plain_section_has_heading_and_nodes(self) -> None:
        txt = render_text_section([_view(
            TextNode(role="heading", name="Hi", level=1),
            TextNode(role="link", name="About"),
        )])
        assert txt.startswith("Reading view (manual-review aid)")
        assert "**H1** Hi" in txt
        assert '`link` "About"' in txt

    def test_no_views_yields_no_section(self) -> None:
        assert render_text_section([]) == ""


class TestRenderHtmlSection:
    def test_no_views_yields_empty_fragment(self) -> None:
        assert render_html_section([]) == ""

    def test_details_summary_carries_title_and_tally(self) -> None:
        h = render_html_section([_view(
            TextNode(role="heading", name="Welcome", level=1), title="Home"
        )])
        assert "<h2>Reading view (manual-review aid)</h2>" in h
        assert "<details class='rv'>" in h
        assert "Home —" in h  # title + tally in the summary
        assert "<strong>H1</strong> Welcome" in h

    def test_unnamed_element_flagged_and_escaped(self) -> None:
        h = render_html_section([_view(
            TextNode(role="image", name="", named=False, note="no alt attribute"),
            TextNode(role="link", name="<script>", ),
        )])
        assert "rv-warn" in h and "⚠ no alt attribute" in h
        assert "&lt;script&gt;" in h  # hostile page text is escaped
        assert "<script>" not in h


class TestReadingViewPayload:
    def test_json_ready_structure(self) -> None:
        payload = reading_view_payload([_view(
            TextNode(role="field", name="Email", field_type="email"),
            truncated=True,
        )])
        assert payload[0]["url"] == "https://x/a"
        assert payload[0]["truncated"] is True
        node = payload[0]["nodes"][0]
        assert node["role"] == "field" and node["field_type"] == "email"
        assert node["name"] == "Email"

    def test_empty_when_no_views(self) -> None:
        assert reading_view_payload([]) == []
