"""An optional per-report ``display_name`` overrides the title host label.

The bulk runner can read a ``name`` column from ``domains.csv`` and pass
it through the report API so a per-site report titles itself by the
site's name (e.g. a school's name) rather than its bare hostname. The
override flows through ``title_host_label``, so every format (HTML,
Markdown, text, PDF cover) picks it up from one place. When no name is
given, behaviour is unchanged (the report titles itself by host).
"""

from __future__ import annotations

from leak_inspector import modules  # noqa: F401  (registers detectors)
from leak_inspector.analysis.runner import analyze_bundle
from leak_inspector.report._branding import title_host_label
from leak_inspector.report.builder import build_report_document
from leak_inspector.report.document import ManifestView
from leak_inspector.report.html import write_html_report
from tests.fixtures.bundles import path as bundle_path


def _manifest(**over) -> ManifestView:
    base = dict(
        target_url="https://www.bsdekleurdoos.be",
        landing_url="", base_domain="bsdekleurdoos.be", session_id="s",
        started_at="2026-06-03T10:00:00Z", ended_at="2026-06-03T10:01:00Z",
        profile="default", browser_name="Firefox", browser_version="128.0",
    )
    base.update(over)
    return ManifestView(**base)


def test_title_falls_back_to_host_without_a_name() -> None:
    """No display_name → the existing host-based label."""
    assert title_host_label(_manifest()) == "www.bsdekleurdoos.be"


def test_display_name_overrides_the_host_label() -> None:
    """A display_name is used verbatim as the title label."""
    m = _manifest(display_name="GO! Basisschool De Kleurdoos")
    assert title_host_label(m) == "GO! Basisschool De Kleurdoos"


def test_build_report_document_threads_display_name() -> None:
    """build_report_document stamps the name onto the manifest view."""
    analysis = analyze_bundle(bundle_path("aalst.zip"))
    doc = build_report_document(analysis, display_name="City of Aalst")
    assert doc.manifest.display_name == "City of Aalst"
    assert title_host_label(doc.manifest) == "City of Aalst"


def test_html_report_titles_itself_by_display_name() -> None:
    """The rendered HTML report carries the name in its title."""
    analysis = analyze_bundle(bundle_path("aalst.zip"))
    html = write_html_report(analysis, display_name="City of Aalst")
    assert "City of Aalst" in html
