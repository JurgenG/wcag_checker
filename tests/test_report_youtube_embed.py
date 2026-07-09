"""The YouTube-embed cookie finding (data-level).

A plain ``www.youtube.com/embed`` sets persistent tracking cookies on
page load, which hard-caps the privacy score. The fix is one step:
the privacy-enhanced ``youtube-nocookie.com`` embed (no cookies until
play), or a European / decentralised host. The report surfaces this
as a HIGH finding so operators see the concrete remedy. Pinned against
``cultuurkuur.zip``, which embeds YouTube and gets the four cookies.
"""

from __future__ import annotations

from leak_inspector import modules  # noqa: F401  (registers detectors)
from leak_inspector.analysis.runner import analyze_events
from leak_inspector.bundle.reader import BundleReader
from leak_inspector.report.builder import build_report_document

from tests.fixtures.bundles import path as bundle_path


def _document(name: str):
    with BundleReader(bundle_path(name)) as b:
        analysis = analyze_events(
            b.manifest, b.events(), cname_chains=b.cname_chains,
        )
    return build_report_document(analysis)


def _finding(doc, kind):
    return next(
        (f for f in doc.executive_summary.findings if f.kind == kind), None
    )


def test_youtube_embed_finding_present_and_high() -> None:
    doc = _document("cultuurkuur.zip")
    f = _finding(doc, "youtube_embed_cookies")
    assert f is not None
    assert f.severity == "high"
    assert "4" in f.headline  # the four persistent cookies


def test_youtube_embed_finding_names_the_remedies() -> None:
    doc = _document("cultuurkuur.zip")
    f = _finding(doc, "youtube_embed_cookies")
    text = (f.detail + " " + f.action).lower()
    assert "youtube-nocookie.com" in text
    assert "peertube" in text


def test_no_youtube_embed_finding_without_youtube_cookies() -> None:
    """doccle-reject sets persistent cookies, but not from a YouTube
    embed → no youtube-specific finding."""
    doc = _document("doccle-reject.zip")
    assert _finding(doc, "youtube_embed_cookies") is None
