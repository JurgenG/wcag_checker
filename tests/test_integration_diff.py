"""Integration test for ``build_report_diff`` on a real consent-pair.

``doccle-reject.zip`` and ``doccle-accept.zip`` are both captures of
``doccle.be``: A is the consent-rejected state (baseline trackers
plus reCAPTCHA + Google Fonts), B is the consent-accepted state
(adds Facebook Pixel, AppNexus, Plausible, Sentry, Adobe Fonts and
their associated tracking cookies).

The diff between them is the canonical use case for the comparison
feature. This file pins the exact deltas — vendor counts, distinct
personal-data fields, cookies, storage — so any regression in the
diff builder surfaces here. Numbers are derived from running the
builder against the frozen bundles; update them only when the
underlying analyser changes and the new numbers have been verified
correct.
"""

from __future__ import annotations

import pytest

from leak_inspector.analysis import analyze_events
from leak_inspector.bundle.reader import BundleReader
from leak_inspector.report.diff import PersonalFieldRef, build_report_diff

from tests.fixtures.bundles import path as bundle_path


def _load(name: str):
    with BundleReader(bundle_path(name)) as b:
        return analyze_events(
            b.manifest, b.events(), cname_chains=b.cname_chains,
        )


@pytest.fixture(scope="module")
def diff():
    """Diff of doccle.be consent-reject (A) vs consent-accept (B)."""
    a = _load("doccle-reject.zip")
    b = _load("doccle-accept.zip")
    return build_report_diff(a, b, label_a="reject", label_b="accept")


# --- bundle compatibility -------------------------------------------------


def test_bundle_mismatch_is_none_when_same_site(diff) -> None:
    """Both bundles target doccle.be — no mismatch warning."""
    assert diff.bundle_mismatch is None


# --- module-level deltas --------------------------------------------------


def test_modules_only_in_accept_are_the_consent_gated_vendors(diff) -> None:
    """Accepting consent unlocks 6 commercial trackers."""
    assert sorted(m.module_id for m in diff.modules_only_in_b) == [
        "adobe_fonts", "appnexus", "facebook_pixel",
        "google_misc", "plausible", "sentry",
    ]


def test_modules_only_in_reject_are_the_baseline_only_vendors(diff) -> None:
    """The reject capture loaded reCAPTCHA + a couple of font CDNs that
    the accept capture didn't (different navigation path / cookie banner)."""
    assert sorted(m.module_id for m in diff.modules_only_in_a) == [
        "google_fonts", "gstatic", "recaptcha",
    ]


# --- personal-data delta --------------------------------------------------


def test_personal_data_counts(diff) -> None:
    pdd = diff.personal_data_delta
    assert pdd.count_a == 11
    assert pdd.count_b == 13


def test_personal_data_fields_only_in_accept(diff) -> None:
    """The exact 4 distinct (vendor, category, key) triples accepting
    unlocks — all visitor-scoped. Property-scoped keys the accept run
    also adds (Adobe Fonts kit/account, Ads conversion label, Pixel ID,
    Sentry DSN key) classify as technical and stay out of this set."""
    assert set(diff.personal_data_delta.only_in_b) == {
        PersonalFieldRef("Google Ads / DoubleClick", "identifier", "auid"),
        PersonalFieldRef("Google Ads / DoubleClick", "identifier", "cid"),
        PersonalFieldRef("Meta (Facebook) Pixel", "identifier", "fbp"),
        PersonalFieldRef("Meta (Facebook) Pixel", "identifier", "hme"),
    }


# --- cookie delta ---------------------------------------------------------


def test_cookies_added_on_accept(diff) -> None:
    """Accept unlocks 6 ad-tech tracking cookies: IDE+test_cookie on
    both DoubleClick hosts, anj+uuid2 on AppNexus."""
    added = {(c.name, c.host) for c in diff.cookies_added}
    assert added == {
        ("IDE", "13662078.fls.doubleclick.net"),
        ("IDE", "googleads.g.doubleclick.net"),
        ("test_cookie", "13662078.fls.doubleclick.net"),
        ("test_cookie", "googleads.g.doubleclick.net"),
        ("anj", "secure.adnxs.com"),
        ("uuid2", "secure.adnxs.com"),
    }


def test_cookies_removed_on_accept(diff) -> None:
    """The reject capture set 8 session-state cookies (AWS load-balancer
    on id.doccle.be, JSESSIONID, reCAPTCHA's _GRECAPTCHA) that the accept
    capture didn't — different navigation, not a privacy-gain. The diff
    surfaces them honestly so the auditor can interpret."""
    removed = {(c.name, c.host) for c in diff.cookies_removed}
    assert removed == {
        ("AWSALBAPP-0", "id.doccle.be"),
        ("AWSALBAPP-1", "id.doccle.be"),
        ("AWSALBAPP-2", "id.doccle.be"),
        ("AWSALBAPP-3", "id.doccle.be"),
        ("JSESSIONID", "id.doccle.be"),
        ("JSESSIONID", "secure.doccle.be"),
        ("deh", "secure.doccle.be"),
        ("_GRECAPTCHA", "www.google.com"),
    }


# --- storage delta --------------------------------------------------------


def test_storage_added_on_accept(diff) -> None:
    """Accept adds 4 storage entries: GCL link-decoration ID, two
    referrer-history slots (Clarity), and _cltk (Clarity user token)."""
    added = {(s.origin, s.kind, s.key) for s in diff.storage_added}
    assert added == {
        ("https://doccle.be", "local", "_gcl_ls"),
        ("https://doccle.be", "local", "lastExternalReferrer"),
        ("https://doccle.be", "local", "lastExternalReferrerTime"),
        ("https://doccle.be", "session", "_cltk"),
    }


def test_storage_removed_on_accept_is_empty(diff) -> None:
    """Accepting consent doesn't remove any storage."""
    assert diff.storage_removed == []


# --- severity-aware headline ----------------------------------------------


def test_headline_includes_personal_data_and_cookie_counts(diff) -> None:
    """The headline names the visitor-side impact, not just the vendor count."""
    assert diff.headline == (
        "'accept' adds 6 new vendors; "
        "4 new distinct personal-data fields; "
        "6 new tracking cookies; "
        "9 vendors with field changes; "
        "3 vendors no longer firing."
    )


# --- bundle-mismatch warning ----------------------------------------------


def test_mismatch_warning_when_diffing_different_sites() -> None:
    """Diffing across sites (e.g. brecht vs cultuurkuur) produces a warning."""
    a = _load("brecht.zip")
    b = _load("cultuurkuur.zip")
    d = build_report_diff(a, b, label_a="brecht", label_b="cultuurkuur")
    assert d.bundle_mismatch is not None
    assert "different sites" in d.bundle_mismatch.lower()
    assert "brecht.be" in d.bundle_mismatch
    assert "cultuurkuur.be" in d.bundle_mismatch


# --- CLI --out mode -------------------------------------------------------


def test_cli_diff_out_writes_three_html_files(tmp_path) -> None:
    """``--out DIR --format html`` produces diff.html + the two side reports
    and the diff HTML embeds relative <a href> links to them."""
    import argparse
    from leak_inspector.cli import _do_diff

    out_dir = tmp_path / "doccle-diff"
    rc = _do_diff(argparse.Namespace(
        bundle_a=bundle_path("doccle-reject.zip"),
        bundle_b=bundle_path("doccle-accept.zip"),
        label_a="reject", label_b="accept",
        format="html", no_color=True,
        out=out_dir, stdout=False,
    ))
    assert rc == 0
    diff_html = (out_dir / "diff.html").read_text(encoding="utf-8")
    assert (out_dir / "reject.report.html").is_file()
    assert (out_dir / "accept.report.html").is_file()
    # The diff embeds relative links to the two side reports.
    assert 'href="reject.report.html"' in diff_html
    assert 'href="accept.report.html"' in diff_html


def test_cli_diff_out_writes_three_markdown_files(tmp_path) -> None:
    import argparse
    from leak_inspector.cli import _do_diff

    out_dir = tmp_path / "doccle-diff-md"
    rc = _do_diff(argparse.Namespace(
        bundle_a=bundle_path("doccle-reject.zip"),
        bundle_b=bundle_path("doccle-accept.zip"),
        label_a="reject", label_b="accept",
        format="markdown", no_color=True,
        out=out_dir, stdout=False,
    ))
    assert rc == 0
    assert (out_dir / "diff.md").is_file()
    assert (out_dir / "reject.report.md").is_file()
    assert (out_dir / "accept.report.md").is_file()
    diff_md = (out_dir / "diff.md").read_text(encoding="utf-8")
    assert "(reject.report.md)" in diff_md
    assert "(accept.report.md)" in diff_md


def test_cli_diff_out_label_with_spaces_is_slugified(tmp_path) -> None:
    """A label like ``"consent rejected"`` slugifies to a safe filename."""
    import argparse
    from leak_inspector.cli import _do_diff

    out_dir = tmp_path / "labels-with-spaces"
    rc = _do_diff(argparse.Namespace(
        bundle_a=bundle_path("doccle-reject.zip"),
        bundle_b=bundle_path("doccle-accept.zip"),
        label_a="consent rejected", label_b="consent accepted",
        format="html", no_color=True,
        out=out_dir, stdout=False,
    ))
    assert rc == 0
    # Spaces become underscores; the original labels still render inside the
    # report text (only the filename is slugified).
    assert (out_dir / "consent_rejected.report.html").is_file()
    assert (out_dir / "consent_accepted.report.html").is_file()


def test_cli_diff_out_json_skips_side_reports(tmp_path) -> None:
    """JSON output is machine-consumed; no side reports are produced."""
    import argparse
    from leak_inspector.cli import _do_diff

    out_dir = tmp_path / "json-only"
    rc = _do_diff(argparse.Namespace(
        bundle_a=bundle_path("doccle-reject.zip"),
        bundle_b=bundle_path("doccle-accept.zip"),
        label_a="A", label_b="B",
        format="json", no_color=True,
        out=out_dir, stdout=False,
    ))
    assert rc == 0
    assert (out_dir / "diff.json").is_file()
    # Exactly one file in the directory.
    assert sorted(p.name for p in out_dir.iterdir()) == ["diff.json"]


# --- auto-derived --out (html / markdown only) ----------------------------


def test_cli_diff_html_auto_derives_directory(tmp_path, monkeypatch) -> None:
    """With format=html and no --out, the CLI derives ``<a>_vs_<b>/`` in CWD."""
    import argparse
    from leak_inspector.cli import _do_diff

    monkeypatch.chdir(tmp_path)
    rc = _do_diff(argparse.Namespace(
        bundle_a=bundle_path("doccle-reject.zip"),
        bundle_b=bundle_path("doccle-accept.zip"),
        label_a="reject", label_b="accept",
        format="html", no_color=True,
        out=None, stdout=False,
    ))
    assert rc == 0
    auto_dir = tmp_path / "doccle-reject_vs_doccle-accept"
    assert auto_dir.is_dir()
    assert (auto_dir / "diff.html").is_file()
    assert (auto_dir / "reject.report.html").is_file()
    assert (auto_dir / "accept.report.html").is_file()


def test_cli_diff_markdown_also_auto_derives(tmp_path, monkeypatch) -> None:
    """Markdown follows the same default as html."""
    import argparse
    from leak_inspector.cli import _do_diff

    monkeypatch.chdir(tmp_path)
    rc = _do_diff(argparse.Namespace(
        bundle_a=bundle_path("doccle-reject.zip"),
        bundle_b=bundle_path("doccle-accept.zip"),
        label_a="A", label_b="B",
        format="markdown", no_color=True,
        out=None, stdout=False,
    ))
    assert rc == 0
    auto_dir = tmp_path / "doccle-reject_vs_doccle-accept"
    assert (auto_dir / "diff.md").is_file()


def test_cli_diff_stdout_flag_opts_out_of_auto_directory(
    tmp_path, monkeypatch, capsys,
) -> None:
    """``--stdout`` skips auto-derivation and writes html to stdout."""
    import argparse
    from leak_inspector.cli import _do_diff

    monkeypatch.chdir(tmp_path)
    rc = _do_diff(argparse.Namespace(
        bundle_a=bundle_path("doccle-reject.zip"),
        bundle_b=bundle_path("doccle-accept.zip"),
        label_a="A", label_b="B",
        format="html", no_color=True,
        out=None, stdout=True,
    ))
    assert rc == 0
    # No auto-directory created.
    assert list(tmp_path.iterdir()) == []
    captured = capsys.readouterr()
    assert "<!doctype html>" in captured.out.lower()


def test_cli_diff_out_and_stdout_are_mutually_exclusive(tmp_path) -> None:
    import argparse
    from leak_inspector.cli import _do_diff

    rc = _do_diff(argparse.Namespace(
        bundle_a=bundle_path("doccle-reject.zip"),
        bundle_b=bundle_path("doccle-accept.zip"),
        label_a="A", label_b="B",
        format="html", no_color=True,
        out=tmp_path / "out", stdout=True,
    ))
    assert rc == 2


def test_cli_diff_text_still_defaults_to_stdout(
    tmp_path, monkeypatch, capsys,
) -> None:
    """Text format is for terminals — auto-out doesn't apply."""
    import argparse
    from leak_inspector.cli import _do_diff

    monkeypatch.chdir(tmp_path)
    rc = _do_diff(argparse.Namespace(
        bundle_a=bundle_path("doccle-reject.zip"),
        bundle_b=bundle_path("doccle-accept.zip"),
        label_a="A", label_b="B",
        format="text", no_color=True,
        out=None, stdout=False,
    ))
    assert rc == 0
    # No auto-directory created.
    assert list(tmp_path.iterdir()) == []
    captured = capsys.readouterr()
    assert "Diff:" in captured.out
