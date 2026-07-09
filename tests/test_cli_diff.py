"""Tests for the ``diff`` subcommand of the leak-inspector CLI.

Argparse contract: ``python -m leak_inspector diff A B [--label-a x]
[--label-b y] [--format text|json|html|markdown] [--no-color]``.

The CLI dispatches to :mod:`leak_inspector.report.diff_renderers`; we
inject test bundles by stubbing ``analyze_bundle`` so no real capture
is needed.
"""

from __future__ import annotations

import argparse
import io
from contextlib import redirect_stdout
from pathlib import Path

from leak_inspector.analysis.runner import Analysis
from leak_inspector.bundle.manifest import Manifest
from leak_inspector.events import RequestEvent, TYPE_REQUEST
from leak_inspector.modules.base import (
    CAT_IDENTIFIER,
    Hit,
    IMPACT_HIGH,
    ParamInfo,
)
from leak_inspector import cli


def _manifest(target: str = "https://example.be/") -> Manifest:
    return Manifest(
        bundle_schema=1, tool="leak_inspector", tool_version="0.1.0",
        session_id="s", started_at="t1", ended_at="t2",
        target_url=target, base_domain="example.be",
        browser={}, profile="p", landing_url=target,
    )


def _analysis(*, with_tracker: bool = False) -> Analysis:
    a = Analysis(manifest=_manifest())
    if with_tracker:
        a.hits.append(Hit(
            module_id="ga4", module_name="GA4",
            url="https://www.google-analytics.com/g/collect",
            host="www.google-analytics.com",
            method="POST", response_status=200, started_at="t",
            params=[ParamInfo(
                key="cid", value="v", category=CAT_IDENTIFIER, meaning="",
                privacy_impact=IMPACT_HIGH, event_index=1,
            )],
            events=[1],
        ))
    a.untracked_requests.append(RequestEvent(
        event_id=99, timestamp="t", type=TYPE_REQUEST, context_id=None,
        payload={}, method="GET", url="https://example.be/",
        host="example.be", headers={}, request_body=None, initiator=None,
        response_status=200, response_mime=None, response_headers={},
    ))
    return a


def _install_fake_analyze_bundle(monkeypatch, *, mapping: dict[Path, Analysis]):
    """Make ``cli.analyze_bundle`` return the given Analysis per path."""
    from leak_inspector import analysis as analysis_mod

    def fake(path):
        return mapping[Path(path)]

    monkeypatch.setattr(analysis_mod, "analyze_bundle", fake)
    # The CLI imports analyze_bundle inside the function — monkeypatch
    # the source module so any subsequent import sees the fake.


# --- argparse contract -----------------------------------------------------


def test_parse_args_accepts_diff_subcommand(tmp_path) -> None:
    a = tmp_path / "a.zip"; a.write_bytes(b"")
    b = tmp_path / "b.zip"; b.write_bytes(b"")
    ns = cli._parse_args(["diff", str(a), str(b)])
    assert ns.command == "diff"
    assert ns.format == "text"  # default
    assert ns.label_a == "A"
    assert ns.label_b == "B"


def test_parse_args_accepts_label_flags(tmp_path) -> None:
    a = tmp_path / "a.zip"; a.write_bytes(b"")
    b = tmp_path / "b.zip"; b.write_bytes(b"")
    ns = cli._parse_args([
        "diff", str(a), str(b),
        "--label-a", "reject",
        "--label-b", "accept",
        "--format", "html",
    ])
    assert ns.label_a == "reject"
    assert ns.label_b == "accept"
    assert ns.format == "html"


def test_parse_args_rejects_unknown_format(tmp_path) -> None:
    a = tmp_path / "a.zip"; a.write_bytes(b"")
    b = tmp_path / "b.zip"; b.write_bytes(b"")
    try:
        cli._parse_args(["diff", str(a), str(b), "--format", "pdf"])
    except SystemExit as exc:
        assert exc.code == 2
    else:
        raise AssertionError("argparse should reject unknown --format value")


# --- dispatch / output format ---------------------------------------------


def test_diff_command_emits_json_when_format_json(tmp_path, monkeypatch) -> None:
    a_path = tmp_path / "a.zip"; a_path.write_bytes(b"")
    b_path = tmp_path / "b.zip"; b_path.write_bytes(b"")
    _install_fake_analyze_bundle(monkeypatch, mapping={
        a_path: _analysis(with_tracker=False),
        b_path: _analysis(with_tracker=True),
    })
    ns = cli._parse_args([
        "diff", str(a_path), str(b_path),
        "--format", "json",
        "--label-a", "reject", "--label-b", "accept",
    ])
    out = io.StringIO()
    with redirect_stdout(out):
        rc = cli._do_diff(ns)
    assert rc == 0
    payload = out.getvalue()
    assert '"label_a"' in payload and '"reject"' in payload
    assert '"label_b"' in payload and '"accept"' in payload


def test_diff_command_emits_html_when_format_html(tmp_path, monkeypatch) -> None:
    a_path = tmp_path / "a.zip"; a_path.write_bytes(b"")
    b_path = tmp_path / "b.zip"; b_path.write_bytes(b"")
    _install_fake_analyze_bundle(monkeypatch, mapping={
        a_path: _analysis(),
        b_path: _analysis(with_tracker=True),
    })
    ns = cli._parse_args([
        "diff", str(a_path), str(b_path), "--format", "html", "--stdout",
    ])
    out = io.StringIO()
    with redirect_stdout(out):
        rc = cli._do_diff(ns)
    assert rc == 0
    payload = out.getvalue()
    assert "<title>" in payload and "BeLibre" in payload
    assert "<body>" in payload


def test_diff_command_emits_markdown_when_format_markdown(tmp_path, monkeypatch) -> None:
    a_path = tmp_path / "a.zip"; a_path.write_bytes(b"")
    b_path = tmp_path / "b.zip"; b_path.write_bytes(b"")
    _install_fake_analyze_bundle(monkeypatch, mapping={
        a_path: _analysis(),
        b_path: _analysis(with_tracker=True),
    })
    ns = cli._parse_args([
        "diff", str(a_path), str(b_path), "--format", "markdown", "--stdout",
    ])
    out = io.StringIO()
    with redirect_stdout(out):
        rc = cli._do_diff(ns)
    assert rc == 0
    payload = out.getvalue()
    assert "## About this report" in payload


def test_diff_command_default_is_text(tmp_path, monkeypatch) -> None:
    a_path = tmp_path / "a.zip"; a_path.write_bytes(b"")
    b_path = tmp_path / "b.zip"; b_path.write_bytes(b"")
    _install_fake_analyze_bundle(monkeypatch, mapping={
        a_path: _analysis(),
        b_path: _analysis(with_tracker=True),
    })
    ns = cli._parse_args(["diff", str(a_path), str(b_path), "--no-color"])
    out = io.StringIO()
    with redirect_stdout(out):
        rc = cli._do_diff(ns)
    assert rc == 0
    payload = out.getvalue()
    # No ANSI escapes when --no-color is set.
    assert "\x1b[" not in payload
    assert "BeLibre Automatic Leak Inspector" in payload


# --- missing-file handling -------------------------------------------------


def test_diff_command_exits_nonzero_when_bundle_a_missing(tmp_path) -> None:
    missing = tmp_path / "nope.zip"
    other = tmp_path / "other.zip"; other.write_bytes(b"")
    ns = cli._parse_args(["diff", str(missing), str(other)])
    rc = cli._do_diff(ns)
    assert rc == 2


def test_diff_command_exits_nonzero_when_bundle_b_missing(tmp_path) -> None:
    a = tmp_path / "a.zip"; a.write_bytes(b"")
    missing = tmp_path / "nope.zip"
    ns = cli._parse_args(["diff", str(a), str(missing)])
    rc = cli._do_diff(ns)
    assert rc == 2
