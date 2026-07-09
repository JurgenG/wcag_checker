"""Tests for the ``enrich`` CLI subcommand and the capture-close hook.

The CLI is a thin shell over :func:`enrich_bundle`; these tests drive
the argparse namespace directly (like the other CLI tests) with the
producer's network seams replaced, so nothing here touches the wire.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

import pytest

from leak_inspector import cli as cli_module
from leak_inspector.enrichment import Enrichment

from tests.fixtures.bundles import path as bundle_path


@pytest.fixture
def bundle(tmp_path) -> Path:
    target = tmp_path / "site.zip"
    shutil.copy(bundle_path("nbb.zip"), target)
    return target


def _args(bundle: Path, *, refresh=None) -> argparse.Namespace:
    return argparse.Namespace(bundle=bundle, refresh=refresh)


# --- the enrich subcommand -----------------------------------------------------


def test_enrich_parses_bare_refresh_as_all() -> None:
    args = cli_module._parse_args(["enrich", "some.zip", "--refresh"])
    assert args.command == "enrich"
    assert args.bundle == Path("some.zip")
    assert args.refresh == "all"


def test_enrich_parses_section_refresh() -> None:
    args = cli_module._parse_args(["enrich", "some.zip", "--refresh", "cms-probe"])
    assert args.refresh == "cms-probe"


def test_enrich_omitted_refresh_is_none() -> None:
    args = cli_module._parse_args(["enrich", "some.zip"])
    assert args.refresh is None


def test_enrich_rejects_unknown_section() -> None:
    with pytest.raises(SystemExit):
        cli_module._parse_args(["enrich", "some.zip", "--refresh", "bogus"])


def test_enrich_missing_bundle_is_exit_2(tmp_path, capsys) -> None:
    rc = cli_module._do_enrich(_args(tmp_path / "missing.zip"))
    assert rc == 2
    assert "not found" in capsys.readouterr().err


def test_enrich_invokes_producer_and_reports(bundle, monkeypatch, capsys) -> None:
    def fake_enrich(path, *, refresh=False, sections=None):
        assert Path(path) == bundle
        assert refresh is False
        assert sections is None
        return Enrichment(enriched_at="2026-06-07T14:00:00Z"), True

    monkeypatch.setattr(cli_module, "_enrich_bundle", fake_enrich)
    rc = cli_module._do_enrich(_args(bundle))
    assert rc == 0
    err = capsys.readouterr().err
    assert "enriched" in err.lower()
    assert "2026-06-07T14:00:00Z" in err


def test_enrich_bare_refresh_routes_full(bundle, monkeypatch) -> None:
    def fake_enrich(path, *, refresh=False, sections=None):
        assert refresh is True
        assert sections is None
        return Enrichment(enriched_at="2026-06-07T14:00:00Z"), True

    monkeypatch.setattr(cli_module, "_enrich_bundle", fake_enrich)
    assert cli_module._do_enrich(_args(bundle, refresh="all")) == 0


def test_enrich_section_refresh_routes_selective(bundle, monkeypatch, capsys) -> None:
    def fake_enrich(path, *, refresh=False, sections=None):
        assert refresh is False
        assert sections == frozenset({"cms-probe"})
        return (
            Enrichment(
                enriched_at="2026-06-07T14:00:00Z",
                section_timestamps={"cms-probe": "2026-06-19T09:00:00Z"},
            ),
            True,
        )

    monkeypatch.setattr(cli_module, "_enrich_bundle", fake_enrich)
    rc = cli_module._do_enrich(_args(bundle, refresh="cms-probe"))
    assert rc == 0
    err = capsys.readouterr().err
    assert "cms-probe" in err
    assert "2026-06-19T09:00:00Z" in err


def test_enrich_selective_without_enrichment_is_exit_2(
    bundle, monkeypatch, capsys
) -> None:
    def boom(path, *, refresh=False, sections=None):
        raise ValueError(
            "nothing to refresh selectively — run a full enrich first"
        )

    monkeypatch.setattr(cli_module, "_enrich_bundle", boom)
    rc = cli_module._do_enrich(_args(bundle, refresh="cms-probe"))
    assert rc == 2
    assert "run a full enrich first" in capsys.readouterr().err


def test_enrich_already_enriched_says_so(bundle, monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        cli_module, "_enrich_bundle",
        lambda path, refresh=False, sections=None: (
            Enrichment(enriched_at="2026-06-01T00:00:00Z"), False,
        ),
    )
    rc = cli_module._do_enrich(_args(bundle))
    assert rc == 0
    err = capsys.readouterr().err
    assert "already enriched" in err.lower()
    assert "--refresh" in err


def test_enrich_surfaces_section_errors(bundle, monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        cli_module, "_enrich_bundle",
        lambda path, refresh=False, sections=None: (
            Enrichment(
                enriched_at="2026-06-07T14:00:00Z",
                errors=["DNS posture lookup failed: resolver unreachable"],
            ),
            True,
        ),
    )
    rc = cli_module._do_enrich(_args(bundle))
    assert rc == 0  # partial enrichment is still a written artifact
    assert "resolver unreachable" in capsys.readouterr().err


def test_enrich_hard_failure_is_exit_2(bundle, monkeypatch, capsys) -> None:
    def boom(path, refresh=False, sections=None):
        raise OSError("bundle is corrupt")

    monkeypatch.setattr(cli_module, "_enrich_bundle", boom)
    rc = cli_module._do_enrich(_args(bundle))
    assert rc == 2
    assert "corrupt" in capsys.readouterr().err


# --- the capture-close hook ------------------------------------------------------


def test_capture_hook_soft_fails(bundle, monkeypatch, capsys) -> None:
    """A failed enrichment after capture must never fail the capture —
    the bundle is already on disk."""
    def boom(path, refresh=False, sections=None):
        raise OSError("offline")

    monkeypatch.setattr(cli_module, "_enrich_bundle", boom)
    cli_module._enrich_after_capture(bundle)  # must not raise
    err = capsys.readouterr().err
    assert "enrichment failed" in err.lower()
    assert "leak-inspector enrich" in err  # points at the retrofit command


def test_capture_hook_reports_success(bundle, monkeypatch, capsys) -> None:
    monkeypatch.setattr(
        cli_module, "_enrich_bundle",
        lambda path, refresh=False, sections=None: (
            Enrichment(enriched_at="2026-06-07T14:00:00Z"), True,
        ),
    )
    cli_module._enrich_after_capture(bundle)
    assert "enriched" in capsys.readouterr().err.lower()
