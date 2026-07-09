"""The bulk runner enriches bundles before analyzing (Phase 4).

``analyze_bundle`` is strictly offline since Phase 3, so the bulk
pipeline must guarantee an enrichment exists: fresh captures enrich
right after the recorder closes, and ``--resume`` re-renders retrofit
un-enriched bundles on touch. Both go through the single seam at the
top of ``_render_report_from_bundle``. Soft-fail: a dead resolver
must not cost the report — it just renders without posture.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

_BULK_DIR = Path(__file__).resolve().parent.parent / "bulk-tool"
if str(_BULK_DIR) not in sys.path:
    sys.path.insert(0, str(_BULK_DIR))

import run as bulk_run  # noqa: E402

from leak_inspector.enrichment import Enrichment  # noqa: E402
from leak_inspector.enrichment.producer import (  # noqa: E402
    read_enrichment,
    strip_enrichment,
    write_enrichment,
)

from tests.fixtures.bundles import path as bundle_path  # noqa: E402


@pytest.fixture
def bare_bundle(tmp_path) -> Path:
    target = tmp_path / "site.zip"
    shutil.copy(bundle_path("cultuurkuur.zip"), target)
    strip_enrichment(target)
    return target


def test_render_enriches_unenriched_bundle(bare_bundle, tmp_path, monkeypatch) -> None:
    calls: list[Path] = []

    def fake_enrich(path, *, refresh=False):
        calls.append(Path(path))
        return Enrichment(enriched_at="2026-06-07T17:00:00Z"), True

    monkeypatch.setattr(bulk_run, "_enrich_bundle", fake_enrich)
    report = tmp_path / "site.report.html"
    bulk_run._render_report_from_bundle(bare_bundle, report)
    assert calls == [bare_bundle]
    assert report.is_file()


def test_render_skips_already_enriched_bundle(bare_bundle, tmp_path) -> None:
    """An enriched bundle is a producer-level no-op — no network seam
    needed at all (idempotence lives in enrich_bundle)."""
    write_enrichment(bare_bundle, Enrichment(enriched_at="2026-06-01T00:00:00Z"))
    report = tmp_path / "site.report.html"
    bulk_run._render_report_from_bundle(bare_bundle, report)
    # Artifact untouched (not refreshed).
    assert read_enrichment(bare_bundle).enriched_at == "2026-06-01T00:00:00Z"
    assert report.is_file()


def test_render_soft_fails_when_enrichment_dies(
    bare_bundle, tmp_path, monkeypatch, capsys
) -> None:
    """Enrichment failure costs the posture, never the report."""
    def boom(path, *, refresh=False):
        raise OSError("resolver unreachable")

    monkeypatch.setattr(bulk_run, "_enrich_bundle", boom)
    report = tmp_path / "site.report.html"
    bulk_run._render_report_from_bundle(bare_bundle, report)
    assert report.is_file()
    assert "enrichment failed" in capsys.readouterr().err.lower()
