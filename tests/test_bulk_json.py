"""The bulk tool supports per-site JSON reports (--format json).

JSON is data-only and self-contained: the bulk renderer writes
``<slug>.report.json`` (the same structured payload as
``analyze --format json``) with no sibling webp files — screenshots are
a presentation concern the JSON document does not carry. The
name-column ``display_name`` still flows into the document's manifest.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

import pytest

_BULK_DIR = Path(__file__).resolve().parent.parent / "bulk-tool"
if str(_BULK_DIR) not in sys.path:
    sys.path.insert(0, str(_BULK_DIR))

import run as bulk_run  # noqa: E402

from leak_inspector.enrichment import Enrichment  # noqa: E402
from tests.fixtures.bundles import path as bundle_path  # noqa: E402


@pytest.fixture
def bundle(tmp_path) -> Path:
    target = tmp_path / "aalst.be.zip"
    shutil.copy(bundle_path("aalst.zip"), target)
    return target


@pytest.fixture(autouse=True)
def _no_network_enrich(monkeypatch) -> None:
    # The fixture is already enriched; make the enrich seam a no-op.
    monkeypatch.setattr(
        bulk_run, "_enrich_bundle",
        lambda path, refresh=False: (Enrichment(enriched_at="t"), False),
    )


def test_json_is_an_accepted_bulk_format() -> None:
    """argparse accepts --format json for the bulk run."""
    args = bulk_run._parse_args(
        ["data.csv", "--out", "ds", "--format", "json"]
    )
    assert args.format == "json"


def test_bulk_json_extension_is_json() -> None:
    """The per-site report extension for json is ``.json``."""
    assert bulk_run._report_ext_for("json") == "json"


def test_bulk_json_carries_the_full_document(bundle, tmp_path) -> None:
    """A per-site JSON carries the full report document (score +
    executive summary + trackers)."""
    report = tmp_path / "aalst.be.report.json"
    bulk_run._render_report_from_bundle(bundle, report, report_format="json")

    payload = json.loads(report.read_text(encoding="utf-8"))
    assert "score" in payload
    assert "executive_summary" in payload
    assert "trackers" in payload


def test_bulk_json_writes_screenshots_beside_the_report(bundle, tmp_path) -> None:
    """Screenshots are written next to the report (same sidecar convention
    as HTML/Markdown) and referenced by relative filename in the JSON."""
    report = tmp_path / "aalst.be.report.json"
    bulk_run._render_report_from_bundle(bundle, report, report_format="json")

    payload = json.loads(report.read_text(encoding="utf-8"))
    post_load = payload["screenshots"]["post_load"]
    assert post_load.endswith(".webp") and "/" not in post_load
    assert payload["screenshots"]["extra"] == []
    # the referenced file exists on disk, relative to the report
    assert (report.parent / post_load).is_file()


def test_bulk_json_honours_display_name(bundle, tmp_path) -> None:
    """The name-column display name reaches the JSON document manifest."""
    report = tmp_path / "aalst.be.report.json"
    bulk_run._render_report_from_bundle(
        bundle, report, report_format="json", display_name="Stad Aalst",
    )
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert payload["manifest"]["display_name"] == "Stad Aalst"
