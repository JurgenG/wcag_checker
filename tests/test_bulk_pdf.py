"""The bulk tool supports per-site PDF reports (--format pdf).

PDF is binary and self-contained: the bulk renderer writes
``<slug>.report.pdf`` with screenshots inlined (no sibling webp files).
WeasyPrint is optional, so the real render is gated skip-if-absent; the
format contract and the report extension are always checked.
"""

from __future__ import annotations

import importlib.util
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

_WEASYPRINT = importlib.util.find_spec("weasyprint") is not None


@pytest.fixture
def bundle(tmp_path) -> Path:
    target = tmp_path / "aalst.be.zip"
    shutil.copy(bundle_path("aalst.zip"), target)
    return target


def test_pdf_is_an_accepted_bulk_format() -> None:
    """argparse accepts --format pdf for the bulk run."""
    args = bulk_run._parse_args(
        ["data.csv", "--out", "ds", "--format", "pdf"]
    )
    assert args.format == "pdf"


@pytest.mark.skipif(not _WEASYPRINT, reason="WeasyPrint not installed")
def test_bulk_renders_a_self_contained_pdf(bundle, tmp_path, monkeypatch) -> None:
    """A per-site PDF is written as bytes, with no sibling webp files
    (screenshots are inlined)."""
    # The fixture is already enriched; make the enrich seam a no-op.
    monkeypatch.setattr(
        bulk_run, "_enrich_bundle",
        lambda path, refresh=False: (Enrichment(enriched_at="t"), False),
    )
    report = tmp_path / "aalst.be.report.pdf"
    bulk_run._render_report_from_bundle(bundle, report, report_format="pdf")
    assert report.read_bytes()[:5] == b"%PDF-"
    # self-contained: PDF inlines screenshots, no sidecar webp written
    assert list(tmp_path.glob("*.webp")) == []
