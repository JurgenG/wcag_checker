"""CLI contract for ``analyze --format pdf``.

PDF is binary, so the CLI requires ``--out FILE`` and writes bytes.
These tests cover the argument contract and the graceful behaviour when
WeasyPrint is absent — without requiring WeasyPrint to be installed.
The end-to-end render is covered (skip-if-absent) in test_report_pdf.py.
"""

from __future__ import annotations

import importlib.util

import pytest

from leak_inspector import cli
from tests.fixtures.bundles import path as bundle_path

_WEASYPRINT = importlib.util.find_spec("weasyprint") is not None


def test_pdf_is_an_accepted_format() -> None:
    """argparse accepts --format pdf (no SystemExit on parse)."""
    parser = cli._build_parser()
    args = parser.parse_args(
        ["analyze", str(bundle_path("aalst.zip")), "--format", "pdf",
         "--out", "x.pdf"]
    )
    assert args.format == "pdf"


def test_pdf_without_out_errors(capsys) -> None:
    """PDF to stdout is refused with a clear message and non-zero exit."""
    rc = cli.main(["analyze", str(bundle_path("aalst.zip")), "--format", "pdf"])
    assert rc == 2
    assert "requires --out" in capsys.readouterr().err


@pytest.mark.skipif(_WEASYPRINT, reason="WeasyPrint IS installed")
def test_pdf_without_weasyprint_errors_cleanly(tmp_path, capsys) -> None:
    """Missing WeasyPrint surfaces an install-pointing error, not a
    traceback, and exits non-zero."""
    out = tmp_path / "report.pdf"
    rc = cli.main([
        "analyze", str(bundle_path("aalst.zip")),
        "--format", "pdf", "--out", str(out),
    ])
    assert rc == 2
    err = capsys.readouterr().err.lower()
    assert "weasyprint" in err and "pip" in err
    assert not out.exists()


@pytest.mark.skipif(not _WEASYPRINT, reason="WeasyPrint not installed")
def test_pdf_written_when_weasyprint_present(tmp_path) -> None:
    out = tmp_path / "report.pdf"
    rc = cli.main([
        "analyze", str(bundle_path("aalst.zip")),
        "--format", "pdf", "--out", str(out),
    ])
    assert rc == 0
    assert out.read_bytes()[:5] == b"%PDF-"
