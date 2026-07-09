"""The bulk runner accepts --out DIR to redirect the reports folder.

Mirrors `analyze -o` / `diff --out`: captures stay under the dataset
(`<dataset>/captures/` — they're the dataset's artifacts), but the
rendered reports + webp sidecars can land anywhere. Default behavior
(no --out) is unchanged: `<dataset>/reports/`.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_BULK_DIR = Path(__file__).resolve().parent.parent / "bulk-tool"
if str(_BULK_DIR) not in sys.path:
    sys.path.insert(0, str(_BULK_DIR))

import run as bulk_run  # noqa: E402

from leak_inspector import modules  # noqa: E402,F401  (registers detectors)
from leak_inspector.analysis.runner import analyze_events  # noqa: E402
from leak_inspector.bundle.reader import BundleReader  # noqa: E402

from tests.fixtures.bundles import path as bundle_path  # noqa: E402


def _hermetic(zip_path):
    with BundleReader(zip_path) as b:
        return analyze_events(b.manifest, b.events(), cname_chains=b.cname_chains)


@pytest.fixture
def dataset(tmp_path):
    """A minimal dataset: one domain whose capture already exists, so
    --resume renders the report without launching Firefox."""
    ds = tmp_path / "ds"
    captures = ds / "captures"
    captures.mkdir(parents=True)
    # NB: real domains.csv files carry no header — a header line would
    # be read as a URL (and the capture path would launch Firefox).
    (ds / "domains.csv").write_text("https://www.cultuurkuur.be\n")
    import shutil

    slug = bulk_run._slug_for_url("https://www.cultuurkuur.be")
    shutil.copy(bundle_path("cultuurkuur.zip"), captures / f"{slug}.zip")
    return ds


def test_out_dir_redirects_reports_and_sidecars(dataset, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(bulk_run, "analyze_bundle", _hermetic)
    out = tmp_path / "elsewhere"
    rc = bulk_run.main([str(dataset), "--resume", "--out", str(out)])
    assert rc == 0
    names = {p.name for p in out.iterdir()}
    assert any(n.endswith(".report.html") for n in names)
    assert any(n.endswith(".post-load.webp") for n in names)
    # The dataset overview follows the reports — its per-site links
    # are relative, so it must live in the same directory.
    assert "index.html" in names
    # Nothing landed in the default location.
    assert not (dataset / "reports").exists() or not any(
        (dataset / "reports").iterdir()
    )


def test_default_reports_dir_unchanged(dataset, monkeypatch) -> None:
    monkeypatch.setattr(bulk_run, "analyze_bundle", _hermetic)
    rc = bulk_run.main([str(dataset), "--resume"])
    assert rc == 0
    names = {p.name for p in (dataset / "reports").iterdir()}
    assert any(n.endswith(".report.html") for n in names)
    assert any(n.endswith(".post-load.webp") for n in names)
