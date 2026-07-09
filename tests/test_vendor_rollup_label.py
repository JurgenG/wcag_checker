"""Tests for the opt-in ``rollup_label`` mechanism on tracker modules.

Some deployment patterns (e.g. Google Tag First-Party Mode proxy)
represent a deliberate operator install distinct from the parent
vendor's other products and warrant their own bucket in the
executive-summary vendor rollup. The ``rollup_label`` ClassVar lets a
module opt into a separate bucket without misrepresenting its
``vendor`` (controller of record) metadata.

The default behaviour (``rollup_label`` empty) is unchanged — vendor
strings with trailing ``" (...)"`` disambiguation still collapse,
so e.g. ``"X Corp (formerly Twitter)"`` keeps grouping under ``"X Corp"``.
"""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import TrackerModule
from leak_inspector.report.builder import _vendor_label


class _StubModule:
    """Minimal duck-typed module for ``_vendor_label`` tests."""

    def __init__(self, *, vendor: str = "", rollup_label: str = "") -> None:
        self.vendor = vendor
        self.rollup_label = rollup_label


# --- _vendor_label honors rollup_label when set ----------------------------


def test_rollup_label_overrides_vendor_when_set() -> None:
    """A non-empty ``rollup_label`` wins over vendor for bucketing."""
    meta = _StubModule(
        vendor="Google LLC",
        rollup_label="Google LLC (Tag First-Party Mode proxy)",
    )
    assert _vendor_label(meta, fallback="anything") == \
        "Google LLC (Tag First-Party Mode proxy)"


def test_empty_rollup_label_falls_back_to_vendor() -> None:
    """Without rollup_label, vendor is used (with parenthetical strip)."""
    meta = _StubModule(vendor="Google LLC", rollup_label="")
    assert _vendor_label(meta, fallback="anything") == "Google LLC"


def test_vendor_with_disambiguation_still_strips_when_no_rollup_label() -> None:
    """Pre-existing behaviour: ``"X (formerly Y)"`` collapses to ``"X"``."""
    meta = _StubModule(vendor="X Corp (formerly Twitter)", rollup_label="")
    assert _vendor_label(meta, fallback="anything") == "X Corp"


def test_no_meta_returns_fallback() -> None:
    assert _vendor_label(None, fallback="My Module") == "My Module"


# --- TrackerModule ClassVar default ----------------------------------------


def test_tracker_module_has_empty_rollup_label_by_default() -> None:
    """The opt-in attribute defaults to empty so existing modules are unaffected."""

    class M(TrackerModule):
        module_id = "_test_default"
        module_name = "test"
        vendor = "Test"

    assert M.rollup_label == ""


# --- FP-Mode module declares the separate bucket ---------------------------


def test_fp_mode_module_declares_separate_rollup_bucket() -> None:
    """Google FP-Mode opts out of the generic ``Google LLC`` bucket."""
    from leak_inspector.modules.google_first_party_mode import (
        GoogleFirstPartyModeModule,
    )
    assert GoogleFirstPartyModeModule.rollup_label
    assert "First-Party Mode" in GoogleFirstPartyModeModule.rollup_label
    # Vendor of record is still Google LLC (jurisdiction / sovereignty unchanged).
    assert GoogleFirstPartyModeModule.vendor == "Google LLC"


# --- End-to-end: FP-Mode gets its own row on the real bundle ---------------


def test_fp_mode_appears_as_separate_vendor_row_on_real_bundle() -> None:
    """On the sokken-nl-max capture, FP-Mode rolls up next to Google LLC, not into it.

    Before this change, the executive-summary rollup bucketed FP-Mode
    proxy traffic under ``Google LLC`` together with GA4 and Google
    Ads — hiding the deliberate-operator-install signal. After: FP-Mode
    gets its own labelled row.
    """
    from pathlib import Path
    bundle_path = Path(__file__).resolve().parents[1] / "captures" / "sokken-nl-max.zip"
    if not bundle_path.exists():
        pytest.skip("working-dataset bundle not present in this checkout")
    from leak_inspector.analysis import analyze_events
    from leak_inspector.bundle.reader import BundleReader
    from leak_inspector.report.builder import build_report_document
    with BundleReader(bundle_path) as b:
        analysis = analyze_events(b.manifest, b.events(), cname_chains=b.cname_chains)
    doc = build_report_document(analysis)

    rollup_labels = [r.vendor_label for r in doc.executive_summary.high_impact_by_vendor]
    assert "Google LLC" in rollup_labels, "regular Google products lost their bucket"
    fp_mode_buckets = [
        label for label in rollup_labels if "First-Party Mode" in label
    ]
    assert fp_mode_buckets, (
        f"FP-Mode bucket missing from rollup: {rollup_labels}"
    )

    # And the FP-Mode bucket lists only the FP-Mode module, not GA4 / Google Ads.
    fp_mode_rollup = next(
        r for r in doc.executive_summary.high_impact_by_vendor
        if "First-Party Mode" in r.vendor_label
    )
    module_names = [m.name for m in fp_mode_rollup.modules]
    assert module_names == ["Google Tag (First-Party Mode proxy)"], module_names