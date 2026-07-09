"""Tests for item 3 of the verdict layer — Finding.kind + owner/effort.

Adds two small surfaces:

* :class:`Finding` gains a ``kind: str`` field (additive; default empty
  so untouched callers compile). At known emit sites the builder sets
  a stable kind slug (e.g. ``"dmarc_p_none"``).
* A flat ``ACTION_METADATA`` map keyed by kind returns ``(owner,
  effort)``. Unmapped kinds (and the default empty string) return
  ``None`` and the renderer leaves the finding untouched.

Per the spec, ``google_fonts_leak`` is NOT seeded — there is no
google-fonts Finding in the builder today (Google Fonts is detected
as a tracker module, not folded into the executive-summary findings).
``dmarc_p_none`` is the only seeded kind in v1.
"""

from __future__ import annotations

from leak_inspector.report.document import Finding
from leak_inspector.report.verdict_action_metadata import (
    ACTION_METADATA,
    metadata_for,
)


# --- Finding.kind: additive, backwards-compatible -------------------------


def test_finding_default_kind_is_empty_string() -> None:
    """Existing callers construct Finding without ``kind`` — must still work."""
    f = Finding(
        severity="medium", badge="🟡",
        headline="X", detail="d", action="a",
    )
    assert f.kind == ""


def test_finding_accepts_explicit_kind() -> None:
    f = Finding(
        severity="medium", badge="🟡",
        headline="X", detail="d", action="a",
        kind="dmarc_p_none",
    )
    assert f.kind == "dmarc_p_none"


# --- metadata lookup ------------------------------------------------------


def test_dmarc_p_none_is_seeded() -> None:
    """The only seed in v1: mail-admin owner, low-medium effort."""
    m = metadata_for("dmarc_p_none")
    assert m is not None
    assert m.owner == "mail admin"
    assert m.effort == "low-medium"


def test_unmapped_kind_returns_none() -> None:
    """Unknown kinds return None so the renderer can fall back to the
    unchanged finding text."""
    assert metadata_for("never_a_kind") is None


def test_empty_kind_returns_none() -> None:
    """Default Finding.kind="" must not accidentally hit a seed."""
    assert metadata_for("") is None


def test_google_fonts_leak_is_not_seeded() -> None:
    """Per the spec: seed only finding kinds that exist in Analysis today.
    google_fonts_leak is NOT a Finding in the builder; not seeded."""
    assert metadata_for("google_fonts_leak") is None
    assert "google_fonts_leak" not in ACTION_METADATA


def test_action_metadata_seed_is_complete() -> None:
    """Exactly the one kind we seeded."""
    assert set(ACTION_METADATA.keys()) == {"dmarc_p_none"}


# --- effort vocabulary -----------------------------------------------------


def test_effort_uses_canonical_strings() -> None:
    """Effort values are constrained to a small fixed vocabulary."""
    for m in ACTION_METADATA.values():
        assert m.effort in {"low", "low-medium", "medium", "high"}
