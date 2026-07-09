"""Tests for the hard-EOL judgment of detected CMS versions.

The judgment is intentionally conservative: only versions whose
end-of-life date is documented and definitively in the past trigger
``is_eol=True``. "One major behind current" is not a judgment we make
— per CLAUDE.md no speculation.
"""

from __future__ import annotations

from datetime import date

from leak_inspector.cms import CMSFingerprint
from leak_inspector.cms.eol import (
    apply_eol_judgment,
    is_eol_past,
)


# ``today`` lets us test deterministically. In production
# ``apply_eol_judgment`` reads the current date.
TODAY = date(2026, 5, 30)


# --- Drupal ---------------------------------------------------------------


def test_drupal_7_is_eol() -> None:
    """Drupal 7 EOL date: 2025-01-05 (Drupal Association announcement)."""
    assert is_eol_past("Drupal", "7", today=TODAY) is True


def test_drupal_8_is_eol() -> None:
    """Drupal 8 EOL: 2021-11-02."""
    assert is_eol_past("Drupal", "8", today=TODAY) is True


def test_drupal_9_is_eol() -> None:
    """Drupal 9 EOL: 2023-11-01."""
    assert is_eol_past("Drupal", "9", today=TODAY) is True


def test_drupal_10_is_not_eol() -> None:
    """Drupal 10 is still supported as of TODAY."""
    assert is_eol_past("Drupal", "10", today=TODAY) is False


def test_drupal_unknown_version_is_not_judged_eol() -> None:
    """We refuse to judge versions we don't have a documented EOL for."""
    assert is_eol_past("Drupal", None, today=TODAY) is False
    assert is_eol_past("Drupal", "99", today=TODAY) is False


# --- Joomla ---------------------------------------------------------------


def test_joomla_3_is_eol() -> None:
    """Joomla 3 EOL: 2023-08-17."""
    assert is_eol_past("Joomla", "3.10.12", today=TODAY) is True
    assert is_eol_past("Joomla", "3", today=TODAY) is True


def test_joomla_4_is_not_eol_in_2026() -> None:
    """Joomla 4 EOL: 2025-10-17. Already past on TODAY."""
    # Per Joomla policy, J4 went EOL 2025-10-17.
    assert is_eol_past("Joomla", "4.4", today=TODAY) is True


def test_joomla_5_is_not_eol() -> None:
    assert is_eol_past("Joomla", "5.1", today=TODAY) is False


# --- Magento --------------------------------------------------------------


def test_magento_1_is_eol() -> None:
    """Magento 1 EOL: 2020-06-30 (Adobe-confirmed)."""
    assert is_eol_past("Magento", "1.9", today=TODAY) is True


def test_magento_2_is_not_judged_eol() -> None:
    """Magento 2 is current; no judgment."""
    assert is_eol_past("Magento", "2.4", today=TODAY) is False


# --- WordPress: skipped intentionally -------------------------------------


def test_wordpress_is_not_judged_eol() -> None:
    """WordPress's security-backport policy makes single-version EOL judgments
    unreliable; we deliberately don't ship a WP EOL claim."""
    assert is_eol_past("WordPress", "4.6", today=TODAY) is False
    assert is_eol_past("WordPress", "6.5", today=TODAY) is False


# --- apply_eol_judgment: mutation contract --------------------------------


def test_apply_eol_judgment_flags_drupal_7_as_eol() -> None:
    fp = CMSFingerprint(
        name="Drupal", version="7", confidence="certain", evidence="…",
    )
    out = apply_eol_judgment(fp, today=TODAY)
    assert out.is_eol is True
    assert "Drupal 7" in out.eol_note
    assert "2025-01-05" in out.eol_note


def test_apply_eol_judgment_leaves_supported_versions_alone() -> None:
    fp = CMSFingerprint(
        name="Drupal", version="10", confidence="certain", evidence="…",
    )
    out = apply_eol_judgment(fp, today=TODAY)
    assert out.is_eol is False
    assert out.eol_note == ""


def test_apply_eol_judgment_handles_unknown_platform_safely() -> None:
    """A platform we have no EOL data for stays untouched."""
    fp = CMSFingerprint(
        name="Shopify", version=None, confidence="certain", evidence="…",
    )
    out = apply_eol_judgment(fp, today=TODAY)
    assert out.is_eol is False
    assert out.eol_note == ""


def test_apply_eol_judgment_handles_none_input() -> None:
    """No fingerprint detected → judgment returns None unchanged."""
    assert apply_eol_judgment(None, today=TODAY) is None
