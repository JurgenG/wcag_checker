"""Tests for item 2 of the verdict layer — the classification map.

Two distinct key kinds:

* ``classify_module(module_id)`` — exact match against
  ``TrackerModule.module_id`` (snake_case slugs).
* ``classify_vendor(vendor)`` — case-insensitive substring match
  against the human-readable vendor string emitted by, e.g., the
  DNS-TXT verification scanner.

Unknown keys never raise; they return the sentinel ``unclassified``
verdict with an empty note.
"""

from __future__ import annotations

from leak_inspector.report.verdict_classification import (
    VendorVerdict,
    classify_module,
    classify_vendor,
    MODULE_VERDICTS,
    VENDOR_VERDICTS,
)


# --- VendorVerdict contract -----------------------------------------------


def test_vendor_verdict_is_frozen() -> None:
    """Frozen dataclass — keeps the verdict map immutable at runtime."""
    v = VendorVerdict("expected", "note")
    try:
        v.category = "actionable"  # type: ignore[misc]
    except Exception:
        return
    raise AssertionError("VendorVerdict must be frozen")


def test_unclassified_sentinel_shape() -> None:
    """The unknown-key fallback returns category 'unclassified' + empty note."""
    v = classify_module("never_a_module_id")
    assert v.category == "unclassified"
    assert v.note == ""


# --- classify_module: exact-match against module_id keys -------------------


def test_gov_flanders_is_expected() -> None:
    v = classify_module("gov_flanders")
    assert v.category == "expected"
    assert v.note  # non-empty


def test_google_fonts_is_actionable() -> None:
    v = classify_module("google_fonts")
    assert v.category == "actionable"
    assert v.note


def test_unknown_module_id_is_unclassified() -> None:
    v = classify_module("entirely_unknown_module")
    assert v.category == "unclassified"


def test_classify_module_does_not_fall_back_to_vendor_matching() -> None:
    """A hypothetical ``apple_pay`` module must NOT inherit Apple's DNS
    verdict via accidental substring matching. Module + vendor keys are
    separate by design."""
    v = classify_module("apple_pay")
    assert v.category == "unclassified"


# --- classify_vendor: case-insensitive substring on vendor strings --------


def test_microsoft_365_vendor_is_strategic() -> None:
    v = classify_vendor("Microsoft 365")
    assert v.category == "strategic"
    assert v.note


def test_google_vendor_is_strategic() -> None:
    """The real DNS TXT scanner emits ``tv.vendor == "Google"``
    (the product detail lives in ``tv.purpose``). The seed key
    ``"Google"`` covers all Google DNS verifications under one
    strategic verdict; the US-jurisdiction question applies
    equally regardless of which Google product."""
    assert classify_vendor("Google").category == "strategic"


def test_apple_substring_is_case_insensitive() -> None:
    """``"apple services"``, ``"APPLE"``, ``"Apple"`` — all match."""
    assert classify_vendor("apple").category == "strategic"
    assert classify_vendor("APPLE").category == "strategic"
    assert classify_vendor("Apple services domain verification").category == "strategic"


def test_unknown_vendor_string_is_unclassified() -> None:
    v = classify_vendor("RandomCorp Analytics")
    assert v.category == "unclassified"


# --- seed completeness -----------------------------------------------------


def test_seeded_module_keys_present() -> None:
    """Exactly the two module-keyed entries we drafted with the operator."""
    assert set(MODULE_VERDICTS.keys()) == {"gov_flanders", "google_fonts"}


def test_seeded_vendor_keys_present() -> None:
    """Exactly the three vendor-keyed DNS-disclosed relationships.

    Keys match the literal ``tv.vendor`` strings emitted by the
    DNS-TXT scanner, not the longer purpose strings.
    """
    assert set(VENDOR_VERDICTS.keys()) == {
        "Microsoft 365", "Google", "Apple",
    }


