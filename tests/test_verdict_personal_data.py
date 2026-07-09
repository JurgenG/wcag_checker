"""Edge-case tests for ``personal_data_line``.

The bundle-driven assertions (real Brecht zero case, real cultuurkuur
non-zero case with its exact 57 fields × 5 trackers) live in
``test_integration_bundles.py``. This file only keeps the
edge cases that aren't represented in a real fixture bundle: a
capture that loaded nothing, and a capture whose only PII flows to a
first-party host (must be ignored — citizen data leaving to a third
party is the thing the verdict measures).
"""

from __future__ import annotations

from leak_inspector.report.verdict import personal_data_line

from tests.fixtures.verdict import (
    analysis_empty,
    analysis_first_party_only,
)


_ZERO_LINE = (
    "No citizen personal data was observed leaving the website "
    "during this scan."
)


def test_empty_capture_renders_canonical_line() -> None:
    assert personal_data_line(analysis_empty()) == _ZERO_LINE


def test_first_party_pii_does_not_count() -> None:
    """First-party PII (a form on the site itself) is not a leak."""
    assert personal_data_line(analysis_first_party_only()) == _ZERO_LINE
