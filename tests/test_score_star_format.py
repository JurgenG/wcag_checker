"""Tests for ``format_stars`` — the float-aware star renderer (Phase 2a).

Resilience can now carry a half-star (the US-ownership deductions), so
the renderers need a helper that shows ``7.5`` as ``7.5`` but a whole
number as ``8`` (not ``8.0``). Security and privacy stay integers and
must pass through unchanged.
"""

from __future__ import annotations

import pytest

from leak_inspector.report.score_v2 import format_stars


@pytest.mark.parametrize("value,expected", [
    (8, "8"),
    (10, "10"),
    (0, "0"),
    (8.0, "8"),
    (10.0, "10"),
    (0.0, "0"),
    (7.5, "7.5"),
    (9.5, "9.5"),
    (4.5, "4.5"),
])
def test_format_stars(value, expected: str) -> None:
    assert format_stars(value) == expected
