"""Tests for the polyfill-fastly.io module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_CONTENT,
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_LOW,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def pf():
    return module_by_id("polyfill_fastly")


def test_identity(pf) -> None:
    assert pf.module_id == "polyfill_fastly"
    assert pf.module_name == "polyfill-fastly.io (Fastly)"
    assert pf.vendor == "Fastly, Inc."
    assert pf.legal_jurisdiction == "US"
    assert pf.data_residency
    assert pf.sovereignty_notes


def test_matches_exact_host(pf) -> None:
    event = make_request(
        host="polyfill-fastly.io",
        url="https://polyfill-fastly.io/v2/polyfill.min.js",
    )
    assert pf.matches(event) is True


def test_matches_is_case_insensitive(pf) -> None:
    event = make_request(
        host="POLYFILL-FASTLY.IO",
        url="https://POLYFILL-FASTLY.IO/v2/polyfill.min.js",
    )
    assert pf.matches(event) is True


def test_does_not_match_original_polyfill_io(pf) -> None:
    """The compromised original domain is NOT claimed by this module."""
    event = make_request(host="polyfill.io", url="https://polyfill.io/v2/polyfill.min.js")
    assert pf.matches(event) is False


def test_features_param_is_content(pf) -> None:
    event = make_request(
        host="polyfill-fastly.io",
        url="https://polyfill-fastly.io/v2/polyfill.min.js?features=es6,fetch",
    )
    hit = pf.parse(event)
    p = next(p for p in hit.params if p.key == "features")
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize("key", ["flags", "version", "ua", "callback", "unknown"])
def test_other_known_params_are_technical(pf, key: str) -> None:
    event = make_request(
        host="polyfill-fastly.io",
        url=f"https://polyfill-fastly.io/v2/polyfill.min.js?{key}=x",
    )
    hit = pf.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param_falls_through(pf) -> None:
    event = make_request(
        host="polyfill-fastly.io",
        url="https://polyfill-fastly.io/v2/polyfill.min.js?surprise=1",
    )
    hit = pf.parse(event)
    p = next(p for p in hit.params if p.key == "surprise")
    assert p.category == CAT_OTHER
    assert p.privacy_impact == IMPACT_LOW
    assert "polyfill" in p.meaning
    assert isinstance(hit, Hit)
