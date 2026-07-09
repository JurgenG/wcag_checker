"""Tests for the Flexmail module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_OTHER
from leak_inspector.impact import ImpactRating
from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("flexmail")


def test_identity(m) -> None:
    assert m.module_id == "flexmail"
    assert m.module_name == "Flexmail"
    assert m.vendor == "Flexmail NV"
    assert m.legal_jurisdiction == "BE"
    assert m.data_residency and m.sovereignty_notes


def test_form_leakage_rating(m) -> None:
    """Email form leakage to an EU controller — privacy 5.0, resilience 1.0."""
    assert m.impact_rating == ImpactRating(privacy=5.0, security=2.5, resilience=1.0)


@pytest.mark.parametrize("host", ["www.flexmail.eu", "return.flexmail.eu", "flexmail.be"])
def test_matches_hosts(m, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/sf-abc")
    assert m.matches(event) is True


def test_case_insensitive(m) -> None:
    event = make_request(host="WWW.FLEXMAIL.EU", url="https://WWW.FLEXMAIL.EU/sf-x")
    assert m.matches(event) is True


def test_rejects_lookalike(m) -> None:
    event = make_request(host="flexmail.eu.evil.example", url="https://flexmail.eu.evil.example/x")
    assert m.matches(event) is False


def test_unknown_param_is_other(m) -> None:
    event = make_request(host="www.flexmail.eu", url="https://www.flexmail.eu/sf-x?id=1")
    hit = m.parse(event)
    p = next(p for p in hit.params if p.key == "id")
    assert p.category == CAT_OTHER
