"""Tests for the AdRoll (NextRoll) retargeting module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_TECHNICAL,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("adroll")


def test_identity(m) -> None:
    assert m.module_id == "adroll"
    assert m.module_name.startswith("AdRoll")
    assert m.legal_jurisdiction == "US"


@pytest.mark.parametrize("host", ["d.adroll.com", "s.adroll.com", "adroll.com"])
def test_matches_adroll_hosts(m, host) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert m.matches(event) is True


def test_does_not_match_unrelated(m) -> None:
    for host in ("example.com", "notadroll.com.evil.com"):
        event = make_request(host=host, url=f"https://{host}/")
        assert m.matches(event) is False


def test_classifies_identifier_referrer_and_account(m) -> None:
    event = make_request(
        host="d.adroll.com",
        url=(
            "https://d.adroll.com/segment/ADV1/SEG2"
            "?adroll_fpc=abc-123&advertisable=ADV1"
            "&arrfrr=https%3A%2F%2Fwww.voxpelt.be%2F"
        ),
    )
    cats = {p.key: p.category for p in m.parse(event).params}
    assert cats["adroll_fpc"] == CAT_IDENTIFIER
    assert cats["advertisable"] == CAT_TECHNICAL
    assert cats["arrfrr"] == CAT_CONTENT