"""Tests for the Microsoft OneCDN static-asset module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_OTHER

from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("microsoft_onecdn")


def test_identity(m) -> None:
    assert m.module_id == "microsoft_onecdn"
    assert m.legal_jurisdiction == "US"


def test_matches_onecdn_host(m) -> None:
    url = ("https://res.public.onecdn.static.microsoft/owamail/hashed-v1/"
           "msalv5/scripts/owa.bookingsc2index.13d2674f.js")
    event = make_request(host="res.public.onecdn.static.microsoft", url=url)
    assert m.matches(event) is True


def test_does_not_match_other_microsoft_hosts(m) -> None:
    for host in ("bookings.cloud.microsoft", "forms.cloud.microsoft",
                 "clarity.ms", "example.com"):
        event = make_request(host=host, url=f"https://{host}/")
        assert m.matches(event) is False


def test_params_are_asset_fetch_low_impact(m) -> None:
    event = make_request(
        host="res.public.onecdn.static.microsoft",
        url="https://res.public.onecdn.static.microsoft/assets/x.js?v=2",
    )
    hit = m.parse(event)
    p = next(p for p in hit.params if p.key == "v")
    assert p.category == CAT_OTHER
