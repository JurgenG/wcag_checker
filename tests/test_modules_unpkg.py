"""Tests for the unpkg module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_OTHER, IMPACT_LOW
from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("unpkg")


def test_identity(m) -> None:
    assert m.module_id == "unpkg"
    assert m.module_name == "unpkg"
    assert m.legal_jurisdiction == "US"
    assert m.vendor and m.data_residency and m.sovereignty_notes


@pytest.mark.parametrize("host", ["unpkg.com", "app.unpkg.com"])
def test_matches_hosts(m, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/leaflet@1.9.4/dist/leaflet.js")
    assert m.matches(event) is True


def test_case_insensitive(m) -> None:
    event = make_request(host="UNPKG.COM", url="https://UNPKG.COM/x.js")
    assert m.matches(event) is True


def test_rejects_lookalike(m) -> None:
    event = make_request(host="fakeunpkg.com", url="https://fakeunpkg.com/x.js")
    assert m.matches(event) is False


def test_unknown_param_is_other(m) -> None:
    event = make_request(host="unpkg.com", url="https://unpkg.com/x.js?ver=3")
    hit = m.parse(event)
    p = next(p for p in hit.params if p.key == "ver")
    assert p.category == CAT_OTHER
    assert p.privacy_impact == IMPACT_LOW
