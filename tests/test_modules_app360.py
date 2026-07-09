"""Tests for the App360 (app360.be) municipal-platform module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_OTHER

from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("app360")


def test_identity(m) -> None:
    assert m.module_id == "app360"
    assert m.legal_jurisdiction == "EU"


def test_matches_app360(m) -> None:
    url = ("https://www.app360.be/sites/default/files/styles/"
           "api_sheet_preview/public/home_background_image/a_001.jpg?itok=TGO-epTq")
    event = make_request(host="www.app360.be", url=url)
    assert m.matches(event) is True


def test_does_not_match_unrelated(m) -> None:
    for host in ("app360.be.evil.com", "example.com"):
        event = make_request(host=host, url=f"https://{host}/")
        assert m.matches(event) is False


def test_params_are_asset_low_impact(m) -> None:
    event = make_request(
        host="www.app360.be",
        url="https://www.app360.be/sites/default/files/x.jpg?itok=TGO-epTq&focalpoint=50,50",
    )
    hit = m.parse(event)
    p = next(p for p in hit.params if p.key == "itok")
    assert p.category == CAT_OTHER
