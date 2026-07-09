"""Tests for the Amazon CloudFront (cloudfront.net) asset module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_OTHER

from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("cloudfront")


def test_identity(m) -> None:
    assert m.module_id == "cloudfront"
    assert m.legal_jurisdiction == "US"


def test_matches_cloudfront(m) -> None:
    url = "https://d3e54v103j8qbb.cloudfront.net/js/jquery-3.5.1.min.js"
    event = make_request(host="d3e54v103j8qbb.cloudfront.net", url=url)
    assert m.matches(event) is True


def test_does_not_match_unrelated(m) -> None:
    for host in ("cdne-rumst-p2-rp.azureedge.net", "example.com"):
        event = make_request(host=host, url=f"https://{host}/")
        assert m.matches(event) is False


def test_params_are_asset_fetch_low_impact(m) -> None:
    event = make_request(
        host="d1bnv20w2037a.cloudfront.net",
        url="https://d1bnv20w2037a.cloudfront.net/x/banner_576.jpg?updated=1773141498000",
    )
    hit = m.parse(event)
    p = next(p for p in hit.params if p.key == "updated")
    assert p.category == CAT_OTHER
