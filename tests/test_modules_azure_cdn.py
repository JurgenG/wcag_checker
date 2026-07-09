"""Tests for the Azure CDN (azureedge.net) asset module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_OTHER

from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("azure_cdn")


def test_identity(m) -> None:
    assert m.module_id == "azure_cdn"
    assert m.legal_jurisdiction == "US"


def test_matches_azureedge(m) -> None:
    url = "https://rumst-p2-mortsel.azureedge.net/static/css/main.css"
    event = make_request(host="rumst-p2-mortsel.azureedge.net", url=url)
    assert m.matches(event) is True


def test_does_not_match_other_azure_or_hosts(m) -> None:
    # The App Insights collector and unrelated hosts must not be claimed.
    for host in ("dc.services.visualstudio.com",
                 "res.public.onecdn.static.microsoft", "example.com"):
        event = make_request(host=host, url=f"https://{host}/")
        assert m.matches(event) is False


def test_params_are_asset_fetch_low_impact(m) -> None:
    event = make_request(
        host="cdne-rumst-p2-rp.azureedge.net",
        url="https://cdne-rumst-p2-rp.azureedge.net/api/config/about_page_url?tenant=mortsel",
    )
    hit = m.parse(event)
    p = next(p for p in hit.params if p.key == "tenant")
    assert p.category == CAT_OTHER
