"""Tests for the Weebly (Square) platform-infrastructure module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_TECHNICAL

from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("weebly")


def test_identity(m) -> None:
    assert m.module_id == "weebly"
    assert m.module_name == "Weebly"
    assert m.legal_jurisdiction == "US"


@pytest.mark.parametrize(
    "host",
    ["cdn1.editmysite.com", "cdn2.editmysite.com", "cdn11.editmysite.com", "www.weebly.com"],
)
def test_matches_weebly_infra_hosts(m, host) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert m.matches(event) is True


def test_does_not_claim_hosted_site_content(m) -> None:
    """A hosted ``<site>.weebly.com`` content host is first-party."""
    for host in ("dehorizon-tspoor.weebly.com", "example.com"):
        event = make_request(host=host, url=f"https://{host}/")
        assert m.matches(event) is False


def test_asset_params_are_technical(m) -> None:
    event = make_request(
        host="cdn2.editmysite.com",
        url="https://cdn2.editmysite.com/css/sites.css?buildtime=1780513462",
    )
    cats = {p.key: p.category for p in m.parse(event).params}
    assert cats["buildtime"] == CAT_TECHNICAL
