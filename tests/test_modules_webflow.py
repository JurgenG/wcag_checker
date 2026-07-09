"""Tests for the Webflow platform-infrastructure module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_TECHNICAL

from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("webflow")


def test_identity(m) -> None:
    assert m.module_id == "webflow"
    assert m.module_name == "Webflow"
    assert m.legal_jurisdiction == "US"


@pytest.mark.parametrize(
    "host",
    ["cdn.prod.website-files.com", "assets.website-files.com", "uploads-ssl.webflow.com"],
)
def test_matches_webflow_infra_hosts(m, host) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert m.matches(event) is True


def test_does_not_claim_hosted_staging_site(m) -> None:
    """A ``*.webflow.io`` staging host serves first-party site content."""
    for host in ("myschool.webflow.io", "example.com"):
        event = make_request(host=host, url=f"https://{host}/")
        assert m.matches(event) is False


def test_asset_params_are_technical(m) -> None:
    event = make_request(
        host="cdn.prod.website-files.com",
        url="https://cdn.prod.website-files.com/645b/css/site.min.css?v=2",
    )
    cats = {p.key: p.category for p in m.parse(event).params}
    assert cats["v"] == CAT_TECHNICAL
