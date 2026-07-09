"""Tests for the Jimdo (Jimdo GmbH) platform-infrastructure module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_TECHNICAL

from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("jimdo")


def test_identity(m) -> None:
    assert m.module_id == "jimdo"
    assert m.module_name == "Jimdo"
    # Jimdo GmbH is Hamburg-based — an EU controller.
    assert m.legal_jurisdiction == "DE"


@pytest.mark.parametrize(
    "host",
    [
        "assets.jimstatic.com",
        "fonts.jimstatic.com",
        "static-assets.jimstatic.com",
        "a.jimdo.com",
        "storage.e.jimdo.com",
        "at.prod.jimdo.systems",
    ],
)
def test_matches_jimdo_infra_hosts(m, host) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert m.matches(event) is True


def test_analytics_beacon_is_behavioral(m) -> None:
    """at.prod.jimdo.systems is Jimdo's first-party analytics beacon."""
    event = make_request(
        host="at.prod.jimdo.systems",
        url="https://at.prod.jimdo.systems/anon",
        method="POST",
    )
    assert m.matches(event) is True
    assert m.impact_rating.privacy == 1.5


def test_does_not_match_unrelated(m) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert m.matches(event) is False


def test_asset_params_are_technical(m) -> None:
    event = make_request(
        host="fonts.jimstatic.com",
        url="https://fonts.jimstatic.com/css?display=swap&family=Lato:400,700",
    )
    cats = {p.key: p.category for p in m.parse(event).params}
    assert cats["display"] == CAT_TECHNICAL
    assert cats["family"] == CAT_TECHNICAL
