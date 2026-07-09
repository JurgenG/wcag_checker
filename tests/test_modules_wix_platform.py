"""Tests for the Wix platform-infrastructure module.

Wix-hosted sites load their assets, page config and code bundles from
Wix-owned CDNs (``*.parastorage.com``, ``static.wixstatic.com``) and emit
first-party telemetry to ``frog.wix.com`` / ``panorama.wixapps.net``. The
module claims those requests so they no longer fall through to
``unclassified_hosts``, and classifies their parameters by host role:
asset/config fetches are technical, telemetry-beacon fields are
behavioral (with the Wix session/site identifiers flagged).
"""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_IDENTIFIER,
    CAT_TECHNICAL,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("wix_platform")


def test_identity(m) -> None:
    assert m.module_id == "wix_platform"
    assert m.module_name == "Wix"
    assert m.vendor.startswith("Wix")
    assert m.legal_jurisdiction == "IL"


@pytest.mark.parametrize(
    "host",
    [
        "static.parastorage.com",
        "siteassets.parastorage.com",
        "bundler-velo.parastorage.com",
        "static.wixstatic.com",
        "frog.wix.com",
        "panorama.wixapps.net",
    ],
)
def test_matches_wix_infrastructure_hosts(m, host) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert m.matches(event) is True


def test_does_not_match_unrelated(m) -> None:
    for host in ("example.com", "static.example.com", "www.wix.com"):
        event = make_request(host=host, url=f"https://{host}/")
        assert m.matches(event) is False


def test_asset_params_are_technical(m) -> None:
    event = make_request(
        host="siteassets.parastorage.com",
        url=(
            "https://siteassets.parastorage.com/pages/pages/thunderbolt"
            "?siteId=95106ffa&viewMode=desktop&language=nl"
        ),
    )
    hit = m.parse(event)
    cats = {p.key: p.category for p in hit.params}
    assert cats["viewMode"] == CAT_TECHNICAL
    assert cats["language"] == CAT_TECHNICAL


def test_telemetry_fields_are_behavioral_with_identifiers_flagged(m) -> None:
    event = make_request(
        host="frog.wix.com",
        url=(
            "https://frog.wix.com/bolt-performance"
            "?evid=21&msid=8c28a015&session_id=0489e4c8&vsi=55a26e34&pv=visible"
        ),
    )
    hit = m.parse(event)
    cats = {p.key: p.category for p in hit.params}
    # Wix session / site identifiers
    assert cats["msid"] == CAT_IDENTIFIER
    assert cats["session_id"] == CAT_IDENTIFIER
    assert cats["vsi"] == CAT_IDENTIFIER
    # Remaining telemetry fields
    assert cats["pv"] == CAT_BEHAVIORAL
    assert cats["evid"] == CAT_BEHAVIORAL