"""Tests for the Adobe Helix RUM tracker module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_OTHER, Hit, IMPACT_LOW

from tests.conftest import make_request, module_by_id


@pytest.fixture
def helix():
    return module_by_id("adobe_helix_rum")


def test_identity(helix) -> None:
    assert helix.module_id == "adobe_helix_rum"
    assert helix.module_name == "Adobe Helix RUM"
    assert helix.vendor == "Adobe Inc."
    assert helix.legal_jurisdiction == "US"
    assert helix.data_residency
    assert helix.sovereignty_notes


def test_matches_rum_hlx_page(helix) -> None:
    event = make_request(
        host="rum.hlx.page",
        url="https://rum.hlx.page/.rum/@adobe/helix-rum-js@^2/dist/micro.js",
    )
    assert helix.matches(event) is True


def test_matches_is_case_insensitive(helix) -> None:
    event = make_request(
        host="RUM.HLX.PAGE",
        url="https://RUM.HLX.PAGE/anything",
    )
    assert helix.matches(event) is True


def test_does_not_match_other_hlx_subdomains(helix) -> None:
    """Only the RUM subdomain — not arbitrary .hlx.page hosts."""
    event = make_request(host="www.hlx.page", url="https://www.hlx.page/")
    assert helix.matches(event) is False


def test_does_not_match_unrelated_host(helix) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert helix.matches(event) is False


def test_parse_hit_metadata(helix) -> None:
    event = make_request(
        host="rum.hlx.page",
        url="https://rum.hlx.page/.rum/foo",
        method="POST",
        event_id=7,
        timestamp="2026-05-01T10:00:00Z",
        response_status=204,
    )
    hit = helix.parse(event)
    assert isinstance(hit, Hit)
    assert hit.module_id == "adobe_helix_rum"
    assert hit.module_name == "Adobe Helix RUM"
    assert hit.url == event.url
    assert hit.host == "rum.hlx.page"
    assert hit.method == "POST"
    assert hit.response_status == 204
    assert hit.started_at == "2026-05-01T10:00:00Z"
    assert hit.events == [7]


def test_parse_no_params_when_url_has_none(helix) -> None:
    event = make_request(host="rum.hlx.page", url="https://rum.hlx.page/")
    hit = helix.parse(event)
    assert hit.params == []


def test_parse_all_params_fall_through_to_other(helix) -> None:
    """Helix RUM has no param dictionary; every key gets CAT_OTHER / IMPACT_LOW."""
    event = make_request(
        host="rum.hlx.page",
        url="https://rum.hlx.page/.rum/web-vitals?id=abc&checkpoint=load",
    )
    hit = helix.parse(event)
    keys = {p.key: p for p in hit.params}
    assert "id" in keys and "checkpoint" in keys
    for p in hit.params:
        assert p.category == CAT_OTHER
        assert p.privacy_impact == IMPACT_LOW
        assert "Adobe Helix RUM" in p.meaning
