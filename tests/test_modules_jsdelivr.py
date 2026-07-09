"""Tests for the jsDelivr CDN module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_OTHER, CAT_TECHNICAL, Hit, IMPACT_LOW

from tests.conftest import make_request, module_by_id


@pytest.fixture
def jsd():
    return module_by_id("jsdelivr")


def test_identity(jsd) -> None:
    assert jsd.module_id == "jsdelivr"
    assert jsd.module_name == "jsDelivr"
    assert jsd.vendor == "Prosperous Net Foundation (jsDelivr)"
    assert jsd.legal_jurisdiction == "CZ"
    assert jsd.data_residency
    assert jsd.sovereignty_notes


@pytest.mark.parametrize(
    "host",
    [
        "jsdelivr.net",
        "jsdelivr.com",
        "cdn.jsdelivr.net",
        "data.jsdelivr.com",
        "anything.jsdelivr.net",
    ],
)
def test_matches_apex_and_subdomains(jsd, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert jsd.matches(event) is True


def test_matches_is_case_insensitive(jsd) -> None:
    event = make_request(host="CDN.JSDELIVR.NET", url="https://CDN.JSDELIVR.NET/x")
    assert jsd.matches(event) is True


def test_does_not_match_unrelated(jsd) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert jsd.matches(event) is False


def test_parse_metadata(jsd) -> None:
    event = make_request(
        host="cdn.jsdelivr.net",
        url="https://cdn.jsdelivr.net/npm/foo@1.0.0/dist/foo.min.js?v=1",
    )
    hit = jsd.parse(event)
    assert isinstance(hit, Hit)
    assert hit.module_id == "jsdelivr"


@pytest.mark.parametrize(
    "key", ["v", "_", "callback", "limit", "structure"],
)
def test_classify_known_params(jsd, key: str) -> None:
    event = make_request(
        host="cdn.jsdelivr.net",
        url=f"https://cdn.jsdelivr.net/x?{key}=1",
    )
    hit = jsd.parse(event)
    param = next(p for p in hit.params if p.key == key)
    assert param.category == CAT_TECHNICAL
    assert param.privacy_impact == IMPACT_LOW


def test_classify_unknown_param(jsd) -> None:
    event = make_request(
        host="cdn.jsdelivr.net",
        url="https://cdn.jsdelivr.net/x?weird=1",
    )
    hit = jsd.parse(event)
    param = next(p for p in hit.params if p.key == "weird")
    assert param.category == CAT_OTHER
    assert "jsDelivr" in param.meaning
