"""Tests for the Index Exchange (CasaleMedia) module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_CONSENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    IMPACT_HIGH,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def ix():
    return module_by_id("index_exchange")


def test_identity(ix) -> None:
    assert ix.module_id == "index_exchange"
    assert ix.module_name == "Index Exchange"
    assert ix.legal_jurisdiction == "CA"


@pytest.mark.parametrize(
    "host",
    [
        "casalemedia.com",
        "indexexchange.com",
        "ssum.casalemedia.com",
        "dsum-sec.casalemedia.com",
        "as-sec.casalemedia.com",
    ],
)
def test_matches(ix, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/cm")
    assert ix.matches(event) is True


def test_does_not_match_unrelated(ix) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert ix.matches(event) is False


def test_external_user_id_is_high_impact(ix) -> None:
    event = make_request(
        host="ssum.casalemedia.com",
        url="https://ssum.casalemedia.com/cm?external_user_id=ABC",
    )
    hit = ix.parse(event)
    p = next(p for p in hit.params if p.key == "external_user_id")
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


def test_partner_uid_is_high_impact(ix) -> None:
    event = make_request(host="ssum.casalemedia.com", url="https://ssum.casalemedia.com/cm?partner_uid=X")
    hit = ix.parse(event)
    p = next(p for p in hit.params if p.key == "partner_uid")
    assert p.privacy_impact == IMPACT_HIGH


@pytest.mark.parametrize("key", ["r", "redir"])
def test_redirect_keys(ix, key: str) -> None:
    event = make_request(host="ssum.casalemedia.com", url=f"https://ssum.casalemedia.com/?{key}=x")
    hit = ix.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


@pytest.mark.parametrize("key", ["gdpr", "gdpr_consent", "us_privacy"])
def test_consent_keys(ix, key: str) -> None:
    event = make_request(host="ssum.casalemedia.com", url=f"https://ssum.casalemedia.com/?{key}=1")
    hit = ix.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONSENT


def test_unknown_param_falls_through(ix) -> None:
    event = make_request(host="ssum.casalemedia.com", url="https://ssum.casalemedia.com/?weird=1")
    hit = ix.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Index Exchange" in p.meaning
