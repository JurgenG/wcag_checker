"""Tests for the Adobe Experience Cloud module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_CONSENT,
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    IMPACT_HIGH,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def adobe():
    return module_by_id("adobe_marketing_cloud")


def test_identity(adobe) -> None:
    assert adobe.module_id == "adobe_marketing_cloud"
    assert adobe.module_name == "Adobe Experience Cloud"


@pytest.mark.parametrize(
    "host",
    [
        "adobedtm.com", "assets.adobedtm.com",
        "demdex.net", "dpm.demdex.net",
        "omtrdc.net", "acme.sc.omtrdc.net",
        "everesttech.net", "pixel.everesttech.net",
    ],
)
def test_matches(adobe, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert adobe.matches(event) is True


def test_mid_is_high_impact(adobe) -> None:
    """``mid`` is the persistent Adobe ECID visitor pseudonym."""
    event = make_request(
        host="dpm.demdex.net",
        url="https://dpm.demdex.net/id?mid=12345678901234567890",
    )
    hit = adobe.parse(event)
    p = next(p for p in hit.params if p.key == "mid")
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


def test_ibs_path_params_extracted(adobe) -> None:
    """Demdex ``/ibs:`` encodes params in the URL path, separated by ``&``."""
    event = make_request(
        host="dpm.demdex.net",
        url="https://dpm.demdex.net/ibs:dpid=ADBE&dpuuid=USERID&google_cver=1",
    )
    hit = adobe.parse(event)
    by_key = {p.key: p for p in hit.params}
    assert "dpid" in by_key
    assert by_key["dpid"].value == "ADBE"
    assert by_key["dpid"].category == CAT_TECHNICAL
    assert "dpuuid" in by_key
    assert by_key["dpuuid"].value == "USERID"
    assert by_key["dpuuid"].privacy_impact == IMPACT_HIGH
    assert "google_cver" in by_key


def test_redir_is_content_high(adobe) -> None:
    """``redir`` names the downstream cookie-sync partner."""
    event = make_request(
        host="sync-tm.everesttech.net",
        url="https://sync-tm.everesttech.net/upi/pid/123?redir=https://partner.example",
    )
    hit = adobe.parse(event)
    p = next(p for p in hit.params if p.key == "redir")
    assert p.category == CAT_CONTENT
    assert p.privacy_impact == IMPACT_HIGH


@pytest.mark.parametrize("key", ["mcorgid", "d_orgid", "advId", "pxId"])
def test_other_identifiers(adobe, key: str) -> None:
    event = make_request(host="dpm.demdex.net", url=f"https://dpm.demdex.net/?{key}=x")
    hit = adobe.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


@pytest.mark.parametrize("key", ["px_evt", "ev_transid"])
def test_behavioral(adobe, key: str) -> None:
    event = make_request(host="pixel.everesttech.net", url=f"https://pixel.everesttech.net/?{key}=x")
    hit = adobe.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_BEHAVIORAL


@pytest.mark.parametrize("key", ["d_fieldgroup", "d_visid_ver", "d_ver", "d_nsid", "d_rtbd", "cachebuster", "ts"])
def test_technical(adobe, key: str) -> None:
    event = make_request(host="dpm.demdex.net", url=f"https://dpm.demdex.net/?{key}=x")
    hit = adobe.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


@pytest.mark.parametrize("key", ["gdpr", "gdpr_consent", "google_cver"])
def test_consent(adobe, key: str) -> None:
    event = make_request(host="dpm.demdex.net", url=f"https://dpm.demdex.net/?{key}=1")
    hit = adobe.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONSENT


def test_unknown_param(adobe) -> None:
    event = make_request(host="dpm.demdex.net", url="https://dpm.demdex.net/?weird=1")
    hit = adobe.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Adobe" in p.meaning
