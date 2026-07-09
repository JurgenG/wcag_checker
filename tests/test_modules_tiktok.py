"""Tests for the TikTok Pixel detector module.

Covers the documented Web Pixel surface only — the mobile-SDK
parameter set that earlier drafts shipped is intentionally out of
scope for this module (no Firefox capture will see it).

Pattern follows ``tests/test_modules_ga4.py`` (the worked example
for tracker module tests).
"""

from __future__ import annotations

import pytest

from leak_inspector.events import RequestEvent
from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_PII,
    CAT_TECHNICAL,
    IMPACT_HIGH,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    all_modules,
    detect,
)


# --- helpers ----------------------------------------------------------------


def _request(
    *,
    host: str,
    url: str,
    method: str = "POST",
    request_body: str | None = None,
    headers: dict[str, str] | None = None,
    event_id: int = 1,
    timestamp: str = "2026-06-04T12:00:00Z",
    response_status: int | None = 200,
) -> RequestEvent:
    return RequestEvent(
        event_id=event_id,
        timestamp=timestamp,
        type="request",
        context_id=None,
        payload={},
        method=method,
        url=url,
        host=host,
        headers=headers or {},
        request_body=request_body,
        initiator=None,
        response_status=response_status,
        response_mime=None,
        response_headers={},
    )


@pytest.fixture
def tiktok():
    for module in all_modules():
        if module.module_id == "tiktok":
            return module
    raise AssertionError("tiktok module not registered")


# --- A. class identity ------------------------------------------------------


def test_module_registered() -> None:
    assert "tiktok" in [m.module_id for m in all_modules()]


def test_module_identity(tiktok) -> None:
    assert tiktok.module_id == "tiktok"
    assert "TikTok" in tiktok.module_name


def test_module_sovereignty(tiktok) -> None:
    """Vendor of record is the Chinese parent — Irish controller is nominal."""
    assert tiktok.vendor == "ByteDance Ltd."
    assert tiktok.legal_jurisdiction == "CN"
    # Sovereignty notes must surface the parallel non-US access regime.
    notes = (tiktok.sovereignty_notes or "").lower()
    assert "pipl" in notes
    assert "schrems" in notes


# --- B. matches() — positive ------------------------------------------------


@pytest.mark.parametrize(
    "host,path",
    [
        # Web pixel beacons
        ("analytics.tiktok.com", "/api/v2/pixel/track/"),
        ("analytics.tiktok.com", "/api/track/"),  # legacy
        # Pixel JS loader
        ("analytics.tiktok.com", "/i18n/pixel/events.js"),
        ("analytics.tiktok.com", "/i18n/pixel/sdk.js"),
        # Ads platform
        ("ads.tiktok.com", "/i18n/pixel/conversion/"),
        # Events API host (server-side primarily, but claimable when it appears)
        ("business-api.tiktok.com", "/open_api/v1.3/event/track/"),
    ],
)
def test_matches_documented_tiktok_hosts(tiktok, host: str, path: str) -> None:
    url = f"https://{host}{path}"
    assert tiktok.matches(_request(host=host, url=url)) is True


# --- C. matches() — negative ------------------------------------------------


def test_does_not_match_unrelated_host(tiktok) -> None:
    url = "https://example.com/api/track/"
    assert tiktok.matches(_request(host="example.com", url=url)) is False


def test_does_not_match_first_party_tiktok_subdomain(tiktok) -> None:
    """``www.tiktok.com`` (the user-facing site) is intentionally not claimed.

    A user visiting tiktok.com itself produces first-party requests; we
    only claim the well-known tracker subdomains.
    """
    url = "https://www.tiktok.com/@user/video/123"
    assert tiktok.matches(_request(host="www.tiktok.com", url=url)) is False


def test_does_not_match_mobile_sdk_hosts(tiktok) -> None:
    """``*.tiktokv.com`` / ``log.byteoversea.com`` are native SDK only."""
    for host in ("api2-16.tiktokv.com", "log.byteoversea.com"):
        url = f"https://{host}/log/"
        assert tiktok.matches(_request(host=host, url=url)) is False


def test_does_not_match_path_only_without_known_host(tiktok) -> None:
    """Earlier draft fell through to path-based matching — must not regress.

    Generic paths like ``/api/track/`` / ``/log/`` / ``/event/`` /
    ``/pixel/`` appear on Magento, Snowplow, Plausible-derived stacks,
    and countless custom analytics endpoints. Claiming them by path
    alone would falsely attribute non-TikTok traffic.
    """
    for path in ("/api/track/", "/log/", "/event/", "/pixel/"):
        url = f"https://magento.example.com{path}"
        assert tiktok.matches(_request(host="magento.example.com", url=url)) is False


# --- D. dispatcher: TikTok hits route to this module ----------------------


def test_detect_routes_to_tiktok() -> None:
    req = _request(
        host="analytics.tiktok.com",
        url="https://analytics.tiktok.com/api/v2/pixel/track/?pixel_code=ABC123&event=PageView",
    )
    module = detect(req)
    assert module is not None
    assert module.module_id == "tiktok"


# --- E. parse() — classification + Hit shape -------------------------------


def test_parse_classifies_pixel_id_and_click_id(tiktok) -> None:
    """Pixel ID is LOW TECHNICAL (operator-scoped); click ID is HIGH IDENTIFIER."""
    url = (
        "https://analytics.tiktok.com/api/v2/pixel/track/"
        "?pixel_code=CTAG000ABC&ttclid=E.C.P.deadbeef&event=PageView"
    )
    hit = tiktok.parse(_request(host="analytics.tiktok.com", url=url))
    by_key = {p.key: p for p in hit.params}
    assert by_key["pixel_code"].category == CAT_TECHNICAL
    assert by_key["pixel_code"].privacy_impact == IMPACT_LOW
    assert by_key["ttclid"].category == CAT_IDENTIFIER
    assert by_key["ttclid"].privacy_impact == IMPACT_HIGH


def test_parse_classifies_hashed_pii(tiktok) -> None:
    """Hashed email / phone (Advanced Matching) are PII / HIGH."""
    url = (
        "https://analytics.tiktok.com/api/v2/pixel/track/"
        "?pixel_code=X&email=abc123&phone_number=def456&external_id=user-42"
    )
    hit = tiktok.parse(_request(host="analytics.tiktok.com", url=url))
    by_key = {p.key: p for p in hit.params}
    for key in ("email", "phone_number", "external_id"):
        assert by_key[key].category == CAT_PII, key
        assert by_key[key].privacy_impact == IMPACT_HIGH, key


def test_parse_classifies_event_payload(tiktok) -> None:
    url = (
        "https://analytics.tiktok.com/api/v2/pixel/track/"
        "?pixel_code=X&event=AddToCart&value=49.99&currency=EUR"
    )
    hit = tiktok.parse(_request(host="analytics.tiktok.com", url=url))
    by_key = {p.key: p for p in hit.params}
    assert by_key["event"].category == CAT_BEHAVIORAL
    assert by_key["event"].privacy_impact == IMPACT_MEDIUM
    assert by_key["value"].category == CAT_BEHAVIORAL
    assert by_key["value"].privacy_impact == IMPACT_MEDIUM
    assert by_key["currency"].category == CAT_BEHAVIORAL
    assert by_key["currency"].privacy_impact == IMPACT_LOW


def test_parse_classifies_technical_fields(tiktok) -> None:
    """``library_version`` / ``timestamp`` / ``partner_name`` are TECHNICAL / LOW."""
    url = (
        "https://analytics.tiktok.com/api/v2/pixel/track/"
        "?pixel_code=X&library_version=1.2.3&partner_name=shopify&timestamp=1780519122"
    )
    hit = tiktok.parse(_request(host="analytics.tiktok.com", url=url))
    by_key = {p.key: p for p in hit.params}
    for key in ("library_version", "partner_name", "timestamp"):
        assert by_key[key].category == CAT_TECHNICAL, key
        assert by_key[key].privacy_impact == IMPACT_LOW, key


def test_parse_unknown_key_falls_through_to_other(tiktok) -> None:
    """Undocumented keys still get recorded — under CAT_OTHER / LOW."""
    url = "https://analytics.tiktok.com/api/v2/pixel/track/?pixel_code=X&qqq_internal=opaque"
    hit = tiktok.parse(_request(host="analytics.tiktok.com", url=url))
    by_key = {p.key: p for p in hit.params}
    assert by_key["qqq_internal"].category == CAT_OTHER
    assert by_key["qqq_internal"].privacy_impact == IMPACT_LOW


def test_parse_hit_basics(tiktok) -> None:
    url = "https://analytics.tiktok.com/api/v2/pixel/track/?pixel_code=X&event=PageView"
    hit = tiktok.parse(_request(host="analytics.tiktok.com", url=url, event_id=99))
    assert hit.module_id == "tiktok"
    assert hit.module_name == "TikTok Pixel"
    assert hit.host == "analytics.tiktok.com"
    assert hit.url == url
    assert hit.events == [99]