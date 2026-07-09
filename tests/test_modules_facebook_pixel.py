"""Tests for the Meta (Facebook) Pixel module."""

from __future__ import annotations

import json

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_CONSENT,
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_PII,
    CAT_TECHNICAL,
    IMPACT_HIGH,
    IMPACT_LOW,
    IMPACT_MEDIUM,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def fb():
    return module_by_id("facebook_pixel")


def test_identity(fb) -> None:
    assert fb.module_id == "facebook_pixel"
    assert fb.module_name == "Meta (Facebook) Pixel"


def test_matches_pixel_endpoint(fb) -> None:
    event = make_request(host="www.facebook.com", url="https://www.facebook.com/tr?id=123&ev=PageView")
    assert fb.matches(event) is True


def test_matches_pixel_with_trailing_slash(fb) -> None:
    event = make_request(host="www.facebook.com", url="https://www.facebook.com/tr/")
    assert fb.matches(event) is True


def test_matches_b_php_cookie_sync(fb) -> None:
    event = make_request(host="www.facebook.com", url="https://www.facebook.com/b.php?p=1&e=X")
    assert fb.matches(event) is True


def test_matches_localized_b_php(fb) -> None:
    """``/<locale>/b.php`` (e.g. ``/fr/b.php``) is also claimed."""
    event = make_request(host="www.facebook.com", url="https://www.facebook.com/fr/b.php?p=1")
    assert fb.matches(event) is True


def test_matches_loader_host(fb) -> None:
    event = make_request(host="connect.facebook.net", url="https://connect.facebook.net/en_US/fbevents.js")
    assert fb.matches(event) is True


def test_does_not_match_facebook_marketing_path(fb) -> None:
    """``facebook.com`` paths other than ``/tr`` and ``/b.php`` are NOT claimed."""
    event = make_request(host="www.facebook.com", url="https://www.facebook.com/somepage")
    assert fb.matches(event) is False


def test_does_not_match_unrelated(fb) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert fb.matches(event) is False


@pytest.mark.parametrize("key", ["fbp", "fbc"])
def test_cookies_high_impact(fb, key: str) -> None:
    event = make_request(host="www.facebook.com", url=f"https://www.facebook.com/tr?{key}=ABC")
    hit = fb.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


def test_external_id_is_pii(fb) -> None:
    event = make_request(host="www.facebook.com", url="https://www.facebook.com/tr?external_id=user@example.com")
    hit = fb.parse(event)
    p = next(p for p in hit.params if p.key == "external_id")
    assert p.category == CAT_PII


@pytest.mark.parametrize("key", ["em", "ph", "fn", "ln", "db", "ge", "ct", "st", "zp", "country"])
def test_advanced_matching_hashed_pii(fb, key: str) -> None:
    event = make_request(host="www.facebook.com", url=f"https://www.facebook.com/tr?{key}=hashedvalue")
    hit = fb.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_PII
    assert p.privacy_impact == IMPACT_HIGH


def test_b_php_e_is_high(fb) -> None:
    """``e`` on /b.php carries the partner-supplied visitor pseudonym (cookie sync)."""
    event = make_request(host="www.facebook.com", url="https://www.facebook.com/b.php?p=1&e=PARTNERUID")
    hit = fb.parse(event)
    p = next(p for p in hit.params if p.key == "e")
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


def test_cd_prefix_is_behavioral(fb) -> None:
    """``cd[content_name]`` → CAT_BEHAVIORAL, meaning includes the inner key."""
    event = make_request(host="www.facebook.com", url="https://www.facebook.com/tr?cd[content_name]=Shoes")
    hit = fb.parse(event)
    p = next(p for p in hit.params if p.key == "cd[content_name]")
    assert p.category == CAT_BEHAVIORAL
    assert "content_name" in p.meaning


def test_ud_prefix_is_pii(fb) -> None:
    """``ud[em]`` → CAT_PII (hashed-PII user-data field)."""
    event = make_request(host="www.facebook.com", url="https://www.facebook.com/tr?ud[em]=hashed")
    hit = fb.parse(event)
    p = next(p for p in hit.params if p.key == "ud[em]")
    assert p.category == CAT_PII


def test_skip_keys_filtered(fb) -> None:
    """Internal noise keys (``cs_est``, ``ler``, ``tm``, ``pmd[…]``, ``expv2[N]``) are filtered."""
    event = make_request(
        host="www.facebook.com",
        url="https://www.facebook.com/tr?id=1&cs_est=2&ler=3&tm=4&pmd[title]=x&expv2[0]=y",
    )
    hit = fb.parse(event)
    keys = [p.key for p in hit.params]
    assert "id" in keys  # kept
    for skipped in ["cs_est", "ler", "tm", "pmd[title]", "expv2[0]"]:
        assert skipped not in keys


def test_capi_json_body_extracts_event_metadata(fb) -> None:
    body = json.dumps({
        "data": [{
            "event_name": "Purchase",
            "event_id": "EID-1",
            "event_time": 1717000000,
            "event_source_url": "https://example.com/checkout",
            "action_source": "website",
            "user_data": {"em": "hashedemail", "fbp": "FBP-VAL"},
            "custom_data": {"value": "49.95", "currency": "EUR", "search_string": "running shoes"},
        }, {
            "event_name": "AddToCart",
        }],
    })
    event = make_request(
        host="www.facebook.com",
        url="https://www.facebook.com/tr",
        method="POST",
        request_body=body,
    )
    hit = fb.parse(event)
    by_key = {p.key: p for p in hit.params}
    assert by_key["(body) capi_event_count"].value == "2"
    assert "Purchase" in by_key["(body) event_names"].value
    assert "AddToCart" in by_key["(body) event_names"].value
    assert by_key["(body) event_name"].value == "Purchase"
    assert by_key["(body) event_source_url"].category == CAT_CONTENT
    # user_data fields are PII HIGH
    assert by_key["(body) user_data.em"].category == CAT_PII
    assert by_key["(body) user_data.em"].privacy_impact == IMPACT_HIGH
    assert "hashed email" in by_key["(body) user_data.em"].meaning
    # custom_data: search_string is PII; other custom keys are behavioral
    assert by_key["(body) custom_data.search_string"].category == CAT_PII
    assert by_key["(body) custom_data.value"].category == CAT_BEHAVIORAL


def test_multipart_body_marker(fb) -> None:
    """Multipart bodies surface a single marker rather than mis-parsed garbage."""
    body = "------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"foo\"\r\n\r\nbar"
    event = make_request(
        host="www.facebook.com",
        url="https://www.facebook.com/tr",
        method="POST",
        request_body=body,
    )
    hit = fb.parse(event)
    p = next(p for p in hit.params if p.key == "(body) multipart_event_data")
    assert "multipart" in p.value.lower()


def test_form_encoded_body_fallback(fb) -> None:
    """Form-encoded body (no content-type header) gets re-parsed via fallback."""
    event = make_request(
        host="www.facebook.com",
        url="https://www.facebook.com/tr",
        method="POST",
        request_body="id=123&ev=Purchase&em=hashedemail",
        headers={},  # no Content-Type — body_params will be empty
    )
    hit = fb.parse(event)
    by_key = {p.key: p for p in hit.params}
    assert by_key["(body) ev"].category == CAT_BEHAVIORAL
    assert by_key["(body) em"].category == CAT_PII


def test_form_encoded_skipped_when_body_params_present(fb) -> None:
    """If Content-Type was set, ``body_params`` already merged the body — no double-count."""
    event = make_request(
        host="www.facebook.com",
        url="https://www.facebook.com/tr",
        method="POST",
        request_body="id=123&ev=Purchase",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    hit = fb.parse(event)
    keys = [p.key for p in hit.params]
    # The query-string parser already picked up id+ev; the fallback parser must NOT re-emit them.
    assert "(body) id" not in keys
    assert "(body) ev" not in keys


def test_unknown_param(fb) -> None:
    event = make_request(host="www.facebook.com", url="https://www.facebook.com/tr?weirdo=1")
    hit = fb.parse(event)
    p = next(p for p in hit.params if p.key == "weirdo")
    assert p.category == CAT_OTHER


# --- Meta social plugins (Page Plugin / tab renderer / plugin logging) ----


@pytest.mark.parametrize(
    "path",
    [
        "/v2.11/plugins/page.php",
        "/v8.0/plugins/page.php",
        "/v2.3/plugins/page.php",
        "/v16.0/plugins/like.php",
        "/plugins/page.php",
    ],
)
def test_matches_social_plugin_versioned_paths(fb, path: str) -> None:
    event = make_request(
        host="www.facebook.com",
        url=f"https://www.facebook.com{path}?app_id=12345&href=https%3A%2F%2Fwww.facebook.com%2Fexample",
    )
    assert fb.matches(event) is True


@pytest.mark.parametrize(
    "path",
    [
        "/platform/plugin/page/logging/",
        "/platform/plugin/tab/renderer/",
    ],
)
def test_matches_platform_plugin_telemetry(fb, path: str) -> None:
    event = make_request(host="www.facebook.com", url=f"https://www.facebook.com{path}")
    assert fb.matches(event) is True


def test_app_id_is_technical(fb) -> None:
    """``app_id`` is the FB App ID the embed is associated with — operator-scoped."""
    event = make_request(
        host="www.facebook.com",
        url="https://www.facebook.com/v2.11/plugins/page.php?app_id=176233119649050",
    )
    hit = fb.parse(event)
    p = next(p for p in hit.params if p.key == "app_id")
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


def test_href_is_content(fb) -> None:
    """``href`` is the FB page being embedded — content disclosure."""
    event = make_request(
        host="www.facebook.com",
        url=(
            "https://www.facebook.com/v2.11/plugins/page.php"
            "?href=https%3A%2F%2Fwww.facebook.com%2Fcommune.example"
        ),
    )
    hit = fb.parse(event)
    p = next(p for p in hit.params if p.key == "href")
    assert p.category == CAT_CONTENT


def test_channel_is_content(fb) -> None:
    """``channel`` exposes the embedding origin (staticxx.facebook.com callback URL)."""
    event = make_request(
        host="www.facebook.com",
        url=(
            "https://www.facebook.com/v2.11/plugins/page.php"
            "?channel=https%3A%2F%2Fstaticxx.facebook.com%2Fx%2Fconnect%2Fxd_arbiter%2F"
        ),
    )
    hit = fb.parse(event)
    p = next(p for p in hit.params if p.key == "channel")
    assert p.category == CAT_CONTENT


# --- Meta CDN assets pulled by social plugins ------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "static.xx.fbcdn.net",
        "scontent.xx.fbcdn.net",
        "scontent-cdg6-1.xx.fbcdn.net",
        "scontent-ams2-1.xx.fbcdn.net",
    ],
)
def test_matches_fbcdn_hosts(fb, host: str) -> None:
    """fbcdn.net serves JS / images for the Page Plugin iframe — claim them as Meta."""
    event = make_request(host=host, url=f"https://{host}/rsrc.php/v4/abc.js")
    assert fb.matches(event) is True


def test_does_not_match_unrelated_facebook_path(fb) -> None:
    """``www.facebook.com/<username>`` (regular profile page) is NOT a tracker hit."""
    event = make_request(host="www.facebook.com", url="https://www.facebook.com/zuckerberg")
    assert fb.matches(event) is False
