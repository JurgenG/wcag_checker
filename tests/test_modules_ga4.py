"""Tests for the GA4 tracker module.

Worked example for the tracker test pattern. Covers the 26 spec rules
across 5 groups: class identity, matches(), Hit construction, body
handling, parameter classification.
"""

from __future__ import annotations

import pytest

from leak_inspector.events import RequestEvent
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
    Hit,
    all_modules,
    detect,
)
from leak_inspector.modules.ga4 import GA4Module


# --- helpers ----------------------------------------------------------------


def _request(
    *,
    host: str,
    url: str,
    method: str = "POST",
    request_body: str | None = None,
    headers: dict[str, str] | None = None,
    event_id: int = 1,
    timestamp: str = "2026-05-01T12:00:00Z",
    response_status: int | None = 204,
) -> RequestEvent:
    """Build a RequestEvent suitable for a tracker module test."""
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
def ga4() -> GA4Module:
    """Return the registered GA4 module instance."""
    for module in all_modules():
        if module.module_id == "ga4":
            return module  # type: ignore[return-value]
    raise AssertionError("GA4 module not registered")


# --- A. class identity ------------------------------------------------------


def test_ga4_is_registered() -> None:
    module_ids = [m.module_id for m in all_modules()]
    assert "ga4" in module_ids


def test_ga4_module_id_and_name(ga4: GA4Module) -> None:
    assert ga4.module_id == "ga4"
    assert ga4.module_name == "Google Analytics 4"


def test_ga4_sovereignty_attributes(ga4: GA4Module) -> None:
    assert ga4.vendor == "Google LLC"
    assert ga4.legal_jurisdiction == "US"
    assert ga4.data_residency  # non-empty
    assert ga4.sovereignty_notes  # non-empty


# --- B. matches() — host/path ----------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "google-analytics.com",
        "www.google-analytics.com",
        "GOOGLE-ANALYTICS.COM",  # case-insensitive
        "analytics.google.com",
    ],
)
@pytest.mark.parametrize(
    "path",
    ["/g/collect", "/collect", "/j/collect", "/r/collect", "/analytics.js"],
)
def test_matches_primary_ga_hosts_and_paths(
    ga4: GA4Module, host: str, path: str,
) -> None:
    event = _request(host=host, url=f"https://{host}{path}?tid=G-XYZ")
    assert ga4.matches(event) is True


def test_matches_does_not_claim_other_paths_on_ga_host(ga4: GA4Module) -> None:
    event = _request(
        host="www.google-analytics.com",
        url="https://www.google-analytics.com/some/other/path",
    )
    assert ga4.matches(event) is False


@pytest.mark.parametrize("path", ["/g/collect", "/collect"])
def test_matches_regional_ga4_ingest(ga4: GA4Module, path: str) -> None:
    event = _request(
        host="region1.analytics.google.com",
        url=f"https://region1.analytics.google.com{path}?tid=G-XYZ",
    )
    assert ga4.matches(event) is True


def test_matches_regional_host_does_not_claim_loader_path(ga4: GA4Module) -> None:
    event = _request(
        host="region1.analytics.google.com",
        url="https://region1.analytics.google.com/analytics.js",
    )
    assert ga4.matches(event) is False


def test_matches_gtm_td(ga4: GA4Module) -> None:
    event = _request(
        host="www.googletagmanager.com",
        url="https://www.googletagmanager.com/td?tid=G-X",
    )
    assert ga4.matches(event) is True


def test_matches_gtm_gtag_js_with_is_td(ga4: GA4Module) -> None:
    event = _request(
        host="www.googletagmanager.com",
        url="https://www.googletagmanager.com/gtag/js?is_td=1&id=G-X",
    )
    assert ga4.matches(event) is True


def test_matches_gtm_gtag_js_without_is_td_does_not_match(ga4: GA4Module) -> None:
    event = _request(
        host="www.googletagmanager.com",
        url="https://www.googletagmanager.com/gtag/js?id=G-X",
    )
    assert ga4.matches(event) is False


def test_matches_doubleclick_sidecar(ga4: GA4Module) -> None:
    event = _request(
        host="stats.g.doubleclick.net",
        url="https://stats.g.doubleclick.net/g/collect?tid=G-X",
    )
    assert ga4.matches(event) is True


@pytest.mark.parametrize(
    "host",
    ["www.google.com", "www.google.co.uk", "www.google.de"],
)
def test_matches_audience_pixel_on_www_google_tlds(
    ga4: GA4Module, host: str,
) -> None:
    event = _request(
        host=host,
        url=f"https://{host}/ads/ga-audiences?tid=G-X",
        method="GET",
    )
    assert ga4.matches(event) is True


def test_matches_audience_pixel_does_not_claim_bare_google_com(
    ga4: GA4Module,
) -> None:
    event = _request(
        host="google.com",
        url="https://google.com/ads/ga-audiences",
    )
    assert ga4.matches(event) is False


def test_matches_returns_false_for_unrelated_host(ga4: GA4Module) -> None:
    event = _request(
        host="example.com",
        url="https://example.com/g/collect",
    )
    assert ga4.matches(event) is False


def test_matches_via_detect_returns_ga4_module() -> None:
    event = _request(
        host="www.google-analytics.com",
        url="https://www.google-analytics.com/g/collect?tid=G-X",
    )
    found = detect(event)
    assert found is not None
    assert found.module_id == "ga4"


# --- C. parse() — Hit construction -----------------------------------------


def test_parse_hit_metadata(ga4: GA4Module) -> None:
    event = _request(
        host="www.google-analytics.com",
        url="https://www.google-analytics.com/g/collect?tid=G-X",
        method="POST",
        event_id=42,
        timestamp="2026-05-01T12:34:56Z",
        response_status=204,
    )
    hit = ga4.parse(event)
    assert isinstance(hit, Hit)
    assert hit.module_id == "ga4"
    assert hit.module_name == "Google Analytics 4"
    assert hit.url == event.url
    assert hit.host == event.host
    assert hit.method == "POST"
    assert hit.response_status == 204
    assert hit.started_at == "2026-05-01T12:34:56Z"
    assert hit.events == [42]


def test_parse_emits_one_paraminfo_per_query_param(ga4: GA4Module) -> None:
    event = _request(
        host="www.google-analytics.com",
        url="https://www.google-analytics.com/g/collect?tid=G-X&cid=12345.67890&dl=https://example.com/p",
    )
    hit = ga4.parse(event)
    keys = [p.key for p in hit.params]
    assert keys[:3] == ["tid", "cid", "dl"]
    values_by_key = {p.key: p.value for p in hit.params}
    assert values_by_key["tid"] == "G-X"
    assert values_by_key["cid"] == "12345.67890"
    assert values_by_key["dl"] == "https://example.com/p"
    for p in hit.params:
        assert p.event_index == event.event_id


def test_parse_query_params_come_before_body_params(ga4: GA4Module) -> None:
    event = _request(
        host="www.google-analytics.com",
        url="https://www.google-analytics.com/g/collect?tid=G-X",
        request_body="en=page_view&dl=https://example.com/",
        headers={"Content-Type": "text/plain"},  # GA4 sendBeacon
    )
    hit = ga4.parse(event)
    keys = [p.key for p in hit.params]
    # Query first, then labeled body params.
    assert keys[0] == "tid"
    assert any(k.startswith("(body)") for k in keys[1:])


# --- D. parse() — body handling --------------------------------------------


def test_parse_empty_body_produces_no_body_params(ga4: GA4Module) -> None:
    event = _request(
        host="www.google-analytics.com",
        url="https://www.google-analytics.com/g/collect?tid=G-X&cid=1",
        request_body="",
    )
    hit = ga4.parse(event)
    assert all(not p.key.startswith("(body") for p in hit.params)


def test_parse_single_line_body_labels_with_body_prefix(ga4: GA4Module) -> None:
    event = _request(
        host="www.google-analytics.com",
        url="https://www.google-analytics.com/g/collect?tid=G-X",
        request_body="en=page_view&dl=https%3A%2F%2Fexample.com%2F",
    )
    hit = ga4.parse(event)
    keys = [p.key for p in hit.params]
    assert "(body) en" in keys
    assert "(body) dl" in keys


def test_parse_single_line_body_skips_keys_already_in_query(ga4: GA4Module) -> None:
    """Keys present in both URL query and body must not be duplicated."""
    event = _request(
        host="www.google-analytics.com",
        url="https://www.google-analytics.com/g/collect?tid=G-X",
        request_body="tid=G-X&en=page_view",
    )
    hit = ga4.parse(event)
    keys = [p.key for p in hit.params]
    # tid is in the URL query, must NOT reappear as "(body) tid".
    assert "(body) tid" not in keys
    assert "tid" in keys
    assert "(body) en" in keys


def test_parse_multiline_body_labels_with_event_index(ga4: GA4Module) -> None:
    event = _request(
        host="www.google-analytics.com",
        url="https://www.google-analytics.com/g/collect?tid=G-X",
        request_body="en=page_view&dl=a\nen=click&dl=b\nen=scroll&dl=c",
    )
    hit = ga4.parse(event)
    keys = [p.key for p in hit.params]
    # 1-indexed labels per line.
    assert "(body ev#1) en" in keys
    assert "(body ev#2) en" in keys
    assert "(body ev#3) en" in keys


def test_parse_multiline_body_emits_batched_event_count(ga4: GA4Module) -> None:
    event = _request(
        host="www.google-analytics.com",
        url="https://www.google-analytics.com/g/collect?tid=G-X",
        request_body="en=page_view\nen=click\nen=scroll",
    )
    hit = ga4.parse(event)
    by_key = {p.key: p for p in hit.params}
    assert "(body) batched_event_count" in by_key
    summary = by_key["(body) batched_event_count"]
    assert summary.value == "3"
    assert summary.category == CAT_BEHAVIORAL
    assert summary.meaning == "Number of events shipped in this batched POST"
    assert summary.privacy_impact == IMPACT_MEDIUM


# --- E. classification ------------------------------------------------------


def _classify_via_parse(ga4: GA4Module, key: str, value: str = "v") -> tuple[str, str, str]:
    """Run a single-key URL through parse() and return the param's classification."""
    event = _request(
        host="www.google-analytics.com",
        url=f"https://www.google-analytics.com/g/collect?{key}={value}",
    )
    hit = ga4.parse(event)
    param = next(p for p in hit.params if p.key == key)
    return param.category, param.meaning, param.privacy_impact


def test_classify_known_cid(ga4: GA4Module) -> None:
    category, meaning, impact = _classify_via_parse(ga4, "cid", "12345.67890")
    assert category == CAT_IDENTIFIER
    assert "client ID" in meaning
    assert impact == IMPACT_HIGH


def test_classify_known_uid(ga4: GA4Module) -> None:
    category, meaning, impact = _classify_via_parse(ga4, "uid", "abc123")
    assert category == CAT_PII
    assert "user ID" in meaning
    assert impact == IMPACT_HIGH


def test_classify_known_dl(ga4: GA4Module) -> None:
    category, meaning, impact = _classify_via_parse(ga4, "dl", "https://x/")
    assert category == CAT_CONTENT
    assert "Document location" in meaning
    assert impact == IMPACT_MEDIUM


def test_classify_known_aip(ga4: GA4Module) -> None:
    category, meaning, impact = _classify_via_parse(ga4, "aip", "1")
    assert category == CAT_CONSENT
    assert "Anonymize-IP" in meaning
    assert impact == IMPACT_LOW


def test_classify_prefix_ep_dot(ga4: GA4Module) -> None:
    category, meaning, impact = _classify_via_parse(ga4, "ep.button_label", "Buy")
    assert category == CAT_BEHAVIORAL
    assert "button_label" in meaning  # sub-key surfaced
    assert impact == IMPACT_MEDIUM


def test_classify_prefix_up_dot(ga4: GA4Module) -> None:
    category, meaning, impact = _classify_via_parse(ga4, "up.account_tier", "gold")
    assert category == CAT_PII
    assert "account_tier" in meaning
    assert impact == IMPACT_HIGH


@pytest.mark.parametrize("key", [
    # Observed in the wild (sokken.nl capture): CMP consent state
    # mirrored into GA4 user properties.
    "up.consent_ad_storage",
    "up.cookie_consent",
    "up.cookie_consent_storage",
    # Numeric variant and uppercase spelling get the same treatment.
    "upn.consent_analytics",
    "up.Consent_Marketing",
])
def test_classify_consent_named_user_property(ga4: GA4Module, key: str) -> None:
    """Consent-named user properties are consent state, not PII."""
    category, meaning, impact = _classify_via_parse(ga4, key, "denied")
    assert category == CAT_CONSENT
    assert key.split(".", 1)[1] in meaning  # sub-key surfaced
    assert "consent" in meaning.lower()
    assert impact == IMPACT_LOW


def test_classify_non_consent_user_property_stays_pii(ga4: GA4Module) -> None:
    """The consent carve-out must not weaken the up.* default."""
    category, _, impact = _classify_via_parse(ga4, "up.email_domain", "x.be")
    assert category == CAT_PII
    assert impact == IMPACT_HIGH


def test_classify_ua_custom_dimension(ga4: GA4Module) -> None:
    category, meaning, impact = _classify_via_parse(ga4, "cd7", "logged_in")
    assert category == CAT_BEHAVIORAL
    assert "dimension" in meaning.lower()
    assert "7" in meaning
    assert impact == IMPACT_MEDIUM


def test_classify_ua_custom_metric(ga4: GA4Module) -> None:
    category, meaning, impact = _classify_via_parse(ga4, "cm42", "3.14")
    assert category == CAT_BEHAVIORAL
    assert "metric" in meaning.lower()
    assert "42" in meaning
    assert impact == IMPACT_MEDIUM


def test_classify_unknown_falls_through_to_other(ga4: GA4Module) -> None:
    category, meaning, impact = _classify_via_parse(ga4, "xyz_unknown_key", "v")
    assert category == CAT_OTHER
    assert meaning == "Unrecognized GA parameter"


# --- legacy Urchin / Universal Analytics (`ga.js` / `__utm.gif`) -----------


@pytest.mark.parametrize(
    "host,path",
    [
        ("ssl.google-analytics.com",  "/ga.js"),
        ("www.google-analytics.com",  "/ga.js"),
        ("ssl.google-analytics.com",  "/__utm.gif"),
        ("www.google-analytics.com",  "/__utm.gif"),
        ("ssl.google-analytics.com",  "/r/__utm.gif"),
        ("ssl.google-analytics.com",  "/urchin.js"),
    ],
)
def test_matches_ga_legacy_paths(ga4: GA4Module, host: str, path: str) -> None:
    event = _request(host=host, url=f"https://{host}{path}", method="GET")
    assert ga4.matches(event) is True


def test_classify_utmac_is_property_identifier(ga4: GA4Module) -> None:
    """``utmac`` carries the UA property ID (e.g. ``UA-12345-1``)."""
    category, meaning, impact = _classify_via_parse(ga4, "utmac", "UA-12345-1")
    assert category == CAT_TECHNICAL
    assert impact == IMPACT_LOW


def test_classify_utmcc_is_high_impact_identifier(ga4: GA4Module) -> None:
    """``utmcc`` carries the ``__utma`` cookie — the visitor pseudonym."""
    category, meaning, impact = _classify_via_parse(
        ga4, "utmcc", "__utma=1.123456789.1700000000.1700000000.1;"
    )
    assert category == CAT_IDENTIFIER
    assert impact == IMPACT_HIGH


@pytest.mark.parametrize("key", ["utmp", "utmr", "utmdt", "utmhn"])
def test_classify_utm_content_fields(ga4: GA4Module, key: str) -> None:
    category, _, _ = _classify_via_parse(ga4, key, "x")
    assert category == CAT_CONTENT


@pytest.mark.parametrize(
    "key", ["utmwv", "utmn", "utms", "utmcs", "utmsr", "utmvp", "utmsc", "utmul",
            "utmje", "utmfl", "utmht", "utmhid", "utmjid", "utmredir", "utmu"],
)
def test_classify_utm_technical_fields(ga4: GA4Module, key: str) -> None:
    category, _, _ = _classify_via_parse(ga4, key, "x")
    assert category in {"technical", "behavioral"}  # behavioral for utme/utmt only
    # Specifically: these should never escalate to PII/identifier.
    from leak_inspector.modules.base import CAT_IDENTIFIER as _ID, CAT_PII as _PII
    assert category not in {_ID, _PII}


def test_classify_utme_is_behavioral(ga4: GA4Module) -> None:
    """``utme`` carries custom variables / events."""
    category, _, _ = _classify_via_parse(ga4, "utme", "5(role*staff)")
    assert category == CAT_BEHAVIORAL


def test_legacy_hit_parses_end_to_end(ga4: GA4Module) -> None:
    """Real-world __utm.gif URL — every classification triggers and the hit is well-formed."""
    url = (
        "https://ssl.google-analytics.com/r/__utm.gif"
        "?utmwv=5.7.2&utms=1&utmn=1003226684&utmhn=www.berlaar.be"
        "&utmcs=UTF-8&utmsr=1920x1200&utmac=UA-12345-1"
        "&utmcc=__utma%3D1.111.1700000000.1700000000.1%3B"
    )
    event = _request(host="ssl.google-analytics.com", url=url, method="GET")
    assert ga4.matches(event)
    hit = ga4.parse(event)
    keys = {p.key for p in hit.params}
    assert "utmwv" in keys and "utmac" in keys and "utmcc" in keys
    utmac = next(p for p in hit.params if p.key == "utmac")
    assert utmac.category == CAT_TECHNICAL
    utmcc = next(p for p in hit.params if p.key == "utmcc")
    assert utmcc.privacy_impact == IMPACT_HIGH