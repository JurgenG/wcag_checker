"""Tests for the Adform SSP / cookie-sync detector module.

Adform (Adform A/S, Denmark) runs a multi-host cookie-sync + ad
exchange stack:

* ``c1.adform.net`` — primary cookie-match endpoint
  (``/serving/cookie/match``). Sets the ``uid`` first-party-side
  pseudonym with ~3-month ``Expires``.
* ``cm.adform.net`` — cookie management endpoint.
* ``track.adform.net`` — tracking / sync (``/serving/cookie/match/``,
  legacy ``/Serving/Cookie/`` with ``adfaction`` param).
* ``adx.adform.net`` — OpenRTB ad exchange (``/adx/openrtb``).

Pattern follows ``tests/test_modules_ga4.py``. The real-bundle
integration test uses ``/tmp/apple-max.zip`` and skips gracefully if
the working-dataset bundle isn't present.
"""

from __future__ import annotations

import pytest

from leak_inspector.events import RequestEvent
from leak_inspector.modules.base import (
    CAT_CONSENT,
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_TECHNICAL,
    IMPACT_HIGH,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    all_modules,
    detect,
)


def _request(
    *,
    host: str,
    url: str,
    method: str = "GET",
    request_body: str | None = None,
    headers: dict[str, str] | None = None,
    event_id: int = 1,
    timestamp: str = "2026-06-04T10:00:00Z",
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
def adform():
    for module in all_modules():
        if module.module_id == "adform":
            return module
    raise AssertionError("adform module not registered")


# --- A. class identity ------------------------------------------------------


def test_module_registered() -> None:
    assert "adform" in [m.module_id for m in all_modules()]


def test_module_identity(adform) -> None:
    assert adform.module_id == "adform"
    assert "Adform" in adform.module_name


def test_module_sovereignty(adform) -> None:
    """Adform A/S is Denmark-based — EU controller, GDPR applies directly."""
    assert "Adform" in adform.vendor
    assert adform.legal_jurisdiction in ("DK", "EU")


# --- B. matches() — positive cases ------------------------------------------


@pytest.mark.parametrize(
    "host,path",
    [
        ("c1.adform.net", "/serving/cookie/match"),
        ("c1.adform.net", "/cookie"),
        ("cm.adform.net", "/cookie"),
        ("track.adform.net", "/serving/cookie/match/"),
        ("track.adform.net", "/Serving/Cookie/"),
        ("adx.adform.net", "/adx/openrtb"),
    ],
)
def test_matches_documented_adform_hosts(adform, host: str, path: str) -> None:
    url = f"https://{host}{path}"
    assert adform.matches(_request(host=host, url=url)) is True


def test_matches_is_case_insensitive_on_host(adform) -> None:
    url = "https://C1.ADFORM.NET/serving/cookie/match"
    assert adform.matches(_request(host="C1.ADFORM.NET", url=url)) is True


# --- C. matches() — negative cases -----------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "example.com",
        "adform-impersonator.example",
        "fakeadform.com",
        "adform.example.com",  # not on the adform.net suffix
    ],
)
def test_does_not_match_unrelated_hosts(adform, host: str) -> None:
    url = f"https://{host}/serving/cookie/match"
    assert adform.matches(_request(host=host, url=url)) is False


# --- D. dispatcher routing -------------------------------------------------


def test_detect_routes_to_adform() -> None:
    req = _request(
        host="c1.adform.net",
        url="https://c1.adform.net/serving/cookie/match?party=22&gdpr=1",
    )
    module = detect(req)
    assert module is not None
    assert module.module_id == "adform"


# --- E. parse() — classification + Hit shape -------------------------------


def test_parse_classifies_partner_identifier(adform) -> None:
    """``party`` is the partner-being-synced — account-scoped TECHNICAL / LOW."""
    url = "https://c1.adform.net/serving/cookie/match?party=22&gdpr=1"
    hit = adform.parse(_request(host="c1.adform.net", url=url))
    by_key = {p.key: p for p in hit.params}
    assert by_key["party"].category == CAT_TECHNICAL
    assert by_key["party"].privacy_impact == IMPACT_LOW


def test_parse_classifies_publisher_user_id(adform) -> None:
    """``publisher_user_id`` is publisher-side PII — HIGH identifier."""
    url = (
        "https://track.adform.net/serving/cookie/match/"
        "?party=5&publisher_user_id=abc-def-123&publisher_dsp_id=11"
    )
    hit = adform.parse(_request(host="track.adform.net", url=url))
    by_key = {p.key: p for p in hit.params}
    assert by_key["publisher_user_id"].category == CAT_IDENTIFIER
    assert by_key["publisher_user_id"].privacy_impact == IMPACT_HIGH


def test_parse_classifies_redirect_chain_as_content(adform) -> None:
    """``redirect_url`` / ``publisher_redirecturl`` / ``sspurl`` leak target URLs."""
    url = (
        "https://c1.adform.net/cookie"
        "?redirect_url=https%3A%2F%2Fs.seedtag.com%2Fcs%2Fcookiesync%2Fadform"
    )
    hit = adform.parse(_request(host="c1.adform.net", url=url))
    by_key = {p.key: p for p in hit.params}
    assert by_key["redirect_url"].category == CAT_CONTENT
    assert by_key["redirect_url"].privacy_impact == IMPACT_MEDIUM


def test_parse_classifies_consent_signals(adform) -> None:
    url = (
        "https://c1.adform.net/serving/cookie/match"
        "?party=22&gdpr=1&gdpr_consent=CQlR&gpp=DBABLA&gpp_sid=7&us_privacy=1YNN"
    )
    hit = adform.parse(_request(host="c1.adform.net", url=url))
    by_key = {p.key: p for p in hit.params}
    for key in ("gdpr", "gdpr_consent", "gpp", "gpp_sid", "us_privacy"):
        assert by_key[key].category == CAT_CONSENT, key
        assert by_key[key].privacy_impact == IMPACT_LOW, key


def test_parse_classifies_adfaction_as_technical(adform) -> None:
    """Legacy ``adfaction`` is a method indicator — TECHNICAL / LOW."""
    url = "https://track.adform.net/Serving/Cookie/?adfaction=getjs;adfcookname=uid"
    hit = adform.parse(_request(host="track.adform.net", url=url))
    by_key = {p.key: p for p in hit.params}
    assert by_key["adfaction"].category == CAT_TECHNICAL
    assert by_key["adfaction"].privacy_impact == IMPACT_LOW


def test_parse_hit_basics(adform) -> None:
    url = "https://c1.adform.net/serving/cookie/match?party=22"
    hit = adform.parse(_request(host="c1.adform.net", url=url, event_id=88))
    assert hit.module_id == "adform"
    assert hit.host == "c1.adform.net"
    assert hit.events == [88]


# --- F. real-bundle integration --------------------------------------------


def test_real_bundle_attribution() -> None:
    """All adform.net hosts on /tmp/apple-max.zip attribute to adform."""
    from pathlib import Path
    bundle_path = Path("/tmp/apple-max.zip")
    if not bundle_path.exists():
        pytest.skip("working-dataset bundle /tmp/apple-max.zip not present")
    from leak_inspector.analysis import analyze_events
    from leak_inspector.bundle.reader import BundleReader
    with BundleReader(bundle_path) as b:
        analysis = analyze_events(b.manifest, b.events(), cname_chains=b.cname_chains)
    adform_hits = [
        h for h in analysis.hits
        if ".adform.net" in h.host or h.host == "adform.net"
    ]
    adform_untracked = [
        e for e in analysis.untracked_requests
        if ".adform.net" in e.host or e.host == "adform.net"
    ]
    assert adform_untracked == [], (
        f"Adform requests still untracked: "
        f"{[(e.host, e.url) for e in adform_untracked[:5]]}"
    )
    assert adform_hits, "no Adform hits attributed at all"
    assert {h.module_id for h in adform_hits} == {"adform"}
