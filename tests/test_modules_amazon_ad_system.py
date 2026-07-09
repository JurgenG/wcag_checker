"""Tests for the Amazon Ad System (APS / DTB / TAM) detector module.

Amazon.com Services LLC (US) operates a multi-host ad exchange:

* ``aax-eu.amazon-adsystem.com`` — EU-region partner-sync + RTB
  (``/s/ecm3``, ``/s/dcm``, ``/s/iu3``, ``/s/v3/pr``).
* ``aax.amazon-adsystem.com`` — global ad exchange.
* ``s.amazon-adsystem.com`` — sync (``/dcm``, ``/ecm3``).
* ``c.amazon-adsystem.com`` / ``c.aps.amazon-adsystem.com`` —
  apstag.js loader CDN.
* ``config.aps.amazon-adsystem.com`` — APS publisher configs
  (``/configs/<UUID>``).
* ``client.aps.amazon-adsystem.com`` — publisher.js client.
* ``web.ads.aps.amazon-adsystem.com`` — Prebid OpenRTB header bidding
  (``/e/pb/bid``).
* ``web-video.ads.aps.amazon-adsystem.com`` /
  ``web-banner.ads.aps.amazon-adsystem.com`` — direct-to-buyer
  bidding (``/e/dtb/bid``) with OpenRTB JSON body.

Pattern follows ``tests/test_modules_ga4.py``. The real-bundle
integration test uses ``/tmp/apple-max.zip``.
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
def amazon():
    for module in all_modules():
        if module.module_id == "amazon_ad_system":
            return module
    raise AssertionError("amazon_ad_system module not registered")


# --- A. class identity ------------------------------------------------------


def test_module_registered() -> None:
    assert "amazon_ad_system" in [m.module_id for m in all_modules()]


def test_module_identity(amazon) -> None:
    assert amazon.module_id == "amazon_ad_system"
    assert "Amazon" in amazon.module_name


def test_module_sovereignty(amazon) -> None:
    """Amazon Ad System is US-controller — CLOUD Act applies."""
    assert "Amazon" in amazon.vendor
    assert amazon.legal_jurisdiction == "US"
    notes = (amazon.sovereignty_notes or "").lower()
    assert "cloud act" in notes or "schrems" in notes


# --- B. matches() — positive cases ------------------------------------------


@pytest.mark.parametrize(
    "host,path",
    [
        # EU-region sync + RTB
        ("aax-eu.amazon-adsystem.com", "/s/ecm3"),
        ("aax-eu.amazon-adsystem.com", "/s/dcm"),
        ("aax-eu.amazon-adsystem.com", "/s/iu3"),
        ("aax-eu.amazon-adsystem.com", "/s/v3/pr"),
        # Global
        ("aax.amazon-adsystem.com", "/e/dtb/bid/54689.54/0/prebid"),
        # Sync
        ("s.amazon-adsystem.com", "/dcm"),
        ("s.amazon-adsystem.com", "/ecm3"),
        # apstag.js CDN
        ("c.amazon-adsystem.com", "/aax2/apstag.js"),
        ("c.amazon-adsystem.com", "/bao-csm/aps-comm/aps_csm.js"),
        ("c.aps.amazon-adsystem.com", "/apstag.js"),
        # APS publisher config
        ("config.aps.amazon-adsystem.com", "/configs/aa05931b-5308-4ea3-95a2-adf84f4ffde4"),
        ("config.aps.amazon-adsystem.com", "/configs/3032"),
        # client.aps publisher.js
        ("client.aps.amazon-adsystem.com", "/publisher.js"),
        # Header bidding (Prebid OpenRTB)
        ("web.ads.aps.amazon-adsystem.com", "/e/pb/bid"),
        # Direct-to-buyer bidding
        ("web-video.ads.aps.amazon-adsystem.com", "/e/dtb/bid"),
        ("web-banner.ads.aps.amazon-adsystem.com", "/e/dtb/bid"),
    ],
)
def test_matches_documented_amazon_hosts(amazon, host: str, path: str) -> None:
    url = f"https://{host}{path}"
    assert amazon.matches(_request(host=host, url=url)) is True


def test_matches_apex_amazon_adsystem(amazon) -> None:
    """The apex ``amazon-adsystem.com`` is also Amazon — claim it too."""
    url = "https://amazon-adsystem.com/some/path"
    assert amazon.matches(_request(host="amazon-adsystem.com", url=url)) is True


def test_matches_is_case_insensitive_on_host(amazon) -> None:
    url = "https://AAX-EU.AMAZON-ADSYSTEM.COM/s/ecm3"
    assert amazon.matches(_request(host="AAX-EU.AMAZON-ADSYSTEM.COM", url=url)) is True


# --- C. matches() — negative cases -----------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        # Amazon Retail / AWS — different controllers, different scopes
        "www.amazon.com",
        "aws.amazon.com",
        # Impersonators
        "amazon-adsystem-impersonator.example",
        "fakeamazon-adsystem.com",
        "amazon-adsystem.example.com",
        "example.com",
    ],
)
def test_does_not_match_unrelated_hosts(amazon, host: str) -> None:
    url = f"https://{host}/s/ecm3"
    assert amazon.matches(_request(host=host, url=url)) is False


# --- D. dispatcher routing -------------------------------------------------


def test_detect_routes_to_amazon_ad_system() -> None:
    req = _request(
        host="aax-eu.amazon-adsystem.com",
        url="https://aax-eu.amazon-adsystem.com/s/ecm3?ex=loopme.com&id=abc",
    )
    module = detect(req)
    assert module is not None
    assert module.module_id == "amazon_ad_system"


# --- E. parse() — query-param classification + Hit shape ------------------


def test_parse_classifies_visitor_id_as_high(amazon) -> None:
    """``id`` is the Amazon visitor pseudonym — HIGH identifier."""
    url = (
        "https://aax-eu.amazon-adsystem.com/s/dcm"
        "?pid=06432402-c0d4-41b0-b9b9-42da4286c781"
        "&id=019e9196-90d6-7639-9a5d-3534a314702c&gdpr=1"
    )
    hit = amazon.parse(_request(host="aax-eu.amazon-adsystem.com", url=url))
    by_key = {p.key: p for p in hit.params}
    assert by_key["id"].category == CAT_IDENTIFIER
    assert by_key["id"].privacy_impact == IMPACT_HIGH


def test_parse_classifies_partner_being_synced(amazon) -> None:
    """``ex`` names the partner being matched — config-scoped TECHNICAL (graph edge)."""
    url = (
        "https://s.amazon-adsystem.com/ecm3"
        "?id=MPZ6V9J4-27-ACRO&ex=d-rubiconproject.com&status=ok"
    )
    hit = amazon.parse(_request(host="s.amazon-adsystem.com", url=url))
    by_key = {p.key: p for p in hit.params}
    assert by_key["ex"].category == CAT_TECHNICAL
    assert by_key["ex"].privacy_impact == IMPACT_LOW


def test_parse_classifies_exlist(amazon) -> None:
    """``exlist`` enumerates the partner graph — config-scoped TECHNICAL."""
    url = (
        "https://aax-eu.amazon-adsystem.com/s/v3/pr"
        "?exlist=n-index_n-start_n-LoopMe_sovrn_n-Outbrain"
    )
    hit = amazon.parse(_request(host="aax-eu.amazon-adsystem.com", url=url))
    by_key = {p.key: p for p in hit.params}
    assert by_key["exlist"].category == CAT_TECHNICAL
    assert by_key["exlist"].privacy_impact == IMPACT_LOW


def test_parse_classifies_consent_signals(amazon) -> None:
    url = (
        "https://aax-eu.amazon-adsystem.com/s/ecm3"
        "?ex=loopme.com&gdpr=1&gdpr_consent=CQlR"
    )
    hit = amazon.parse(_request(host="aax-eu.amazon-adsystem.com", url=url))
    by_key = {p.key: p for p in hit.params}
    for key in ("gdpr", "gdpr_consent"):
        assert by_key[key].category == CAT_CONSENT, key
        assert by_key[key].privacy_impact == IMPACT_LOW, key


def test_parse_classifies_technical_internals(amazon) -> None:
    url = (
        "https://aax-eu.amazon-adsystem.com/s/iu3"
        "?cm3ppd=1&d=dtb-pub&csif=t&fv=1&status=ok"
    )
    hit = amazon.parse(_request(host="aax-eu.amazon-adsystem.com", url=url))
    by_key = {p.key: p for p in hit.params}
    for key in ("cm3ppd", "csif", "fv", "status"):
        assert by_key[key].category == CAT_TECHNICAL, key
        assert by_key[key].privacy_impact == IMPACT_LOW, key


# --- F. parse() — JSON body handling ---------------------------------------


def test_parse_surfaces_body_visited_url(amazon) -> None:
    """``u`` in the JSON body leaks the visited page URL — CONTENT MEDIUM."""
    body = (
        '{"src":3032,"u":"https://www.imore.com/","pid":"igONjGlBZwdXS",'
        '"cb":0,"ws":"1280x955","v":"26.526.2229","t":2000,"slots":[]}'
    )
    hit = amazon.parse(_request(
        host="web-banner.ads.aps.amazon-adsystem.com",
        url="https://web-banner.ads.aps.amazon-adsystem.com/e/dtb/bid",
        method="POST",
        request_body=body,
    ))
    by_key = {p.key: p for p in hit.params}
    u = by_key.get("(body) u")
    assert u is not None
    assert u.value == "https://www.imore.com/"
    assert u.category == CAT_CONTENT
    assert u.privacy_impact == IMPACT_MEDIUM


def test_parse_surfaces_body_publisher_and_version(amazon) -> None:
    body = '{"u":"https://example.com/","pid":"KsOITQwuKPR1d","v":"26.526.2229"}'
    hit = amazon.parse(_request(
        host="web.ads.aps.amazon-adsystem.com",
        url="https://web.ads.aps.amazon-adsystem.com/e/pb/bid",
        method="POST",
        request_body=body,
    ))
    by_key = {p.key: p for p in hit.params}
    pid = by_key.get("(body) pid")
    v = by_key.get("(body) v")
    assert pid is not None and pid.category == CAT_TECHNICAL
    assert v is not None and v.category == CAT_TECHNICAL


def test_parse_surfaces_body_slot_count(amazon) -> None:
    """``slots`` array → ``(body) slots_count`` so the report shows fan-out."""
    body = (
        '{"u":"https://example.com/","slots":'
        '[{"id":"a"},{"id":"b"},{"id":"c"}]}'
    )
    hit = amazon.parse(_request(
        host="web.ads.aps.amazon-adsystem.com",
        url="https://web.ads.aps.amazon-adsystem.com/e/pb/bid",
        method="POST",
        request_body=body,
    ))
    by_key = {p.key: p for p in hit.params}
    count = by_key.get("(body) slots_count")
    assert count is not None
    assert count.value == "3"


def test_parse_handles_invalid_body_gracefully(amazon) -> None:
    """A malformed body must not crash parse() — module fails silently."""
    hit = amazon.parse(_request(
        host="web.ads.aps.amazon-adsystem.com",
        url="https://web.ads.aps.amazon-adsystem.com/e/pb/bid",
        method="POST",
        request_body="not json {",
    ))
    # parse() must complete; no body-derived params surface but query params still do.
    assert hit.module_id == "amazon_ad_system"


def test_parse_handles_empty_body(amazon) -> None:
    hit = amazon.parse(_request(
        host="aax-eu.amazon-adsystem.com",
        url="https://aax-eu.amazon-adsystem.com/s/ecm3?ex=loopme.com",
        request_body=None,
    ))
    assert hit.module_id == "amazon_ad_system"
    by_key = {p.key: p for p in hit.params}
    assert "(body) u" not in by_key


def test_parse_hit_basics(amazon) -> None:
    url = "https://aax-eu.amazon-adsystem.com/s/ecm3?ex=loopme.com&id=abc"
    hit = amazon.parse(_request(
        host="aax-eu.amazon-adsystem.com", url=url, event_id=33,
    ))
    assert hit.module_id == "amazon_ad_system"
    assert hit.host == "aax-eu.amazon-adsystem.com"
    assert hit.events == [33]


# --- G. real-bundle integration --------------------------------------------


def test_real_bundle_attribution() -> None:
    """All amazon-adsystem.com hosts on /tmp/apple-max.zip attribute to this module."""
    from pathlib import Path
    bundle_path = Path("/tmp/apple-max.zip")
    if not bundle_path.exists():
        pytest.skip("working-dataset bundle /tmp/apple-max.zip not present")
    from leak_inspector.analysis import analyze_events
    from leak_inspector.bundle.reader import BundleReader
    with BundleReader(bundle_path) as b:
        analysis = analyze_events(b.manifest, b.events(), cname_chains=b.cname_chains)
    amazon_hits = [h for h in analysis.hits if "amazon-adsystem.com" in h.host]
    amazon_untracked = [
        e for e in analysis.untracked_requests if "amazon-adsystem.com" in e.host
    ]
    assert amazon_untracked == [], (
        f"Amazon Ad System requests still untracked: "
        f"{[(e.host, e.url) for e in amazon_untracked[:5]]}"
    )
    assert amazon_hits, "no Amazon Ad System hits attributed at all"
    assert {h.module_id for h in amazon_hits} == {"amazon_ad_system"}
