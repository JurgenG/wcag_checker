"""Tests for the Apple Pay on the Web detector module.

Apple Pay JS / Wallet SDK loads from ``applepay.cdn-apple.com``. The
URLs are parameter-less asset paths, so the module's value comes from
two pieces of behaviour:

1. **Scope discipline** — it claims exactly one host and refuses to
   over-claim Apple's other CDN subdomains.
2. **Path-derived params** — the ``_path_params`` helper turns
   ``/jsapi/1.latest/apple-pay-sdk.js`` into ``version=1.latest`` +
   ``asset=apple-pay-sdk.js`` so the report can distinguish SDK
   variants instead of just listing "Apple Pay loaded".

The pattern follows ``tests/test_modules_ga4.py`` (worked example for
tracker module tests) with a real-bundle integration test pinned to
``captures/sokken-nl-max.zip``, which contains the three documented
asset paths.
"""

from __future__ import annotations

import pytest

from leak_inspector.events import RequestEvent
from leak_inspector.modules.apple_pay import _path_params
from leak_inspector.modules.base import (
    CAT_OTHER,
    CAT_TECHNICAL,
    IMPACT_LOW,
    all_modules,
    detect,
)


# --- helpers ----------------------------------------------------------------


def _request(
    *,
    host: str,
    url: str,
    method: str = "GET",
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
def apple_pay():
    for module in all_modules():
        if module.module_id == "apple_pay":
            return module
    raise AssertionError("apple_pay module not registered")


# --- A. class identity ------------------------------------------------------


def test_module_registered() -> None:
    assert "apple_pay" in [m.module_id for m in all_modules()]


def test_module_identity(apple_pay) -> None:
    assert apple_pay.module_id == "apple_pay"
    assert "Apple Pay" in apple_pay.module_name


def test_module_sovereignty(apple_pay) -> None:
    """Apple Inc., US jurisdiction, CLOUD Act mentioned in sovereignty notes."""
    assert apple_pay.vendor == "Apple Inc."
    assert apple_pay.legal_jurisdiction == "US"
    notes = (apple_pay.sovereignty_notes or "").lower()
    assert "cloud act" in notes
    # Calibration: notes should make clear this is asset traffic, not a beacon.
    assert "asset" in notes or "not advertising" in notes or "not a tracker" in notes


# --- B. matches() — positive cases on the documented host -----------------


@pytest.mark.parametrize(
    "path",
    [
        "/jsapi/1.latest/apple-pay-sdk.js",
        "/jsapi/1.latest/apple-wallet-sdk.js",
        "/jsapi/1.latest/apple-pay-button.js",
        # Forward-compatible: future version channels under the same host
        "/jsapi/2.0/apple-pay-sdk.js",
        # Even non-/jsapi/ paths on this host count — we own the host entirely
        "/some/other/asset.js",
    ],
)
def test_matches_documented_host(apple_pay, path: str) -> None:
    url = f"https://applepay.cdn-apple.com{path}"
    assert apple_pay.matches(_request(host="applepay.cdn-apple.com", url=url)) is True


def test_matches_is_case_insensitive_on_host(apple_pay) -> None:
    """A capture with an upper-cased Host header still matches."""
    url = "https://APPLEPAY.CDN-APPLE.COM/jsapi/1.latest/apple-pay-sdk.js"
    assert apple_pay.matches(
        _request(host="APPLEPAY.CDN-APPLE.COM", url=url)
    ) is True


# --- C. matches() — negative cases: don't over-claim Apple's other hosts --


@pytest.mark.parametrize(
    "host",
    [
        # Other Apple CDNs that are NOT Apple Pay
        "cdn-apple.com",
        "smoot.apple.com",
        "www.apple.com",
        "support.apple.com",
        # Server-to-server Apple Pay gateway — not browser-visible
        "apple-pay-gateway.apple.com",
        "apple-pay-gateway-cert.apple.com",
        # Subdomain of the matched host — exact match only, by design
        "v2.applepay.cdn-apple.com",
        # Unrelated host
        "example.com",
    ],
)
def test_does_not_overclaim_other_apple_hosts(apple_pay, host: str) -> None:
    url = f"https://{host}/jsapi/1.latest/apple-pay-sdk.js"
    assert apple_pay.matches(_request(host=host, url=url)) is False


# --- D. dispatcher routing -------------------------------------------------


def test_detect_routes_to_apple_pay() -> None:
    req = _request(
        host="applepay.cdn-apple.com",
        url="https://applepay.cdn-apple.com/jsapi/1.latest/apple-pay-sdk.js",
    )
    module = detect(req)
    assert module is not None
    assert module.module_id == "apple_pay"


# --- E. _path_params helper -----------------------------------------------


@pytest.mark.parametrize(
    "path,expected",
    [
        # The three asset paths observed in real captures
        ("/jsapi/1.latest/apple-pay-sdk.js",
         {"version": "1.latest", "asset": "apple-pay-sdk.js"}),
        ("/jsapi/1.latest/apple-wallet-sdk.js",
         {"version": "1.latest", "asset": "apple-wallet-sdk.js"}),
        ("/jsapi/1.latest/apple-pay-button.js",
         {"version": "1.latest", "asset": "apple-pay-button.js"}),
        # Forward-compatible: any version channel
        ("/jsapi/2.0/apple-pay-sdk.js",
         {"version": "2.0", "asset": "apple-pay-sdk.js"}),
        # Deeper paths still extract the last segment as asset
        ("/jsapi/1.latest/sub/apple-pay-sdk.js",
         {"version": "1.latest", "asset": "apple-pay-sdk.js"}),
    ],
)
def test_path_params_extracts_version_and_asset(path: str, expected: dict) -> None:
    assert _path_params(path) == expected


@pytest.mark.parametrize(
    "path",
    [
        "/",                          # bare root
        "/jsapi/",                    # /jsapi only — no version, no asset
        "/jsapi/1.latest",            # only one segment after /jsapi/
        "/some/other/path.js",        # not /jsapi/
        "",                           # empty
    ],
)
def test_path_params_returns_empty_for_non_jsapi_or_short_paths(path: str) -> None:
    assert _path_params(path) == {}


# --- F. parse() — Hit shape + path-derived params -------------------------


def test_parse_surfaces_path_derived_version_and_asset(apple_pay) -> None:
    """The Apple Pay SDK loader has no query params — the path is the signal."""
    url = "https://applepay.cdn-apple.com/jsapi/1.latest/apple-pay-sdk.js"
    hit = apple_pay.parse(_request(host="applepay.cdn-apple.com", url=url))
    by_key = {p.key: p for p in hit.params}
    assert by_key["version"].value == "1.latest"
    assert by_key["version"].category == CAT_TECHNICAL
    assert by_key["version"].privacy_impact == IMPACT_LOW
    assert by_key["asset"].value == "apple-pay-sdk.js"
    assert by_key["asset"].category == CAT_TECHNICAL
    assert by_key["asset"].privacy_impact == IMPACT_LOW


def test_parse_query_params_override_path_derived(apple_pay) -> None:
    """An actual ``?version=...`` query wins over the path-derived synthetic."""
    url = (
        "https://applepay.cdn-apple.com/jsapi/1.latest/apple-pay-sdk.js"
        "?version=actual-from-query"
    )
    hit = apple_pay.parse(_request(host="applepay.cdn-apple.com", url=url))
    by_key = {p.key: p for p in hit.params}
    assert by_key["version"].value == "actual-from-query"


def test_parse_unknown_query_param_falls_through_to_other(apple_pay) -> None:
    url = (
        "https://applepay.cdn-apple.com/jsapi/1.latest/apple-pay-sdk.js"
        "?qqq_internal=opaque"
    )
    hit = apple_pay.parse(_request(host="applepay.cdn-apple.com", url=url))
    by_key = {p.key: p for p in hit.params}
    assert by_key["qqq_internal"].category == CAT_OTHER
    assert by_key["qqq_internal"].privacy_impact == IMPACT_LOW


def test_parse_path_without_jsapi_prefix_yields_no_path_params(apple_pay) -> None:
    """Non-/jsapi/ paths produce no synthetic params (still a valid hit)."""
    url = "https://applepay.cdn-apple.com/static/some-asset.png"
    hit = apple_pay.parse(_request(host="applepay.cdn-apple.com", url=url))
    keys = [p.key for p in hit.params]
    assert "version" not in keys
    assert "asset" not in keys


def test_parse_hit_basics(apple_pay) -> None:
    url = "https://applepay.cdn-apple.com/jsapi/1.latest/apple-pay-sdk.js"
    hit = apple_pay.parse(_request(host="applepay.cdn-apple.com", url=url, event_id=77))
    assert hit.module_id == "apple_pay"
    assert hit.host == "applepay.cdn-apple.com"
    assert hit.url == url
    assert hit.method == "GET"
    assert hit.events == [77]


# --- G. real-bundle integration -------------------------------------------


def test_real_bundle_attribution() -> None:
    """All applepay.cdn-apple.com requests on sokken-nl-max.zip attribute to apple_pay.

    The capture exhibits 18 requests across three SDK asset variants
    (``apple-pay-sdk.js`` / ``apple-wallet-sdk.js`` /
    ``apple-pay-button.js``). Before this module they were all
    untracked.
    """
    from pathlib import Path
    bundle_path = Path(__file__).resolve().parents[1] / "captures" / "sokken-nl-max.zip"
    if not bundle_path.exists():
        pytest.skip("working-dataset bundle not present in this checkout")
    from leak_inspector.analysis import analyze_events
    from leak_inspector.bundle.reader import BundleReader
    with BundleReader(bundle_path) as b:
        analysis = analyze_events(b.manifest, b.events(), cname_chains=b.cname_chains)
    apple_hits = [h for h in analysis.hits if h.host == "applepay.cdn-apple.com"]
    apple_untracked = [
        e for e in analysis.untracked_requests if e.host == "applepay.cdn-apple.com"
    ]
    assert apple_untracked == [], (
        f"Apple Pay requests still untracked: "
        f"{[(e.host, e.url) for e in apple_untracked[:5]]}"
    )
    assert apple_hits, "no Apple Pay hits attributed at all"
    assert {h.module_id for h in apple_hits} == {"apple_pay"}
    # The three real-world asset variants must all be surfaced.
    assets = {
        next((p.value for p in h.params if p.key == "asset"), None)
        for h in apple_hits
    }
    assert assets == {
        "apple-pay-sdk.js",
        "apple-wallet-sdk.js",
        "apple-pay-button.js",
    }, assets