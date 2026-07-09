"""Tests for the Google Tag First-Party Mode (FP-Mode) detector.

FP-Mode is the operator-owned reverse-proxy variant of GA4: the
operator deploys Google's "tagging server" at a custom subdomain
(commonly ``g.<operator-tld>``) which the browser sees as
first-party. The proxy forwards beacons server-side to Google's
real analytics infrastructure. The browser-visible URLs mirror the
canonical Google ones (``/g/collect``, ``/gtag/js``) plus
FP-Mode-specific infrastructure (``/_/set_cookie``,
``/_/service_worker/<n>/sw_iframe.html``); cookies are set with
``FPID``/``FPLC``/``FPGSID``/``FPAU`` names and 2-year ``Max-Age``.

The module must:

* Claim FP-Mode requests on non-Google hosts (the whole point — they
  look first-party in the browser).
* **Not** shadow the canonical GA4 / GTM modules on
  ``*.google-analytics.com`` / ``*.googletagmanager.com`` /
  ``*.analytics.google.com``.
* Attach a HIGH-impact ``(fp-proxy)`` ParamInfo to every hit so the
  pattern is visible in the report, mirroring how the
  ``(cname-cloak)`` finding works.
* Surface the GA4 measurement ID (``tid``/``id`` value).
* Reuse GA4's parameter classification so existing GA4 keys carry
  the same category / meaning / impact under this module.
"""

from __future__ import annotations

import pytest

from leak_inspector.events import RequestEvent
from leak_inspector.modules.base import (
    CAT_HTTP_TRAFFIC,
    CAT_IDENTIFIER,
    CAT_TECHNICAL,
    IMPACT_HIGH,
    IMPACT_LOW,
    all_modules,
    detect,
)


# --- helpers ---------------------------------------------------------------


def _request(
    *,
    host: str,
    url: str,
    method: str = "POST",
    request_body: str | None = None,
    headers: dict[str, str] | None = None,
    event_id: int = 1,
    timestamp: str = "2026-06-03T20:38:42Z",
    response_status: int | None = 204,
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
def fpmode():
    """Return the registered Google FP-Mode module instance."""
    for module in all_modules():
        if module.module_id == "google_first_party_mode":
            return module
    raise AssertionError("google_first_party_mode module not registered")


# --- A. class identity ------------------------------------------------------


def test_module_is_registered() -> None:
    assert "google_first_party_mode" in [m.module_id for m in all_modules()]


def test_module_identity(fpmode) -> None:
    assert fpmode.module_id == "google_first_party_mode"
    assert "Google" in fpmode.module_name
    assert "First-Party" in fpmode.module_name or "First Party" in fpmode.module_name


def test_module_sovereignty(fpmode) -> None:
    """Vendor of record is still Google despite the operator-owned proxy."""
    assert fpmode.vendor == "Google LLC"
    assert fpmode.legal_jurisdiction == "US"
    # Sovereignty notes should make the proxy-evasion semantics explicit.
    assert fpmode.sovereignty_notes
    assert "proxy" in fpmode.sovereignty_notes.lower() or "server-side" in fpmode.sovereignty_notes.lower()


# --- B. matches() — positive cases on FP-Mode proxy hosts ------------------


@pytest.mark.parametrize(
    "host,path,query",
    [
        # GA4 transport on operator-owned subdomain
        ("g.sokken.nl", "/g/collect", "v=2&tid=G-61ND3W70GR&cid=12345"),
        ("g.boxers.nl", "/g/collect", "v=2&tid=G-JHG9WLK1GY&cid=67890"),
        # gtag.js loader on operator-owned subdomain
        ("g.sokken.nl", "/gtag/js", "id=G-61ND3W70GR&cx=c&gtm=4e6620"),
        # FP-Mode cookie-setting endpoint (host-agnostic — path is unique)
        ("g.sokken.nl", "/_/set_cookie", "val=encoded"),
        ("gtm.example.be", "/_/set_cookie", "val=anything"),
        # FP-Mode service-worker iframe
        ("g.sokken.nl", "/_/service_worker/6631/sw_iframe.html",
         "origin=https%3A%2F%2Fwww.sokken.nl&1p=1"),
        ("g.boxers.nl", "/_/service_worker/9999/sw_iframe.html", ""),
    ],
)
def test_matches_fp_mode_proxy_hosts(fpmode, host: str, path: str, query: str) -> None:
    url = f"https://{host}{path}" + (f"?{query}" if query else "")
    assert fpmode.matches(_request(host=host, url=url)) is True


# --- B2. matches() — Google Tag Gateway (path-prefixed, May 2025) ----------


@pytest.mark.parametrize(
    "host,path,query",
    [
        # Tag Gateway reserves a measurement path on the MAIN domain
        # (e.g. /metrics) and serves the Google paths under it.
        ("www.example.be", "/metrics/g/collect",
         "v=2&tid=G-FVDBDW3R80&cid=12345"),
        ("www.example.be", "/abjfo/gtag/js", "id=G-12345AB&cx=c"),
        # FP-Mode infrastructure endpoints under the prefix.
        ("www.example.be", "/metrics/_/set_cookie", "val=encoded"),
        ("www.example.be", "/metrics/_/service_worker/6631/sw_iframe.html",
         "origin=https%3A%2F%2Fwww.example.be&1p=1"),
        # Google's documented gateway origin domain.
        ("g-12345.fps.goog", "/metrics/g/collect", "v=2&tid=G-FVDBDW3R80"),
        ("gtm-abcdef.fps.goog", "/cvfjk/", ""),
    ],
)
def test_matches_tag_gateway_forms(fpmode, host: str, path: str, query: str) -> None:
    url = f"https://{host}{path}" + (f"?{query}" if query else "")
    assert fpmode.matches(_request(host=host, url=url)) is True


def test_prefixed_collect_without_ga4_id_not_claimed(fpmode) -> None:
    """The G-* guard applies to path-prefixed collect requests too."""
    url = "https://www.example.be/metrics/g/collect?v=1&tid=UA-1-1&cid=1"
    assert fpmode.matches(_request(host="www.example.be", url=url)) is False


def test_path_substring_without_boundary_not_claimed(fpmode) -> None:
    """``…g/collected`` must not match — the suffix needs the full segment."""
    url = "https://www.example.be/blog/g/collected?tid=G-FVDBDW3R80"
    assert fpmode.matches(_request(host="www.example.be", url=url)) is False


def test_canonical_google_host_with_prefixed_path_not_claimed(fpmode) -> None:
    url = "https://www.googletagmanager.com/metrics/g/collect?tid=G-FVDBDW3R80"
    assert fpmode.matches(
        _request(host="www.googletagmanager.com", url=url)
    ) is False


# --- C. matches() — negative cases: leave canonical Google to GA4/GTM -----


@pytest.mark.parametrize(
    "host",
    [
        "www.google-analytics.com",
        "google-analytics.com",
        "stats.g.doubleclick.net",
        "region1.analytics.google.com",
        "analytics.google.com",
        "www.googletagmanager.com",
        "googletagmanager.com",
    ],
)
def test_does_not_claim_canonical_google_hosts(fpmode, host: str) -> None:
    """The canonical GA4 / GTM modules own these — we must not shadow them."""
    url = f"https://{host}/g/collect?v=2&tid=G-61ND3W70GR&cid=1"
    assert fpmode.matches(_request(host=host, url=url)) is False


def test_collect_path_without_ga4_measurement_id_not_claimed(fpmode) -> None:
    """``/g/collect`` without a ``G-*`` tid isn't FP-Mode — don't over-claim."""
    url = "https://g.example.be/g/collect?v=1&tid=UA-12345-1&cid=1"
    assert fpmode.matches(_request(host="g.example.be", url=url)) is False


def test_collect_path_without_any_tid_not_claimed(fpmode) -> None:
    url = "https://g.example.be/g/collect?v=2&cid=1"
    assert fpmode.matches(_request(host="g.example.be", url=url)) is False


def test_gtag_js_without_ga4_id_not_claimed(fpmode) -> None:
    """gtag.js with a UA-* id is too ambiguous to claim — let it fall through."""
    url = "https://operator.example/gtag/js?id=UA-12345-1"
    assert fpmode.matches(_request(host="operator.example", url=url)) is False


def test_unrelated_path_not_claimed(fpmode) -> None:
    url = "https://g.sokken.nl/css/main.css"
    assert fpmode.matches(_request(host="g.sokken.nl", url=url)) is False


# --- D. dispatcher: FP-Mode hits route to this module ----------------------


def test_detect_routes_to_fp_mode_module() -> None:
    """End-to-end: a real-shape FP-Mode hit ends up claimed by us, not GA4."""
    req = _request(
        host="g.sokken.nl",
        url="https://g.sokken.nl/g/collect?v=2&tid=G-61ND3W70GR&cid=1",
    )
    module = detect(req)
    assert module is not None
    assert module.module_id == "google_first_party_mode"


def test_detect_keeps_ga4_for_canonical_host() -> None:
    """Canonical GA4 host still routes to GA4 — we didn't steal its hits."""
    req = _request(
        host="www.google-analytics.com",
        url="https://www.google-analytics.com/g/collect?v=2&tid=G-X&cid=1",
    )
    module = detect(req)
    assert module is not None
    assert module.module_id == "ga4"


# --- E. parse() — fp-proxy ParamInfo + measurement ID + GA4 dictionary ----


def test_parse_attaches_fp_proxy_param(fpmode) -> None:
    """Every FP-Mode hit carries a HIGH-impact ``(fp-proxy)`` ParamInfo."""
    url = "https://g.sokken.nl/g/collect?v=2&tid=G-61ND3W70GR&cid=12345.6789"
    hit = fpmode.parse(_request(host="g.sokken.nl", url=url))
    fp_proxy = [p for p in hit.params if p.key.startswith("(fp-proxy)")]
    assert fp_proxy, "no (fp-proxy) ParamInfo attached"
    # The flag describing the proxy nature is HIGH impact.
    host_marker = next((p for p in fp_proxy if p.key == "(fp-proxy) host"), None)
    assert host_marker is not None
    assert host_marker.value == "g.sokken.nl"
    assert host_marker.privacy_impact == IMPACT_HIGH
    assert host_marker.category == CAT_HTTP_TRAFFIC


def test_parse_surfaces_ga4_measurement_id(fpmode) -> None:
    """The GA4 property ID gets its own labelled ParamInfo for attribution."""
    url = "https://g.sokken.nl/g/collect?v=2&tid=G-61ND3W70GR&cid=1"
    hit = fpmode.parse(_request(host="g.sokken.nl", url=url))
    mid = next((p for p in hit.params if p.key == "(fp-proxy) measurement_id"), None)
    assert mid is not None
    assert mid.value == "G-61ND3W70GR"
    assert mid.category == CAT_TECHNICAL
    assert mid.privacy_impact == IMPACT_LOW


def test_parse_surfaces_measurement_id_for_gtag_js(fpmode) -> None:
    """``/gtag/js`` carries the property in the ``id`` query param — same handling."""
    url = "https://g.sokken.nl/gtag/js?id=G-JHG9WLK1GY&cx=c&gtm=4e6620"
    hit = fpmode.parse(_request(host="g.sokken.nl", url=url))
    mid = next((p for p in hit.params if p.key == "(fp-proxy) measurement_id"), None)
    assert mid is not None
    assert mid.value == "G-JHG9WLK1GY"


def test_parse_classifies_known_ga4_params(fpmode) -> None:
    """A ``cid`` (GA visitor pseudonym) keeps GA4's HIGH IDENTIFIER classification."""
    url = "https://g.sokken.nl/g/collect?v=2&tid=G-61ND3W70GR&cid=1867949943.1780519122"
    hit = fpmode.parse(_request(host="g.sokken.nl", url=url))
    cid = next((p for p in hit.params if p.key == "cid"), None)
    assert cid is not None
    assert cid.category == CAT_IDENTIFIER
    assert cid.privacy_impact == IMPACT_HIGH


def test_parse_records_hit_basics(fpmode) -> None:
    """Hit shape: module + method + url + host + events — basics for the reporter."""
    url = "https://g.sokken.nl/g/collect?v=2&tid=G-61ND3W70GR&cid=1"
    hit = fpmode.parse(_request(host="g.sokken.nl", url=url, event_id=42))
    assert hit.module_id == "google_first_party_mode"
    assert hit.host == "g.sokken.nl"
    assert hit.url == url
    assert hit.events == [42]


# --- F. integration with the runner on the real bundle --------------------
#
# Exercises the path the user actually hit: a real capture that goes
# sokken.nl → boxers.nl → zwembroeken.nl, each running a Google FP-Mode
# tagging server on g.<site>.nl. Before this module, all 96 g.* requests
# were untracked. After: all 96 attribute to google_first_party_mode.


def test_real_bundle_attribution() -> None:
    """All g.* FP-Mode requests on sokken-nl-max.zip route to this module."""
    from pathlib import Path
    bundle_path = Path(__file__).resolve().parents[1] / "captures" / "sokken-nl-max.zip"
    if not bundle_path.exists():
        pytest.skip("working-dataset bundle not present in this checkout")
    from leak_inspector.analysis import analyze_events
    from leak_inspector.bundle.reader import BundleReader
    with BundleReader(bundle_path) as b:
        analysis = analyze_events(b.manifest, b.events(), cname_chains=b.cname_chains)
    g_hits = [h for h in analysis.hits if h.host.startswith("g.")]
    g_untracked = [e for e in analysis.untracked_requests if e.host.startswith("g.")]
    assert g_untracked == [], (
        f"FP-Mode requests still untracked: "
        f"{[(e.host, e.url) for e in g_untracked[:5]]}"
    )
    assert g_hits, "no FP-Mode hits attributed at all"
    # Every g.* hit must be claimed by this module (not GA4).
    assert {h.module_id for h in g_hits} == {"google_first_party_mode"}