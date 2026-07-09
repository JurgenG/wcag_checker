"""Tests for the Criteo retargeting / SSP detector module.

Criteo runs a multi-host federated cookie-sync + bidding stack:

* ``grid-bidder.criteo.com`` — Prebid header-bidding endpoint
  (``/openrtb_2_5/pbjs/auction/request``), OpenRTB body.
* ``gum.criteo.com`` — main user-sync hub
  (``/sid/json``, ``/syncframe``).
* ``dis.criteo.com`` / ``dis.eu.criteo.com`` — display cookie sync
  (``/dis/usersync.aspx``); ``url=`` carries the downstream partner
  pixel + ``@@CRITEO_USERID@@`` placeholder.
* ``ssp-sync.criteo.com`` — SSP-side user-sync (``/user-sync/match``,
  ``/user-sync/redirect``, ``/user-sync/iframe``,
  ``/user-sync/bidder-initiated``).
* ``ag.gbc.criteo.com`` / ``gem.gbc.criteo.com`` — additional sync
  infrastructure (``/newidsd``).
* ``static.criteo.net`` — publisher tag JS
  (``/js/ld/publishertag.ids.js``).

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


# --- helpers ----------------------------------------------------------------


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
def criteo():
    for module in all_modules():
        if module.module_id == "criteo":
            return module
    raise AssertionError("criteo module not registered")


# --- A. class identity ------------------------------------------------------


def test_module_registered() -> None:
    assert "criteo" in [m.module_id for m in all_modules()]


def test_module_identity(criteo) -> None:
    assert criteo.module_id == "criteo"
    assert "Criteo" in criteo.module_name


def test_module_sovereignty(criteo) -> None:
    """Criteo S.A. is France-headquartered — primary EU regulator is CNIL."""
    assert "Criteo" in criteo.vendor
    assert criteo.legal_jurisdiction in ("FR", "EU")
    notes = (criteo.sovereignty_notes or "").lower()
    # The CNIL enforcement context is the most relevant sovereignty signal.
    assert "cnil" in notes or "france" in notes or "eu" in notes


# --- B. matches() — positive cases ------------------------------------------


@pytest.mark.parametrize(
    "host,path",
    [
        # Header bidder
        ("grid-bidder.criteo.com", "/openrtb_2_5/pbjs/auction/request"),
        # User-sync hub
        ("gum.criteo.com", "/sid/json"),
        ("gum.criteo.com", "/syncframe"),
        # Display cookie sync
        ("dis.criteo.com", "/dis/usersync.aspx"),
        ("dis.eu.criteo.com", "/dis/usersync.aspx"),
        # SSP-side sync family
        ("ssp-sync.criteo.com", "/user-sync/match"),
        ("ssp-sync.criteo.com", "/user-sync/redirect"),
        ("ssp-sync.criteo.com", "/user-sync/iframe"),
        ("ssp-sync.criteo.com", "/user-sync/bidder-initiated"),
        # Extra sync infrastructure
        ("ag.gbc.criteo.com", "/newidsd"),
        ("gem.gbc.criteo.com", "/newidsd"),
        # Publisher tag JS
        ("static.criteo.net", "/js/ld/publishertag.ids.js"),
    ],
)
def test_matches_documented_criteo_hosts(criteo, host: str, path: str) -> None:
    url = f"https://{host}{path}"
    assert criteo.matches(_request(host=host, url=url)) is True


def test_matches_is_case_insensitive_on_host(criteo) -> None:
    url = "https://GUM.CRITEO.COM/sid/json"
    assert criteo.matches(_request(host="GUM.CRITEO.COM", url=url)) is True


@pytest.mark.parametrize(
    "host",
    [
        # Criteo's documented CNAME-cloaking delegation domains (NextDNS
        # cname-cloaking blocklist). A first-party-looking subdomain
        # CNAMEs to these; matching them lets the cloak detector
        # attribute the chain's canonical tail to Criteo.
        "x.dnsdelegation.io",
        "dnsdelegation.io",
        "shop.storetail.io",
        "storetail.io",
    ],
)
def test_matches_cname_cloaking_delegation_domains(criteo, host: str) -> None:
    url = f"https://{host}/track"
    assert criteo.matches(_request(host=host, url=url)) is True


# --- C. matches() — negative cases -----------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "example.com",
        "criteo-impersonator.example",
        "fakecriteo.com",
        "criteo.example.com",  # not on the criteo.com / criteo.net suffixes
    ],
)
def test_does_not_match_unrelated_hosts(criteo, host: str) -> None:
    url = f"https://{host}/openrtb_2_5/pbjs/auction/request"
    assert criteo.matches(_request(host=host, url=url)) is False


# --- D. dispatcher routing -------------------------------------------------


def test_detect_routes_to_criteo() -> None:
    req = _request(
        host="grid-bidder.criteo.com",
        url="https://grid-bidder.criteo.com/openrtb_2_5/pbjs/auction/request?profileId=207",
    )
    module = detect(req)
    assert module is not None
    assert module.module_id == "criteo"


# --- E. parse() — classification + Hit shape -------------------------------


def test_parse_classifies_visitor_pseudonym(criteo) -> None:
    """``u`` is the partner-supplied user pseudonym — HIGH identifier."""
    url = (
        "https://ssp-sync.criteo.com/user-sync/match"
        "?p=encrypted&u=31f39fdb-d733-443a-aaaa-1234567890ab"
    )
    hit = criteo.parse(_request(host="ssp-sync.criteo.com", url=url))
    by_key = {p.key: p for p in hit.params}
    assert by_key["u"].category == CAT_IDENTIFIER
    assert by_key["u"].privacy_impact == IMPACT_HIGH


def test_parse_classifies_partner_identifiers(criteo) -> None:
    """``profileId`` / ``networkId`` are account-scoped — TECHNICAL / LOW."""
    url = (
        "https://grid-bidder.criteo.com/openrtb_2_5/pbjs/auction/request"
        "?profileId=207&networkId=3927"
    )
    hit = criteo.parse(_request(host="grid-bidder.criteo.com", url=url))
    by_key = {p.key: p for p in hit.params}
    for key in ("profileId", "networkId"):
        assert by_key[key].category == CAT_TECHNICAL, key
        assert by_key[key].privacy_impact == IMPACT_LOW, key


def test_parse_classifies_page_context_as_content(criteo) -> None:
    """``topUrl`` / ``domain`` / ``url`` leak the visited page — CONTENT."""
    url = (
        "https://gum.criteo.com/sid/json"
        "?origin=prebid&topUrl=https%3A%2F%2Fwww.macrumors.com%2F"
        "&domain=www.macrumors.com&cw=1&lsw=1"
    )
    hit = criteo.parse(_request(host="gum.criteo.com", url=url))
    by_key = {p.key: p for p in hit.params}
    assert by_key["topUrl"].category == CAT_CONTENT
    assert by_key["topUrl"].privacy_impact == IMPACT_MEDIUM
    assert by_key["domain"].category == CAT_CONTENT


def test_parse_classifies_consent_signals(criteo) -> None:
    """``gdpr`` / ``gdpr_consent`` / ``gpp`` / ``us_privacy`` are CONSENT / LOW."""
    url = (
        "https://ssp-sync.criteo.com/user-sync/iframe"
        "?gdpr=1&gdpr_consent=CQlRmbAQlR&gpp=DBABLA&gpp_sid=7&us_privacy=1YNN"
    )
    hit = criteo.parse(_request(host="ssp-sync.criteo.com", url=url))
    by_key = {p.key: p for p in hit.params}
    for key in ("gdpr", "gdpr_consent", "gpp", "gpp_sid", "us_privacy"):
        assert by_key[key].category == CAT_CONSENT, key
        assert by_key[key].privacy_impact == IMPACT_LOW, key


def test_parse_classifies_technical_versions(criteo) -> None:
    """``av`` / ``wv`` / ``cb`` / ``lsavail`` are TECHNICAL / LOW."""
    url = (
        "https://grid-bidder.criteo.com/openrtb_2_5/pbjs/auction/request"
        "?profileId=207&av=37&wv=10.29.1&cb=63088344535&lsavail=1"
    )
    hit = criteo.parse(_request(host="grid-bidder.criteo.com", url=url))
    by_key = {p.key: p for p in hit.params}
    for key in ("av", "wv", "cb", "lsavail"):
        assert by_key[key].category == CAT_TECHNICAL, key
        assert by_key[key].privacy_impact == IMPACT_LOW, key


def test_parse_hit_basics(criteo) -> None:
    url = "https://gum.criteo.com/sid/json?origin=prebid&topUrl=https%3A%2F%2Fexample.be%2F"
    hit = criteo.parse(_request(host="gum.criteo.com", url=url, event_id=42))
    assert hit.module_id == "criteo"
    assert hit.host == "gum.criteo.com"
    assert hit.events == [42]


# --- F. real-bundle integration --------------------------------------------


def test_real_bundle_attribution() -> None:
    """All Criteo-host requests on /tmp/apple-max.zip attribute to criteo.

    The capture has 70 Criteo hits across 8 distinct subdomains.
    """
    from pathlib import Path
    bundle_path = Path("/tmp/apple-max.zip")
    if not bundle_path.exists():
        pytest.skip("working-dataset bundle /tmp/apple-max.zip not present")
    from leak_inspector.analysis import analyze_events
    from leak_inspector.bundle.reader import BundleReader
    with BundleReader(bundle_path) as b:
        analysis = analyze_events(b.manifest, b.events(), cname_chains=b.cname_chains)
    criteo_hits = [
        h for h in analysis.hits
        if ".criteo.com" in h.host or ".criteo.net" in h.host
        or h.host in ("criteo.com", "criteo.net")
    ]
    criteo_untracked = [
        e for e in analysis.untracked_requests
        if ".criteo.com" in e.host or ".criteo.net" in e.host
        or e.host in ("criteo.com", "criteo.net")
    ]
    assert criteo_untracked == [], (
        f"Criteo requests still untracked: "
        f"{[(e.host, e.url) for e in criteo_untracked[:5]]}"
    )
    assert criteo_hits, "no Criteo hits attributed at all"
    assert {h.module_id for h in criteo_hits} == {"criteo"}
