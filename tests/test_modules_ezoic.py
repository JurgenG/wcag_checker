"""Tests for the Ezoic publisher-monetization detector module.

Ezoic Inc. (US) operates a three-host publisher-monetization stack:

* ``g.ezoic.net`` — primary beacon / config / pixel host.
* ``go.ezodn.com`` — JS loader host. Both use Ezoic's whimsical city-name
  path scheme (``/detroitchicago/``, ``/parsonsmaize/``,
  ``/porpoiseant/``, ``/tardisrocinante/``).
* ``qvdt3feo.com`` — shadow domain Ezoic uses for the cookie-sync into
  Google's ad graph. Carries ``google_push`` / ``google_gid`` /
  ``google_cver`` tokens and sets ``sa-user-id`` / ``sa-user-id-v2``
  with 1-year ``Max-Age``.

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
def ezoic():
    for module in all_modules():
        if module.module_id == "ezoic":
            return module
    raise AssertionError("ezoic module not registered")


# --- A. class identity ------------------------------------------------------


def test_module_registered() -> None:
    assert "ezoic" in [m.module_id for m in all_modules()]


def test_module_identity(ezoic) -> None:
    assert ezoic.module_id == "ezoic"
    assert "Ezoic" in ezoic.module_name


def test_module_sovereignty(ezoic) -> None:
    """Ezoic Inc. is US-headquartered — CLOUD Act applies."""
    assert "Ezoic" in ezoic.vendor
    assert ezoic.legal_jurisdiction == "US"
    notes = (ezoic.sovereignty_notes or "").lower()
    assert "cloud act" in notes or "schrems" in notes
    # The shadow-domain / Google-sync pattern is the distinctive privacy story.
    assert "shadow" in notes or "google" in notes or "qvdt3feo" in notes


# --- B. matches() — positive cases ------------------------------------------


@pytest.mark.parametrize(
    "host,path",
    [
        # Primary beacon family
        ("g.ezoic.net", "/detroitchicago/ce.gif"),
        ("g.ezoic.net", "/ez-vasts"),
        ("g.ezoic.net", "/detroitchicago/ezconfig"),
        ("g.ezoic.net", "/saa.go"),
        ("g.ezoic.net", "/ezoic/ezoiclitedata.go"),
        ("g.ezoic.net", "/cmp/log.gif"),
        ("g.ezoic.net", "/porpoiseant/army.gif"),
        ("g.ezoic.net", "/tardisrocinante/vitals.js"),
        # JS loader family
        ("go.ezodn.com", "/detroitchicago/kenai.js"),
        ("go.ezodn.com", "/parsonsmaize/mulvane.js"),
        ("go.ezodn.com", "/ezoicanalytics.js"),
        ("go.ezodn.com", "/ezoic/ezorca.min.js"),
        # Shadow domain
        ("qvdt3feo.com", "/sync"),
        ("qvdt3feo.com", "/events.js"),
    ],
)
def test_matches_documented_ezoic_hosts(ezoic, host: str, path: str) -> None:
    url = f"https://{host}{path}"
    assert ezoic.matches(_request(host=host, url=url)) is True


def test_matches_is_case_insensitive_on_host(ezoic) -> None:
    url = "https://G.EZOIC.NET/detroitchicago/ce.gif"
    assert ezoic.matches(_request(host="G.EZOIC.NET", url=url)) is True


# --- C. matches() — negative cases -----------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "example.com",
        "ezoic-impersonator.example",
        "fakeezoic.com",
        "ezoic.example.com",
        # Other random-looking domains are NOT auto-claimed (we don't
        # pattern-match random TLDs; only known shadow hosts are claimed)
        "qweasdzxc.com",
    ],
)
def test_does_not_match_unrelated_hosts(ezoic, host: str) -> None:
    url = f"https://{host}/sync"
    assert ezoic.matches(_request(host=host, url=url)) is False


# --- D. dispatcher routing -------------------------------------------------


def test_detect_routes_to_ezoic() -> None:
    req = _request(
        host="g.ezoic.net",
        url="https://g.ezoic.net/detroitchicago/ce.gif?did=27792&pid=abc",
    )
    module = detect(req)
    assert module is not None
    assert module.module_id == "ezoic"


def test_detect_routes_shadow_domain_to_ezoic() -> None:
    req = _request(
        host="qvdt3feo.com",
        url="https://qvdt3feo.com/sync?nid=154&google_push=AXcoOmR",
    )
    module = detect(req)
    assert module is not None
    assert module.module_id == "ezoic"


# --- E. parse() — classification + Hit shape -------------------------------


def test_parse_classifies_publisher_and_page_identifiers(ezoic) -> None:
    """``did`` (publisher domain ID) is property-scoped TECHNICAL; ``pid`` (page instance) is an identifier."""
    url = (
        "https://g.ezoic.net/saa.go"
        "?did=27792&pid=60031e31-3579-4a0f-8b4b-d95aadee362e"
    )
    hit = ezoic.parse(_request(host="g.ezoic.net", url=url))
    by_key = {p.key: p for p in hit.params}
    assert by_key["did"].category == CAT_TECHNICAL
    assert by_key["did"].privacy_impact == IMPACT_LOW
    assert by_key["pid"].category == CAT_IDENTIFIER


def test_parse_classifies_google_sync_tokens_as_high_identifiers(ezoic) -> None:
    """``google_push`` / ``google_gid`` / ``google_cver`` carry the cross-graph ID."""
    url = (
        "https://qvdt3feo.com/sync"
        "?nid=154&google_gid=CAESEGnq&google_cver=1"
        "&google_push=AXcoOmRf_6Jrx6sOlrV8iSIH"
    )
    hit = ezoic.parse(_request(host="qvdt3feo.com", url=url))
    by_key = {p.key: p for p in hit.params}
    for key in ("google_push", "google_gid", "google_cver"):
        assert by_key[key].category == CAT_IDENTIFIER, key
        assert by_key[key].privacy_impact == IMPACT_HIGH, key
    # ``nid`` is the Ezoic-side network/partner config ID for the sync
    assert by_key["nid"].category == CAT_TECHNICAL


def test_parse_classifies_page_url_leaks_as_content(ezoic) -> None:
    """``url`` / ``ref`` / ``d`` / ``orig`` leak the visited page."""
    url = (
        "https://g.ezoic.net/saa.go"
        "?url=https%3A%2F%2Fwww.cultofmac.com%2F&ref=&orig=cultofmac.com"
    )
    hit = ezoic.parse(_request(host="g.ezoic.net", url=url))
    by_key = {p.key: p for p in hit.params}
    assert by_key["url"].category == CAT_CONTENT
    assert by_key["url"].privacy_impact == IMPACT_MEDIUM
    assert by_key["ref"].category == CAT_CONTENT
    assert by_key["orig"].category == CAT_CONTENT


def test_parse_classifies_cmp_consent_signals(ezoic) -> None:
    """``gdpr`` / ``gdpr_consent`` / ``consentV2`` / ``gpp`` are CONSENT / LOW."""
    url = (
        "https://g.ezoic.net/cmp/log.gif"
        "?dId=27792&dcId=106&buttonId=2&consentV2=CQlR&gdpr=1&gdpr_consent=CQlR"
        "&gpp=DBABLA&gpp_sid=7&us_privacy=1YNN"
    )
    hit = ezoic.parse(_request(host="g.ezoic.net", url=url))
    by_key = {p.key: p for p in hit.params}
    for key in ("gdpr", "gdpr_consent", "gpp", "gpp_sid", "us_privacy", "consentV2"):
        assert by_key[key].category == CAT_CONSENT, key


def test_parse_classifies_cache_busters_as_technical(ezoic) -> None:
    """``cb`` / ``gcb`` / ``dcb`` / ``shcb`` are TECHNICAL / LOW cache-busters."""
    url = (
        "https://go.ezodn.com/detroitchicago/birmingham.js"
        "?gcb=195-23&cb=539c47377c&dcb=1&shcb=2"
    )
    hit = ezoic.parse(_request(host="go.ezodn.com", url=url))
    by_key = {p.key: p for p in hit.params}
    for key in ("cb", "gcb", "dcb", "shcb"):
        assert by_key[key].category == CAT_TECHNICAL, key
        assert by_key[key].privacy_impact == IMPACT_LOW, key


def test_parse_hit_basics(ezoic) -> None:
    url = "https://g.ezoic.net/detroitchicago/ce.gif?did=27792"
    hit = ezoic.parse(_request(host="g.ezoic.net", url=url, event_id=55))
    assert hit.module_id == "ezoic"
    assert hit.host == "g.ezoic.net"
    assert hit.events == [55]


# --- F. real-bundle integration --------------------------------------------


def test_real_bundle_attribution() -> None:
    """All Ezoic-cluster requests on /tmp/apple-max.zip attribute to ezoic.

    The capture has 163 hits across the three known hosts.
    """
    from pathlib import Path
    bundle_path = Path("/tmp/apple-max.zip")
    if not bundle_path.exists():
        pytest.skip("working-dataset bundle /tmp/apple-max.zip not present")
    from leak_inspector.analysis import analyze_events
    from leak_inspector.bundle.reader import BundleReader
    ezoic_hosts = {"g.ezoic.net", "go.ezodn.com", "qvdt3feo.com"}
    with BundleReader(bundle_path) as b:
        analysis = analyze_events(b.manifest, b.events(), cname_chains=b.cname_chains)
    ezoic_hits = [h for h in analysis.hits if h.host in ezoic_hosts]
    ezoic_untracked = [
        e for e in analysis.untracked_requests if e.host in ezoic_hosts
    ]
    assert ezoic_untracked == [], (
        f"Ezoic-cluster requests still untracked: "
        f"{[(e.host, e.url) for e in ezoic_untracked[:5]]}"
    )
    assert ezoic_hits, "no Ezoic hits attributed at all"
    assert {h.module_id for h in ezoic_hits} == {"ezoic"}
