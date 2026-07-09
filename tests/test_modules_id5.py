"""Tests for the ID5 universal-identity detector module.

ID5 Technology SA (UK) operates a deterministic cross-publisher
visitor-identity service — the post-third-party-cookie deterministic
identifier. Observed host fingerprint:

* ``id5-sync.com`` — primary endpoint family. Sync pixels (``/c/<...>``,
  ``/i/<...>``, ``/s/<...>``, ``/k/<...>``, ``/qp/<...>``), match
  endpoint (``/match``), bounce (``/bounce``), graph fetch
  (``/gm/v3``), Prebid config (``/api/config/prebid``).
* ``cdn.id5-sync.com`` — JS asset CDN (``/api/1.0/id5-api.js``,
  ``/api/1.0/id5PrebidModule.js``).
* ``api.id5-sync.com`` — analytics (``/analytics/<partner>/id5-api-js``).
* ``lb.eu-1-id5-sync.com`` / ``lbs.eu-1-id5-sync.com`` — EU-region
  load balancers (``/lb/v1``, ``/lbs/v1``).

Sovereignty: ID5 is UK-incorporated; **post-Brexit**, UK is a
"third country" from the EU's perspective with a current adequacy
decision (subject to renewal). The privacy story is the
**cross-publisher deterministic identifier** (the ``id5`` cookie has
a 90-day lifetime and is the core graph-key ID5 sells access to).

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
def id5():
    for module in all_modules():
        if module.module_id == "id5":
            return module
    raise AssertionError("id5 module not registered")


# --- A. class identity ------------------------------------------------------


def test_module_registered() -> None:
    assert "id5" in [m.module_id for m in all_modules()]


def test_module_identity(id5) -> None:
    assert id5.module_id == "id5"
    assert "ID5" in id5.module_name


def test_module_sovereignty(id5) -> None:
    """ID5 Technology SA is UK-incorporated post-Brexit — flag the regime."""
    assert "ID5" in id5.vendor
    assert id5.legal_jurisdiction == "UK"
    notes = (id5.sovereignty_notes or "").lower()
    # The deterministic / cross-publisher pattern is the distinctive story.
    assert "cross-publisher" in notes or "deterministic" in notes or "universal" in notes


# --- B. matches() — positive cases ------------------------------------------


@pytest.mark.parametrize(
    "host,path",
    [
        # Primary endpoint family
        ("id5-sync.com", "/k/264.gif"),
        ("id5-sync.com", "/i/102/9.gif"),
        ("id5-sync.com", "/c/124/2/1/2.gif"),
        ("id5-sync.com", "/s/1854/9.gif"),
        ("id5-sync.com", "/qp/18.gif"),
        ("id5-sync.com", "/match"),
        ("id5-sync.com", "/bounce"),
        ("id5-sync.com", "/gm/v3"),
        ("id5-sync.com", "/api/config/prebid"),
        # CDN
        ("cdn.id5-sync.com", "/api/1.0/id5-api.js"),
        ("cdn.id5-sync.com", "/api/1.0/id5PrebidModule.js"),
        # Analytics
        ("api.id5-sync.com", "/analytics/367/id5-api-js"),
        # EU load balancer
        ("lb.eu-1-id5-sync.com", "/lb/v1"),
        ("lbs.eu-1-id5-sync.com", "/lbs/v1"),
    ],
)
def test_matches_documented_id5_hosts(id5, host: str, path: str) -> None:
    url = f"https://{host}{path}"
    assert id5.matches(_request(host=host, url=url)) is True


def test_matches_is_case_insensitive_on_host(id5) -> None:
    url = "https://ID5-SYNC.COM/match"
    assert id5.matches(_request(host="ID5-SYNC.COM", url=url)) is True


# --- C. matches() — negative cases -----------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "example.com",
        "id5-sync-impersonator.example",
        "fakeid5-sync.com",
        "id5-sync.example.com",
        "id5.io",  # not the production sync domain — also belongs to ID5 but separate
    ],
)
def test_does_not_match_unrelated_hosts(id5, host: str) -> None:
    url = f"https://{host}/match"
    assert id5.matches(_request(host=host, url=url)) is False


# --- D. dispatcher routing -------------------------------------------------


def test_detect_routes_to_id5() -> None:
    req = _request(
        host="id5-sync.com",
        url="https://id5-sync.com/match?publisher_user_id=abc-123&gdpr=1",
    )
    module = detect(req)
    assert module is not None
    assert module.module_id == "id5"


# --- E. parse() — classification + Hit shape -------------------------------


def test_parse_classifies_partner_visitor_pseudonym_as_high(id5) -> None:
    """``puid`` (partner user pseudonym) is HIGH — the cross-publisher graph key."""
    url = "https://id5-sync.com/c/102/2/6/4.gif?puid=3371944291962409524&gdpr=1"
    hit = id5.parse(_request(host="id5-sync.com", url=url))
    by_key = {p.key: p for p in hit.params}
    assert by_key["puid"].category == CAT_IDENTIFIER
    assert by_key["puid"].privacy_impact == IMPACT_HIGH


def test_parse_classifies_publisher_user_id_as_high_pii(id5) -> None:
    """``publisher_user_id`` is the publisher's own user ID being linked into ID5's graph."""
    url = (
        "https://id5-sync.com/match"
        "?publisher_user_id=f3d82139-53d9-4dbd-ab58-6de67a271dbd"
        "&publisher_dsp_id=313&publisher_call_type=redirect&dsp_callback=2"
    )
    hit = id5.parse(_request(host="id5-sync.com", url=url))
    by_key = {p.key: p for p in hit.params}
    assert by_key["publisher_user_id"].category == CAT_IDENTIFIER
    assert by_key["publisher_user_id"].privacy_impact == IMPACT_HIGH


def test_parse_classifies_id5id_as_high(id5) -> None:
    """``id5id`` is the ID5 universal identifier being passed between callers."""
    url = "https://id5-sync.com/match?id5id=ID5*abc123"
    hit = id5.parse(_request(host="id5-sync.com", url=url))
    by_key = {p.key: p for p in hit.params}
    assert by_key["id5id"].category == CAT_IDENTIFIER
    assert by_key["id5id"].privacy_impact == IMPACT_HIGH


def test_parse_classifies_consent_signals(id5) -> None:
    url = (
        "https://id5-sync.com/match"
        "?gdpr=1&gdpr_consent=CQlR&gpp=DBABLA&gpp_sid=7&us_privacy=1YNN"
    )
    hit = id5.parse(_request(host="id5-sync.com", url=url))
    by_key = {p.key: p for p in hit.params}
    for key in ("gdpr", "gdpr_consent", "gpp", "gpp_sid", "us_privacy"):
        assert by_key[key].category == CAT_CONSENT, key
        assert by_key[key].privacy_impact == IMPACT_LOW, key


def test_parse_classifies_redirect_chain_as_content(id5) -> None:
    """``publisher_redirecturl`` / ``callback`` leak downstream URLs."""
    url = (
        "https://id5-sync.com/match"
        "?publisher_redirecturl=https%3A%2F%2Fpartner.example%2Fsync"
        "&callback=https%3A%2F%2Fexample.com%2Fcb"
    )
    hit = id5.parse(_request(host="id5-sync.com", url=url))
    by_key = {p.key: p for p in hit.params}
    assert by_key["publisher_redirecturl"].category == CAT_CONTENT
    assert by_key["callback"].category == CAT_CONTENT


def test_parse_classifies_technical_internals(id5) -> None:
    """``ttl`` / ``sd`` / ``o`` are technical plumbing — LOW."""
    url = "https://id5-sync.com/k/264.gif?puid=abc&ttl=86400&sd=1&o=1"
    hit = id5.parse(_request(host="id5-sync.com", url=url))
    by_key = {p.key: p for p in hit.params}
    for key in ("ttl", "sd", "o"):
        assert by_key[key].category == CAT_TECHNICAL, key
        assert by_key[key].privacy_impact == IMPACT_LOW, key


# --- F. JSON body handling -------------------------------------------------


def test_parse_surfaces_body_partner_and_visited_page(id5) -> None:
    """``/gm/v3`` body carries ``tml`` (visited URL), ``partner``, ``v`` (version)."""
    body = (
        '{"requests":[{"requestId":"abc","cacheId":"3690","partner":367,'
        '"v":"v10.29.1","o":"pbjs","tml":"https://www.macrumors.com/",'
        '"ref":null,"cu":"https://www.macrumors.com/"}]}'
    )
    hit = id5.parse(_request(
        host="id5-sync.com",
        url="https://id5-sync.com/gm/v3",
        method="POST",
        request_body=body,
    ))
    by_key = {p.key: p for p in hit.params}
    tml = by_key.get("(body) tml")
    assert tml is not None
    assert tml.value == "https://www.macrumors.com/"
    assert tml.category == CAT_CONTENT
    assert tml.privacy_impact == IMPACT_MEDIUM
    partner = by_key.get("(body) partner")
    assert partner is not None
    assert partner.value == "367"
    assert partner.category == CAT_TECHNICAL
    assert partner.privacy_impact == IMPACT_LOW


def test_parse_surfaces_prebid_config_body(id5) -> None:
    """``/api/config/prebid`` body carries partner ID + storage policy."""
    body = (
        '{"enabledStorageTypes":["html5"],"name":"id5Id",'
        '"params":{"partner":367},'
        '"storage":{"type":"html5","name":"id5id","expires":90,'
        '"refreshInSeconds":7200},"bounce":true}'
    )
    hit = id5.parse(_request(
        host="id5-sync.com",
        url="https://id5-sync.com/api/config/prebid",
        method="POST",
        request_body=body,
    ))
    by_key = {p.key: p for p in hit.params}
    partner = by_key.get("(body) partner")
    assert partner is not None
    assert partner.value == "367"


def test_parse_handles_invalid_body_gracefully(id5) -> None:
    """A malformed body must not crash parse()."""
    hit = id5.parse(_request(
        host="id5-sync.com",
        url="https://id5-sync.com/gm/v3",
        method="POST",
        request_body="not json {",
    ))
    assert hit.module_id == "id5"


def test_parse_hit_basics(id5) -> None:
    url = "https://id5-sync.com/match?publisher_user_id=abc"
    hit = id5.parse(_request(host="id5-sync.com", url=url, event_id=21))
    assert hit.module_id == "id5"
    assert hit.host == "id5-sync.com"
    assert hit.events == [21]


# --- G. real-bundle integration --------------------------------------------


def test_real_bundle_attribution() -> None:
    """All id5-sync.com / *.id5-sync.com hosts attribute to id5."""
    from pathlib import Path
    bundle_path = Path("/tmp/apple-max.zip")
    if not bundle_path.exists():
        pytest.skip("working-dataset bundle /tmp/apple-max.zip not present")
    from leak_inspector.analysis import analyze_events
    from leak_inspector.bundle.reader import BundleReader
    with BundleReader(bundle_path) as b:
        analysis = analyze_events(b.manifest, b.events(), cname_chains=b.cname_chains)
    id5_hits = [h for h in analysis.hits if "id5-sync.com" in h.host]
    id5_untracked = [
        e for e in analysis.untracked_requests if "id5-sync.com" in e.host
    ]
    assert id5_untracked == [], (
        f"ID5 requests still untracked: "
        f"{[(e.host, e.url) for e in id5_untracked[:5]]}"
    )
    assert id5_hits, "no ID5 hits attributed at all"
    assert {h.module_id for h in id5_hits} == {"id5"}
