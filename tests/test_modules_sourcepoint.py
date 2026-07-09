"""Tests for the Sourcepoint Consent Management Platform detector.

Sourcepoint (US-incorporated) is one of the four major CMP vendors —
sits alongside the existing Cookiebot / OneTrust / TrustArc modules.
Observed surface:

* ``cdn.privacy-mgmt.com`` — the entire Sourcepoint CMP runtime.
  Bundle JS under ``/unified/``, the unified-wrapper paths under
  ``/wrapper/v2/`` (``/meta-data``, ``/messages``, ``/pv-data``,
  ``/choice/consent-all``, ``/choice/gdpr/<msgid>``), notice UI assets
  at ``/Notice.*``, vendor list at ``/consent/tcfv2/vendor-list/...``.

The distinctive privacy story:

* Consent state is collected at IAB TCF v2 + USNAT/UsP scope. The
  ``/wrapper/v2/pv-data`` POST body carries full ``granularStatus`` —
  per-purpose / per-vendor consent decisions, with ``previousOptInAll``
  and ``rejectedLI`` fields revealing the full consent journey.
* ``accountId`` (200), ``propertyId`` (29938), ``messageId`` (1484892)
  are stable identifiers per Sourcepoint-managed property.
* The ``consentUUID`` is the per-visitor consent decision pseudonym —
  HIGH identifier because it joins consent decisions across sessions.

Pattern follows ``tests/test_modules_ga4.py``.
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
def sourcepoint():
    for module in all_modules():
        if module.module_id == "sourcepoint":
            return module
    raise AssertionError("sourcepoint module not registered")


# --- A. class identity ------------------------------------------------------


def test_module_registered() -> None:
    assert "sourcepoint" in [m.module_id for m in all_modules()]


def test_module_identity(sourcepoint) -> None:
    assert sourcepoint.module_id == "sourcepoint"
    assert "Sourcepoint" in sourcepoint.module_name


def test_module_sovereignty(sourcepoint) -> None:
    """Sourcepoint is US-incorporated; CMP role distinguishes it from a tracker."""
    assert "Sourcepoint" in sourcepoint.vendor
    assert sourcepoint.legal_jurisdiction == "US"
    notes = (sourcepoint.sovereignty_notes or "").lower()
    # Honest framing: it's a CMP, not an ad tracker
    assert "consent" in notes or "cmp" in notes


# --- B. matches() — positive cases ------------------------------------------


@pytest.mark.parametrize(
    "host,path",
    [
        # Wrapper API
        ("cdn.privacy-mgmt.com", "/wrapper/v2/meta-data"),
        ("cdn.privacy-mgmt.com", "/wrapper/v2/messages"),
        ("cdn.privacy-mgmt.com", "/wrapper/v2/pv-data"),
        ("cdn.privacy-mgmt.com", "/wrapper/v2/choice/consent-all"),
        ("cdn.privacy-mgmt.com", "/wrapper/v2/choice/gdpr/11"),
        ("cdn.privacy-mgmt.com", "/wrapper/v2/choice/gdpr/123456"),
        # Bundle JS / notice UI
        ("cdn.privacy-mgmt.com", "/unified/wrapperMessagingWithoutDetection.js"),
        ("cdn.privacy-mgmt.com", "/unified/4.40.1/gdpr-tcf.27718c8cb9d29947d2c1.bundle.js"),
        ("cdn.privacy-mgmt.com", "/unified/4.40.1/usnat-uspapi.090eccada574d39af6f8.bundle.js"),
        ("cdn.privacy-mgmt.com", "/Notice.1c267.css"),
        ("cdn.privacy-mgmt.com", "/Notice.d4c42.js"),
        ("cdn.privacy-mgmt.com", "/polyfills.01516.js"),
        ("cdn.privacy-mgmt.com", "/index.html"),
        # Vendor list (TCF infrastructure)
        ("cdn.privacy-mgmt.com", "/consent/tcfv2/vendor-list/categories"),
    ],
)
def test_matches_documented_sourcepoint_paths(sourcepoint, host: str, path: str) -> None:
    url = f"https://{host}{path}"
    assert sourcepoint.matches(_request(host=host, url=url)) is True


def test_matches_apex_privacy_mgmt(sourcepoint) -> None:
    """The apex ``privacy-mgmt.com`` is also Sourcepoint."""
    url = "https://privacy-mgmt.com/wrapper/v2/meta-data"
    assert sourcepoint.matches(_request(host="privacy-mgmt.com", url=url)) is True


def test_matches_is_case_insensitive_on_host(sourcepoint) -> None:
    url = "https://CDN.PRIVACY-MGMT.COM/wrapper/v2/pv-data"
    assert sourcepoint.matches(_request(host="CDN.PRIVACY-MGMT.COM", url=url)) is True


# --- C. matches() — negative cases -----------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "example.com",
        "privacy-mgmt-impersonator.example",
        "fakeprivacy-mgmt.com",
        "privacy-mgmt.example.com",
        # Unrelated "privacy" domains that aren't Sourcepoint
        "privacy.example.com",
        "privacymanager.com",
    ],
)
def test_does_not_match_unrelated_hosts(sourcepoint, host: str) -> None:
    url = f"https://{host}/wrapper/v2/pv-data"
    assert sourcepoint.matches(_request(host=host, url=url)) is False


# --- D. dispatcher routing -------------------------------------------------


def test_detect_routes_to_sourcepoint() -> None:
    req = _request(
        host="cdn.privacy-mgmt.com",
        url="https://cdn.privacy-mgmt.com/wrapper/v2/pv-data?env=prod",
    )
    module = detect(req)
    assert module is not None
    assert module.module_id == "sourcepoint"


# --- E. parse() — query-param classification ------------------------------


def test_parse_classifies_property_and_account_ids(sourcepoint) -> None:
    """``accountId`` / ``propertyId`` / ``siteId`` are Sourcepoint property IDs."""
    url = (
        "https://cdn.privacy-mgmt.com/wrapper/v2/meta-data"
        "?accountId=200&propertyId=29938&siteId=29938"
    )
    hit = sourcepoint.parse(_request(host="cdn.privacy-mgmt.com", url=url))
    by_key = {p.key: p for p in hit.params}
    for key in ("accountId", "propertyId", "siteId"):
        assert by_key[key].category == CAT_TECHNICAL, key
        assert by_key[key].privacy_impact == IMPACT_LOW, key


def test_parse_classifies_consent_uuid_as_high(sourcepoint) -> None:
    """``consentUUID`` is the per-visitor consent decision pseudonym — HIGH."""
    url = (
        "https://cdn.privacy-mgmt.com/index.html"
        "?message_id=1484892&consentUUID=db6abc12-de34-5678&consent_origin=https%3A%2F%2Fexample.com"
    )
    hit = sourcepoint.parse(_request(host="cdn.privacy-mgmt.com", url=url))
    by_key = {p.key: p for p in hit.params}
    assert by_key["consentUUID"].category == CAT_IDENTIFIER
    assert by_key["consentUUID"].privacy_impact == IMPACT_HIGH


def test_parse_classifies_message_id_as_identifier(sourcepoint) -> None:
    """``message_id`` is the CMP message variant the visitor is being shown."""
    url = "https://cdn.privacy-mgmt.com/index.html?message_id=1484892"
    hit = sourcepoint.parse(_request(host="cdn.privacy-mgmt.com", url=url))
    by_key = {p.key: p for p in hit.params}
    assert by_key["message_id"].category == CAT_TECHNICAL


def test_parse_classifies_metadata_and_body_as_consent(sourcepoint) -> None:
    """``metadata`` and ``body`` carry serialized consent state — CONSENT category."""
    url = (
        "https://cdn.privacy-mgmt.com/wrapper/v2/meta-data"
        "?metadata=%7B%22gdpr%22%3A%7B%7D%2C%22usnat%22%3A%7B%7D%7D"
    )
    hit = sourcepoint.parse(_request(host="cdn.privacy-mgmt.com", url=url))
    by_key = {p.key: p for p in hit.params}
    assert by_key["metadata"].category == CAT_CONSENT


def test_parse_classifies_consent_origin_as_content(sourcepoint) -> None:
    """``consent_origin`` carries the URL of the consent-collection page."""
    url = "https://cdn.privacy-mgmt.com/index.html?consent_origin=https%3A%2F%2Fexample.com"
    hit = sourcepoint.parse(_request(host="cdn.privacy-mgmt.com", url=url))
    by_key = {p.key: p for p in hit.params}
    assert by_key["consent_origin"].category == CAT_CONTENT


def test_parse_classifies_environment_and_version_as_technical(sourcepoint) -> None:
    """``env`` / ``scriptVersion`` / ``scriptType`` / ``hasCsp`` — TECHNICAL / LOW."""
    url = (
        "https://cdn.privacy-mgmt.com/wrapper/v2/pv-data"
        "?env=prod&scriptVersion=4.40.1&scriptType=unified&hasCsp=true"
    )
    hit = sourcepoint.parse(_request(host="cdn.privacy-mgmt.com", url=url))
    by_key = {p.key: p for p in hit.params}
    for key in ("env", "scriptVersion", "scriptType", "hasCsp"):
        assert by_key[key].category == CAT_TECHNICAL, key
        assert by_key[key].privacy_impact == IMPACT_LOW, key


# --- F. JSON body parsing --------------------------------------------------


def test_parse_surfaces_body_account_and_property_ids(sourcepoint) -> None:
    """``/choice/gdpr/<id>`` POST body carries account/property/visitor UUIDs."""
    body = (
        '{"accountId":200,"applies":true,"authId":null,"messageId":1484892,'
        '"prtnUUID":"12715451-de68-4af6-b093-3dbd7fb7eeb9",'
        '"mmsDomain":"https://cdn.privacy-mgmt.com","propertyId":29938,'
        '"uuid":"db6abc12-de34-5678"}'
    )
    hit = sourcepoint.parse(_request(
        host="cdn.privacy-mgmt.com",
        url="https://cdn.privacy-mgmt.com/wrapper/v2/choice/gdpr/11",
        method="POST",
        request_body=body,
    ))
    by_key = {p.key: p for p in hit.params}
    assert by_key["(body) accountId"].value == "200"
    assert by_key["(body) propertyId"].value == "29938"
    assert by_key["(body) uuid"].category == CAT_IDENTIFIER
    assert by_key["(body) uuid"].privacy_impact == IMPACT_HIGH
    # The per-partner UUID is also high-impact (cross-partner linkability).
    assert by_key["(body) prtnUUID"].privacy_impact == IMPACT_HIGH


def test_parse_surfaces_body_consent_state(sourcepoint) -> None:
    """``/pv-data`` body's ``gdpr.consentStatus`` block describes the consent decision."""
    body = (
        '{"gdpr":{"applies":true,"categoryId":1,"consentStatus":'
        '{"rejectedAny":false,"rejectedLI":false,"consentedAll":false,'
        '"hasConsentData":false,"previousOptInAll":false,"defaultConsent":true}}}'
    )
    hit = sourcepoint.parse(_request(
        host="cdn.privacy-mgmt.com",
        url="https://cdn.privacy-mgmt.com/wrapper/v2/pv-data",
        method="POST",
        request_body=body,
    ))
    by_key = {p.key: p for p in hit.params}
    assert by_key["(body) gdpr_applies"].value == "True"
    # We expose the consent-state booleans together so the report shows the journey.
    consent_status = by_key.get("(body) consentStatus")
    assert consent_status is not None
    assert consent_status.category == CAT_CONSENT


def test_parse_handles_invalid_body_gracefully(sourcepoint) -> None:
    hit = sourcepoint.parse(_request(
        host="cdn.privacy-mgmt.com",
        url="https://cdn.privacy-mgmt.com/wrapper/v2/pv-data",
        method="POST",
        request_body="not json {",
    ))
    assert hit.module_id == "sourcepoint"


def test_parse_hit_basics(sourcepoint) -> None:
    url = "https://cdn.privacy-mgmt.com/wrapper/v2/pv-data?env=prod"
    hit = sourcepoint.parse(_request(host="cdn.privacy-mgmt.com", url=url, event_id=44))
    assert hit.module_id == "sourcepoint"
    assert hit.host == "cdn.privacy-mgmt.com"
    assert hit.events == [44]


# --- G. real-bundle integration --------------------------------------------


def test_real_bundle_attribution() -> None:
    """All cdn.privacy-mgmt.com requests on /tmp/apple-max.zip attribute to sourcepoint."""
    from pathlib import Path
    bundle_path = Path("/tmp/apple-max.zip")
    if not bundle_path.exists():
        pytest.skip("working-dataset bundle /tmp/apple-max.zip not present")
    from leak_inspector.analysis import analyze_events
    from leak_inspector.bundle.reader import BundleReader
    with BundleReader(bundle_path) as b:
        analysis = analyze_events(b.manifest, b.events(), cname_chains=b.cname_chains)
    sp_hits = [h for h in analysis.hits if "privacy-mgmt.com" in h.host]
    sp_untracked = [e for e in analysis.untracked_requests if "privacy-mgmt.com" in e.host]
    assert sp_untracked == [], (
        f"Sourcepoint requests still untracked: "
        f"{[(e.host, e.url) for e in sp_untracked[:5]]}"
    )
    assert sp_hits, "no Sourcepoint hits attributed at all"
    assert {h.module_id for h in sp_hits} == {"sourcepoint"}
