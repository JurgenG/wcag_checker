"""Tests for the Snowplow Analytics module."""

from __future__ import annotations

import base64
import json

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
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
def sp():
    return module_by_id("snowplow")


def test_identity(sp) -> None:
    assert sp.module_id == "snowplow"
    # Snowplow is self-hostable: jurisdiction is per-instance, not per-module.
    # It's surfaced via a per-hit ``(deployment)`` ParamInfo instead.
    assert sp.legal_jurisdiction == ""


@pytest.mark.parametrize(
    "host", ["collector.snplow.net", "acme.snowplowanalytics.com"],
)
def test_matches_hosted(sp, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/com.snowplowanalytics.snowplow/tp2")
    assert sp.matches(event) is True


@pytest.mark.parametrize(
    "path", ["/com.snowplowanalytics.snowplow/tp2", "/r/tp2"],
)
def test_matches_canonical_paths_on_any_host(sp, path: str) -> None:
    event = make_request(host="self-hosted.example.com", url=f"https://self-hosted.example.com{path}")
    assert sp.matches(event) is True


def test_matches_via_param_signature(sp) -> None:
    """``tv`` + ``e`` with a known event code matches custom-pathed collectors."""
    event = make_request(
        host="tracker.example.com",
        url="https://tracker.example.com/track?tv=js-3.0.0&e=pv",
    )
    assert sp.matches(event) is True


def test_does_not_match_appnexus_vevent_collision(sp) -> None:
    """``/vevent`` on adnxs.com also ships ``tv``+``e`` but with non-Snowplow ``e`` values."""
    event = make_request(
        host="ib.adnxs.com",
        url="https://ib.adnxs.com/vevent?tv=view7&e=opaqueblob",
    )
    assert sp.matches(event) is False


def test_matches_via_body_schema_marker(sp) -> None:
    """Body containing the Iglu schema URL is sufficient even with fully-custom host+path."""
    body = json.dumps({
        "schema": "iglu:com.snowplowanalytics.snowplow/payload_data/jsonschema/1-0-4",
        "data": [{"e": "pv", "aid": "myapp"}],
    })
    event = make_request(
        host="sneeuwploeg.museumpassmusees.be",
        url="https://sneeuwploeg.museumpassmusees.be/publiq/t",
        request_body=body,
    )
    assert sp.matches(event) is True


def test_does_not_match_unrelated(sp) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert sp.matches(event) is False


@pytest.mark.parametrize("key", ["nuid", "duid", "tnuid", "fp"])
def test_persistent_identifiers_high(sp, key: str) -> None:
    event = make_request(host="acme.snplow.net", url=f"https://acme.snplow.net/r/tp2?{key}=ABC")
    hit = sp.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


def test_uid_is_pii_high(sp) -> None:
    event = make_request(host="acme.snplow.net", url="https://acme.snplow.net/r/tp2?uid=alice")
    hit = sp.parse(event)
    p = next(p for p in hit.params if p.key == "uid")
    assert p.category == CAT_PII
    assert p.privacy_impact == IMPACT_HIGH


def test_ip_is_pii(sp) -> None:
    event = make_request(host="acme.snplow.net", url="https://acme.snplow.net/r/tp2?ip=1.2.3.4")
    hit = sp.parse(event)
    p = next(p for p in hit.params if p.key == "ip")
    assert p.category == CAT_PII


@pytest.mark.parametrize("key", ["url", "refr", "page"])
def test_content(sp, key: str) -> None:
    event = make_request(host="acme.snplow.net", url=f"https://acme.snplow.net/r/tp2?{key}=x")
    hit = sp.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize("key", ["e", "se_ca", "se_ac", "se_la", "tr_id", "ti_sk"])
def test_behavioral(sp, key: str) -> None:
    event = make_request(host="acme.snplow.net", url=f"https://acme.snplow.net/r/tp2?{key}=x")
    hit = sp.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_BEHAVIORAL


@pytest.mark.parametrize("key", ["co", "cx", "ue_pr", "ue_px"])
def test_opaque_payloads_high_impact(sp, key: str) -> None:
    """Schema-bound JSON blobs can carry arbitrary PII — flagged HIGH on principle."""
    event = make_request(host="acme.snplow.net", url=f"https://acme.snplow.net/r/tp2?{key}=x")
    hit = sp.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_BEHAVIORAL
    assert p.privacy_impact == IMPACT_HIGH


@pytest.mark.parametrize("key", ["aid", "tv", "tna", "p", "dtm", "lang", "res", "f_pdf", "f_java"])
def test_technical(sp, key: str) -> None:
    event = make_request(host="acme.snplow.net", url=f"https://acme.snplow.net/r/tp2?{key}=x")
    hit = sp.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_query_aid_is_technical_low(sp) -> None:
    """``aid`` is the operator-scoped application ID — technical, low impact."""
    event = make_request(host="acme.snplow.net", url="https://acme.snplow.net/r/tp2?aid=myapp")
    hit = sp.parse(event)
    p = next(p for p in hit.params if p.key == "aid")
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


def test_tp2_body_extracts_event_batch(sp) -> None:
    body = json.dumps({
        "schema": "iglu:com.snowplowanalytics.snowplow/payload_data/jsonschema/1-0-4",
        "data": [
            {"e": "pv", "aid": "myapp", "duid": "DUID-1", "nuid": "NUID-1", "url": "https://example.com/"},
            {"e": "pp", "aid": "myapp"},
            {"e": "se", "aid": "myapp"},
        ],
    })
    event = make_request(host="acme.snplow.net", url="https://acme.snplow.net/com.snowplowanalytics.snowplow/tp2", request_body=body)
    hit = sp.parse(event)
    by_key = {p.key: p for p in hit.params}
    assert by_key["(body) batched_event_count"].value == "3"
    # Distinct event types are sorted
    assert "pp" in by_key["(body) event_types"].value
    assert "pv" in by_key["(body) event_types"].value
    assert "se" in by_key["(body) event_types"].value
    # First event's identifying fields surface
    assert by_key["(body) duid"].category == CAT_IDENTIFIER
    assert by_key["(body) duid"].privacy_impact == IMPACT_HIGH
    # Application ID is operator-scoped — technical, low impact
    assert by_key["(body) aid"].category == CAT_TECHNICAL
    assert by_key["(body) aid"].privacy_impact == IMPACT_LOW
    assert by_key["(body) nuid"].value == "NUID-1"
    assert by_key["(body) url"].value == "https://example.com/"


def test_tp2_body_contexts_with_pii_field_names_promoted(sp) -> None:
    """Context-entity field names matching PII patterns promote impact to HIGH."""
    contexts = json.dumps({
        "schema": "iglu:com.snowplowanalytics.snowplow/contexts/jsonschema/1-0-1",
        "data": [{
            "schema": "iglu:com.acme/user/jsonschema/1-0-0",
            "data": {"user_id": "alice", "email": "alice@example.com"},
        }],
    })
    body = json.dumps({
        "schema": "iglu:com.snowplowanalytics.snowplow/payload_data/jsonschema/1-0-4",
        "data": [{"e": "pv", "co": contexts}],
    })
    event = make_request(host="acme.snplow.net", url="https://acme.snplow.net/com.snowplowanalytics.snowplow/tp2", request_body=body)
    hit = sp.parse(event)
    by_key = {p.key: p for p in hit.params}
    p = by_key["(body) co #1 fields"]
    assert p.category == CAT_PII
    assert p.privacy_impact == IMPACT_HIGH
    assert "email" in p.value


def test_tp2_body_contexts_without_pii_stay_behavioral(sp) -> None:
    contexts = json.dumps({
        "schema": "iglu:com.snowplowanalytics.snowplow/contexts/jsonschema/1-0-1",
        "data": [{
            "schema": "iglu:com.acme/page/jsonschema/1-0-0",
            "data": {"section": "home", "variant": "A"},
        }],
    })
    body = json.dumps({
        "schema": "iglu:com.snowplowanalytics.snowplow/payload_data/jsonschema/1-0-4",
        "data": [{"e": "pv", "co": contexts}],
    })
    event = make_request(host="acme.snplow.net", url="https://acme.snplow.net/com.snowplowanalytics.snowplow/tp2", request_body=body)
    hit = sp.parse(event)
    p = next(p for p in hit.params if p.key == "(body) co #1 fields")
    assert p.category == CAT_BEHAVIORAL


def test_tp2_body_cx_base64_contexts(sp) -> None:
    """``cx`` field is the same JSON wrapped in base64."""
    contexts_json = json.dumps({
        "schema": "iglu:com.snowplowanalytics.snowplow/contexts/jsonschema/1-0-1",
        "data": [{
            "schema": "iglu:com.acme/user/jsonschema/1-0-0",
            "data": {"phone": "+32..."},
        }],
    })
    cx = base64.b64encode(contexts_json.encode("utf-8")).decode("ascii")
    body = json.dumps({
        "schema": "iglu:com.snowplowanalytics.snowplow/payload_data/jsonschema/1-0-4",
        "data": [{"e": "pv", "cx": cx}],
    })
    event = make_request(host="acme.snplow.net", url="https://acme.snplow.net/com.snowplowanalytics.snowplow/tp2", request_body=body)
    hit = sp.parse(event)
    p = next(p for p in hit.params if p.key == "(body) co #1 fields")
    assert "phone" in p.value
    assert p.category == CAT_PII  # phone is PII-shaped


def test_tp2_body_unstruct_event_schema_surfaced(sp) -> None:
    ue = json.dumps({
        "schema": "iglu:com.snowplowanalytics.snowplow/unstruct_event/jsonschema/1-0-0",
        "data": {
            "schema": "iglu:com.acme/purchase/jsonschema/1-0-0",
            "data": {"order_id": "ORDER-1", "value": 49.95},
        },
    })
    body = json.dumps({
        "schema": "iglu:com.snowplowanalytics.snowplow/payload_data/jsonschema/1-0-4",
        "data": [{"e": "ue", "ue_pr": ue}],
    })
    event = make_request(host="acme.snplow.net", url="https://acme.snplow.net/com.snowplowanalytics.snowplow/tp2", request_body=body)
    hit = sp.parse(event)
    by_key = {p.key: p for p in hit.params}
    assert "com.acme/purchase" in by_key["(body) ue schema"].value
    assert "order_id" in by_key["(body) ue fields"].value


def test_tp2_body_handles_invalid_json(sp) -> None:
    event = make_request(host="acme.snplow.net", url="https://acme.snplow.net/com.snowplowanalytics.snowplow/tp2", request_body="not-json")
    hit = sp.parse(event)
    assert not any(p.key.startswith("(body)") for p in hit.params)


def test_unknown_param(sp) -> None:
    event = make_request(host="acme.snplow.net", url="https://acme.snplow.net/r/tp2?weirdo=1")
    hit = sp.parse(event)
    p = next(p for p in hit.params if p.key == "weirdo")
    assert p.category == CAT_OTHER
    assert "Snowplow" in p.meaning


# --- deployment annotation (hosted vs self-hosted) -------------------------


@pytest.mark.parametrize(
    "host", ["collector.snplow.net", "acme.snowplowanalytics.com"],
)
def test_deployment_hosted_annotation(sp, host: str) -> None:
    """Hosted Snowplow BDP hits carry a Snowplow-BDP deployment ParamInfo."""
    event = make_request(host=host, url=f"https://{host}/com.snowplowanalytics.snowplow/tp2")
    hit = sp.parse(event)
    p = next(p for p in hit.params if p.key == "(deployment) Snowplow BDP")
    assert "Snowplow Analytics Ltd" in p.meaning
    assert not any(p.key == "(deployment) self-hosted" for p in hit.params)


def test_deployment_self_hosted_annotation(sp) -> None:
    """A tp2 hit on a non-hosted host gets the self-hosted ParamInfo."""
    event = make_request(
        host="sp.example.be",
        url="https://sp.example.be/com.snowplowanalytics.snowplow/tp2",
    )
    hit = sp.parse(event)
    p = next(p for p in hit.params if p.key == "(deployment) self-hosted")
    assert p.privacy_impact == IMPACT_LOW
    assert "operator" in p.meaning.lower()
    assert not any(p.key == "(deployment) Snowplow BDP" for p in hit.params)
