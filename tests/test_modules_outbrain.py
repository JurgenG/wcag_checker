"""Tests for the Outbrain module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_CONSENT,
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def ob():
    return module_by_id("outbrain")


def test_identity(ob) -> None:
    assert ob.module_id == "outbrain"
    assert ob.module_name == "Outbrain"


@pytest.mark.parametrize(
    "host",
    ["outbrain.com", "tr.outbrain.com", "amplify.outbrain.com", "widgets.outbrain.com"],
)
def test_matches(ob, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert ob.matches(event) is True


@pytest.mark.parametrize(
    "key", ["ctp"],
)
def test_identifiers(ob, key: str) -> None:
    event = make_request(host="tr.outbrain.com", url=f"https://tr.outbrain.com/?{key}=x")
    hit = ob.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER


@pytest.mark.parametrize("key", ["name", "event", "category"])
def test_behavioral(ob, key: str) -> None:
    event = make_request(host="tr.outbrain.com", url=f"https://tr.outbrain.com/?{key}=x")
    hit = ob.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_BEHAVIORAL


@pytest.mark.parametrize("key", ["permalink", "referrer", "pRef", "dl", "url", "title"])
def test_content(ob, key: str) -> None:
    event = make_request(host="tr.outbrain.com", url=f"https://tr.outbrain.com/?{key}=x")
    hit = ob.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize(
    "key",
    ["marketerId", "obApiKey", "widgetJSId", "widgetId", "id",
     "cht", "obApiVersion", "zone", "v"],
)
def test_technical(ob, key: str) -> None:
    event = make_request(host="tr.outbrain.com", url=f"https://tr.outbrain.com/?{key}=x")
    hit = ob.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


@pytest.mark.parametrize("key", ["gdpr", "gdpr_consent"])
def test_consent(ob, key: str) -> None:
    event = make_request(host="tr.outbrain.com", url=f"https://tr.outbrain.com/?{key}=1")
    hit = ob.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONSENT


def test_unknown_param(ob) -> None:
    event = make_request(host="tr.outbrain.com", url="https://tr.outbrain.com/?weird=1")
    hit = ob.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Outbrain" in p.meaning
