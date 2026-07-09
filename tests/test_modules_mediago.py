"""Tests for the Mediago (Bytedance) module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_CONSENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    IMPACT_HIGH,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def mg():
    return module_by_id("mediago")


def test_identity(mg) -> None:
    assert mg.module_id == "mediago"
    assert mg.module_name == "Mediago (Bytedance)"
    assert mg.legal_jurisdiction == "China"


@pytest.mark.parametrize(
    "host", ["mediago.io", "images.mediago.io", "trace-eu.mediago.io", "gtrace.mediago.io"],
)
def test_matches(mg, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert mg.matches(event) is True


@pytest.mark.parametrize("key", ["uid", "mguid", "rdid", "google_gid", "google_push"])
def test_high_impact_identifiers(mg, key: str) -> None:
    event = make_request(host="trace-eu.mediago.io", url=f"https://trace-eu.mediago.io/?{key}=x")
    hit = mg.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


@pytest.mark.parametrize("key", ["trackingid", "acid"])
def test_account_identifiers(mg, key: str) -> None:
    event = make_request(host="trace-eu.mediago.io", url=f"https://trace-eu.mediago.io/?{key}=x")
    hit = mg.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER


@pytest.mark.parametrize("key", ["data", "app", "ext"])
def test_behavioral(mg, key: str) -> None:
    event = make_request(host="trace-eu.mediago.io", url=f"https://trace-eu.mediago.io/?{key}=x")
    hit = mg.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_BEHAVIORAL


@pytest.mark.parametrize("key", ["gdpr", "gdpr_consent"])
def test_consent(mg, key: str) -> None:
    event = make_request(host="trace-eu.mediago.io", url=f"https://trace-eu.mediago.io/?{key}=1")
    hit = mg.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONSENT


@pytest.mark.parametrize("key", ["tn", "c_sync", "dm", "google_cver", "mcb"])
def test_technical(mg, key: str) -> None:
    event = make_request(host="trace-eu.mediago.io", url=f"https://trace-eu.mediago.io/?{key}=x")
    hit = mg.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param(mg) -> None:
    event = make_request(host="trace-eu.mediago.io", url="https://trace-eu.mediago.io/?weird=1")
    hit = mg.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Mediago" in p.meaning
