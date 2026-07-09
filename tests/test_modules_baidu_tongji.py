"""Tests for the Baidu Tongji module."""

from __future__ import annotations

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
def bd():
    return module_by_id("baidu_tongji")


def test_identity(bd) -> None:
    assert bd.module_id == "baidu_tongji"
    assert bd.legal_jurisdiction == "CN"
    assert "PRC" in bd.sovereignty_notes or "China" in bd.sovereignty_notes


@pytest.mark.parametrize("host", ["hm.baidu.com", "hmcdn.baidu.com"])
def test_matches(bd, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/hm.gif?si=abc")
    assert bd.matches(event) is True


def test_does_not_match_baidu_com_bare(bd) -> None:
    """Only the specific subdomains — not the bare baidu.com."""
    event = make_request(host="baidu.com", url="https://baidu.com/")
    assert bd.matches(event) is False


def test_si_is_technical_low(bd) -> None:
    """``si`` is the per-customer Baidu Tongji counter key — technical, low impact."""
    event = make_request(host="hm.baidu.com", url="https://hm.baidu.com/hm.gif?si=ABC")
    hit = bd.parse(event)
    p = next(p for p in hit.params if p.key == "si")
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


def test_uid_is_pii_high(bd) -> None:
    """Site-supplied uid is PII."""
    event = make_request(host="hm.baidu.com", url="https://hm.baidu.com/hm.gif?uid=user")
    hit = bd.parse(event)
    p = next(p for p in hit.params if p.key == "uid")
    assert p.category == CAT_PII
    assert p.privacy_impact == IMPACT_HIGH


@pytest.mark.parametrize("key", ["u", "su", "tt", "hn", "lo"])
def test_content(bd, key: str) -> None:
    event = make_request(host="hm.baidu.com", url=f"https://hm.baidu.com/hm.gif?{key}=x")
    hit = bd.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize("key", ["nv", "lt", "st", "ep", "et", "se_cat"])
def test_behavioral(bd, key: str) -> None:
    event = make_request(host="hm.baidu.com", url=f"https://hm.baidu.com/hm.gif?{key}=x")
    hit = bd.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_BEHAVIORAL


@pytest.mark.parametrize("key", ["v", "cv", "sw", "sh", "ln", "rnd"])
def test_technical(bd, key: str) -> None:
    event = make_request(host="hm.baidu.com", url=f"https://hm.baidu.com/hm.gif?{key}=x")
    hit = bd.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param(bd) -> None:
    event = make_request(host="hm.baidu.com", url="https://hm.baidu.com/hm.gif?weird=1")
    hit = bd.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Baidu" in p.meaning
