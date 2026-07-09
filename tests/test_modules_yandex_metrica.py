"""Tests for the Yandex.Metrica module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_CONSENT,
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_PII,
    CAT_TECHNICAL,
    IMPACT_HIGH,
    IMPACT_LOW,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def ym():
    return module_by_id("yandex_metrica")


def test_identity(ym) -> None:
    assert ym.module_id == "yandex_metrica"
    assert ym.legal_jurisdiction == "RU"
    assert "152-FZ" in ym.sovereignty_notes or "Russia" in ym.sovereignty_notes


@pytest.mark.parametrize(
    "host",
    [
        "mc.yandex.ru", "mc.yandex.com", "mc.yandex.com.tr",
        "mc.yandex.by", "mc.yandex.kz", "mc.webvisor.org", "mc.webvisor.com",
    ],
)
def test_matches(ym, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/watch/12345")
    assert ym.matches(event) is True


def test_does_not_match_lookalike(ym) -> None:
    """Conservative — ``mc.yandex.evilcorp.com`` must NOT match."""
    event = make_request(host="mc.yandex.evilcorp.com", url="https://mc.yandex.evilcorp.com/")
    assert ym.matches(event) is False


def test_does_not_match_unrelated(ym) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert ym.matches(event) is False


def test_path_extracts_counter_id_from_watch(ym) -> None:
    event = make_request(host="mc.yandex.ru", url="https://mc.yandex.ru/watch/12345678")
    hit = ym.parse(event)
    p = next(p for p in hit.params if p.key == "(path) counter_id")
    assert p.value == "12345678"
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


def test_path_extracts_webvisor_counter_id(ym) -> None:
    """``/watch/X/1`` is the WebVisor session-replay endpoint."""
    event = make_request(host="mc.yandex.ru", url="https://mc.yandex.ru/watch/99999/1")
    hit = ym.parse(event)
    p = next(p for p in hit.params if p.key == "(path) webvisor_counter_id")
    assert p.value == "99999"
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW
    # And the regular counter_id pattern must NOT also match (break in loop).
    assert not any(p.key == "(path) counter_id" for p in hit.params)


def test_path_extracts_clmap_counter_id(ym) -> None:
    event = make_request(host="mc.yandex.ru", url="https://mc.yandex.ru/clmap/77")
    hit = ym.parse(event)
    p = next(p for p in hit.params if p.key == "(path) clmap_counter_id")
    assert p.value == "77"
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


def test_path_extracts_informer_counter_id(ym) -> None:
    event = make_request(host="mc.yandex.ru", url="https://mc.yandex.ru/informer/42")
    hit = ym.parse(event)
    p = next(p for p in hit.params if p.key == "(path) informer_counter_id")
    assert p.value == "42"
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW
    assert p.category == CAT_TECHNICAL
    assert p.privacy_impact == IMPACT_LOW


@pytest.mark.parametrize("key", ["i", "ym_uid"])
def test_persistent_pseudonym_high(ym, key: str) -> None:
    event = make_request(host="mc.yandex.ru", url=f"https://mc.yandex.ru/watch/1?{key}=ABC")
    hit = ym.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER
    assert p.privacy_impact == IMPACT_HIGH


def test_uid_is_pii(ym) -> None:
    event = make_request(host="mc.yandex.ru", url="https://mc.yandex.ru/watch/1?uid=user")
    hit = ym.parse(event)
    p = next(p for p in hit.params if p.key == "uid")
    assert p.category == CAT_PII


def test_wv_type_is_behavioral_high(ym) -> None:
    """WebVisor record type — session-replay payload framing."""
    event = make_request(host="mc.yandex.ru", url="https://mc.yandex.ru/watch/1/1?wv-type=mouse")
    hit = ym.parse(event)
    p = next(p for p in hit.params if p.key == "wv-type")
    assert p.category == CAT_BEHAVIORAL
    assert p.privacy_impact == IMPACT_HIGH


@pytest.mark.parametrize("key", ["page-url", "dl", "page-ref", "r", "t"])
def test_content(ym, key: str) -> None:
    event = make_request(host="mc.yandex.ru", url=f"https://mc.yandex.ru/watch/1?{key}=x")
    hit = ym.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONTENT


@pytest.mark.parametrize("key", ["ev-id", "ev-type", "goal-id", "params", "experiments"])
def test_behavioral(ym, key: str) -> None:
    event = make_request(host="mc.yandex.ru", url=f"https://mc.yandex.ru/watch/1?{key}=x")
    hit = ym.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_BEHAVIORAL


@pytest.mark.parametrize("key", ["consent", "gdpr"])
def test_consent(ym, key: str) -> None:
    event = make_request(host="mc.yandex.ru", url=f"https://mc.yandex.ru/watch/1?{key}=1")
    hit = ym.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONSENT


def test_unknown_param(ym) -> None:
    event = make_request(host="mc.yandex.ru", url="https://mc.yandex.ru/watch/1?weird=1")
    hit = ym.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Yandex" in p.meaning
