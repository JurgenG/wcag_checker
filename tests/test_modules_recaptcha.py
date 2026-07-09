"""Tests for the Google reCAPTCHA module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_BEHAVIORAL,
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def rc():
    return module_by_id("recaptcha")


def test_identity(rc) -> None:
    assert rc.module_id == "recaptcha"
    assert rc.module_name == "Google reCAPTCHA"
    assert rc.vendor == "Google LLC"


@pytest.mark.parametrize("host", ["www.recaptcha.net", "recaptcha.net"])
def test_matches_recaptcha_only_hosts(rc, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/anything")
    assert rc.matches(event) is True


def test_matches_path_gated_google(rc) -> None:
    event = make_request(
        host="www.google.com",
        url="https://www.google.com/recaptcha/api.js",
    )
    assert rc.matches(event) is True


def test_does_not_match_google_without_recaptcha_path(rc) -> None:
    event = make_request(host="www.google.com", url="https://www.google.com/search")
    assert rc.matches(event) is False


def test_matches_path_gated_gstatic(rc) -> None:
    event = make_request(
        host="www.gstatic.com",
        url="https://www.gstatic.com/recaptcha/releases/abc/recaptcha.js",
    )
    assert rc.matches(event) is True


def test_does_not_match_gstatic_without_recaptcha_path(rc) -> None:
    event = make_request(host="www.gstatic.com", url="https://www.gstatic.com/other.png")
    assert rc.matches(event) is False


@pytest.mark.parametrize("key", ["c"])
def test_identifiers(rc, key: str) -> None:
    event = make_request(host="www.recaptcha.net", url=f"https://www.recaptcha.net/recaptcha/api.js?{key}=x")
    hit = rc.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_IDENTIFIER


@pytest.mark.parametrize("key", ["co", "host"])
def test_content(rc, key: str) -> None:
    event = make_request(host="www.recaptcha.net", url=f"https://www.recaptcha.net/recaptcha/api.js?{key}=x")
    hit = rc.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_CONTENT


def test_action_is_behavioral(rc) -> None:
    event = make_request(host="www.recaptcha.net", url="https://www.recaptcha.net/recaptcha/api.js?action=login")
    hit = rc.parse(event)
    p = next(p for p in hit.params if p.key == "action")
    assert p.category == CAT_BEHAVIORAL


@pytest.mark.parametrize("key", ["k", "render", "size", "theme", "badge", "hl", "v"])
def test_technical(rc, key: str) -> None:
    event = make_request(host="www.recaptcha.net", url=f"https://www.recaptcha.net/recaptcha/api.js?{key}=x")
    hit = rc.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param(rc) -> None:
    event = make_request(host="www.recaptcha.net", url="https://www.recaptcha.net/recaptcha/api.js?weird=1")
    hit = rc.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "reCAPTCHA" in p.meaning
