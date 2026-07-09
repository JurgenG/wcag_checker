"""Tests for the googleapis.com residual catch-all module.

The critical contract is ordering: the specific Google modules
(``google_fonts`` / ``google_cdn`` / ``google_maps``) must still win on
their own hosts, and only the residual googleapis.com hosts fall through
to ``google_apis``. These tests assert against the live registry's
first-match-wins dispatch, not the module in isolation.
"""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_TECHNICAL, detect

from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("google_apis")


def test_identity(m) -> None:
    assert m.module_id == "google_apis"
    assert m.legal_jurisdiction == "US"


def test_matches_residual_googleapis_hosts(m) -> None:
    for host in ("mt.googleapis.com", "places.googleapis.com",
                 "translate.googleapis.com", "translate-pa.googleapis.com"):
        event = make_request(host=host, url=f"https://{host}/x")
        assert m.matches(event) is True


def test_does_not_match_unrelated(m) -> None:
    for host in ("googleapis.com.evil.com", "notgoogleapis.com",
                 "example.com"):
        event = make_request(host=host, url=f"https://{host}/")
        assert m.matches(event) is False


@pytest.mark.parametrize("host,expected", [
    ("fonts.googleapis.com", "google_fonts"),
    ("ajax.googleapis.com", "google_cdn"),
    ("maps.googleapis.com", "google_maps"),
    ("mt.googleapis.com", "google_apis"),
    ("translate.googleapis.com", "google_apis"),
    ("places.googleapis.com", "google_apis"),
])
def test_specific_google_modules_win_residual_falls_through(host, expected) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    module = detect(event)
    assert module is not None and module.module_id == expected


def test_public_api_key_is_technical_not_visitor(m) -> None:
    url = ("https://translate-pa.googleapis.com/v1/supportedLanguages"
           "?client=te&display_language=nl&key=AIzaSyBWDj0QJ")
    hit = m.parse(make_request(host="translate-pa.googleapis.com", url=url))
    key = next(p for p in hit.params if p.key == "key")
    assert key.category == CAT_TECHNICAL
