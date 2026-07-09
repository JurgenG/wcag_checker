"""Tests for the google_misc catch-all module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_OTHER,
    CAT_TECHNICAL,
    all_modules,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def gm():
    return module_by_id("google_misc")


def test_identity(gm) -> None:
    assert gm.module_id == "google_misc"
    assert gm.vendor == "Google LLC"


def test_registered_last() -> None:
    """The catch-all must come AFTER specific Google-product modules.

    First-match-wins means any earlier registration would shadow this one.
    """
    ids = [m.module_id for m in all_modules()]
    assert ids[-1] == "google_misc", (
        "google_misc must be the last registered module to preserve first-match-wins ordering"
    )


@pytest.mark.parametrize(
    "host",
    [
        "google.com", "www.google.com",
        "google.de", "www.google.de",
        "google.co.uk", "www.google.co.uk",
        "google.fr", "google.com.au",
    ],
)
def test_matches_known_google_tlds(gm, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/")
    assert gm.matches(event) is True


@pytest.mark.parametrize(
    "host",
    [
        # Real uncaught subdomains seen across the municipalities dataset:
        # gapi loader, embedded Calendar, Calendar API backend, log endpoint.
        "apis.google.com",
        "calendar.google.com",
        "clients6.google.com",
        "play.google.com",
        "accounts.google.com",
        "www.google.de",
    ],
)
def test_matches_google_subdomains(gm, host: str) -> None:
    """The catch-all owns any *.google.<known-tld> the specific modules left."""
    event = make_request(host=host, url=f"https://{host}/")
    assert gm.matches(event) is True


def test_does_not_match_googleblog_com(gm) -> None:
    """Conservative match: 'googleblog.com' must not match."""
    event = make_request(host="googleblog.com", url="https://googleblog.com/")
    assert gm.matches(event) is False


def test_does_not_match_random_google_lookalike(gm) -> None:
    event = make_request(host="notreally-google.io", url="https://notreally-google.io/")
    assert gm.matches(event) is False


@pytest.mark.parametrize(
    "host",
    # Suffix-confusion: end in "google.com" but with no dot boundary, or a
    # google host re-parented under an attacker domain. None may match.
    ["mygoogle.com", "evilgoogle.com", "google.com.evil.example"],
)
def test_does_not_match_suffix_confusion(gm, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/")
    assert gm.matches(event) is False


@pytest.mark.parametrize("key", ["v", "_", "hl", "gl", "callback"])
def test_known_params_are_technical(gm, key: str) -> None:
    event = make_request(host="www.google.com", url=f"https://www.google.com/?{key}=x")
    hit = gm.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_unknown_param(gm) -> None:
    event = make_request(host="www.google.com", url="https://www.google.com/?weird=1")
    hit = gm.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "google.com" in p.meaning
