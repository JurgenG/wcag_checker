"""Tests for the google_cdn (non-analytics Google asset hosts) module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_OTHER, Hit, IMPACT_LOW

from tests.conftest import make_request, module_by_id


@pytest.fixture
def gcdn():
    return module_by_id("google_cdn")


def test_identity(gcdn) -> None:
    assert gcdn.module_id == "google_cdn"
    assert gcdn.module_name == "Google CDN / asset hosts"
    assert gcdn.vendor == "Google LLC"
    assert gcdn.legal_jurisdiction == "US"
    assert gcdn.data_residency
    assert gcdn.sovereignty_notes


@pytest.mark.parametrize(
    "host",
    [
        "storage.googleapis.com",
        "csp.withgoogle.com",
        "cdn.ampproject.org",
        "youtube.googleapis.com",
        "ajax.googleapis.com",
    ],
)
def test_matches_exact_hosts(gcdn, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert gcdn.matches(event) is True


@pytest.mark.parametrize(
    "host", ["lh1.googleusercontent.com", "lh6.googleusercontent.com"],
)
def test_matches_googleusercontent_subdomains(gcdn, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/img")
    assert gcdn.matches(event) is True


def test_matches_is_case_insensitive(gcdn) -> None:
    event = make_request(
        host="STORAGE.GOOGLEAPIS.COM",
        url="https://STORAGE.GOOGLEAPIS.COM/x",
    )
    assert gcdn.matches(event) is True


def test_does_not_match_unrelated_host(gcdn) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert gcdn.matches(event) is False


def test_parse_metadata_and_passthrough_params(gcdn) -> None:
    event = make_request(
        host="storage.googleapis.com",
        url="https://storage.googleapis.com/bucket/file.png?token=abc",
    )
    hit = gcdn.parse(event)
    assert isinstance(hit, Hit)
    assert hit.module_id == "google_cdn"
    # All params fall through to CAT_OTHER (no _PARAMS table).
    p = next(p for p in hit.params if p.key == "token")
    assert p.category == CAT_OTHER
    assert p.privacy_impact == IMPACT_LOW
    assert "Asset-fetch" in p.meaning
