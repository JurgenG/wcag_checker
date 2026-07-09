"""Tests for the CookieYes CMP module."""

from __future__ import annotations

import pytest

from leak_inspector.analysis.consent import _CMP_MODULE_IDS
from leak_inspector.modules.base import CAT_OTHER

from tests.conftest import make_request, module_by_id


@pytest.fixture
def cy():
    return module_by_id("cookieyes")


def test_identity(cy) -> None:
    assert cy.module_id == "cookieyes"
    assert cy.module_name == "CookieYes"
    assert cy.legal_jurisdiction == "UK"


def test_registered_as_cmp() -> None:
    """A CookieYes beacon must be exempt from the pre-consent offender tally
    and named as a banner — both keyed off ``_CMP_MODULE_IDS`` membership."""
    assert "cookieyes" in _CMP_MODULE_IDS


@pytest.mark.parametrize(
    "host",
    [
        # The banner CDN is its own registrable domain, not a cookieyes.com sub.
        "cdn-cookieyes.com",
        "cookieyes.com",
        "app.cookieyes.com",
        "log.cookieyes.com",
    ],
)
def test_matches(cy, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert cy.matches(event) is True


def test_matches_real_banner_script(cy) -> None:
    """The real per-site banner loader (client id in the path)."""
    url = "https://cdn-cookieyes.com/client_data/ee3c39e2d7d07f39ce969feb/script.js"
    event = make_request(host="cdn-cookieyes.com", url=url)
    assert cy.matches(event) is True


def test_does_not_match_unrelated(cy) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert cy.matches(event) is False


def test_does_not_match_lookalike(cy) -> None:
    event = make_request(host="notcookieyes.org", url="https://notcookieyes.org/")
    assert cy.matches(event) is False


def test_unknown_param_falls_through(cy) -> None:
    event = make_request(
        host="log.cookieyes.com", url="https://log.cookieyes.com/x?weird=1")
    hit = cy.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "CookieYes" in p.meaning
