"""Tests for the Eyeota (Dun & Bradstreet) audience ID-sync module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_CONSENT,
    CAT_IDENTIFIER,
    CAT_TECHNICAL,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("eyeota")


def test_identity(m) -> None:
    assert m.module_id == "eyeota"
    assert m.legal_jurisdiction == "US"


@pytest.mark.parametrize("host", ["ps.eyeota.net", "eyeota.net"])
def test_matches_eyeota_hosts(m, host) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert m.matches(event) is True


def test_does_not_match_unrelated(m) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert m.matches(event) is False


def test_classifies_uid_and_consent(m) -> None:
    event = make_request(
        host="ps.eyeota.net",
        url="https://ps.eyeota.net/match?bid=d9gd6vu&uid=ABC&gdpr=1&gdpr_consent=",
    )
    cats = {p.key: p.category for p in m.parse(event).params}
    assert cats["uid"] == CAT_IDENTIFIER
    assert cats["bid"] == CAT_TECHNICAL
    assert cats["gdpr"] == CAT_CONSENT