"""Tests for the BidSwitch (IPONWEB / Criteo) ID-sync module."""

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
    return module_by_id("bidswitch")


def test_identity(m) -> None:
    assert m.module_id == "bidswitch"
    # IPONWEB is owned by Criteo S.A. (France) — controller is EU.
    assert m.legal_jurisdiction == "FR"


@pytest.mark.parametrize("host", ["x.bidswitch.net", "bidswitch.net"])
def test_matches_bidswitch_hosts(m, host) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert m.matches(event) is True


def test_does_not_match_unrelated(m) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert m.matches(event) is False


def test_classifies_user_id_and_consent(m) -> None:
    event = make_request(
        host="x.bidswitch.net",
        url="https://x.bidswitch.net/sync?dsp_id=44&user_id=ABC&gdpr=1&gdpr_consent=",
    )
    cats = {p.key: p.category for p in m.parse(event).params}
    assert cats["user_id"] == CAT_IDENTIFIER
    assert cats["dsp_id"] == CAT_TECHNICAL
    assert cats["gdpr_consent"] == CAT_CONSENT