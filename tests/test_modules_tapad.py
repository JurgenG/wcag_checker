"""Tests for the Tapad (Experian) cross-device ID-sync module."""

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
    return module_by_id("tapad")


def test_identity(m) -> None:
    assert m.module_id == "tapad"
    assert m.legal_jurisdiction == "US"


@pytest.mark.parametrize("host", ["pixel.tapad.com", "tapad.com"])
def test_matches_tapad_hosts(m, host) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert m.matches(event) is True


def test_does_not_match_unrelated(m) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert m.matches(event) is False


def test_classifies_device_id_and_consent(m) -> None:
    event = make_request(
        host="pixel.tapad.com",
        url=(
            "https://pixel.tapad.com/idsync/ex/receive"
            "?partner_id=3521&partner_device_id=ABC&gdpr=1&gdpr_consent="
        ),
    )
    cats = {p.key: p.category for p in m.parse(event).params}
    assert cats["partner_device_id"] == CAT_IDENTIFIER
    assert cats["partner_id"] == CAT_TECHNICAL
    assert cats["gdpr"] == CAT_CONSENT
    assert cats["gdpr_consent"] == CAT_CONSENT