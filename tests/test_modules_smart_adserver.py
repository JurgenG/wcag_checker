"""Tests for the Smart AdServer / Equativ ad-server / SSP cookie-sync module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_CONSENT,
    CAT_CONTENT,
    CAT_TECHNICAL,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("smart_adserver")


def test_identity(m) -> None:
    assert m.module_id == "smart_adserver"
    assert m.vendor.startswith("Equativ")
    # Equativ S.A.S. is Paris-based — an EU controller.
    assert m.legal_jurisdiction == "FR"


@pytest.mark.parametrize(
    "host",
    [
        "csync.smartadserver.com",
        "rtb-csync.smartadserver.com",
        "sync.smartadserver.com",
        "ced-ns.sascdn.com",
        "equativ.com",
    ],
)
def test_matches_equativ_hosts(m, host) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert m.matches(event) is True


def test_does_not_match_unrelated(m) -> None:
    for host in ("example.com", "smartadserver.com.evil.com"):
        event = make_request(host=host, url=f"https://{host}/")
        assert m.matches(event) is False


def test_classifies_sync_params(m) -> None:
    event = make_request(
        host="sync.smartadserver.com",
        url=(
            "https://sync.smartadserver.com/getuid"
            "?nwid=3905&url=https://af.pubmine.com/user-sync"
            "&gdpr=1&gdpr_consent=CQly1YAQ"
        ),
    )
    cats = {p.key: p.category for p in m.parse(event).params}
    assert cats["nwid"] == CAT_TECHNICAL
    assert cats["url"] == CAT_CONTENT
    assert cats["gdpr"] == CAT_CONSENT
    assert cats["gdpr_consent"] == CAT_CONSENT
