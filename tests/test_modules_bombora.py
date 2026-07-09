"""Tests for the Bombora (ml314.com) B2B intent ID-sync module."""

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
    return module_by_id("bombora")


def test_identity(m) -> None:
    assert m.module_id == "bombora"
    assert m.module_name.startswith("Bombora")
    assert m.legal_jurisdiction == "US"


@pytest.mark.parametrize("host", ["ml314.com", "sync.ml314.com"])
def test_matches_ml314_hosts(m, host) -> None:
    event = make_request(host=host, url=f"https://{host}/utsync.ashx")
    assert m.matches(event) is True


def test_does_not_match_unrelated(m) -> None:
    for host in ("example.com", "ml314.com.evil.com"):
        event = make_request(host=host, url=f"https://{host}/")
        assert m.matches(event) is False


def test_classifies_sync_id_and_consent(m) -> None:
    event = make_request(
        host="ml314.com",
        url="https://ml314.com/utsync.ashx?et=0&eid=92980&fp=ABC&gdpr=1&gdpr_consent=",
    )
    cats = {p.key: p.category for p in m.parse(event).params}
    assert cats["fp"] == CAT_IDENTIFIER
    assert cats["eid"] == CAT_TECHNICAL
    assert cats["gdpr"] == CAT_CONSENT