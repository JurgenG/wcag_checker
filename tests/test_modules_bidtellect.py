"""Tests for the Bidtellect (bttrack.com) module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_CONTENT, CAT_OTHER
from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("bidtellect")


def test_identity(m) -> None:
    assert m.module_id == "bidtellect"
    assert m.module_name == "Bidtellect"
    assert m.vendor == "Bidtellect, Inc."
    assert m.legal_jurisdiction == "US"
    assert m.data_residency and m.sovereignty_notes


@pytest.mark.parametrize("host", ["bttrack.com", "sync.bttrack.com"])
def test_matches_hosts(m, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/pixel/cookiesyncredir?rurl=https://x")
    assert m.matches(event) is True


def test_case_insensitive(m) -> None:
    event = make_request(host="BTTRACK.COM", url="https://BTTRACK.COM/pixel/cookiesyncredir")
    assert m.matches(event) is True


def test_rejects_lookalike(m) -> None:
    event = make_request(host="bttrack.com.evil.example", url="https://bttrack.com.evil.example/x")
    assert m.matches(event) is False


def test_redirect_param_is_content(m) -> None:
    event = make_request(
        host="bttrack.com",
        url="https://bttrack.com/pixel/cookiesyncredir?rurl=https%3A%2F%2Frtb-csync.smartadserver.com",
    )
    hit = m.parse(event)
    assert next(p for p in hit.params if p.key == "rurl").category == CAT_CONTENT


def test_unknown_param_is_other(m) -> None:
    event = make_request(host="bttrack.com", url="https://bttrack.com/x?weird=1")
    hit = m.parse(event)
    assert next(p for p in hit.params if p.key == "weird").category == CAT_OTHER
