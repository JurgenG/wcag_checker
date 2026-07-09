"""Tests for the UserWay module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_OTHER
from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("userway")


def test_identity(m) -> None:
    assert m.module_id == "userway"
    assert m.module_name == "UserWay"
    assert m.vendor == "UserWay Inc."
    assert m.legal_jurisdiction == "US"
    assert m.data_residency and m.sovereignty_notes


@pytest.mark.parametrize("host", ["cdn.userway.org", "api.userway.org"])
def test_matches_hosts(m, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/widget.js")
    assert m.matches(event) is True


def test_case_insensitive(m) -> None:
    event = make_request(host="CDN.USERWAY.ORG", url="https://CDN.USERWAY.ORG/widget.js")
    assert m.matches(event) is True


def test_rejects_lookalike_tld(m) -> None:
    """Only ``.userway.org`` is claimed, not ``.userway.com``."""
    event = make_request(host="userway.com", url="https://userway.com/")
    assert m.matches(event) is False


def test_unknown_param_is_other(m) -> None:
    event = make_request(host="cdn.userway.org", url="https://cdn.userway.org/widget.js?v=2")
    hit = m.parse(event)
    p = next(p for p in hit.params if p.key == "v")
    assert p.category == CAT_OTHER
