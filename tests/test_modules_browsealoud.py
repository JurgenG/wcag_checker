"""Tests for the Browsealoud (Texthelp) module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_OTHER
from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("browsealoud")


def test_identity(m) -> None:
    assert m.module_id == "browsealoud"
    assert m.module_name == "Browsealoud (Texthelp)"
    assert m.vendor == "Texthelp Ltd"
    assert m.legal_jurisdiction == "UK"
    assert m.data_residency and m.sovereignty_notes


@pytest.mark.parametrize(
    "host",
    ["www.browsealoud.com", "plus.browsealoud.com", "static.browsealoud.nl", "browsealoud.com"],
)
def test_matches_hosts(m, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/plus/scripts/ba.js")
    assert m.matches(event) is True


def test_case_insensitive(m) -> None:
    event = make_request(host="WWW.BROWSEALOUD.COM", url="https://WWW.BROWSEALOUD.COM/ba.js")
    assert m.matches(event) is True


def test_rejects_lookalike(m) -> None:
    event = make_request(host="browsealoud.com.evil.example", url="https://browsealoud.com.evil.example/x")
    assert m.matches(event) is False


def test_unknown_param_is_other(m) -> None:
    event = make_request(host="www.browsealoud.com", url="https://www.browsealoud.com/ba.js?x=1")
    hit = m.parse(event)
    p = next(p for p in hit.params if p.key == "x")
    assert p.category == CAT_OTHER
