"""Tests for the AddToAny module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_OTHER
from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("addtoany")


def test_identity(m) -> None:
    assert m.module_id == "addtoany"
    assert m.module_name == "AddToAny"
    assert m.legal_jurisdiction == "US"
    assert m.vendor and m.data_residency and m.sovereignty_notes


@pytest.mark.parametrize("host", ["static.addtoany.com", "addtoany.com"])
def test_matches_hosts(m, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/x")
    assert m.matches(event) is True


def test_case_insensitive(m) -> None:
    event = make_request(host="static.addtoany.com".upper(), url="https://X/x")
    assert m.matches(event) is True


def test_rejects_lookalike(m) -> None:
    event = make_request(host="addtoany.com.evil.example", url="https://addtoany.com.evil.example/x")
    assert m.matches(event) is False


def test_unknown_param_is_other(m) -> None:
    event = make_request(host="static.addtoany.com", url="https://static.addtoany.com/x?weird=1")
    hit = m.parse(event)
    assert next(p for p in hit.params if p.key == "weird").category == CAT_OTHER
