"""Tests for the MyFonts module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_OTHER
from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("myfonts")


def test_identity(m) -> None:
    assert m.module_id == "myfonts"
    assert m.module_name == "MyFonts"
    assert m.legal_jurisdiction == "US"
    assert m.vendor and m.data_residency and m.sovereignty_notes


def test_matches_host(m) -> None:
    event = make_request(host="hello.myfonts.net", url="https://hello.myfonts.net/count/abc")
    assert m.matches(event) is True


def test_case_insensitive(m) -> None:
    event = make_request(host="HELLO.MYFONTS.NET", url="https://HELLO.MYFONTS.NET/x")
    assert m.matches(event) is True


def test_rejects_lookalike(m) -> None:
    event = make_request(host="myfonts.net.evil.example", url="https://myfonts.net.evil.example/x")
    assert m.matches(event) is False


def test_unknown_param_is_other(m) -> None:
    event = make_request(host="hello.myfonts.net", url="https://hello.myfonts.net/x?v=1")
    hit = m.parse(event)
    assert next(p for p in hit.params if p.key == "v").category == CAT_OTHER
