"""Tests for the Font Awesome module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_OTHER
from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("font_awesome")


def test_identity(m) -> None:
    assert m.module_id == "font_awesome"
    assert m.module_name == "Font Awesome"
    assert m.vendor == "Fonticons, Inc. (Font Awesome)"
    assert m.legal_jurisdiction == "US"
    assert m.data_residency and m.sovereignty_notes


@pytest.mark.parametrize("host", ["use.fontawesome.com", "pro.fontawesome.com", "kit.fontawesome.com"])
def test_matches_hosts(m, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/releases/v5.15.3/css/all.css")
    assert m.matches(event) is True


def test_case_insensitive(m) -> None:
    event = make_request(host="USE.FONTAWESOME.COM", url="https://USE.FONTAWESOME.COM/x.css")
    assert m.matches(event) is True


def test_rejects_lookalike(m) -> None:
    event = make_request(host="myfontawesome.com", url="https://myfontawesome.com/x.css")
    assert m.matches(event) is False


def test_unknown_param_is_other(m) -> None:
    event = make_request(host="use.fontawesome.com", url="https://use.fontawesome.com/x.css?ver=5")
    hit = m.parse(event)
    p = next(p for p in hit.params if p.key == "ver")
    assert p.category == CAT_OTHER
