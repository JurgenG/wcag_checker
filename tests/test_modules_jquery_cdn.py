"""Tests for the jQuery CDN module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_OTHER
from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("jquery_cdn")


def test_identity(m) -> None:
    assert m.module_id == "jquery_cdn"
    assert m.module_name == "jQuery CDN"
    assert m.legal_jurisdiction == "US"
    assert m.vendor and m.data_residency and m.sovereignty_notes


def test_matches_host(m) -> None:
    event = make_request(host="code.jquery.com", url="https://code.jquery.com/jquery-3.6.0.min.js")
    assert m.matches(event) is True


def test_case_insensitive(m) -> None:
    event = make_request(host="CODE.JQUERY.COM", url="https://CODE.JQUERY.COM/x.js")
    assert m.matches(event) is True


def test_rejects_other_jquery_hosts(m) -> None:
    """Only the CDN host is claimed, not the project site."""
    event = make_request(host="jquery.com", url="https://jquery.com/")
    assert m.matches(event) is False


def test_unknown_param_is_other(m) -> None:
    event = make_request(host="code.jquery.com", url="https://code.jquery.com/x.js?v=3")
    hit = m.parse(event)
    assert next(p for p in hit.params if p.key == "v").category == CAT_OTHER
