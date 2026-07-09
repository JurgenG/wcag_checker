"""Tests for the BootstrapCDN module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_OTHER
from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("bootstrapcdn")


def test_identity(m) -> None:
    assert m.module_id == "bootstrapcdn"
    assert m.module_name == "BootstrapCDN"
    assert m.legal_jurisdiction == "US"
    assert m.vendor and m.data_residency and m.sovereignty_notes


@pytest.mark.parametrize("host", ["maxcdn.bootstrapcdn.com", "stackpath.bootstrapcdn.com"])
def test_matches_hosts(m, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/bootstrap/4.0.0/css/bootstrap.min.css")
    assert m.matches(event) is True


def test_case_insensitive(m) -> None:
    event = make_request(host="MAXCDN.BOOTSTRAPCDN.COM", url="https://MAXCDN.BOOTSTRAPCDN.COM/x.js")
    assert m.matches(event) is True


def test_rejects_lookalike(m) -> None:
    event = make_request(host="bootstrapcdn.com.evil.example", url="https://bootstrapcdn.com.evil.example/x")
    assert m.matches(event) is False


def test_unknown_param_is_other(m) -> None:
    event = make_request(host="maxcdn.bootstrapcdn.com", url="https://maxcdn.bootstrapcdn.com/x.js?v=4")
    hit = m.parse(event)
    assert next(p for p in hit.params if p.key == "v").category == CAT_OTHER
