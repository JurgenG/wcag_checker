"""Tests for the Tribal Fusion (Exponential) module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_CONTENT, CAT_OTHER, CAT_TECHNICAL
from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("tribalfusion")


def test_identity(m) -> None:
    assert m.module_id == "tribalfusion"
    assert m.module_name == "Tribal Fusion (Exponential)"
    assert m.vendor == "Exponential Interactive, Inc."
    assert m.legal_jurisdiction == "US"
    assert m.data_residency and m.sovereignty_notes


@pytest.mark.parametrize("host", ["a.tribalfusion.com", "s.tribalfusion.com"])
def test_matches_hosts(m, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/i.match?p=b11&redirect=https://x")
    assert m.matches(event) is True


def test_case_insensitive(m) -> None:
    event = make_request(host="A.TRIBALFUSION.COM", url="https://A.TRIBALFUSION.COM/i.match")
    assert m.matches(event) is True


def test_rejects_lookalike(m) -> None:
    event = make_request(host="tribalfusion.com.evil.example", url="https://tribalfusion.com.evil.example/x")
    assert m.matches(event) is False


def test_sync_params(m) -> None:
    event = make_request(
        host="a.tribalfusion.com",
        url="https://a.tribalfusion.com/i.match?p=b11&redirect=https://simage2.pubmatic.com/x",
    )
    hit = m.parse(event)
    assert next(p for p in hit.params if p.key == "p").category == CAT_TECHNICAL
    assert next(p for p in hit.params if p.key == "redirect").category == CAT_CONTENT


def test_unknown_param_is_other(m) -> None:
    event = make_request(host="a.tribalfusion.com", url="https://a.tribalfusion.com/i.match?weird=1")
    hit = m.parse(event)
    assert next(p for p in hit.params if p.key == "weird").category == CAT_OTHER
