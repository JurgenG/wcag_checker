"""Tests for the ReadSpeaker module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_OTHER
from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("readspeaker")


def test_identity(m) -> None:
    assert m.module_id == "readspeaker"
    assert m.module_name == "ReadSpeaker"
    assert m.legal_jurisdiction == "EU"
    assert m.vendor and m.data_residency and m.sovereignty_notes


@pytest.mark.parametrize("host", ["cdn1.readspeaker.com", "cdn-eu.readspeaker.com", "f1-eu.readspeaker.com"])
def test_matches_hosts(m, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/script/12229/webReader/webReader.js")
    assert m.matches(event) is True


def test_case_insensitive(m) -> None:
    event = make_request(host="CDN1.READSPEAKER.COM", url="https://CDN1.READSPEAKER.COM/x.js")
    assert m.matches(event) is True


def test_rejects_lookalike(m) -> None:
    event = make_request(host="readspeaker.com.evil.example", url="https://readspeaker.com.evil.example/x")
    assert m.matches(event) is False


def test_unknown_param_is_other(m) -> None:
    event = make_request(host="cdn1.readspeaker.com", url="https://cdn1.readspeaker.com/x.js?pids=wr")
    hit = m.parse(event)
    p = next(p for p in hit.params if p.key == "pids")
    assert p.category == CAT_OTHER
