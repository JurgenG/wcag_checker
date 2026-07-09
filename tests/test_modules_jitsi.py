"""Tests for the Jitsi Meet (meet.jit.si) module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_TECHNICAL

from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("jitsi")


def test_identity(m) -> None:
    assert m.module_id == "jitsi"
    assert m.legal_jurisdiction == "US"


def test_matches_meet_jitsi(m) -> None:
    url = "https://meet.jit.si/external_api.js?ver=2.5.5"
    event = make_request(host="meet.jit.si", url=url)
    assert m.matches(event) is True


def test_does_not_match_unrelated(m) -> None:
    for host in ("notjit.si.evil.com", "example.com"):
        event = make_request(host=host, url=f"https://{host}/")
        assert m.matches(event) is False


def test_ver_param_is_technical(m) -> None:
    event = make_request(
        host="meet.jit.si",
        url="https://meet.jit.si/external_api.js?ver=2.5.5",
    )
    hit = m.parse(event)
    p = next(p for p in hit.params if p.key == "ver")
    assert p.category == CAT_TECHNICAL
