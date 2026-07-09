"""Tests for the Letsgocity module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_OTHER
from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("letsgocity")


def test_identity(m) -> None:
    assert m.module_id == "letsgocity"
    assert m.module_name == "Letsgocity"
    assert m.legal_jurisdiction == "BE"
    assert m.vendor and m.data_residency and m.sovereignty_notes


@pytest.mark.parametrize(
    "host",
    ["files.letsgocity.be", "api.letsgocity.be", "mapi.letsgocity.be", "internal-api.letsgocity.be"],
)
def test_matches_hosts(m, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/resize/172x172/abc")
    assert m.matches(event) is True


def test_case_insensitive(m) -> None:
    event = make_request(host="FILES.LETSGOCITY.BE", url="https://FILES.LETSGOCITY.BE/x")
    assert m.matches(event) is True


def test_rejects_lookalike(m) -> None:
    event = make_request(host="letsgocity.be.evil.example", url="https://letsgocity.be.evil.example/x")
    assert m.matches(event) is False


def test_unknown_param_is_other(m) -> None:
    event = make_request(
        host="api.letsgocity.be",
        url="https://api.letsgocity.be/file-view-service/api/v1/convert?key=undefined",
    )
    hit = m.parse(event)
    p = next(p for p in hit.params if p.key == "key")
    assert p.category == CAT_OTHER
