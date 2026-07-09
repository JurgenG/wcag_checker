"""Tests for the Nativo (PostRelease) module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_CONTENT, CAT_OTHER
from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("nativo")


def test_identity(m) -> None:
    assert m.module_id == "nativo"
    assert m.module_name == "Nativo"
    assert m.vendor == "Nativo, Inc."
    assert m.legal_jurisdiction == "US"
    assert m.data_residency and m.sovereignty_notes


@pytest.mark.parametrize("host", ["jadserve.postrelease.com", "postrelease.com"])
def test_matches_hosts(m, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/t?ntv_kv=channel&ntv_url=https://x")
    assert m.matches(event) is True


def test_case_insensitive(m) -> None:
    event = make_request(host="JADSERVE.POSTRELEASE.COM", url="https://JADSERVE.POSTRELEASE.COM/t")
    assert m.matches(event) is True


def test_rejects_lookalike(m) -> None:
    event = make_request(host="postrelease.com.evil.example", url="https://postrelease.com.evil.example/x")
    assert m.matches(event) is False


def test_page_url_param_is_content(m) -> None:
    event = make_request(
        host="jadserve.postrelease.com",
        url="https://jadserve.postrelease.com/t?ntv_kv=channel&ntv_url=https://www.macworld.com",
    )
    hit = m.parse(event)
    assert next(p for p in hit.params if p.key == "ntv_url").category == CAT_CONTENT


def test_unknown_param_is_other(m) -> None:
    event = make_request(host="jadserve.postrelease.com", url="https://jadserve.postrelease.com/t?weird=1")
    hit = m.parse(event)
    assert next(p for p in hit.params if p.key == "weird").category == CAT_OTHER
