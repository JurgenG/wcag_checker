"""Tests for the TinyMCE module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_OTHER
from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("tinymce")


def test_identity(m) -> None:
    assert m.module_id == "tinymce"
    assert m.module_name == "TinyMCE"
    assert m.vendor == "Tiny Technologies, Inc."
    assert m.legal_jurisdiction == "US"
    assert m.data_residency and m.sovereignty_notes


@pytest.mark.parametrize("host", ["cdn.tiny.cloud", "sp.tinymce.com"])
def test_matches_hosts(m, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/1/key/tinymce/6/tinymce.min.js")
    assert m.matches(event) is True


def test_case_insensitive(m) -> None:
    event = make_request(host="CDN.TINY.CLOUD", url="https://CDN.TINY.CLOUD/x.js")
    assert m.matches(event) is True


def test_rejects_lookalike(m) -> None:
    event = make_request(host="tiny.cloud.evil.example", url="https://tiny.cloud.evil.example/x")
    assert m.matches(event) is False


def test_unknown_param_is_other(m) -> None:
    event = make_request(host="cdn.tiny.cloud", url="https://cdn.tiny.cloud/x.js?apiKey=abc")
    hit = m.parse(event)
    assert next(p for p in hit.params if p.key == "apiKey").category == CAT_OTHER
