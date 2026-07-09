"""Tests for the ImageKit module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_OTHER
from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("imagekit")


def test_identity(m) -> None:
    assert m.module_id == "imagekit"
    assert m.module_name == "ImageKit"
    assert m.legal_jurisdiction == "IN"
    assert m.vendor and m.data_residency and m.sovereignty_notes


def test_matches_host(m) -> None:
    event = make_request(host="ik.imagekit.io", url="https://ik.imagekit.io/demo/img/x.jpg?tr=w-300")
    assert m.matches(event) is True


def test_case_insensitive(m) -> None:
    event = make_request(host="IK.IMAGEKIT.IO", url="https://IK.IMAGEKIT.IO/x.jpg")
    assert m.matches(event) is True


def test_rejects_lookalike(m) -> None:
    event = make_request(host="imagekit.io.evil.example", url="https://imagekit.io.evil.example/x")
    assert m.matches(event) is False


def test_unknown_param_is_other(m) -> None:
    event = make_request(host="ik.imagekit.io", url="https://ik.imagekit.io/x.jpg?tr=w-300")
    hit = m.parse(event)
    assert next(p for p in hit.params if p.key == "tr").category == CAT_OTHER
