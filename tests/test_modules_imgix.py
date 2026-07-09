"""Tests for the Imgix module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import (
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
)

from tests.conftest import make_request, module_by_id


@pytest.fixture
def im():
    return module_by_id("imgix")


def test_identity(im) -> None:
    assert im.module_id == "imgix"
    assert im.module_name == "Imgix"
    assert im.legal_jurisdiction == "US"


@pytest.mark.parametrize(
    "host", ["imgix.net", "customer.imgix.net", "museumpassmusees.imgix.net"],
)
def test_matches(im, host: str) -> None:
    event = make_request(host=host, url=f"https://{host}/image.png")
    assert im.matches(event) is True


def test_does_not_match_unrelated(im) -> None:
    event = make_request(host="example.com", url="https://example.com/")
    assert im.matches(event) is False


@pytest.mark.parametrize("key", ["w", "h", "fit", "crop", "q", "fm", "dpr", "auto"])
def test_transform_keys_are_technical(im, key: str) -> None:
    event = make_request(host="customer.imgix.net", url=f"https://customer.imgix.net/img.png?{key}=x")
    hit = im.parse(event)
    p = next(p for p in hit.params if p.key == key)
    assert p.category == CAT_TECHNICAL


def test_txt_is_content(im) -> None:
    """``txt`` overlays carry operator-rendered visitor-facing text."""
    event = make_request(host="customer.imgix.net", url="https://customer.imgix.net/img.png?txt=Hello")
    hit = im.parse(event)
    p = next(p for p in hit.params if p.key == "txt")
    assert p.category == CAT_CONTENT


def test_ixid_is_identifier(im) -> None:
    event = make_request(host="customer.imgix.net", url="https://customer.imgix.net/img.png?ixid=ABC")
    hit = im.parse(event)
    p = next(p for p in hit.params if p.key == "ixid")
    assert p.category == CAT_IDENTIFIER


def test_unknown_param(im) -> None:
    event = make_request(host="customer.imgix.net", url="https://customer.imgix.net/img.png?weird=1")
    hit = im.parse(event)
    p = next(p for p in hit.params if p.key == "weird")
    assert p.category == CAT_OTHER
    assert "Imgix" in p.meaning
