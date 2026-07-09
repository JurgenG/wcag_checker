"""Tests for the Microsoft Forms module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_TECHNICAL

from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("microsoft_forms")


def test_identity(m) -> None:
    assert m.module_id == "microsoft_forms"
    assert m.legal_jurisdiction == "US"


def test_matches_forms_hosts(m) -> None:
    for host in ("forms.cloud.microsoft", "forms.office.com"):
        event = make_request(
            host=host,
            url=f"https://{host}/Pages/ResponsePage.aspx?id=abc&embed=true",
        )
        assert m.matches(event) is True


def test_does_not_match_other_hosts(m) -> None:
    for host in ("bookings.cloud.microsoft", "clarity.ms", "example.com"):
        event = make_request(host=host, url=f"https://{host}/")
        assert m.matches(event) is False


def test_form_id_is_technical_not_visitor_identifier(m) -> None:
    url = ("https://forms.cloud.microsoft/Pages/ResponsePage.aspx"
           "?id=h7-f_0UhJEeltbG0rVIVG3tt5LzWmbBBmU2ZMw_r4qlUMjI5&embed=true")
    hit = m.parse(make_request(host="forms.cloud.microsoft", url=url))
    form_id = next(p for p in hit.params if p.key == "id")
    # The form id is operator config (same for every visitor), not a
    # per-visitor pseudonym — so it must classify technical, not identifier.
    assert form_id.category == CAT_TECHNICAL
