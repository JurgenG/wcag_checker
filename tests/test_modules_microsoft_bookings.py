"""Tests for the Microsoft Bookings module."""

from __future__ import annotations

import pytest

from leak_inspector.modules.base import CAT_TECHNICAL

from tests.conftest import make_request, module_by_id


@pytest.fixture
def m():
    return module_by_id("microsoft_bookings")


def test_identity(m) -> None:
    assert m.module_id == "microsoft_bookings"
    assert m.legal_jurisdiction == "US"


def test_matches_bookings_host(m) -> None:
    url = ("https://bookings.cloud.microsoft/book/"
           "Aanmelden1AB1@kabeveren.com/?ismsaljsauthenabled")
    event = make_request(host="bookings.cloud.microsoft", url=url)
    assert m.matches(event) is True


def test_matches_outlook_only_on_book_path(m) -> None:
    book = make_request(
        host="outlook.office.com",
        url="https://outlook.office.com/book/Aanmelden1AB1@kabeveren.com/",
    )
    assert m.matches(book) is True
    # General Outlook-on-the-web must not be claimed.
    mail = make_request(
        host="outlook.office.com",
        url="https://outlook.office.com/mail/inbox",
    )
    assert m.matches(mail) is False


def test_does_not_match_other_hosts(m) -> None:
    for host in ("forms.cloud.microsoft", "clarity.ms", "example.com"):
        event = make_request(host=host, url=f"https://{host}/")
        assert m.matches(event) is False


def test_action_param_is_technical(m) -> None:
    url = ("https://bookings.cloud.microsoft/owa/published/service.svc"
           "?action=GetTimeZoneOffsets&app=BookingsC2&n=0")
    hit = m.parse(make_request(host="bookings.cloud.microsoft", url=url))
    action = next(p for p in hit.params if p.key == "action")
    assert action.category == CAT_TECHNICAL
