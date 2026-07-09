# leak_inspector — record what data a website leaks during a real
# human-driven browsing session.
# Copyright (C) 2026 Jurgen Gaeremyn
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Microsoft Bookings detector.

Microsoft Bookings is the Microsoft 365 appointment-scheduling service.
Sites embed a booking page (``/book/<mailbox>/``) so visitors can book
an appointment; the widget then calls the Bookings API for the
business's services, staff and availability.

Recognised hosts:

* ``bookings.cloud.microsoft`` — the Bookings page + API
  (``/book/...``, ``/BookingsService/api/V1/...``,
  ``/owa/published/service.svc``).
* ``outlook.office.com`` — **only** on the ``/book/`` path (the legacy
  Bookings entry point that redirects into ``bookings.cloud.microsoft``);
  scoped by path so the module never claims general Outlook-on-the-web.

Privacy story: a booking flow collects the visitor's name / email /
phone for the appointment — first-party-intent data, but it lands in the
operator's Microsoft 365 tenant (US controller). The URL path carries
the *operator's* booking mailbox, not visitor data; the query string is
plumbing only.
"""

from __future__ import annotations

from urllib.parse import urlparse

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_LOW,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_BOOKINGS = "bookings.cloud.microsoft"
_HOST_OUTLOOK = "outlook.office.com"
_OUTLOOK_BOOK_PREFIX = "/book/"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "action":             (CAT_TECHNICAL, "Bookings API action (e.g. ``GetTimeZoneOffsets``)", IMPACT_LOW),
    "app":                (CAT_TECHNICAL, "Bookings app identifier (e.g. ``BookingsC2``)", IMPACT_LOW),
    "n":                  (CAT_TECHNICAL, "Bookings API request counter", IMPACT_LOW),
    "ismsaljsauthenabled": (CAT_TECHNICAL, "MSAL JS auth feature flag", IMPACT_LOW),
}


@register
class MicrosoftBookingsModule(TrackerModule):
    """Detect Microsoft Bookings appointment-scheduling embeds."""

    module_id = "microsoft_bookings"
    module_name = "Microsoft Bookings"
    vendor = "Microsoft Corporation"
    legal_jurisdiction = "US"
    data_residency = "Microsoft 365 (operator's tenant); US controller"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # Embedded appointment-scheduling functional service: privacy 2.0
    #   (a booking flow collects visitor name/email/phone — operator-
    #   intended, transaction-scoped, not profiling). security 2.0
    #   (loads a Microsoft 365 widget — third-party iframe/XHR surface in
    #   the page; bundle JS itself is attributed to microsoft_onecdn).
    #   resilience 3.0 (a US Microsoft 365 dependency for a site function;
    #   cf. hubspot/mailchimp resilience 3.0).
    impact_rating = ImpactRating(privacy=2.0, security=2.0, resilience=3.0)
    impact_notes = {
        "privacy": "An appointment booking collects the visitor's name, "
            "email and phone into the operator's Microsoft 365 tenant (US "
            "controller).",
        "security": "Embeds a Microsoft 365 widget — third-party iframe / "
            "API surface running in the page.",
        "resilience": "A US Microsoft 365 service the site depends on for "
            "its booking function.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host == _HOST_BOOKINGS:
            return True
        if host == _HOST_OUTLOOK:
            return urlparse(event.url).path.startswith(_OUTLOOK_BOOK_PREFIX)
        return False

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Microsoft Bookings parameter", IMPACT_LOW)
            )
            params.append(ParamInfo(
                key=key, value=value, category=category, meaning=meaning,
                privacy_impact=impact, event_index=event.event_id,
            ))
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
