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

"""Flexmail detector.

Flexmail NV (Hasselt, Belgium) is a Belgian email-marketing platform —
the EU alternative to Mailchimp, with servers and data kept in Belgium.
Its web footprint is the embedded **newsletter signup / opt-in form**:

* ``www.flexmail.eu/sf-<hash>`` — the embedded subscribe form (loads its
  own jQuery / jQuery-UI bundle).
* ``return.flexmail.eu/page/opt-in-form/<jwt>`` — the double-opt-in
  confirmation page.

When the visitor submits, their email (plus any fields) is POSTed to
Flexmail — the same form-leakage class as Mailchimp / Mailjet: identified
personal data leaves the browser to a third-party controller. Flexmail is
an **EU (Belgian)** processor, so the sovereignty cost is low, but the
person-level privacy cost is the same.

Recognized hosts: any subdomain of ``flexmail.eu`` / ``flexmail.be``. The
actual submitted email travels in a POST body v1.0 capture does not
record; the *presence* of the form endpoint is the signal.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_OTHER,
    Hit,
    IMPACT_LOW,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIXES: tuple[str, ...] = (".flexmail.eu", ".flexmail.be")
_HOST_EXACTS: frozenset[str] = frozenset({"flexmail.eu", "flexmail.be"})


@register
class FlexmailModule(TrackerModule):
    """Detect Flexmail newsletter signup / opt-in form traffic."""

    module_id = "flexmail"
    module_name = "Flexmail"
    vendor = "Flexmail NV"
    legal_jurisdiction = "BE"
    data_residency = "EU (Belgium) — Flexmail keeps servers and data in Belgium"
    sovereignty_notes = (
        "EU-controlled (Belgium) — GDPR-native, no Schrems II transfer "
        "concern; the EU alternative to Mailchimp / Mailjet"
    )
    # Newsletter signup form (like mailjet): privacy 5.0 (the form POSTs the
    #   visitor's email + fields to a third-party controller — identified-
    #   person data leaves the site), security 2.5 (loads an unpinned widget
    #   + jQuery script into the origin), resilience 1.0 (EU vendor, Belgium
    #   — GDPR-native).
    impact_rating = ImpactRating(privacy=5.0, security=2.5, resilience=1.0)
    impact_notes = {
        "privacy": "The newsletter signup / opt-in form POSTs the visitor's "
            "email (and any fields) to Flexmail — identified-person data "
            "leaves the site (to an EU controller).",
        "security": "Loads an unpinned form widget + jQuery bundle into "
            "your origin.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host in _HOST_EXACTS:
            return True
        return any(host.endswith(suffix) for suffix in _HOST_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            params.append(
                ParamInfo(
                    key=key,
                    value=value,
                    category=CAT_OTHER,
                    meaning="Flexmail form parameter — unclassified",
                    privacy_impact=IMPACT_LOW,
                    event_index=event.event_id,
                )
            )
        return Hit(
            module_id=self.module_id,
            module_name=self.module_name,
            url=event.url,
            host=event.host,
            method=event.method,
            response_status=event.response_status,
            started_at=event.timestamp,
            params=params,
            events=[event.event_id],
        )
