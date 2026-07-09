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

"""Microsoft Office configuration / federation-discovery detector.

``odc.officeapps.live.com`` is the Office "ODC" configuration service.
Embedded Microsoft 365 products call its federation-provider discovery
endpoint (``/odc/v2.1/federationprovider?domain=<tenant-GUID>``) during
sign-in / bootstrap to find the right identity provider for the
operator's tenant.

Privacy story: this is a tenant-level configuration lookup — the only
parameter is the operator's tenant GUID, identical for every visitor and
carrying no visitor data. The privacy event is the fetch itself (a US
controller learns the visitor's IP / ``User-Agent`` / ``Referer``).
"""

from __future__ import annotations

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


_HOST_EXACT = "odc.officeapps.live.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "domain": (CAT_TECHNICAL, "Microsoft 365 tenant GUID (operator config — same for every visitor)", IMPACT_LOW),
}


@register
class MicrosoftOfficeConfigModule(TrackerModule):
    """Detect Microsoft Office federation / configuration discovery."""

    module_id = "microsoft_office_config"
    module_name = "Microsoft Office configuration (ODC)"
    vendor = "Microsoft Corporation"
    legal_jurisdiction = "US"
    data_residency = "Microsoft 365 configuration service; US controller"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # Tenant configuration / federation-discovery lookup: privacy 0.5
    #   (presence leak only — the single parameter is the operator's
    #   tenant GUID, no visitor data). security 1.0 (a config endpoint —
    #   no in-origin executable surface). resilience 1.5 (a minor US
    #   Microsoft 365 config dependency riding along with an embedded
    #   Microsoft product).
    impact_rating = ImpactRating(privacy=0.5, security=1.0, resilience=1.5)
    impact_notes = {
        "resilience": "A US Microsoft 365 configuration lookup that "
            "happens only because an embedded Microsoft product is "
            "present.",
    }

    def matches(self, event: RequestEvent) -> bool:
        return event.host.lower() == _HOST_EXACT

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Office configuration parameter", IMPACT_LOW)
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
