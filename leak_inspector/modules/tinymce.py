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

"""TinyMCE (Tiny Cloud) detector.

TinyMCE is a rich-text editor by Tiny Technologies (HQ Palo Alto, CA,
US). Its cloud-hosted build loads from ``cdn.tiny.cloud`` (the editor
JavaScript, keyed by an ``apiKey``) with supporting assets on
``sp.tinymce.com``. As an editor it runs **unpinned third-party
JavaScript** in the page origin, and the fetch discloses the visitor's
IP / ``User-Agent`` / ``Referer`` to a US operator.

Recognized hosts: any subdomain of ``tiny.cloud`` or ``tinymce.com``.
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


_HOST_SUFFIXES: tuple[str, ...] = (".tiny.cloud", ".tinymce.com")
_HOST_EXACTS: frozenset[str] = frozenset({"tiny.cloud", "tinymce.com"})


@register
class TinyMCEModule(TrackerModule):
    """Detect TinyMCE (Tiny Cloud) editor asset fetches."""

    module_id = "tinymce"
    module_name = "TinyMCE"
    vendor = "Tiny Technologies, Inc."
    legal_jurisdiction = "US"
    data_residency = "US (Palo Alto, CA HQ; Brisbane, AU office); Tiny Cloud CDN"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # Cloud-hosted rich-text editor (executable JS library CDN): privacy 1.0
    #   (presence leak), security 2.5 (unpinned editor JavaScript runs in
    #   the origin — a CDN compromise runs as your site), resilience 2.0
    #   (US-served, replaceable / self-hostable editor).
    impact_rating = ImpactRating(privacy=1.0, security=2.5, resilience=2.0)
    impact_notes = {
        "security": "Loads the TinyMCE editor JavaScript into your origin "
            "unpinned — a CDN compromise would run as your site.",
        "resilience": "A US-served editor that can be self-hosted instead.",
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
                    meaning="TinyMCE asset parameter (not a tracking field)",
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
