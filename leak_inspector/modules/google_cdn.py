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

"""Google asset / CDN detector — non-analytics Google-operated content hosts.

A bundle of Google-owned CDN and asset hosts that are not themselves
analytics or ad-serving endpoints but still send the visitor's IP,
``User-Agent``, and ``Referer`` to Google with every fetch. Sister
to ``google_fonts.py`` — same privacy framing, different hosts.

Recognized hosts (exact match, narrower than ``google_misc`` so this
module fires first):

* ``storage.googleapis.com`` — Google Cloud Storage public-object
  delivery (images, JSON, blobs).
* ``*.googleusercontent.com`` — user-content CDN (``lh1.``–``lh6.``
  for avatars / Photos / Drive previews; profile images).
* ``csp.withgoogle.com`` — "Content from Google" syndication.
* ``cdn.ampproject.org`` — AMP runtime CDN.
* ``youtube.googleapis.com`` — YouTube Data API host (assets and the
  IFrame Player API; the consumer-facing ``youtube.com`` is claimed
  by ``youtube.py``).
* ``ajax.googleapis.com`` — Google Hosted Libraries (jQuery, Angular,
  … served from Google's CDN). The fonts / maps googleapis hosts are
  claimed by ``google_fonts`` / ``google_maps``; this is the residual
  library-CDN host.

These hosts rarely carry analytics parameters; the privacy event is
*the fetch itself*. URL params, when present, are surfaced as
``CAT_OTHER`` so they're still inspectable.
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


_HOST_EXACTS = {
    "storage.googleapis.com",
    "csp.withgoogle.com",
    "cdn.ampproject.org",
    "youtube.googleapis.com",
    "ajax.googleapis.com",
}

_HOST_SUFFIXES = (".googleusercontent.com",)


@register
class GoogleCDNModule(TrackerModule):
    """Detect non-analytics Google-operated asset / CDN fetches."""

    module_id = "google_cdn"
    module_name = "Google CDN / asset hosts"
    vendor = "Google LLC"
    legal_jurisdiction = "US"
    data_residency = "US (Mountain View, CA HQ); Google global CDN edge"
    sovereignty_notes = "US CLOUD Act / FISA 702 apply"
    # privacy 1.0: presence-of-visit leak to a US controller, no
    #   identifier (rubric privacy 1.0). security 2.5: these hosts
    #   (storage.googleapis.com buckets, cdn.ampproject.org runtime) can
    #   serve operator-chosen *executable* JS into the origin, unpinned,
    #   from a general-purpose bucket host — ordinary RCI exposure (rubric
    #   2.5), above gstatic's narrow chrome. resilience 2.0: US controller,
    #   replaceable asset/CDN function (rubric 2.0).
    impact_rating = ImpactRating(privacy=1.0, security=2.5, resilience=2.0)
    impact_notes = {
        "security": "Serves operator-chosen JavaScript into your origin "
            "from a general-purpose Google bucket/CDN host, unpinned — a "
            "compromise runs as your site.",
        "resilience": "A US-controlled asset host for content that could "
            "be served from EU/own infrastructure.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host in _HOST_EXACTS:
            return True
        return any(host.endswith(s) for s in _HOST_SUFFIXES)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            params.append(
                ParamInfo(
                    key=key,
                    value=value,
                    category=CAT_OTHER,
                    meaning="Asset-fetch URL parameter (not a tracking field)",
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
