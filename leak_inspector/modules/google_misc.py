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

"""Catch-all ``google.com`` detector.

The bare ``www.google.com`` host serves dozens of unrelated assets:
search-page resources, Google Identity Services (the ``/js/th/<hash>``
loader pattern), generic JS libraries, doodle artwork, log endpoints,
and product chrome that doesn't fit a dedicated module.

This module is a *fallback*: every Google product that runs on
``google.com`` and has a dedicated detector (reCAPTCHA, Google Ads
``/pagead/``, Google Maps redirects, …) is registered earlier in
:mod:`leak_inspector.modules.__init__`, and :func:`detect` is
first-match-wins. So by the time a request reaches us here, it's
been deliberately left orphaned by every specific module.

.. important::

   This module **must** be imported *after* every other Google-product
   module. The package ``__init__`` enforces that by importing it
   out-of-alphabetical-order at the end of the import block.

Recognized hosts: ``google.com`` (and the country-coded landing
variants ``google.de`` / ``google.co.uk`` / …) plus **any subdomain**
of those — ``www.``, ``apis.`` (the gapi loader), ``calendar.`` /
``clients6.`` (embedded Calendar + its API), ``play.`` (the ``/log``
endpoint), and so on. The match is anchored on a dot boundary against a
known-TLD list, so lookalikes like ``googleblog.com`` or
``mygoogle.com`` are still rejected — we only widen to *subdomains of*
the well-known Google registrable domains, never to arbitrary hosts
containing the word "google".
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


#: Registrable Google landing domains. The catch-all matches each of
#: these exactly *and* any subdomain of them (``apis.``, ``calendar.``,
#: ``clients6.``, ``play.``, ``www.``, …). Anchoring on a leading dot
#: keeps lookalikes (``googleblog.com``, ``mygoogle.com``) out.
_GOOGLE_BASE_DOMAINS: frozenset[str] = frozenset({
    "google.com",
    "google.co.uk",
    "google.de",
    "google.fr",
    "google.it",
    "google.es",
    "google.nl",
    "google.be",
    "google.ca",
    "google.com.au",
    "google.co.jp",
    "google.com.br",
    "google.com.mx",
    "google.pl",
    "google.ru",
    "google.com.tr",
    "google.co.in",
})


def _is_google_host(host: str) -> bool:
    """True iff ``host`` is a known Google landing domain or a subdomain of one."""
    host = host.lower()
    return any(
        host == base or host.endswith("." + base)
        for base in _GOOGLE_BASE_DOMAINS
    )


_PARAMS: dict[str, tuple[str, str, str]] = {
    "v":   (CAT_TECHNICAL, "Version / cache-bust tag",         IMPACT_LOW),
    "_":   (CAT_TECHNICAL, "Cache-busting timestamp",          IMPACT_LOW),
    "hl":  (CAT_TECHNICAL, "Host-language code",               IMPACT_LOW),
    "gl":  (CAT_TECHNICAL, "Geo-location country code",        IMPACT_LOW),
    "callback": (CAT_TECHNICAL, "JSONP callback name",         IMPACT_LOW),
}


@register
class GoogleMiscModule(TrackerModule):
    """Catch-all detector for non-product-specific google.com traffic."""

    module_id = "google_misc"
    module_name = "Google (generic google.com)"
    vendor = "Google LLC"
    legal_jurisdiction = "US"
    data_residency = "Google global infrastructure"
    sovereignty_notes = "US CLOUD Act applies; catch-all for google.com requests not claimed by a more specific module (reCAPTCHA / Google Ads / Maps / …)"
    # Catch-all residual: by construction these are google.com fetches no
    # specific module claimed, so we rate the *floor* of what such a fetch
    # implies, never guessing worse (certainty rule).
    # privacy 1.0: an unattributed google.com fetch discloses presence-of-
    #   visit (IP/UA/Referer) to a US controller, no identified payload we
    #   can name (rubric privacy 1.0). security 2.0: www.google.com serves
    #   executable chrome (e.g. Identity Services loader) into the origin,
    #   unpinned but narrow/hardened (rubric 2.0). resilience 2.0: US
    #   controller for a non-load-bearing function (rubric 2.0).
    impact_rating = ImpactRating(privacy=1.0, security=2.0, resilience=2.0)
    impact_notes = {
        "security": "Unattributed google.com resources can include "
            "executable chrome (e.g. the Identity Services loader) running "
            "in your origin.",
        "resilience": "A US-controlled dependency for a non-load-bearing "
            "function.",
    }

    def matches(self, event: RequestEvent) -> bool:
        return _is_google_host(event.host)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized google.com parameter", IMPACT_LOW)
            )
            params.append(
                ParamInfo(
                    key=key, value=value, category=category, meaning=meaning,
                    privacy_impact=impact, event_index=event.event_id,
                )
            )
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
