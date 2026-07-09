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

"""Shared helpers for the public-sector third-party modules.

Used by both the governmental modules (EU, federal Belgium, Flanders,
Wallonia, Brussels) and the para-governmental modules (publiq, IMIO, …).
All of them share the same shape: host-suffix matching against a curated
set of public-sector domains, plus a minimal :meth:`parse` that records
the request without trying to classify per-parameter privacy impact.
The point of a public-sector hit is "yes, this third-party request goes
to a public-sector (or public-sector-adjacent) entity X" — the privacy
implications come from the *fact* of the data flow (visitor IP / Referer
/ User-Agent), not from the URL parameters.
"""

from __future__ import annotations

from ..events import RequestEvent
from .base import (
    CAT_OTHER,
    Hit,
    IMPACT_LOW,
    ParamInfo,
    TrackerModule,
)


def host_matches_suffix_set(
    host: str,
    *,
    suffix_matches: tuple[str, ...] = (),
    exact_matches: frozenset[str] = frozenset(),
    excluded_suffixes: tuple[str, ...] = (),
) -> bool:
    """Return ``True`` iff ``host`` is one of a curated set of domains.

    ``suffix_matches`` are matched as ``host == s or host.endswith("." + s)``
    so e.g. ``("vlaanderen.be",)`` claims ``vlaanderen.be`` itself and any
    subdomain. ``exact_matches`` only matches the exact host. ``excluded_suffixes``
    is checked AFTER the positive match — used to carve out a subdomain
    that is more specifically classified by another module (e.g. ``.bosa.be``
    is federal-Belgian by ownership but its Matomo deployment is more
    informatively labelled as Matomo).
    """
    host = host.lower()
    for excluded in excluded_suffixes:
        if host == excluded or host.endswith("." + excluded):
            return False
    if host in exact_matches:
        return True
    for suffix in suffix_matches:
        if host == suffix or host.endswith("." + suffix):
            return True
    return False


def build_public_sector_hit(module: TrackerModule, event: RequestEvent) -> Hit:
    """Build a minimal :class:`Hit` for a public-sector third-party request.

    Parameter-level classification is intentionally left to the ambient
    HTTP-traffic params attached by the runner (visitor IP / Referer /
    User-Agent / Cookie) — those are the actual disclosures here. URL
    query params on a public-sector API call are operator-supplied
    identifiers (widget IDs, language codes, …) without a generic privacy
    taxonomy, so we keep them visible but unclassified.
    """
    params: list[ParamInfo] = []
    for key, value in event.all_params.items():
        params.append(ParamInfo(
            key=key,
            value=value,
            category=CAT_OTHER,
            meaning="Public-sector service parameter — unclassified",
            privacy_impact=IMPACT_LOW,
            event_index=event.event_id,
        ))
    return Hit(
        module_id=module.module_id, module_name=module.module_name,
        url=event.url, host=event.host, method=event.method,
        response_status=event.response_status, started_at=event.timestamp,
        params=params, events=[event.event_id],
    )
