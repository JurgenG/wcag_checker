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

"""Lightweight DNSSEC presence check.

Full DNSSEC validation requires walking the chain of trust from the
root, verifying each signature with the corresponding DNSKEY, and
honouring the appropriate algorithm/cipher choices. That's a
non-trivial chunk of code and a hard dependency on the local
resolver's behaviour.

v1 answers a simpler, useful question: *is this zone signed?* — by
checking that

* the parent zone publishes a DS record for the domain, and
* the zone itself serves a DNSKEY.

Both checks together mean the operator has deployed DNSSEC. They do
not prove that the records the user receives are validated end-to-end
by the resolver they're using — that's a property of the resolver,
not of the published zone.
"""

from __future__ import annotations

from .resolvers import query_dnskey, query_ds
from .types import DNSSECStatus


def check_dnssec(domain: str) -> DNSSECStatus:
    """Return whether DNSSEC is deployed for ``domain``.

    Both a DS record (at the parent zone) and a DNSKEY (at the zone
    itself) must be present for the zone to be considered signed.
    """
    ds_records = query_ds(domain)
    dnskey_records = query_dnskey(domain)

    parent_has_ds = bool(ds_records)
    zone_has_dnskey = bool(dnskey_records)

    if parent_has_ds and zone_has_dnskey:
        summary = "Zone is DNSSEC-signed (DS at parent + DNSKEY in zone)."
    elif parent_has_ds and not zone_has_dnskey:
        summary = (
            "Parent publishes DS but the zone serves no DNSKEY — broken "
            "chain (resolvers will return SERVFAIL when validating)."
        )
    elif not parent_has_ds and zone_has_dnskey:
        summary = (
            "Zone serves DNSKEY but parent publishes no DS — DNSSEC is "
            "configured but the chain of trust is not anchored."
        )
    else:
        summary = "Zone is not DNSSEC-signed."

    return DNSSECStatus(
        parent_has_ds=parent_has_ds,
        zone_has_dnskey=zone_has_dnskey,
        summary=summary,
    )


__all__ = ["check_dnssec"]
