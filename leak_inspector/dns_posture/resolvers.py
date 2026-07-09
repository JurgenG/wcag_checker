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

"""Thin dnspython wrappers, all soft-fail.

Every helper here catches the resolver's expected exception family
(``NoAnswer`` / ``NXDOMAIN`` / ``Timeout`` / ``NoNameservers``) and
returns an empty result. The rest of the subpackage can therefore
issue lookups without try/except clutter around every call.

Timeouts are conservative (3 s per query, 5 s total lifetime) so a
single broken record type doesn't stall the report for a minute.
"""

from __future__ import annotations

import dns.resolver
import dns.rdatatype
import dns.exception


_DEFAULT_TIMEOUT = 3.0
_DEFAULT_LIFETIME = 5.0


def _make_resolver(
    timeout: float = _DEFAULT_TIMEOUT, lifetime: float = _DEFAULT_LIFETIME
) -> dns.resolver.Resolver:
    """Build a resolver with tight timeouts."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = lifetime
    return resolver


def query(
    name: str,
    rdtype: str,
    *,
    timeout: float = _DEFAULT_TIMEOUT,
    lifetime: float = _DEFAULT_LIFETIME,
) -> list:
    """Return the answer rdata list for ``(name, rdtype)``, empty on failure.

    Soft-fails for the usual "answer is absent" exceptions and for
    timeouts; the caller doesn't need a try/except. Any other unexpected
    error propagates (intentional — those are programmer bugs).
    """
    resolver = _make_resolver(timeout=timeout, lifetime=lifetime)
    try:
        answer = resolver.resolve(name, rdtype, raise_on_no_answer=False)
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
    ):
        return []
    if answer.rrset is None:
        return []
    return list(answer.rrset)


def query_a(name: str) -> list[str]:
    """Return A records (IPv4 dotted strings) for ``name``."""
    return [r.address for r in query(name, "A")]


def query_aaaa(name: str) -> list[str]:
    """Return AAAA records (IPv6 strings) for ``name``."""
    return [r.address for r in query(name, "AAAA")]


def query_ns(name: str) -> list[str]:
    """Return nameserver hostnames (trailing dot stripped)."""
    return [str(r.target).rstrip(".") for r in query(name, "NS")]


def query_cname(name: str) -> list[str]:
    """Return CNAME target hostnames (trailing dot stripped).

    Empty list when ``name`` has no CNAME record (i.e. when it either
    doesn't exist or resolves directly via an A/AAAA record without an
    intermediate alias).
    """
    return [str(r.target).rstrip(".") for r in query(name, "CNAME")]


def query_mx(name: str) -> list[tuple[int, str]]:
    """Return ``(preference, exchange)`` pairs, trailing dot stripped."""
    out: list[tuple[int, str]] = []
    for r in query(name, "MX"):
        host = str(r.exchange).rstrip(".")
        if host:
            out.append((int(r.preference), host))
    return out


def query_txt(name: str) -> list[str]:
    """Return TXT-record string values for ``name``.

    Multi-segment TXT records (where a single record holds several
    quoted strings) are concatenated into one string per record, per
    RFC 7208 §3.3.
    """
    out: list[str] = []
    for r in query(name, "TXT"):
        # dnspython exposes the per-record strings as a tuple of bytes.
        joined = b"".join(r.strings).decode("utf-8", errors="replace")
        out.append(joined)
    return out


def query_caa(name: str) -> list[tuple[int, str, str]]:
    """Return ``(flags, tag, value)`` triples for CAA records."""
    out: list[tuple[int, str, str]] = []
    for r in query(name, "CAA"):
        value = r.value
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="replace")
        tag = r.tag
        if isinstance(tag, bytes):
            tag = tag.decode("utf-8", errors="replace")
        out.append((int(r.flags), tag, value))
    return out


def query_https(name: str) -> list[dict]:
    """Return parsed HTTPS/SVCB records (RFC 9460) for ``name``.

    Each entry is ``{"priority": int, "target": str, "params": {key: value}}``.
    Parameter values are stringified for portability; the caller can
    re-parse for specific keys (``alpn``, ``ech``).
    """
    out: list[dict] = []
    try:
        rdtype = dns.rdatatype.from_text("HTTPS")
    except dns.rdatatype.UnknownRdatatype:
        return out
    for r in query(name, "HTTPS"):
        params: dict[str, str] = {}
        # rdtype-specific parsing: dnspython exposes ``params`` as a dict
        # keyed by SvcParamKey objects; stringify to keep us decoupled
        # from dnspython internals.
        record_params = getattr(r, "params", None)
        if record_params:
            for key, value in record_params.items():
                params[str(key).lower()] = str(value)
        target = str(getattr(r, "target", "")).rstrip(".")
        out.append({
            "priority": int(getattr(r, "priority", 0)),
            "target": target,
            "params": params,
        })
    return out


def query_ds(name: str) -> list:
    """Return DS records for ``name`` (parent zone). Used for DNSSEC probe."""
    return query(name, "DS")


def query_dnskey(name: str) -> list:
    """Return DNSKEY records for ``name``. Used for DNSSEC probe."""
    return query(name, "DNSKEY")


def reverse_via_cymru(ip: str) -> tuple[int | None, str, str]:
    """Look up ASN + org + country for an IP via Team Cymru's DNS service.

    Returns ``(asn, org, country)``. Any field is empty/``None`` if the
    lookup didn't return that piece.

    The Team Cymru "IP-to-ASN mapping service" is a public DNS-based
    interface that requires no API key. Format:

      * For IPv4 ``a.b.c.d`` query ``d.c.b.a.origin.asn.cymru.com``;
        the TXT response is ``"asn | prefix | cc | rir | date"``.
      * For IPv6 query ``<reversed-nibbles>.origin6.asn.cymru.com``.
      * Then query ``ASN<asn>.asn.cymru.com`` for the org name.
    """
    # Build the reverse-IP query name.
    if ":" in ip:
        reverse_zone = "origin6.asn.cymru.com"
        reverse_name = _ipv6_reverse_nibbles(ip)
        if not reverse_name:
            return None, "", ""
    else:
        reverse_zone = "origin.asn.cymru.com"
        try:
            octets = ip.split(".")
            if len(octets) != 4:
                return None, "", ""
            reverse_name = ".".join(reversed(octets))
        except (ValueError, AttributeError):
            return None, "", ""

    txt_records = query_txt(f"{reverse_name}.{reverse_zone}")
    if not txt_records:
        return None, "", ""

    # First record wins; format is "asn | prefix | cc | rir | date"
    parts = [p.strip() for p in txt_records[0].split("|")]
    if not parts or not parts[0]:
        return None, "", ""
    # parts[0] may contain multiple ASNs separated by space ("13335 14789");
    # keep the first (the announcing AS).
    asn_field = parts[0].split()[0]
    try:
        asn = int(asn_field)
    except ValueError:
        return None, "", ""
    country = parts[2] if len(parts) > 2 else ""

    # AS-info lookup for the org name.
    org = ""
    org_records = query_txt(f"AS{asn}.asn.cymru.com")
    if org_records:
        # Format: "asn | cc | rir | date | org-name"
        org_parts = [p.strip() for p in org_records[0].split("|")]
        if len(org_parts) >= 5:
            org = org_parts[4]
    return asn, org, country


def _ipv6_reverse_nibbles(address: str) -> str:
    """Return the dotted-nibble reverse form of an IPv6 address.

    Mirrors the ``ip6.arpa`` layout: ``2001:db8::1`` → ``1.0.0.…`` (32
    nibbles separated by dots, in reverse order). Returns an empty
    string for malformed input.
    """
    import ipaddress

    try:
        addr = ipaddress.IPv6Address(address)
    except ValueError:
        return ""
    hex_form = addr.exploded.replace(":", "")
    return ".".join(reversed(hex_form))


__all__ = [
    "query",
    "query_a",
    "query_aaaa",
    "query_caa",
    "query_dnskey",
    "query_ds",
    "query_https",
    "query_mx",
    "query_ns",
    "query_txt",
    "reverse_via_cymru",
]