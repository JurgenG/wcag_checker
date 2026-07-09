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

"""DNS-posture data records.

These dataclasses are produced by the resolvers/parsers in this
subpackage and consumed by the report builder. The shape is JSON-
native (no tuples, no sets, no enums) so :func:`dataclasses.asdict`
serialises cleanly through the JSON reporter and the markdown / HTML
renderers can walk it the same way.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class IPInfo:
    """A single IP address plus geo/ASN enrichment.

    ``version`` is 4 or 6. The ASN / org / country fields are empty
    when the corresponding enrichment lookup failed (e.g. no GeoLite2
    mmdb installed, or Team Cymru unreachable).
    """

    address: str
    version: int
    asn: int | None = None
    as_org: str = ""
    #: Physical geolocation of the IP (MaxMind), ISO-3166-1 alpha-2.
    country_code: str = ""
    country_name: str = ""
    #: Legal jurisdiction: the ASN's registration country (Team Cymru),
    #: ISO-3166-1 alpha-2. Distinct from ``country_code`` — an IP can sit
    #: physically in one country while its operator is registered in
    #: another (e.g. a US-registered network announcing an EU-located IP).
    asn_country: str = ""


@dataclass
class HostRecord:
    """A named DNS host (MX or SPF include target) plus its IPs."""

    name: str
    priority: int | None = None  # MX preference; None for non-MX hosts
    ips: list[IPInfo] = field(default_factory=list)


@dataclass
class NameserverRecord:
    """A nameserver host plus its IPs and resolved provider."""

    name: str
    ips: list[IPInfo] = field(default_factory=list)
    #: Friendly provider label inferred from ASN org (e.g. ``"Cloudflare,
    #: Inc."`` or ``"Amazon.com, Inc."``). Empty if ASN lookup failed.
    provider: str = ""


@dataclass
class SPFRecord:
    """Parsed Sender Policy Framework record (RFC 7208)."""

    raw: str
    #: Final qualifier: one of ``"-all"``, ``"~all"``, ``"?all"``,
    #: ``"+all"``, or empty if no terminal ``all`` mechanism.
    final_qualifier: str = ""
    #: Flattened list of every ``include:`` target (recursively
    #: resolved). The senders the listed third parties may mail on
    #: behalf of this domain are derived from these.
    includes: list[str] = field(default_factory=list)
    ip4: list[str] = field(default_factory=list)
    ip6: list[str] = field(default_factory=list)
    a: list[str] = field(default_factory=list)
    mx: list[str] = field(default_factory=list)
    redirect: str = ""
    #: Human-readable list of sender vendors inferred from the includes
    #: (e.g. ``"Mailchimp"``, ``"SendGrid"``, ``"Microsoft 365"``).
    sender_vendors: list[str] = field(default_factory=list)


@dataclass
class DMARCRecord:
    """Parsed Domain-based Message Authentication record (RFC 7489)."""

    raw: str
    policy: str = ""             # p=
    subdomain_policy: str = ""   # sp=
    pct: int = 100
    rua: list[str] = field(default_factory=list)  # aggregate-report mailto: URIs
    ruf: list[str] = field(default_factory=list)  # forensic-report mailto: URIs
    #: Third-party DMARC processors inferred from rua/ruf hostnames
    #: (Postmark, dmarcian, Valimail, Agari, …). Each is a self-
    #: disclosed third-party data flow.
    report_processors: list[str] = field(default_factory=list)


@dataclass
class DKIMSelector:
    """Result of probing a single DKIM selector."""

    selector: str
    found: bool
    #: Raw TXT value (truncated) when ``found`` is True; otherwise empty.
    raw: str = ""


@dataclass
class DNSSECStatus:
    """Lightweight DNSSEC presence check.

    Not a full validation chain — that needs a validating resolver and
    cryptographic verification. v1 just answers "is the zone signed?":
    parent publishes a DS record, and the zone serves a DNSKEY.
    """

    parent_has_ds: bool
    zone_has_dnskey: bool
    summary: str = ""  # short human-readable state


@dataclass
class CAARecord:
    """Certification Authority Authorization records (RFC 8659)."""

    raw_records: list[str] = field(default_factory=list)
    issue_cas: list[str] = field(default_factory=list)
    issuewild_cas: list[str] = field(default_factory=list)


@dataclass
class HTTPSRecord:
    """RFC 9460 HTTPS/SVCB summary."""

    present: bool
    alpn: list[str] = field(default_factory=list)
    has_ech: bool = False  # Encrypted Client Hello advertised
    raw_records: list[str] = field(default_factory=list)


@dataclass
class TXTVerification:
    """One self-disclosed third-party SaaS verification token.

    These TXT records are published by the domain owner to prove
    ownership to an external service. Each one therefore discloses a
    third-party relationship — gold for sovereignty mapping.
    """

    vendor: str       # e.g. "Google", "Microsoft 365", "Meta"
    purpose: str      # e.g. "Workspace / Search Console", "Office 365"
    jurisdiction: str = ""  # the vendor's home jurisdiction (ISO-3166-1 alpha-2)


@dataclass
class MTASTSStatus:
    """MTA-STS presence (RFC 8461).

    Only the TXT advertisement is checked here. Fetching and parsing
    the policy file at ``https://mta-sts.<domain>/.well-known/mta-sts.txt``
    is left as a follow-up; the TXT record alone tells whether the
    operator has deployed MTA-STS at all.
    """

    txt_present: bool
    txt_id: str = ""  # v=STSv1; id=<id>


@dataclass
class TLSRPTStatus:
    """SMTP TLS Reporting record (RFC 8460)."""

    txt_present: bool
    rua: list[str] = field(default_factory=list)


@dataclass
class BIMIRecord:
    """Brand Indicators for Message Identification — TXT record only."""

    present: bool
    svg_url: str = ""
    vmc_url: str = ""


@dataclass
class DNSPosture:
    """The full DNS-posture report for one registrable domain.

    Every nested field is ``None``/empty by default. The orchestrator
    populates each one on a best-effort basis; partial network failure
    leaves some fields blank and pushes a short message onto
    :attr:`errors` rather than raising.
    """

    domain: str
    looked_up_at: str   # ISO-8601 UTC timestamp
    #: ``True`` if a GeoLite2 mmdb was found and successfully opened.
    #: When ``False``, country fields on IPs stay empty but ASN data is
    #: still populated from Team Cymru.
    geoip_available: bool = False

    # --- web / HTTP layer ----------------------------------------------------
    a_records: list[IPInfo] = field(default_factory=list)
    aaaa_records: list[IPInfo] = field(default_factory=list)

    # --- DNS infrastructure --------------------------------------------------
    nameservers: list[NameserverRecord] = field(default_factory=list)
    dnssec: DNSSECStatus | None = None
    caa: CAARecord | None = None
    https: HTTPSRecord | None = None

    # --- email infrastructure ------------------------------------------------
    mx: list[HostRecord] = field(default_factory=list)
    spf: SPFRecord | None = None
    dmarc: DMARCRecord | None = None
    dkim: list[DKIMSelector] = field(default_factory=list)
    mta_sts: MTASTSStatus | None = None
    tls_rpt: TLSRPTStatus | None = None
    bimi: BIMIRecord | None = None

    # --- self-disclosed third-party SaaS relationships -----------------------
    txt_verifications: list[TXTVerification] = field(default_factory=list)

    # --- productivity-suite OSINT probes -------------------------------------
    #: MX-hostname-classifier hits — one entry per recognised mail vendor
    #: found in the domain's MX records (e.g. "Microsoft 365 (Exchange
    #: Online)", "Google Workspace / Gmail"). Order-preserving dedup.
    mail_providers: list[str] = field(default_factory=list)
    #: Microsoft 365 / Google Workspace CNAME / DKIM signals — populated
    #: by :mod:`leak_inspector.dns_posture.productivity`. Empty when no
    #: productivity-suite signal could be confirmed.
    productivity_probes: list = field(default_factory=list)

    # --- non-fatal lookup errors --------------------------------------------
    errors: list[str] = field(default_factory=list)