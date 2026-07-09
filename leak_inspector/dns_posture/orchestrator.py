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

"""Top-level :func:`lookup` that drives every record-specific helper.

Designed to be the single call-site the analysis runner uses. Each
sub-query runs in a thread-pool so total wall time is bounded by the
slowest record type rather than the sum of every lookup; failures on
any one record type leave that field blank rather than abort the run.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from .dnssec import check_dnssec
from .email_security import (
    classify_mx_vendor,
    parse_bimi,
    parse_dmarc,
    parse_mta_sts,
    parse_spf,
    parse_tls_rpt,
    probe_dkim,
)
from .geoip import CountryReader, open_country_reader
from .productivity import probe_all as probe_productivity
from .resolvers import (
    query_a,
    query_aaaa,
    query_caa,
    query_https,
    query_mx,
    query_ns,
    query_txt,
)
from .sovereignty import asn_to_provider, detect_verification, enrich_ip
from .types import (
    CAARecord,
    DNSPosture,
    HostRecord,
    HTTPSRecord,
    IPInfo,
    NameserverRecord,
)


def lookup(domain: str) -> DNSPosture:
    """Run the full DNS-posture check on ``domain``.

    ``domain`` is the registrable domain (eTLD+1). The function never
    raises for missing/unreachable records — each soft-failure is
    captured in :attr:`DNSPosture.errors` and the corresponding field
    is left empty.
    """
    geo_reader = open_country_reader()
    posture = DNSPosture(
        domain=domain,
        looked_up_at=_now_iso(),
        geoip_available=geo_reader is not None,
    )

    if not domain:
        posture.errors.append("no domain to look up")
        if geo_reader:
            geo_reader.close()
        return posture

    try:
        _populate(domain, posture, geo_reader)
    finally:
        if geo_reader is not None:
            geo_reader.close()
    return posture


def _populate(domain: str, posture: DNSPosture, geo_reader: CountryReader | None) -> None:
    """Run every top-level lookup concurrently and stitch results into ``posture``."""
    with ThreadPoolExecutor(max_workers=8) as pool:
        # Schedule the leaf queries first.
        a_future        = pool.submit(query_a, domain)
        aaaa_future     = pool.submit(query_aaaa, domain)
        ns_future       = pool.submit(query_ns, domain)
        mx_future       = pool.submit(query_mx, domain)
        txt_apex_future = pool.submit(query_txt, domain)
        caa_future      = pool.submit(query_caa, domain)
        https_future    = pool.submit(query_https, domain)
        spf_future      = pool.submit(parse_spf, domain)
        dmarc_future    = pool.submit(parse_dmarc, domain)
        bimi_future     = pool.submit(parse_bimi, domain)
        mta_sts_future  = pool.submit(parse_mta_sts, domain)
        tls_rpt_future  = pool.submit(parse_tls_rpt, domain)
        dnssec_future   = pool.submit(check_dnssec, domain)
        dkim_future     = pool.submit(probe_dkim, domain)
        productivity_future = pool.submit(probe_productivity, domain)

        # --- A / AAAA → enrich each IP with ASN + country ----------------
        for address in _safe_call(a_future, posture, "A"):
            posture.a_records.append(enrich_ip(address, 4, geo_reader))
        for address in _safe_call(aaaa_future, posture, "AAAA"):
            posture.aaaa_records.append(enrich_ip(address, 6, geo_reader))

        # --- NS → for each NS, resolve to IPs, enrich, label provider ----
        ns_names = _safe_call(ns_future, posture, "NS")
        if ns_names:
            posture.nameservers = _enrich_nameservers(ns_names, geo_reader, pool)

        # --- MX → same enrichment, preserve preference -------------------
        mx_entries = _safe_call(mx_future, posture, "MX")
        if mx_entries:
            posture.mx = _enrich_mx(mx_entries, geo_reader, pool)
            # Classify each MX hostname against the known mail-provider
            # catalog; order-preserving dedup so the first MX provider
            # encountered comes first in the report.
            seen: set[str] = set()
            for _, exchange in mx_entries:
                label = classify_mx_vendor(exchange)
                if label and label not in seen:
                    seen.add(label)
                    posture.mail_providers.append(label)

        # --- productivity-suite OSINT probes -----------------------------
        # M365 / Workspace CNAME + DKIM signals. Resolves to an empty list
        # when no signal could be confirmed, so always-attached without
        # gating.
        posture.productivity_probes = _safe_call(
            productivity_future, posture, "productivity"
        ) or []

        # --- direct records ---------------------------------------------
        posture.spf      = _safe_call(spf_future, posture, "SPF")
        posture.dmarc    = _safe_call(dmarc_future, posture, "DMARC")
        posture.dkim     = _safe_call(dkim_future, posture, "DKIM") or []
        posture.bimi     = _safe_call(bimi_future, posture, "BIMI")
        posture.mta_sts  = _safe_call(mta_sts_future, posture, "MTA-STS")
        posture.tls_rpt  = _safe_call(tls_rpt_future, posture, "TLS-RPT")
        posture.dnssec   = _safe_call(dnssec_future, posture, "DNSSEC")

        caa_records = _safe_call(caa_future, posture, "CAA")
        if caa_records:
            posture.caa = _build_caa_record(caa_records)

        https_records = _safe_call(https_future, posture, "HTTPS")
        if https_records:
            posture.https = _build_https_record(https_records)

        # --- TXT verifications -----------------------------------------
        txt_records = _safe_call(txt_apex_future, posture, "TXT")
        for record in txt_records or []:
            verification = detect_verification(record)
            if verification is not None:
                posture.txt_verifications.append(verification)


def _safe_call(future, posture: DNSPosture, label: str):
    """Resolve a future, recording any unexpected error on the posture."""
    try:
        return future.result()
    except Exception as exc:  # pragma: no cover -- defensive; resolvers soft-fail
        posture.errors.append(f"{label}: {type(exc).__name__}: {exc}")
        return None


def _enrich_nameservers(
    ns_names: list[str],
    geo_reader: CountryReader | None,
    pool: ThreadPoolExecutor,
) -> list[NameserverRecord]:
    """Resolve each NS hostname's IPs, enrich, and label its provider."""
    futures = {name: pool.submit(query_a, name) for name in ns_names}
    out: list[NameserverRecord] = []
    for name, future in futures.items():
        try:
            addresses = future.result() or []
        except Exception:
            addresses = []
        ips = [enrich_ip(addr, 4, geo_reader) for addr in addresses]
        # Provider label = first non-empty asn-org translation.
        provider = ""
        for ip in ips:
            label = asn_to_provider(ip.as_org)
            if label:
                provider = label
                break
        out.append(NameserverRecord(name=name, ips=ips, provider=provider))
    return out


def _enrich_mx(
    mx_entries: list[tuple[int, str]],
    geo_reader: CountryReader | None,
    pool: ThreadPoolExecutor,
) -> list[HostRecord]:
    """Resolve each MX hostname's IPs and attach them as :class:`IPInfo`."""
    futures = {
        host: pool.submit(query_a, host)
        for _, host in mx_entries
    }
    out: list[HostRecord] = []
    for pref, host in mx_entries:
        try:
            addresses = futures[host].result() or []
        except Exception:
            addresses = []
        out.append(HostRecord(
            name=host,
            priority=pref,
            ips=[enrich_ip(addr, 4, geo_reader) for addr in addresses],
        ))
    out.sort(key=lambda h: (h.priority if h.priority is not None else 0, h.name))
    return out


def _build_caa_record(records: list[tuple[int, str, str]]) -> CAARecord:
    """Group CAA tuples ``(flags, tag, value)`` into a :class:`CAARecord`."""
    record = CAARecord()
    for flags, tag, value in records:
        record.raw_records.append(f"{flags} {tag} \"{value}\"")
        tag_lower = tag.lower()
        if tag_lower == "issue":
            record.issue_cas.append(value)
        elif tag_lower == "issuewild":
            record.issuewild_cas.append(value)
    return record


def _build_https_record(records: list[dict]) -> HTTPSRecord:
    """Summarise a list of HTTPS/SVCB records into one :class:`HTTPSRecord`."""
    alpn: list[str] = []
    has_ech = False
    raw: list[str] = []
    for r in records:
        params = r.get("params") or {}
        if "alpn" in params:
            for proto in str(params["alpn"]).strip().split(","):
                proto = proto.strip().strip('"')
                if proto and proto not in alpn:
                    alpn.append(proto)
        if "ech" in params and str(params["ech"]).strip() not in ("", "none"):
            has_ech = True
        raw.append(f"prio={r.get('priority')} target={r.get('target') or '.'} {params}")
    return HTTPSRecord(present=True, alpn=alpn, has_ech=has_ech, raw_records=raw)


def _now_iso() -> str:
    """Current time as an ISO-8601 UTC string."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


__all__ = ["lookup"]
