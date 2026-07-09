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

"""Human-readable text reporter.

Walks a :class:`~.document.ReportDocument` and emits a terminal-
friendly text rendition. No derivation logic here — the document is
the contract; this file is pure formatting.

Report structure:

1. Banner — capture target + session metadata.
2. Executive summary — KEY FINDINGS → RECOMMENDED ACTIONS →
   DETAILED FINDINGS.
3. Unclassified third-party hosts (only when any).
4. One section per tracker module with classified per-hit detail.

ANSI color is opt-out via ``color=False``; verbose mode adds the
source ``event_id`` list under each representative hit.
"""

from __future__ import annotations

from io import StringIO

from ..analysis import Analysis
from ..modules.base import (
    CATEGORIES,
    IMPACT_HIGH,
    IMPACT_LOW,
    IMPACT_MEDIUM,
)
from .builder import build_report_document
from .score_v2 import DEFAULT_P50, DEFAULT_S, EXPLAINER_THRESHOLD, format_stars
from .document import (
    DNSPosture,
    ExecutiveSummary,
    IPInfo,
    ManifestView,
    ModuleSection,
    RepresentativeHit,
    ReportDocument,
    UnclassifiedHost,
)


# --- ANSI palette ----------------------------------------------------------

_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_CYAN = "\033[36m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_GREEN = "\033[32m"

_IMPACT_COLORS = {
    IMPACT_HIGH: _RED,
    IMPACT_MEDIUM: _YELLOW,
    IMPACT_LOW: _GREEN,
}


class _Palette:
    """Tiny ANSI helper that no-ops when color is disabled."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if self.enabled else text

    def header(self, text: str) -> str:
        return self._wrap(_BOLD, text)

    def section(self, text: str) -> str:
        return self._wrap(_BOLD + _CYAN, text)

    def dim(self, text: str) -> str:
        return self._wrap(_DIM, text)

    def impact(self, level: str, text: str) -> str:
        color = _IMPACT_COLORS.get(level, "")
        return self._wrap(color, text) if color else text


# --- value formatting ------------------------------------------------------

_VALUE_MAX = 60


def _truncate(value: str, limit: int = _VALUE_MAX) -> str:
    """Shorten long parameter values for readable single-line display."""
    if len(value) <= limit:
        return value
    return value[: limit - 1] + "…"


def _format_categories(counts: dict[str, int]) -> str:
    """Render the category counts dict as ``name=N, name=N`` in canonical order."""
    parts = [f"{cat}={counts[cat]}" for cat in CATEGORIES if counts.get(cat)]
    return ", ".join(parts) if parts else "(none)"


# --- writers ---------------------------------------------------------------


def _write_header(out: StringIO, m: ManifestView, p: _Palette) -> None:
    from ._branding import BRANDING_TITLE_PREFIX, title_host_label
    bar = "=" * 78
    out.write(f"{bar}\n")
    out.write(p.header(f"{BRANDING_TITLE_PREFIX} : {title_host_label(m)}") + "\n")
    out.write(p.dim(f"target:     {m.target_url}") + "\n")
    out.write(p.dim(f"session_id: {m.session_id}") + "\n")
    out.write(p.dim(f"captured:   {m.started_at} → {m.ended_at}") + "\n")
    out.write(p.dim(f"profile:    {m.profile}") + "\n")
    if m.landing_url and m.landing_url != m.target_url:
        out.write(p.dim(f"landed at:  {m.landing_url}") + "\n")
    out.write(f"{bar}\n\n")


def _write_capture_status_banner(out: StringIO, status, p: _Palette) -> None:
    """Single-line failure banner. No-op for healthy captures."""
    if status is None or not status.is_failure:
        return
    if status.http_status is not None:
        label = f"HTTP {status.http_status} — {status.reason}"
    else:
        label = status.reason or "Unreachable"
    out.write(p.impact("high", f"⚠ Capture failed: {label}") + "\n")
    out.write(p.dim(
        "  Findings below reflect what loaded before the failure — "
        "usually very little. Verify the URL and the site's availability."
    ) + "\n\n")


def _write_intro(out: StringIO, p: _Palette) -> None:
    """Plain-prose intro driven by the shared template in :mod:`._branding`.

    Hyperlinks degrade gracefully: ``BeLibre`` stays as bare text and
    the URL is appended in parentheses on the third paragraph.
    """
    from ._branding import (
        BELIBRE_HOMEPAGE,
        INTRO_DISCLAIMER_TEXT,
        INTRO_PARAGRAPHS,
        INTRO_TITLE,
    )
    belibre_link = "BeLibre"
    belibre_url = f"belibre.be ({BELIBRE_HOMEPAGE})"
    disclaimer_bold = p.header(INTRO_DISCLAIMER_TEXT)

    out.write(p.section(INTRO_TITLE) + "\n")
    out.write("─" * 78 + "\n")
    for paragraph in INTRO_PARAGRAPHS:
        rendered = paragraph.format(
            belibre_link=belibre_link,
            disclaimer_bold=disclaimer_bold,
            belibre_url=belibre_url,
        )
        out.write(_wrap_prose(rendered, width=78) + "\n\n")


def _wrap_prose(text: str, width: int = 78) -> str:
    """Wrap a paragraph to ``width`` columns, preserving the existing
    in-line markup (ANSI escape codes pass through). Uses
    :func:`textwrap.fill` with conservative defaults so the output stays
    grep-able and readable in a 80-column terminal."""
    import textwrap
    return textwrap.fill(
        text, width=width,
        break_long_words=False, break_on_hyphens=False,
    )


def _write_executive_summary(
    out: StringIO, summary: ExecutiveSummary, p: _Palette
) -> None:
    out.write(p.section("Executive summary") + "\n")
    out.write("─" * 78 + "\n")

    # Key findings — headline + detail joined into one visual line.
    # The headline carries the severity color; the detail follows as
    # dim text in the same line so the eye scans one row per finding.
    if summary.findings:
        from .verdict_action_metadata import metadata_for

        def _write_findings(label: str, items: list) -> None:
            if not items:
                return
            out.write(p.header(label) + "\n")
            for finding in items:
                line = f"  {finding.badge} {p.impact(finding.severity, finding.headline)}"
                if finding.detail:
                    line += f". {p.dim(finding.detail)}"
                meta = metadata_for(finding.kind)
                if meta is not None:
                    line += p.dim(
                        f"  (owner: {meta.owner} · effort: {meta.effort})"
                    )
                out.write(line + "\n")
            out.write("\n")

        capture_findings = [f for f in summary.findings if f.source != "dns"]
        dns_findings = [f for f in summary.findings if f.source == "dns"]
        if dns_findings:
            _write_findings(""
                            "", capture_findings)
            _write_findings("KEY FINDINGS - INSFRASTRUCTURE", dns_findings)
        else:
            _write_findings("KEY FINDINGS", capture_findings)

    # Recommended actions
    if summary.actions:
        out.write(p.header("RECOMMENDED ACTIONS") + "\n")
        for idx, action in enumerate(summary.actions, start=1):
            out.write(f"  {idx}. {action}\n")
        out.write("\n")

    # Detailed findings
    out.write(p.header("DETAILED FINDINGS") + "\n")

    # CNAME-cloak alias list (the headline finding showed the first 3;
    # here we render up to 6 with full attribution).
    if summary.cname_cloaks:
        cloaks = summary.cname_cloaks
        out.write(
            f"  {p.impact(IMPACT_HIGH, 'CNAME-cloaked trackers:')} "
            f"{len(cloaks)} alias{'es' if len(cloaks) != 1 else ''} "
            "resolve to known vendors\n"
        )
        for cloak in cloaks[:6]:
            out.write(
                f"    {cloak.alias}  →  {cloak.canonical}  "
                f"[{cloak.vendor_module_name}]\n"
            )
        if len(cloaks) > 6:
            out.write(
                f"    + {len(cloaks) - 6} more (see per-tracker sections)\n"
            )

    # HIGH-impact tracking by vendor
    if summary.high_impact_by_vendor:
        out.write(f"  {p.impact(IMPACT_HIGH, 'HIGH-impact tracking by vendor:')}\n")
        for rollup in summary.high_impact_by_vendor[:6]:
            mod_list = ", ".join(m.name for m in rollup.modules[:3])
            if len(rollup.modules) > 3:
                mod_list += f" +{len(rollup.modules) - 3}"
            out.write(f"    {rollup.vendor_label}  [{mod_list}]\n")
            for cat in rollup.categories:
                keys = [f.key for f in cat.fields]
                shown = ", ".join(keys[:5])
                if len(keys) > 5:
                    shown += f", +{len(keys) - 5} more"
                out.write(f"      {cat.category.ljust(11)} {shown}\n")
        if len(summary.high_impact_by_vendor) > 6:
            out.write(
                f"    + {len(summary.high_impact_by_vendor) - 6} more vendor(s) "
                "with HIGH-impact fields\n"
            )

    # Jurisdictions tally — single line with flag prefixes
    if summary.jurisdictions:
        parts = []
        for j in summary.jurisdictions:
            sample = ", ".join(j.vendors[:2])
            if len(j.vendors) > 2:
                sample += f", +{len(j.vendors) - 2} more"
            flag_prefix = f"{j.flag} " if j.flag else ""
            parts.append(f"{j.module_count}× {flag_prefix}{j.code} ({sample})")
        out.write(f"  Vendor jurisdictions: {' · '.join(parts)}\n")

    # Volume stats
    stats = summary.stats
    if stats is not None:
        out.write(
            f"  Trackers fired:      {stats.trackers_fired} modules · "
            f"{stats.total_requests} requests "
            f"({stats.unique_requests} unique after dedup)\n"
        )
        out.write(
            f"  Third-party hosts:   {stats.third_party_hosts_touched} touched · "
            f"{stats.third_party_hosts_claimed} claimed, "
            f"{stats.third_party_hosts_unclassified} unclassified\n"
        )
        if stats.top_by_impact:
            top_parts = [
                f"{e.module_name} ({e.high_impact_field_count}H/{e.medium_impact_field_count}M/{e.hit_count}×)"
                for e in stats.top_by_impact
            ]
            out.write(f"  Top by impact:       {', '.join(top_parts)}\n")

    out.write("\n")


def _write_dns_posture(
    out: StringIO, posture: DNSPosture | None, p: _Palette
) -> None:
    if posture is None:
        return
    out.write(p.section(f"DNS posture — {posture.domain}") + "\n")
    out.write("─" * 78 + "\n")

    # --- network footprint ----------------------------------------------
    if posture.a_records or posture.aaaa_records:
        out.write(p.header("  Hosting") + "\n")
        for ip in posture.a_records:
            out.write(f"    {_format_ip(ip)}\n")
        for ip in posture.aaaa_records:
            out.write(f"    {_format_ip(ip)}\n")

    if posture.nameservers:
        out.write(p.header("  Authoritative DNS") + "\n")
        for ns in posture.nameservers:
            line = f"    {ns.name}"
            if ns.provider:
                line += f"  [{ns.provider}]"
            jurisdictions = sorted({ip.country_code for ip in ns.ips if ip.country_code})
            if jurisdictions:
                line += f"  ({', '.join(jurisdictions)})"
            out.write(line + "\n")

    if posture.mx:
        out.write(p.header("  Mail (MX)") + "\n")
        for mx in posture.mx:
            prio = mx.priority if mx.priority is not None else 0
            host_line = f"    {prio:>3}  {mx.name}"
            jurisdictions = sorted({ip.country_code for ip in mx.ips if ip.country_code})
            asns = sorted({ip.as_org for ip in mx.ips if ip.as_org})
            extras: list[str] = []
            if asns:
                extras.append(", ".join(asns[:2]))
            if jurisdictions:
                extras.append(", ".join(jurisdictions))
            if extras:
                host_line += "  (" + " · ".join(extras) + ")"
            out.write(host_line + "\n")

    # --- transport security ---------------------------------------------
    if posture.dnssec is not None:
        signed = posture.dnssec.parent_has_ds and posture.dnssec.zone_has_dnskey
        mark = p.impact(IMPACT_LOW, "✓") if signed else p.impact(IMPACT_MEDIUM, "✗")
        out.write(f"  DNSSEC:    {mark} {p.dim(posture.dnssec.summary)}\n")

    if posture.caa is not None:
        cas = posture.caa.issue_cas or ["(none)"]
        out.write(f"  CAA issue: {', '.join(cas)}\n")
        if posture.caa.issuewild_cas:
            out.write(
                f"  CAA wild:  {', '.join(posture.caa.issuewild_cas)}\n"
            )

    if posture.https is not None:
        parts: list[str] = []
        if posture.https.alpn:
            parts.append("ALPN " + "/".join(posture.https.alpn))
        if posture.https.has_ech:
            parts.append(p.impact(IMPACT_LOW, "ECH advertised"))
        out.write(
            f"  HTTPS:     {' · '.join(parts) if parts else '(record present, no params)'}\n"
        )

    # --- email security -------------------------------------------------
    if posture.spf is not None:
        line = f"  SPF:       {posture.spf.final_qualifier or '(no terminal all)'}"
        if posture.spf.sender_vendors:
            line += f"  · senders: {', '.join(posture.spf.sender_vendors[:5])}"
            if len(posture.spf.sender_vendors) > 5:
                line += f", +{len(posture.spf.sender_vendors) - 5}"
        out.write(line + "\n")
    else:
        out.write(f"  SPF:       {p.impact(IMPACT_MEDIUM, '(not published)')}\n")

    if posture.dmarc is not None:
        line = f"  DMARC:     p={posture.dmarc.policy or '(unset)'}"
        if posture.dmarc.pct != 100:
            line += f" pct={posture.dmarc.pct}"
        if posture.dmarc.report_processors:
            line += f"  · reports → {', '.join(posture.dmarc.report_processors)}"
        out.write(line + "\n")
    else:
        out.write(f"  DMARC:     {p.impact(IMPACT_MEDIUM, '(not published)')}\n")

    if posture.dkim:
        names = ", ".join(d.selector for d in posture.dkim)
        out.write(f"  DKIM:      {len(posture.dkim)} selector(s): {names}\n")

    if posture.bimi is not None and posture.bimi.present:
        bits = []
        if posture.bimi.svg_url:
            bits.append(f"l={posture.bimi.svg_url}")
        if posture.bimi.vmc_url:
            bits.append(f"a={posture.bimi.vmc_url}")
        out.write(f"  BIMI:      {' · '.join(bits) if bits else 'present'}\n")

    if posture.mta_sts is not None and posture.mta_sts.txt_present:
        suffix = f" id={posture.mta_sts.txt_id}" if posture.mta_sts.txt_id else ""
        out.write(f"  MTA-STS:   present{suffix}\n")

    if posture.tls_rpt is not None and posture.tls_rpt.txt_present:
        rua = ", ".join(posture.tls_rpt.rua) if posture.tls_rpt.rua else "(no rua)"
        out.write(f"  TLS-RPT:   {rua}\n")

    # --- self-disclosed SaaS --------------------------------------------
    if posture.txt_verifications:
        out.write(p.header("  Self-disclosed SaaS (via TXT verifications)") + "\n")
        for txt in posture.txt_verifications:
            jur = f" [{txt.jurisdiction}]" if txt.jurisdiction else ""
            out.write(f"    • {txt.vendor}{jur}  {p.dim(txt.purpose)}\n")

    if posture.errors:
        out.write(p.dim(f"  ({len(posture.errors)} lookup error(s) — see JSON output)") + "\n")
    out.write("\n")


def _format_ip(ip: IPInfo) -> str:
    """One-line ``addr  (AS … · CC)`` summary for an IPInfo."""
    parts: list[str] = []
    if ip.asn is not None:
        org_bit = f" {ip.as_org}" if ip.as_org else ""
        parts.append(f"AS{ip.asn}{org_bit}")
    if ip.country_code:
        parts.append(ip.country_code)
    suffix = f"  ({' · '.join(parts)})" if parts else ""
    return f"{ip.address}{suffix}"


def _write_cookies(
    out: StringIO,
    cookies: list,
    p: _Palette,
    forwarded_keys: list[tuple[str, str]] = (),
) -> None:
    """Render the cookie overview as a plain-text section.

    ``forwarded_keys`` — ``(name, host)`` of first-party cookies whose
    vendor forwards/cloaks here; those entries get a
    "(via first-party proxy)" note next to the honest ``[1P]`` tag.
    """
    if not cookies:
        return
    forwarded = set(forwarded_keys or ())
    out.write(p.section(f"Cookies set during this capture ({len(cookies)})") + "\n")
    out.write("─" * 78 + "\n")
    out.write(p.dim(
        "  Cookie values are redacted; only metadata (lifetime, flags, "
        "issuing party) is surfaced."
    ) + "\n\n")
    for c in cookies:
        party = "1P" if c.is_first_party else "3P"
        flags: list[str] = []
        flags.append(f"SameSite={c.same_site or '(unset)'}")
        if c.secure:
            flags.append("Secure")
        if c.http_only:
            flags.append("HttpOnly")
        if c.partitioned:
            flags.append("Partitioned")
        impact_color = p.impact(c.privacy_impact, c.privacy_impact.upper())
        note = (
            "  (via first-party proxy)"
            if (c.name, c.host) in forwarded else ""
        )
        out.write(
            f"  [{party}] {c.name}{note}\n"
            f"      issued by: {c.vendor}  ({c.host})\n"
            f"      lifetime:  {c.lifetime_human}\n"
            f"      flags:     {', '.join(flags)}\n"
            f"      impact:    {impact_color}\n"
        )
    out.write("\n")


def _enrichment_status_line(document) -> str | None:
    """Single wording source for the network-posture provenance line.

    Returns ``None`` when there is nothing to say (enriched bundles
    whose posture sections speak for themselves carry the timestamp;
    un-enriched bundles get the honest pointer instead of a silent
    re-probe).
    """
    if document.enriched_at:
        line = f"Network posture captured at {document.enriched_at}."
        reprobed = [
            f"{section} at {when}"
            for section, when in sorted(
                getattr(document, "section_timestamps", {}).items()
            )
            if when != document.enriched_at
        ]
        if reprobed:
            line += " Re-probed since: " + "; ".join(reprobed) + "."
        return line
    return (
        "Network posture not captured — this bundle predates the "
        "enrichment phase. Run `leak-inspector enrich <bundle.zip>` to "
        "add DNS/transport posture (enables the security score)."
    )


def _write_enrichment_status(out: StringIO, document, p: _Palette) -> None:
    """One dim provenance line under the verdict."""
    line = _enrichment_status_line(document)
    if line:
        out.write(p.dim(line) + "\n\n")


def _security_txt_line(probe) -> str | None:
    """One-line RFC 9116 ``security.txt`` status. Single wording source
    for every renderer; ``None`` (silence) when the probe never ran."""
    if probe is None:
        return None
    if probe.found:
        return "security.txt: published (RFC 9116 security contact)"
    return (
        "security.txt: not found — no machine-readable way for security "
        "researchers to reach the operator (RFC 9116)"
    )


def _write_transport_posture(
    out: StringIO, posture, p: _Palette, security_txt=None, tls=None,
) -> None:
    """Render the HTTP/HTTPS posture as a plain-text section."""
    if posture is None:
        return
    out.write(p.section("Transport posture") + "\n")
    out.write("─" * 78 + "\n")
    hosts = [posture.primary]
    if posture.alternate is not None:
        hosts.append(posture.alternate)
    for hp in hosts:
        http = f"{hp.http_status}" if hp.http_responded else "✗"
        https = f"{hp.https_status}" if hp.https_responded else "✗"
        if hp.http_redirects_to_https:
            upgrade = "redirect→HTTPS"
        elif hp.http_responded:
            upgrade = "no upgrade"
        else:
            upgrade = "n/a"
        out.write(
            f"  {hp.host:<40s}  HTTP: {http:<5s}  HTTPS: {https:<5s}  "
            f"{upgrade}\n"
        )
    for line in _tls_lines(tls) or []:
        out.write(f"  {line}\n")
    sec_txt = _security_txt_line(security_txt)
    if sec_txt:
        out.write(f"  {sec_txt}\n")
    out.write("\n")


def _tls_lines(tls) -> list[str] | None:
    """Single wording source for the TLS-quality lines (reused by all
    renderers). ``None`` when the host was not TLS-probed.

    Reports certificate validity/expiry, the negotiated protocol, and
    whether deprecated TLS 1.0/1.1 are accepted (the three-state verdict
    is honoured: only a confirmed acceptance is flagged; an untestable
    result says so rather than implying a clean posture).
    """
    if tls is None:
        return None
    if not tls.connected:
        return ["TLS: no TLS handshake completed on the landing host"]
    if tls.verify_error:
        cert = f"TLS: certificate INVALID — {tls.verify_error}"
    else:
        cert = "TLS: valid certificate"
        if tls.issuer:
            cert += f" (issuer {tls.issuer})"
        if tls.cert_not_after:
            cert += f", expires {tls.cert_not_after[:10]}"
            if tls.days_until_expiry is not None:
                cert += f" ({tls.days_until_expiry} days)"
    proto = tls.protocol or "unknown protocol"
    return [cert, f"     negotiated {proto}; {_tls_legacy_note(tls)}"]


def _tls_legacy_note(tls) -> str:
    """Phrase the deprecated-TLS verdict for the report line."""
    accepted = [
        version for version, state in (
            ("1.0", tls.legacy_tls10), ("1.1", tls.legacy_tls11),
        ) if state == "accepted"
    ]
    if accepted:
        return "deprecated TLS " + "/".join(accepted) + " ACCEPTED"
    if "rejected" in (tls.legacy_tls10, tls.legacy_tls11):
        return "TLS 1.0/1.1 not accepted"
    return "TLS 1.0/1.1 acceptance untestable"


def _write_security_headers(out: StringIO, checks, p: _Palette) -> None:
    """Render the main document's security-response-header posture.

    ``checks`` is the evaluated list (or ``None`` when no document
    response was observed, in which case nothing is written)."""
    if not checks:
        return
    out.write(p.section("Security headers") + "\n")
    out.write("─" * 78 + "\n")
    for c in checks:
        mark = "✓" if c.ok else "✗"
        detail = f"  {c.value}" if (c.ok and c.value) else ""
        line = f"  {mark} {c.label}{detail}"
        out.write((line if c.ok else p.impact("medium", line)) + "\n")
    out.write("\n")


#: Per-status glyph + whether to dim/flag the line in the baseline view.
_CF_MARK = {
    "ok": ("✓", None),
    "fail": ("✗", "medium"),
    "not_deployed": ("○", "dim"),
    "not_assessed": ("–", "dim"),
}
_CF_TRAILER = {"not_deployed": "not deployed", "not_assessed": "not assessed"}


def _write_cyberfundamentals(out: StringIO, view, p: _Palette) -> None:
    """Render the NIS2 / CyberFundamentals baseline.

    Renders nothing when ``view`` is ``None`` (un-enriched bundle). It is
    an indicator over the observable technical controls, not a conformity
    assessment — the header says so explicitly."""
    if view is None:
        return
    out.write(p.section("NIS2 / CyberFundamentals baseline") + "\n")
    out.write("─" * 78 + "\n")
    out.write(p.dim(
        "Observable technical controls only — an indicator, not a "
        "conformity assessment.") + "\n")
    out.write(p.dim(
        f"Assessed: {view.passed}/{view.assessed} controls passed.") + "\n\n")
    for area in view.areas:
        out.write(f"  {area.name}  [{area.nis2}]\n")
        for c in area.checks:
            glyph, style = _CF_MARK.get(c.status, ("?", None))
            trailer = _CF_TRAILER.get(c.status, "")
            line = f"    {glyph} {c.label}"
            if trailer:
                line += f"  ({trailer})"
            if style == "dim":
                out.write(p.dim(line) + "\n")
            elif style == "medium":
                out.write(p.impact("medium", line) + "\n")
            else:
                out.write(line + "\n")
        out.write("\n")


def _write_score(out: StringIO, score, p: _Palette) -> None:
    """Render the composite resilience / security / privacy scorecard.

    Renders nothing when ``score`` is ``None`` (hermetic analysis).
    Headline leads with the total (the number readers actually care
    about) and lists the three dimensions as accompanying detail. The
    earlier ``×`` form misled because the total is the geometric mean,
    not the product.
    """
    if score is None:
        return
    headline = (
        f"Total: {score.total} / {score.max_total}  ·  "
        f"🛡️ {format_stars(score.resilience.stars)}  "
        f"🔐 {format_stars(score.security.stars)}  "
        f"🕶️ {format_stars(score.privacy.stars)}"
    )
    out.write(p.header(headline) + "\n")
    out.write(
        p.dim(
            f"resilience · security · privacy — "
            f"🛡️ {score.resilience.rationale}; "
            f"🔐 {score.security.rationale}; "
            f"🕶️ {score.privacy.rationale}"
        )
        + "\n"
    )
    if score.top_action:
        out.write(f"Biggest win: {score.top_action}\n")
    _write_score_breakdown(out, score, p)
    out.write("\n")


def _write_score_breakdown(out: StringIO, score, p: _Palette) -> None:
    """List what cost each dimension points — every contributor with its
    impact on the line below it (not a running ``−`` column: the impacts
    do not subtract one-for-one; the curve maps their sum, see the
    "How the score is calculated" section)."""
    dims = (
        ("🛡️", "resilience", score.resilience),
        ("🔐", "security", score.security),
        ("🕶️", "privacy", score.privacy),
    )
    if not any(d.deductions for _, _, d in dims):
        return
    out.write(p.dim("  What lowered each dimension:") + "\n")
    for emoji, label, dim in dims:
        if not dim.deductions:
            continue
        out.write(p.dim(
            f"    {emoji} {label} ({format_stars(dim.stars)}/{dim.max_stars})"
        ) + "\n")
        for line in dim.deductions:
            out.write(p.dim(f"        {line.label}") + "\n")
            out.write(p.dim(f"            impact {line.amount:g}") + "\n")
            if line.explainer and line.amount > EXPLAINER_THRESHOLD:
                out.write(p.dim(
                    f"            {_wrap_prose(line.explainer, 60)}"
                    .replace("\n", "\n            ")
                ) + "\n")


def _consent_line(consent) -> str | None:
    """One-line cookie-consent status for the report header.

    Every state gets a line — including ``unknown``, which is split by
    whether a known CMP banner was detected: "banner present but its
    stored decision can't be read" is a different story from "no known
    consent banner at all". ``None`` only when the consent pass never
    ran (pre-feature documents).
    """
    if consent is None:
        return None
    if consent.state == "accepted":
        line = "Consent: visitor accepted"
        if consent.granted:
            line += f" ({', '.join(consent.granted)})"
        return line
    if consent.state == "rejected":
        return "Consent: visitor rejected (or accepted essential only)"
    if consent.state == "none":
        if consent.cmp_names:
            return (
                f"Consent: banner shown ({', '.join(consent.cmp_names)}), "
                "no choice made"
            )
        return "Consent: banner shown, no choice made"
    if consent.cmp_names:
        return (
            f"Consent: banner detected ({', '.join(consent.cmp_names)}) "
            "but its stored decision is not machine-readable — status unknown"
        )
    return "Consent: no known consent banner detected"


def _write_consent(out: StringIO, consent, p: _Palette) -> None:
    """Render the one-line consent-state summary under the scorecard."""
    line = _consent_line(consent)
    if line is None:
        return
    out.write(p.dim(line) + "\n\n")


def _write_verdict(out: StringIO, verdict, p: _Palette) -> None:
    """Render the verdict as a short labelled paragraph above the exec summary."""
    if verdict is None or not verdict.top_sentences:
        return
    out.write(p.header("VERDICT") + "\n")
    paragraph = " ".join(verdict.top_sentences)
    out.write(f"  {paragraph}\n\n")


def _write_cms(out: StringIO, fp, p: _Palette) -> None:
    """Render the detected web platform + version + EOL status."""
    if fp is None:
        return
    label = "Platform end-of-life" if fp.is_eol else "Web platform"
    out.write(p.section(label) + "\n")
    out.write("─" * 78 + "\n")
    version = f" {fp.version}" if fp.version else " (version unknown)"
    eol_tag = "  END-OF-LIFE" if fp.is_eol else ""
    out.write(f"  {fp.name}{version}{eol_tag}\n")
    if fp.is_eol and fp.eol_note:
        out.write(f"  {fp.eol_note}\n")
    if fp.evidence:
        out.write(p.dim(f"  Detected via: {fp.evidence}") + "\n")
    out.write("\n")


def _write_storage(out: StringIO, storage: list, p: _Palette) -> None:
    """Render the browser-storage overview as a plain-text section."""
    if not storage:
        return
    out.write(p.section(
        f"Browser storage during this capture ({len(storage)})"
    ) + "\n")
    out.write("─" * 78 + "\n")
    out.write(p.dim(
        "  Keys observed in localStorage / sessionStorage at session end. "
        "Values are redacted; only the byte size is surfaced."
    ) + "\n\n")
    for e in storage:
        out.write(
            f"  [{e.kind}] {e.key}\n"
            f"      origin: {e.origin}\n"
            f"      size:   {e.value_bytes} B\n"
        )
    out.write("\n")


def _write_unknown_hosts(
    out: StringIO, unclassified: list[UnclassifiedHost], p: _Palette
) -> None:
    if not unclassified:
        return
    out.write(p.section(f"Unclassified third-party hosts ({len(unclassified)})") + "\n")
    out.write("─" * 78 + "\n")
    out.write(
        p.dim(
            "  Third-party domains contacted that no registered module "
            "recognized. May include untracked trackers, asset CDNs, vendor "
            "infrastructure, or partner content. Use --debug for sample URLs "
            "+ param keys."
        )
        + "\n\n"
    )
    shown_limit = 20
    for host in unclassified[:shown_limit]:
        methods = ", ".join(f"{m}×{n}" for m, n in host.methods.items())
        if host.cdn_provider is not None:
            via = f"  via {host.cdn_provider.name} ({host.cdn_provider.jurisdiction})"
        else:
            via = ""
        out.write(
            f"  {host.count:>4}  {host.host:<42s}  {methods}{p.dim(via)}\n"
        )
    if len(unclassified) > shown_limit:
        out.write(
            p.dim(
                f"  ... + {len(unclassified) - shown_limit} more "
                "(use --debug for full list)\n"
            )
        )
    out.write("\n")


def _write_module_section(
    out: StringIO, index: int, section: ModuleSection, p: _Palette, verbose: bool
) -> None:
    out.write(p.section(f"[{index}] {section.module_name} ({section.module_id})") + "\n")

    meta = section.vendor_meta
    if meta.vendor or meta.legal_jurisdiction:
        vendor = meta.vendor or "?"
        jurisdiction = meta.legal_jurisdiction or "?"
        line = f"  Vendor: {vendor} ({jurisdiction})"
        if meta.data_residency:
            line += f" — {meta.data_residency}"
        out.write(line + "\n")
        if meta.sovereignty_notes:
            out.write(f"  {p.dim('Note: ' + meta.sovereignty_notes)}\n")

    out.write(
        f"  Total hits: {section.total_hits}   "
        f"Representatives: {section.representative_count}   "
        f"Unique param keys: {section.unique_param_keys}\n"
    )
    out.write(f"  Categories: {_format_categories(section.category_counts)}\n\n")

    for rep in section.representative_hits:
        _write_representative(out, rep, p, verbose)


def _write_representative(
    out: StringIO, rep: RepresentativeHit, p: _Palette, verbose: bool
) -> None:
    status = "—" if rep.response_status is None else str(rep.response_status)
    out.write(
        f"  → {rep.method} {rep.url}\n"
        f"    {p.dim(f'(HTTP {status})  collapsed events: {rep.collapsed_event_count}')}\n"
    )

    if rep.request_body:
        snippet = _truncate(rep.request_body, limit=400)
        out.write(f"    {p.dim('request body  :')} {snippet}\n")
    show_response_body = rep.response_body and not rep.params and not rep.request_body
    if show_response_body:
        snippet = _truncate(rep.response_body, limit=400)
        out.write(f"    {p.dim('response body :')} {snippet}\n")

    if not rep.params:
        if not rep.request_body and not show_response_body:
            out.write(p.dim("    (no parameters)") + "\n")
        out.write("\n")
        return

    impact_order = {IMPACT_HIGH: 0, IMPACT_MEDIUM: 1, IMPACT_LOW: 2}
    category_order = {cat: i for i, cat in enumerate(CATEGORIES)}
    sorted_params = sorted(
        rep.params,
        key=lambda x: (
            impact_order.get(x.privacy_impact, 99),
            category_order.get(x.category, 99),
            x.key,
        ),
    )
    for param in sorted_params:
        impact_tag = p.impact(
            param.privacy_impact, param.privacy_impact.upper().ljust(6)
        )
        out.write(
            f"      {param.key.ljust(18)}"
            f"{param.category.ljust(11)} {impact_tag} "
            f"= {_truncate(param.value)}\n"
        )
        if param.meaning:
            out.write(f"        {p.dim(param.meaning)}\n")

    if verbose:
        out.write(p.dim(f"    source event_ids: {rep.event_ids}") + "\n")
    out.write("\n")


# --- entry points ----------------------------------------------------------


def write_text_report(
    analysis: Analysis,
    *,
    color: bool = True,
    verbose: bool = False,
) -> str:
    """Render ``analysis`` as a human-readable text report.

    Builds the canonical :class:`ReportDocument` and walks it.
    """
    return render_text_document(
        build_report_document(analysis), color=color, verbose=verbose
    )


def render_text_document(
    document: ReportDocument, *, color: bool = True, verbose: bool = False
) -> str:
    """Render an already-built :class:`ReportDocument` as text."""
    p = _Palette(color)
    out = StringIO()
    _write_header(out, document.manifest, p)
    _write_score(out, document.score, p)
    _write_consent(out, document.consent, p)
    _write_intro(out, p)
    _write_capture_status_banner(out, document.capture_status, p)

    if (
        not document.trackers
        and not document.executive_summary.findings
        and not document.cookies
        and not document.storage
        and document.cms_fingerprint is None
        and document.transport_posture is None
    ):
        out.write(p.dim("No tracker hits found in this capture.") + "\n")
        return out.getvalue()

    _write_verdict(out, document.verdict, p)
    _write_enrichment_status(out, document, p)
    _write_executive_summary(out, document.executive_summary, p)
    _write_cms(out, document.cms_fingerprint, p)
    _write_transport_posture(
        out, document.transport_posture, p, document.security_txt,
        document.tls_posture,
    )
    _write_security_headers(out, document.security_headers, p)
    _write_dns_posture(out, document.dns_posture, p)
    _write_cyberfundamentals(out, document.cyberfundamentals, p)
    _write_cookies(out, document.cookies, p, document.forwarded_cookie_keys)
    _write_storage(out, document.storage, p)
    _write_unknown_hosts(out, document.unclassified_hosts, p)
    for index, section in enumerate(document.trackers, start=1):
        _write_module_section(out, index, section, p, verbose)

    _write_score_calculation(out, document.score, p)

    return out.getvalue()


def _write_score_calculation(out: StringIO, score, p: _Palette) -> None:
    """Write out the arithmetic behind the score, step by step.

    Makes the non-linearity explicit: impacts are *summed* per
    dimension, then a logistic curve maps the sum to a 0–100 score
    (it is not ``100 − penalty``); the total is the cube root of the
    three. Shows the exact raw values and their ceil-rounded display so
    a reader can verify every number."""
    if score is None:
        return
    dims = (
        ("🛡️", "resilience", score.resilience),
        ("🔐", "security", score.security),
        ("🕶️", "privacy", score.privacy),
    )
    out.write(p.section("How the score is calculated") + "\n")
    out.write("─" * 78 + "\n")
    out.write(_wrap_prose(
        "Each tracker and posture signal adds an impact penalty (0–5) per "
        "dimension. The penalties are summed (P), then mapped through a "
        "logistic curve — steep in the middle, flattening toward 0 and 100 — "
        "so they do NOT subtract one-for-one. The same curve scores all "
        "three dimensions:"
    ) + "\n\n")
    out.write(
        f"      score(P) = 100 / (1 + e^((P − {DEFAULT_P50:g}) / {DEFAULT_S:g}))"
        + "\n\n"
    )
    out.write(_wrap_prose(
        "The total is the cube root (geometric mean) of the three dimension "
        "scores. Scores are shown ceil-rounded, so the reachable printed "
        "range is 1–99."
    ) + "\n\n")
    raw_product = 1.0
    for emoji, label, dim in dims:
        amounts = [f"{line.amount:g}" for line in dim.deductions]
        sum_expr = " + ".join(amounts) if amounts else "0"
        out.write(
            f"  {emoji} {label}: penalties {sum_expr} = {dim.penalty:g}\n"
        )
        out.write(p.dim(
            f"        curve({dim.penalty:g}) = {dim.raw_score:.1f}"
            f"  →  shown as {format_stars(dim.stars)}/100"
        ) + "\n")
        raw_product *= dim.raw_score
    raw_total = raw_product ** (1 / 3) if raw_product > 0 else 0.0
    r, s, pv = (score.resilience, score.security, score.privacy)
    out.write(
        f"\n  Total = ³√({r.raw_score:.1f} × {s.raw_score:.1f} × "
        f"{pv.raw_score:.1f}) = {raw_total:.1f}"
        f"  →  shown as {score.total}/100\n\n"
    )


__all__ = ["render_text_document", "write_text_report"]
