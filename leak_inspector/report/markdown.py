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

"""Markdown reporter — two flavors.

Both walk a :class:`~.document.ReportDocument` and emit GitHub-
flavored markdown. The difference is whether per-hit detail tables
are inlined:

* :func:`write_markdown_summary` stops at each tracker's stat row +
  harvested-fields list. Equivalent to the HTML report with every
  ``<details>`` block collapsed.
* :func:`write_markdown_detailed` additionally renders every
  representative hit and its full classified-parameter table.
  Equivalent to the HTML report with every ``<details>`` block opened.

Output renders cleanly in any markdown viewer (GitHub, GitLab,
VS Code preview, Obsidian, …).
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
    ManifestView,
    ModuleSection,
    ParamRow,
    RepresentativeHit,
    ReportDocument,
    UnclassifiedHost,
)


_VALUE_MAX = 100
_BODY_MAX = 1500


# --- entry points ----------------------------------------------------------


def write_markdown_summary(
    analysis: Analysis,
    *,
    screenshot_filename: str | None = None,
    extra_screenshot_filenames: list[str] | None = None,
    extra_screenshot_captions: list[str] | None = None,
) -> str:
    """Markdown report with per-hit detail tables omitted."""
    return render_markdown_document(
        build_report_document(analysis),
        detailed=False,
        screenshot_filename=screenshot_filename,
        extra_screenshot_filenames=extra_screenshot_filenames,
        extra_screenshot_captions=extra_screenshot_captions,
    )


def write_markdown_detailed(
    analysis: Analysis,
    *,
    screenshot_filename: str | None = None,
    extra_screenshot_filenames: list[str] | None = None,
    extra_screenshot_captions: list[str] | None = None,
    display_name: str | None = None,
) -> str:
    """Markdown report with every representative hit + param table rendered inline.

    ``display_name`` (optional) overrides the report's title label
    (the host is used when None).
    """
    return render_markdown_document(
        build_report_document(analysis, display_name=display_name),
        detailed=True,
        screenshot_filename=screenshot_filename,
        extra_screenshot_filenames=extra_screenshot_filenames,
        extra_screenshot_captions=extra_screenshot_captions,
    )


def render_markdown_document(
    document: ReportDocument,
    *,
    detailed: bool,
    screenshot_filename: str | None = None,
    extra_screenshot_filenames: list[str] | None = None,
    extra_screenshot_captions: list[str] | None = None,
) -> str:
    """Render an already-built :class:`ReportDocument` as markdown.

    When ``screenshot_filename`` is provided, the report embeds an
    ``![](...)`` reference near the top using that exact relative
    filename. ``extra_screenshot_filenames`` (optional) appends one
    additional reference per operator-triggered screenshot.
    ``extra_screenshot_captions`` (optional, parallel list) supplies
    explicit captions; an empty entry (or omitting the list) falls
    back to deriving the caption from the filename.
    """
    out = StringIO()
    _render_header(out, document.manifest)
    _render_score(out, document.score)
    _render_consent(out, document.consent)
    _render_intro(out)
    _render_capture_status_banner(out, document.capture_status)
    if screenshot_filename:
        out.write(
            f"\n![Captured page (post-load)]({screenshot_filename})\n\n"
        )
    _render_verdict(out, document.verdict)
    _render_executive_summary(out, document.executive_summary)
    _render_dns_posture(out, document.dns_posture)
    _render_cms(out, document.cms_fingerprint)
    _render_transport_posture(
        out, document.transport_posture, document.security_txt,
        document.tls_posture,
    )
    _render_security_headers(out, document.security_headers)
    _render_cyberfundamentals(out, document.cyberfundamentals)
    _render_cookies(out, document.cookies, document.forwarded_cookie_keys)
    _render_storage(out, document.storage)
    _render_unknown_hosts(out, document.unclassified_hosts)
    _render_trackers(out, document.trackers, detailed=detailed)
    if extra_screenshot_filenames:
        out.write("\n## Operator-triggered screenshots\n\n")
        captions = extra_screenshot_captions or []
        for idx, name in enumerate(extra_screenshot_filenames):
            explicit = captions[idx] if idx < len(captions) else ""
            caption = explicit or _caption_from_extra_screenshot(name)
            out.write(f"![{caption}]({name})\n\n")
    _render_score_calculation(out, document.score)
    return out.getvalue()


def _render_score(out: StringIO, score) -> None:
    """Render the composite scorecard. Silent when score is None.

    Leads with the total, lists the three dimensions as accompanying
    detail. Avoids the ``×`` form because the total is the geometric
    mean of the dimensions, not their product — readers parsing
    ``10 × 4 × 6 = 62`` would (correctly) see arithmetic that doesn't
    add up.
    """
    if score is None:
        return
    out.write(
        f"\n## Score: {score.total} / {score.max_total}\n\n"
        f"**🛡️ {format_stars(score.resilience.stars)}  "
        f"🔐 {format_stars(score.security.stars)}  "
        f"🕶️ {format_stars(score.privacy.stars)}**  "
        f"(resilience · security · privacy)\n\n"
        f"- 🛡️ **resilience** ({format_stars(score.resilience.stars)}/"
        f"{score.resilience.max_stars}): {score.resilience.rationale}\n"
        f"- 🔐 **security** ({format_stars(score.security.stars)}/"
        f"{score.security.max_stars}): {score.security.rationale}\n"
        f"- 🕶️ **privacy** ({format_stars(score.privacy.stars)}/"
        f"{score.privacy.max_stars}): {score.privacy.rationale}\n\n"
    )
    _render_score_breakdown(out, score)


def _render_score_breakdown(out: StringIO, score) -> None:
    """List what cost each dimension points — each contributor with its
    impact nested beneath it (not a running ``−`` column; the impacts do
    not subtract one-for-one — see "How the score is calculated")."""
    dims = (
        ("🛡️", "resilience", score.resilience),
        ("🔐", "security", score.security),
        ("🕶️", "privacy", score.privacy),
    )
    if not any(d.deductions for _, _, d in dims):
        return
    out.write("**What lowered each dimension:**\n\n")
    for emoji, label, dim in dims:
        if not dim.deductions:
            continue
        out.write(f"- {emoji} **{label}** "
                  f"({format_stars(dim.stars)}/{dim.max_stars})\n")
        for line in dim.deductions:
            out.write(f"    - {line.label}\n")
            out.write(f"        - impact {line.amount:g}\n")
            if line.explainer and line.amount > EXPLAINER_THRESHOLD:
                out.write(f"        - {line.explainer}\n")
    out.write("\n")


def _render_score_calculation(out: StringIO, score) -> None:
    """Write out the arithmetic behind the score, step by step (impacts
    summed per dimension → logistic curve → cube-root total)."""
    if score is None:
        return
    dims = (
        ("🛡️", "resilience", score.resilience),
        ("🔐", "security", score.security),
        ("🕶️", "privacy", score.privacy),
    )
    out.write("## How the score is calculated\n\n")
    out.write(
        "Each tracker and posture signal adds an impact penalty (0–5) per "
        "dimension. The penalties are summed (P), then mapped through a "
        "logistic curve — steep in the middle, flattening toward 0 and 100 — "
        "so they do **not** subtract one-for-one. The same curve scores all "
        "three dimensions:\n\n")
    out.write(
        f"> score(P) = 100 / (1 + e^((P − {DEFAULT_P50:g}) / {DEFAULT_S:g}))\n\n")
    out.write(
        "The total is the cube root (geometric mean) of the three dimension "
        "scores; scores are shown ceil-rounded (printed range 1–99).\n\n")
    for emoji, label, dim in dims:
        amounts = [f"{line.amount:g}" for line in dim.deductions]
        sum_expr = " + ".join(amounts) if amounts else "0"
        out.write(
            f"- {emoji} **{label}**: penalties {sum_expr} = {dim.penalty:g} → "
            f"curve = {dim.raw_score:.1f} → shown as "
            f"{format_stars(dim.stars)}/100\n"
        )
    r, s, pv = score.resilience, score.security, score.privacy
    out.write(
        f"\n**Total** = ³√({r.raw_score:.1f} × {s.raw_score:.1f} × "
        f"{pv.raw_score:.1f}) → {score.total}/100\n\n"
    )


def _render_consent(out: StringIO, consent) -> None:
    """Render the one-line consent-state summary (all states, including
    ``unknown``). Single wording source: :func:`.text._consent_line`."""
    from .text import _consent_line

    line = _consent_line(consent)
    if line is None:
        return
    out.write(f"**{line}**\n\n")


def _caption_from_extra_screenshot(filename: str) -> str:
    """Derive a markdown alt-text caption from an extra-screenshot filename."""
    stem = filename.rsplit("/", 1)[-1]
    if stem.endswith(".png"):
        stem = stem[: -len(".png")]
    parts = stem.split("_")
    if len(parts) >= 3 and parts[-1].isdigit() and len(parts[-1]) == 6:
        host = parts[-2]
        hhmmss = parts[-1]
        return f"{host} @ {hhmmss[:2]}:{hhmmss[2:4]}:{hhmmss[4:6]}"
    return stem


# --- helpers ---------------------------------------------------------------


def _truncate(text: str | None, limit: int = _VALUE_MAX) -> str:
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"


def _md_escape(text: str) -> str:
    """Escape characters that would break markdown table cells."""
    if text is None:
        return ""
    return (
        str(text)
        .replace("\\", "\\\\")
        .replace("|", "\\|")
        .replace("\n", " ")
        .replace("\r", "")
    )


def _fence_safe(body: str | None) -> str:
    """Truncate a body and avoid breaking a triple-backtick fence."""
    truncated = _truncate(body, _BODY_MAX)
    # Replace ``` with a visually identical look-alike to keep the fence intact.
    return truncated.replace("```", "`​``")


# --- sections --------------------------------------------------------------


def _render_header(out: StringIO, m: ManifestView) -> None:
    from .html import _BRANDING_TITLE_PREFIX, _title_host_label
    out.write(f"# {_BRANDING_TITLE_PREFIX} : {_title_host_label(m)}\n\n")
    out.write(f"- **session**: `{m.session_id}`\n")
    out.write(f"- **captured**: {m.started_at} → {m.ended_at}\n")
    out.write(f"- **profile**: {m.profile}\n")
    out.write(f"- **target**: <{m.target_url}>\n")
    if m.landing_url and m.landing_url != m.target_url:
        out.write(f"- **landed at**: `{m.landing_url}`\n")
    out.write("\n")


def _render_capture_status_banner(out: StringIO, status) -> None:
    """Surface a capture failure as a markdown callout block."""
    if status is None or not status.is_failure:
        return
    if status.http_status is not None:
        label = f"HTTP {status.http_status} — {status.reason}"
    else:
        label = status.reason or "Unreachable"
    out.write(
        f"> **⚠ Capture failed.** The landing page returned `{label}`. "
        "Findings below reflect what loaded before the failure — usually "
        "very little. Verify the URL, the site's availability, and any "
        "regional-blocking before drawing conclusions.\n\n"
    )


def _render_intro(out: StringIO) -> None:
    """Plain-prose intro driven by the shared template in :mod:`._branding`."""
    from ._branding import (
        BELIBRE_HOMEPAGE,
        INTRO_DISCLAIMER_TEXT,
        INTRO_PARAGRAPHS,
        INTRO_TITLE,
    )
    belibre_link = f"[BeLibre]({BELIBRE_HOMEPAGE})"
    belibre_url = f"<{BELIBRE_HOMEPAGE}>"
    disclaimer_bold = f"**{INTRO_DISCLAIMER_TEXT}**"

    out.write(f"## {INTRO_TITLE}\n\n")
    for paragraph in INTRO_PARAGRAPHS:
        rendered = paragraph.format(
            belibre_link=belibre_link,
            disclaimer_bold=disclaimer_bold,
            belibre_url=belibre_url,
        )
        out.write(f"{rendered}\n\n")


def _render_verdict(out: StringIO, verdict) -> None:
    """Render the verdict as a short labelled paragraph."""
    if verdict is None or not verdict.top_sentences:
        return
    out.write("## Verdict\n\n")
    out.write(" ".join(verdict.top_sentences) + "\n\n")


def _render_executive_summary(out: StringIO, summary: ExecutiveSummary) -> None:
    out.write("## Executive summary\n\n")

    # Key findings — headline + detail joined into one bullet.
    if summary.findings:
        from .verdict_action_metadata import metadata_for

        def _write_findings(label: str, items: list) -> None:
            if not items:
                return
            out.write(f"### {label}\n\n")
            for finding in items:
                line = f"- {finding.badge} **{finding.headline}**"
                if finding.detail:
                    line += f". {finding.detail}"
                meta = metadata_for(finding.kind)
                if meta is not None:
                    line += f" *(owner: {meta.owner} · effort: {meta.effort})*"
                out.write(line + "\n")
            out.write("\n")

        capture_findings = [f for f in summary.findings if f.source != "dns"]
        dns_findings = [f for f in summary.findings if f.source == "dns"]
        if dns_findings:
            _write_findings("Key findings — Website", capture_findings)
            _write_findings("Key findings — Back-office", dns_findings)
        else:
            _write_findings("Key findings", capture_findings)

    # Recommended actions
    if summary.actions:
        out.write("### Recommended actions\n\n")
        for idx, action in enumerate(summary.actions, start=1):
            out.write(f"{idx}. {action}\n")
        out.write("\n")

    # Detailed findings
    out.write("### Detailed findings\n\n")

    # CNAME-cloaks
    if summary.cname_cloaks:
        cloaks = summary.cname_cloaks
        out.write(
            f"- ⚠️ **CNAME-cloaked trackers** "
            f"({len(cloaks)} alias{'es' if len(cloaks) != 1 else ''} "
            "resolve to known vendors)\n"
        )
        for cloak in cloaks[:6]:
            out.write(
                f"  - `{cloak.alias}` → `{cloak.canonical}` "
                f"[{cloak.vendor_module_name}]\n"
            )
        if len(cloaks) > 6:
            out.write(f"  - + {len(cloaks) - 6} more (see per-tracker sections)\n")

    # HIGH-impact tracking by vendor
    if summary.high_impact_by_vendor:
        out.write("- **HIGH-impact tracking by vendor**\n")
        for rollup in summary.high_impact_by_vendor[:6]:
            mod_list = ", ".join(m.name for m in rollup.modules[:3])
            if len(rollup.modules) > 3:
                mod_list += f" +{len(rollup.modules) - 3}"
            out.write(f"  - **{rollup.vendor_label}** [{mod_list}]\n")
            for cat in rollup.categories:
                keys = [f.key for f in cat.fields]
                shown = ", ".join(f"`{k}`" for k in keys[:5])
                if len(keys) > 5:
                    shown += f", +{len(keys) - 5} more"
                out.write(f"    - _{cat.category}_: {shown}\n")
        if len(summary.high_impact_by_vendor) > 6:
            out.write(
                f"  - + {len(summary.high_impact_by_vendor) - 6} "
                "more vendor(s) with HIGH-impact fields\n"
            )

    # Jurisdictions tally
    if summary.jurisdictions:
        parts = []
        for j in summary.jurisdictions:
            sample = ", ".join(j.vendors[:2])
            if len(j.vendors) > 2:
                sample += f", +{len(j.vendors) - 2} more"
            flag_prefix = f"{j.flag} " if j.flag else ""
            parts.append(f"{j.module_count}× **{flag_prefix}{j.code}** ({sample})")
        out.write(f"- **Vendor jurisdictions**: {' · '.join(parts)}\n")

    # Volume stats
    stats = summary.stats
    if stats is not None:
        out.write(
            f"- **Trackers fired**: {stats.trackers_fired} modules · "
            f"{stats.total_requests} requests "
            f"({stats.unique_requests} unique after dedup)\n"
        )
        out.write(
            f"- **Third-party hosts**: {stats.third_party_hosts_touched} touched · "
            f"{stats.third_party_hosts_claimed} claimed, "
            f"{stats.third_party_hosts_unclassified} unclassified\n"
        )
        if stats.top_by_impact:
            top_parts = [
                f"{e.module_name} ({e.high_impact_field_count}H/{e.medium_impact_field_count}M/{e.hit_count}×)"
                for e in stats.top_by_impact
            ]
            out.write(f"- **Top by impact**: {', '.join(top_parts)}\n")

    out.write("\n")


def _render_dns_posture(out: StringIO, posture: DNSPosture | None) -> None:
    if posture is None:
        return
    out.write(f"## DNS posture — `{_md_escape(posture.domain)}`\n\n")

    # Hosting + AAAA
    ips = posture.a_records + posture.aaaa_records
    if ips:
        out.write("**Hosting**\n\n")
        out.write("| Address | AS | Org | Country |\n|---|---|---|---|\n")
        for ip in ips:
            asn = f"AS{ip.asn}" if ip.asn is not None else "—"
            out.write(
                f"| `{_md_escape(ip.address)}` | {asn} | "
                f"{_md_escape(ip.as_org) or '—'} | "
                f"{_md_escape(ip.country_code) or '—'} |\n"
            )
        out.write("\n")

    if posture.nameservers:
        out.write("**Authoritative DNS**\n\n")
        for ns in posture.nameservers:
            provider = f" — {_md_escape(ns.provider)}" if ns.provider else ""
            jurisdictions = sorted({ip.country_code for ip in ns.ips if ip.country_code})
            jur = f" _( {', '.join(jurisdictions)} )_" if jurisdictions else ""
            out.write(f"- `{_md_escape(ns.name)}`{provider}{jur}\n")
        out.write("\n")

    if posture.mx:
        out.write("**Mail (MX)**\n\n")
        out.write("| Pref | Host | AS / org | Country |\n|---:|---|---|---|\n")
        for mx in posture.mx:
            jurisdictions = sorted({ip.country_code for ip in mx.ips if ip.country_code})
            orgs = sorted({ip.as_org for ip in mx.ips if ip.as_org})
            out.write(
                f"| {mx.priority if mx.priority is not None else ''} | "
                f"`{_md_escape(mx.name)}` | "
                f"{_md_escape(', '.join(orgs)) or '—'} | "
                f"{_md_escape(', '.join(jurisdictions)) or '—'} |\n"
            )
        out.write("\n")

    # Transport + email security signals in a single compact table.
    rows: list[tuple[str, str]] = []
    if posture.dnssec is not None:
        signed = posture.dnssec.parent_has_ds and posture.dnssec.zone_has_dnskey
        rows.append(("DNSSEC", "✅ signed" if signed else "❌ not signed"))
    if posture.caa is not None:
        rows.append((
            "CAA",
            ", ".join(f"`{_md_escape(c)}`" for c in posture.caa.issue_cas) or "(none)",
        ))
    if posture.https is not None:
        parts: list[str] = []
        if posture.https.alpn:
            parts.append("ALPN " + "/".join(posture.https.alpn))
        if posture.https.has_ech:
            parts.append("ECH advertised")
        rows.append(("HTTPS", " · ".join(parts) or "(present)"))
    if posture.spf is not None:
        senders = ", ".join(posture.spf.sender_vendors[:5]) or "(no known SaaS senders)"
        rows.append(("SPF", f"`{posture.spf.final_qualifier or '?'}` · {senders}"))
    else:
        rows.append(("SPF", "❌ not published"))
    if posture.dmarc is not None:
        bits = [f"p=`{posture.dmarc.policy or 'unset'}`"]
        if posture.dmarc.pct != 100:
            bits.append(f"pct={posture.dmarc.pct}")
        if posture.dmarc.report_processors:
            bits.append("reports → " + ", ".join(posture.dmarc.report_processors))
        rows.append(("DMARC", " · ".join(bits)))
    else:
        rows.append(("DMARC", "❌ not published"))
    if posture.dkim:
        rows.append((
            "DKIM",
            f"{len(posture.dkim)} selector(s): "
            + ", ".join(f"`{_md_escape(d.selector)}`" for d in posture.dkim),
        ))
    if posture.bimi is not None and posture.bimi.present:
        rows.append(("BIMI", "present"))
    if posture.mta_sts is not None and posture.mta_sts.txt_present:
        rows.append(("MTA-STS", f"present (id `{_md_escape(posture.mta_sts.txt_id)}`)"))
    if posture.tls_rpt is not None and posture.tls_rpt.txt_present:
        rows.append(("TLS-RPT", ", ".join(posture.tls_rpt.rua) or "present"))

    if rows:
        out.write("| Signal | Status |\n|---|---|\n")
        for key, value in rows:
            out.write(f"| **{key}** | {value} |\n")
        out.write("\n")

    if posture.txt_verifications:
        out.write("**Self-disclosed SaaS (via TXT verifications)**\n\n")
        out.write("| Vendor | Purpose | Jurisdiction |\n|---|---|---|\n")
        for txt in posture.txt_verifications:
            out.write(
                f"| {_md_escape(txt.vendor)} | {_md_escape(txt.purpose)} | "
                f"{_md_escape(txt.jurisdiction) or '—'} |\n"
            )
        out.write("\n")

    if posture.errors:
        out.write(f"_({len(posture.errors)} lookup error(s) — see JSON output.)_\n\n")


_CF_STATUS_LABEL = {
    "ok": "✅ ok",
    "fail": "❌ fail",
    "not_deployed": "➖ not deployed",
    "not_assessed": "·  not assessed",
}


def _render_cyberfundamentals(out: StringIO, view) -> None:
    """Render the NIS2 / CyberFundamentals baseline as grouped tables.

    Renders nothing when ``view`` is ``None`` (un-enriched bundle)."""
    if view is None:
        return
    out.write("## NIS2 / CyberFundamentals baseline\n\n")
    out.write(
        "_Observable technical controls only — an indicator, not a "
        f"conformity assessment. {view.passed}/{view.assessed} controls "
        "passed._\n\n"
    )
    for area in view.areas:
        out.write(f"### {_md_escape(area.name)} — {area.nis2}\n\n")
        out.write("| Control | Status | Note |\n|---|---|---|\n")
        for c in area.checks:
            status = _CF_STATUS_LABEL.get(c.status, c.status)
            out.write(
                f"| {_md_escape(c.label)} | {status} | "
                f"{_md_escape(c.detail) or '—'} |\n"
            )
        out.write("\n")


def _render_cookies(
    out: StringIO,
    cookies: list,
    forwarded_keys: list[tuple[str, str]] = (),
) -> None:
    """Render the cookie overview as a markdown table.

    No-op when the list is empty so reports stay tight when no
    cookies were observed. ``forwarded_keys`` — ``(name, host)`` of
    first-party cookies whose vendor forwards/cloaks here; those rows
    get a "(via first-party proxy)" note next to the ``1P`` tag.
    """
    if not cookies:
        return
    forwarded = set(forwarded_keys or ())
    out.write(f"## Cookies set during this capture ({len(cookies)})\n\n")
    out.write(
        "Every `Set-Cookie` response header observed. Cookie values are "
        "redacted; only metadata (lifetime + flags + issuing party) is "
        "surfaced.\n\n"
    )
    out.write("| Cookie | Issued by | Party | Lifetime | Flags | Impact |\n")
    out.write("|---|---|---|---|---|---|\n")
    for c in cookies:
        flags = _markdown_cookie_flags(c)
        party = "1P" if c.is_first_party else "3P"
        if (c.name, c.host) in forwarded:
            party += " (via first-party proxy)"
        out.write(
            f"| `{c.name}` | {c.vendor}<br>`{c.host}` | {party} | "
            f"`{c.lifetime_human}` | {flags} | "
            f"{c.privacy_impact} |\n"
        )
    out.write("\n")


def _markdown_cookie_flags(c) -> str:
    flags: list[str] = []
    samesite = c.same_site or "(unset)"
    flags.append(f"SameSite={samesite}")
    if c.secure:
        flags.append("Secure")
    if c.http_only:
        flags.append("HttpOnly")
    if c.partitioned:
        flags.append("Partitioned")
    return ", ".join(flags)


def _render_transport_posture(
    out: StringIO, posture, security_txt=None, tls=None,
) -> None:
    """Render the HTTP/HTTPS transport posture as a markdown table.

    Appends the TLS-quality lines and the RFC 9116 ``security.txt``
    status line (single wording source in :mod:`.text`) when those
    probes ran.
    """
    if posture is None:
        return
    out.write("## Transport posture\n\n")
    out.write("| Host | HTTP | HTTPS | HTTP→HTTPS |\n")
    out.write("|---|---|---|---|\n")
    hosts = [posture.primary]
    if posture.alternate is not None:
        hosts.append(posture.alternate)
    for hp in hosts:
        http_cell = (
            f"✓ `{hp.http_status}`" if hp.http_responded else "✗"
        )
        https_cell = (
            f"✓ `{hp.https_status}`" if hp.https_responded else "✗"
        )
        if hp.http_redirects_to_https:
            upgrade_cell = "✓"
        elif hp.http_responded:
            upgrade_cell = "✗"
        else:
            upgrade_cell = "—"
        out.write(
            f"| `{hp.host}` | {http_cell} | {https_cell} | {upgrade_cell} |\n"
        )
    out.write("\n")
    from .text import _security_txt_line, _tls_lines

    for line in _tls_lines(tls) or []:
        out.write(f"{line.strip()}\n\n")
    line = _security_txt_line(security_txt)
    if line:
        out.write(f"{line}\n\n")


def _render_security_headers(out: StringIO, checks) -> None:
    """Render the main document's security headers as a markdown table.

    ``checks`` is the evaluated list (or ``None`` when no document
    response was observed — nothing is written then)."""
    if not checks:
        return
    out.write("## Security headers\n\n")
    out.write("| Header | Present | Value |\n")
    out.write("|---|---|---|\n")
    for c in checks:
        present = "✓" if c.ok else "✗"
        value = f"`{c.value}`" if (c.ok and c.value) else "—"
        out.write(f"| {c.label} | {present} | {value} |\n")
    out.write("\n")


def _render_cms(out: StringIO, fp) -> None:
    """Render the detected web platform + version + EOL status."""
    if fp is None:
        return
    heading = "Platform end-of-life" if fp.is_eol else "Web platform"
    out.write(f"## {heading}\n\n")
    if fp.version:
        out.write(f"**{fp.name}** `{fp.version}`")
    else:
        out.write(f"**{fp.name}** (version unknown)")
    if fp.is_eol:
        out.write("  —  **END-OF-LIFE**")
    out.write("\n\n")
    if fp.is_eol and fp.eol_note:
        out.write(f"> {fp.eol_note}\n\n")
    if fp.evidence:
        out.write(f"_Detected via: {fp.evidence}_\n\n")


def _render_storage(out: StringIO, storage: list) -> None:
    """Render the browser-storage overview as a markdown table.

    No-op when the list is empty.
    """
    if not storage:
        return
    out.write(f"## Browser storage during this capture ({len(storage)})\n\n")
    out.write(
        "Keys observed in `localStorage` and `sessionStorage` at session "
        "end. Values are redacted; only the byte size is surfaced.\n\n"
    )
    out.write("| Key | Kind | Origin | Size |\n")
    out.write("|---|---|---|---:|\n")
    for e in storage:
        out.write(
            f"| `{e.key}` | {e.kind} | `{e.origin}` | "
            f"{e.value_bytes} B |\n"
        )
    out.write("\n")


def _render_unknown_hosts(
    out: StringIO, unclassified: list[UnclassifiedHost]
) -> None:
    if not unclassified:
        return
    out.write(f"## Unclassified third-party hosts ({len(unclassified)})\n\n")
    out.write(
        "Third-party domains the visited page contacted that no registered "
        "tracker module recognized. May include untracked trackers, asset "
        "CDNs, vendor infrastructure, or partner content.\n\n"
    )
    out.write("| Hits | Host | Via (CDN/edge) | Methods | Sample request |\n")
    out.write("|---:|---|---|---|---|\n")
    for host in unclassified:
        methods = ", ".join(f"{m} × {n}" for m, n in host.methods.items())
        sample = ""
        if host.sample_urls:
            s = host.sample_urls[0]
            sample = f"`{s.method} {_md_escape(_truncate(s.url, 90))}`"
        if host.cdn_provider is not None:
            p = host.cdn_provider
            via = f"{p.name} ({p.jurisdiction})"
        else:
            via = "—"
        out.write(
            f"| {host.count} | `{_md_escape(host.host)}` | {via} | "
            f"{_md_escape(methods)} | {sample} |\n"
        )
    out.write("\n")


def _render_trackers(
    out: StringIO, trackers: list[ModuleSection], *, detailed: bool
) -> None:
    if not trackers:
        out.write("_No tracker hits found in this capture._\n")
        return
    out.write("## Trackers\n\n")
    for idx, section in enumerate(trackers, start=1):
        _render_tracker(out, idx, section, detailed=detailed)


def _render_tracker(
    out: StringIO, idx: int, section: ModuleSection, *, detailed: bool
) -> None:
    meta = section.vendor_meta
    # Heading
    jur_suffix = ""
    if meta.legal_jurisdiction:
        flag_prefix = f"{meta.flag} " if meta.flag else ""
        jur_suffix = f" — **{flag_prefix}{meta.legal_jurisdiction}**"
    out.write(f"### {idx}. {section.module_name} (`{section.module_id}`){jur_suffix}\n\n")

    # Vendor block
    if meta.vendor or meta.data_residency:
        vendor_parts = []
        if meta.vendor:
            vendor_parts.append(f"**Vendor:** {meta.vendor}")
        if meta.data_residency:
            vendor_parts.append(meta.data_residency)
        out.write(" · ".join(vendor_parts) + "\n\n")
    if meta.sovereignty_notes:
        out.write(f"> {meta.sovereignty_notes}\n\n")

    # Stats — pull pii / identifier-high counts out of category_counts
    pii = section.category_counts.get("pii", 0)
    out.write(
        "| Total hits | Representatives | Unique fields | PII fields |\n"
    )
    out.write("|---:|---:|---:|---:|\n")
    out.write(
        f"| {section.total_hits} | {section.representative_count} | "
        f"{section.unique_param_keys} | {pii} |\n\n"
    )

    # Harvested-fields summary
    if section.harvested_fields:
        rendered = [
            f"`{_md_escape(f.key)}`" for f in section.harvested_fields[:15]
        ]
        if len(section.harvested_fields) > 15:
            rendered.append(f"+ {len(section.harvested_fields) - 15} more")
        out.write(f"**Harvested fields:** {', '.join(rendered)}\n\n")

    # Per-hit detail
    reps = section.representative_hits
    if detailed and reps:
        out.write(f"#### Representative hits ({len(reps)})\n\n")
        for rep in reps:
            _render_hit(out, rep)
    elif reps:
        out.write(
            f"_{len(reps)} representative hit(s) omitted — "
            "use `--format markdown_detailed` for per-hit detail._\n\n"
        )


def _render_hit(out: StringIO, rep: RepresentativeHit) -> None:
    status = "—" if rep.response_status is None else str(rep.response_status)
    out.write(f"##### `{_md_escape(rep.method)} {_md_escape(rep.url)}`\n\n")
    out.write(
        f"HTTP {_md_escape(status)} · collapsed events: {rep.collapsed_event_count}\n\n"
    )

    if rep.request_body:
        out.write(
            f"**Request body** ({len(rep.request_body)} chars):\n\n"
            f"```\n{_fence_safe(rep.request_body)}\n```\n\n"
        )
    show_resp = rep.response_body and not rep.params and not rep.request_body
    if show_resp:
        out.write(
            f"**Response body** ({len(rep.response_body)} chars):\n\n"
            f"```\n{_fence_safe(rep.response_body)}\n```\n\n"
        )

    if rep.params:
        _render_params_table(out, rep.params)


def _render_params_table(out: StringIO, params: list[ParamRow]) -> None:
    impact_order = {IMPACT_HIGH: 0, IMPACT_MEDIUM: 1, IMPACT_LOW: 2}
    category_order = {cat: i for i, cat in enumerate(CATEGORIES)}
    sorted_params = sorted(
        params,
        key=lambda x: (
            impact_order.get(x.privacy_impact, 99),
            category_order.get(x.category, 99),
            x.key,
        ),
    )
    out.write("| Field | Category | Impact | Value | Meaning |\n")
    out.write("|---|---|---|---|---|\n")
    for p in sorted_params:
        value = _md_escape(_truncate(p.value, 80))
        out.write(
            f"| `{_md_escape(p.key)}` | {p.category} | "
            f"**{p.privacy_impact.upper()}** | {value} | "
            f"{_md_escape(p.meaning)} |\n"
        )
    out.write("\n")


__all__ = [
    "render_markdown_document",
    "write_markdown_detailed",
    "write_markdown_summary",
]
