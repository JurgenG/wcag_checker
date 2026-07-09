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

"""Matomo (formerly Piwik) detector.

Matomo is self-hostable: there's no canonical first-party domain. To
recognize it across the wild we combine three signals:

1. Hosted variants — ``*.matomo.cloud``, ``*.innocraft.cloud``, ``*.piwik.pro``.
2. Canonical filenames — ``matomo.php`` / ``piwik.php`` / ``matomo.js`` / ``piwik.js``.
3. Parameter signature — ``idsite`` is essentially unique to Matomo.

The Matomo Tag Manager container (``/js/container_<id>.js``) carries none
of these signals, so :meth:`MatomoModule.matches` does not claim it
directly. Instead :func:`is_mtm_container_path` lets the analysis runner's
same-host pass confirm the host and attribute the container (and the rest
of that host's traffic) to Matomo — this catches self-hosted instances on
captures where the ``/matomo.php`` collect hit never fired.

Because Matomo is jurisdiction-ambiguous by default (NZ for hosted SaaS,
operator-controlled for self-hosted), the class-level ``legal_jurisdiction``
is left blank. Each hit instead carries a ``(deployment) …`` ParamInfo
naming the deployment mode, and the runner attaches an ``(infra) hosting``
ParamInfo for self-hosted collectors so the actual controller is visible.

The HeatmapSessionRecording plugin is also surfaced separately: its path
prefix (``/plugins/HeatmapSessionRecording/``) signals heatmaps + full
session-replay capture, which is meaningfully higher impact than the
baseline page-view analytics Matomo.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_BEHAVIORAL,
    CAT_CONSENT,
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_PII,
    CAT_TECHNICAL,
    Hit,
    IMPACT_HIGH,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    register,
)


_HOSTED_SUFFIXES: tuple[str, ...] = (
    ".matomo.cloud",
    ".innocraft.cloud",
    ".piwik.pro",
)

_PATH_SUFFIXES: tuple[str, ...] = (
    "/matomo.php",
    "/piwik.php",
    "/matomo.js",
    "/piwik.js",
)


_PARAMS: dict[str, tuple[str, str, str]] = {
    "idsite": (CAT_TECHNICAL, "Site ID (the Matomo property identifier)",       IMPACT_LOW),
    "idSite": (CAT_TECHNICAL, "Site ID (camelCase alias of ``idsite``)",        IMPACT_LOW),
    "trackerid": (CAT_TECHNICAL, "HeatmapSessionRecording tracker/recorder id (property-scoped, not a visitor id)", IMPACT_LOW),
    "_id":    (CAT_IDENTIFIER, "Persistent visitor ID (16-char hex, the user pseudonym)", IMPACT_HIGH),
    "cid":    (CAT_IDENTIFIER, "Visitor ID (alternative form of ``_id``)",      IMPACT_HIGH),
    "uid":    (CAT_PII,        "Site-supplied user ID — often a real account id", IMPACT_HIGH),
    "cip":    (CAT_PII,        "Client IP override (server-to-server tracking)", IMPACT_HIGH),
    "pv_id":  (CAT_IDENTIFIER, "Page-view ID (per-pageload random)",            IMPACT_MEDIUM),
    "_idts":   (CAT_IDENTIFIER, "Visitor first-seen timestamp",                 IMPACT_LOW),
    "_idvc":   (CAT_BEHAVIORAL, "Visit count for this visitor",                 IMPACT_LOW),
    "_idn":    (CAT_BEHAVIORAL, "New visitor indicator",                        IMPACT_LOW),
    "_refts":  (CAT_TECHNICAL,  "Referrer timestamp",                           IMPACT_LOW),
    "_viewts": (CAT_BEHAVIORAL, "Last visit timestamp",                         IMPACT_LOW),
    "url":         (CAT_CONTENT, "Page URL the hit fired on",                   IMPACT_MEDIUM),
    "urlref":      (CAT_CONTENT, "Document referrer",                           IMPACT_MEDIUM),
    "action_name": (CAT_CONTENT, "Page title / action name",                    IMPACT_LOW),
    "link":        (CAT_CONTENT, "Outlink URL (the link the visitor clicked)",  IMPACT_MEDIUM),
    "download":    (CAT_CONTENT, "Downloaded resource URL",                     IMPACT_MEDIUM),
    "search":      (CAT_CONTENT, "Internal-site search keyword",                IMPACT_MEDIUM),
    "search_cat":  (CAT_CONTENT, "Internal-site search category",               IMPACT_LOW),
    "search_count": (CAT_BEHAVIORAL, "Internal-site search result count",       IMPACT_LOW),
    "e_c": (CAT_BEHAVIORAL, "Event category",                                   IMPACT_MEDIUM),
    "e_a": (CAT_BEHAVIORAL, "Event action",                                     IMPACT_MEDIUM),
    "e_n": (CAT_BEHAVIORAL, "Event name",                                       IMPACT_MEDIUM),
    "e_v": (CAT_BEHAVIORAL, "Event value",                                      IMPACT_MEDIUM),
    "c_n": (CAT_CONTENT,    "Content tracking: content name",                   IMPACT_LOW),
    "c_p": (CAT_CONTENT,    "Content tracking: content piece",                  IMPACT_LOW),
    "c_t": (CAT_CONTENT,    "Content tracking: content target (link/CTA)",     IMPACT_LOW),
    "c_i": (CAT_BEHAVIORAL, "Content tracking: interaction (view/click)",       IMPACT_LOW),
    "ec_id":    (CAT_BEHAVIORAL, "Ecommerce order ID",                          IMPACT_MEDIUM),
    "ec_items": (CAT_BEHAVIORAL, "Ecommerce items (JSON list of purchased items)", IMPACT_HIGH),
    "revenue":  (CAT_BEHAVIORAL, "Order revenue / goal value",                  IMPACT_MEDIUM),
    "ec_st":    (CAT_BEHAVIORAL, "Ecommerce subtotal",                          IMPACT_LOW),
    "ec_tx":    (CAT_BEHAVIORAL, "Ecommerce tax",                               IMPACT_LOW),
    "ec_sh":    (CAT_BEHAVIORAL, "Ecommerce shipping",                          IMPACT_LOW),
    "ec_dt":    (CAT_BEHAVIORAL, "Ecommerce discount",                          IMPACT_LOW),
    "idgoal":   (CAT_BEHAVIORAL, "Goal ID (which conversion goal was triggered)", IMPACT_MEDIUM),
    "res":    (CAT_TECHNICAL, "Screen resolution",                              IMPACT_LOW),
    "h":      (CAT_TECHNICAL, "Local-time hour",                                IMPACT_LOW),
    "m":      (CAT_TECHNICAL, "Local-time minute",                              IMPACT_LOW),
    "s":      (CAT_TECHNICAL, "Local-time second",                              IMPACT_LOW),
    "ua":     (CAT_TECHNICAL, "User-Agent override",                            IMPACT_LOW),
    "lang":   (CAT_TECHNICAL, "Browser language",                               IMPACT_LOW),
    "cookie": (CAT_TECHNICAL, "Cookies-enabled flag",                           IMPACT_LOW),
    "java":   (CAT_TECHNICAL, "Java-plugin probe (legacy)",                     IMPACT_LOW),
    "fla":    (CAT_TECHNICAL, "Flash-plugin probe (legacy)",                    IMPACT_LOW),
    "pdf":    (CAT_TECHNICAL, "PDF-plugin probe",                               IMPACT_LOW),
    "qt":     (CAT_TECHNICAL, "QuickTime-plugin probe (legacy)",                IMPACT_LOW),
    "realp":  (CAT_TECHNICAL, "RealPlayer-plugin probe (legacy)",               IMPACT_LOW),
    "wma":    (CAT_TECHNICAL, "Windows Media Audio plugin probe (legacy)",      IMPACT_LOW),
    "dir":    (CAT_TECHNICAL, "Director-plugin probe (legacy)",                 IMPACT_LOW),
    "gears":  (CAT_TECHNICAL, "Google Gears plugin probe (legacy)",             IMPACT_LOW),
    "ag":     (CAT_TECHNICAL, "Silverlight-plugin probe (legacy)",              IMPACT_LOW),
    "pf_net": (CAT_TECHNICAL, "Page-load: network time",                        IMPACT_LOW),
    "pf_srv": (CAT_TECHNICAL, "Page-load: server time",                         IMPACT_LOW),
    "pf_tfr": (CAT_TECHNICAL, "Page-load: transfer time",                       IMPACT_LOW),
    "pf_dm1": (CAT_TECHNICAL, "Page-load: DOM processing time",                 IMPACT_LOW),
    "pf_dm2": (CAT_TECHNICAL, "Page-load: DOM ready time",                      IMPACT_LOW),
    "pf_onl": (CAT_TECHNICAL, "Page-load: onload time",                         IMPACT_LOW),
    "gt_ms":  (CAT_TECHNICAL, "Generation time on the server (ms)",             IMPACT_LOW),
    "rec":        (CAT_TECHNICAL, "Record flag (``1`` = persist this hit)",     IMPACT_LOW),
    "apiv":       (CAT_TECHNICAL, "Tracking API version",                       IMPACT_LOW),
    "r":          (CAT_TECHNICAL, "Random cache-buster",                        IMPACT_LOW),
    "rand":       (CAT_TECHNICAL, "Random cache-buster (alt)",                  IMPACT_LOW),
    "cdt":        (CAT_TECHNICAL, "Custom datetime override",                   IMPACT_LOW),
    "send_image": (CAT_TECHNICAL, "Send 1×1 GIF response flag",                 IMPACT_LOW),
    "ping":       (CAT_BEHAVIORAL, "Heartbeat ping (visitor still on page)",    IMPACT_LOW),
    "bots":       (CAT_TECHNICAL, "Track-bots flag",                            IMPACT_LOW),
    "_cvar":      (CAT_BEHAVIORAL, "Legacy custom-variables blob (JSON)",       IMPACT_MEDIUM),
    "cvar":       (CAT_BEHAVIORAL, "Page-scoped custom variables (JSON)",       IMPACT_MEDIUM),
    "consent":                  (CAT_CONSENT, "Consent state",                  IMPACT_LOW),
    "consent_management":       (CAT_CONSENT, "Consent-management signal",      IMPACT_LOW),
    "idsite_actions_consent":   (CAT_CONSENT, "Per-site actions consent flag",  IMPACT_LOW),
}

_PARAM_PREFIXES: tuple[tuple[str, str, str, str], ...] = (
    ("dimension", CAT_BEHAVIORAL, "Custom dimension #{}",                     IMPACT_MEDIUM),
    ("customDimension", CAT_BEHAVIORAL, "Custom dimension #{} (legacy form)", IMPACT_MEDIUM),
)


_HSR_PLUGIN_PATH_PREFIX = "/plugins/HeatmapSessionRecording/"

#: Matomo Tag Manager container script. The default install snippet loads
#: ``/js/container_<id>.js`` where ``<id>`` is an 8-char base64url token.
#: Anchored to the default ``/js/`` directory and an 8+-char id so unrelated
#: bundles named ``container*.js`` (or the short synthetic ids used in tests)
#: don't match. Distinctive enough to *confirm* a self-hosted Matomo host on
#: its own — see :func:`is_mtm_container_path` and the analysis same-host pass.
_MTM_CONTAINER_RE = re.compile(r"/js/container_[A-Za-z0-9]{8,}\.js$")


def is_mtm_container_path(path: str) -> bool:
    """True iff ``path`` is a Matomo Tag Manager container script.

    The default MTM install snippet loads ``/js/container_<id>.js`` (id is
    an 8-char base64url token). The path is distinctive enough to confirm a
    self-hosted Matomo host on its own — unlike the ``/matomo.js`` loader,
    which sites commonly first-party-proxy. Used by the analysis runner's
    same-host pass to attribute a host that served only the container (the
    ``/matomo.php`` collect hit may not fire before the capture ends).
    """
    return bool(_MTM_CONTAINER_RE.search(path))


def is_hosted_matomo_host(host: str) -> bool:
    """True iff ``host`` belongs to a Matomo-operated SaaS suffix.

    Public helper so the analysis runner can decide whether to enrich a
    confirmed Matomo collector with ASN / country (only self-hosted
    deployments need that — hosted instances live under InnoCraft's
    known infrastructure).
    """
    host = host.lower()
    return any(host.endswith(suffix) for suffix in _HOSTED_SUFFIXES)


# Internal alias preserved for the in-module deployment annotation.
_is_hosted = is_hosted_matomo_host


def _classify(key: str) -> tuple[str, str, str]:
    if key in _PARAMS:
        return _PARAMS[key]
    for prefix, cat, template, impact in _PARAM_PREFIXES:
        if key.startswith(prefix):
            suffix = key[len(prefix):]
            if suffix.isdigit():
                return cat, template.format(suffix), impact
    return CAT_OTHER, "Unrecognized Matomo parameter", IMPACT_LOW


@register
class MatomoModule(TrackerModule):
    """Detect Matomo / Piwik tracking traffic across hosted, self-hosted, and custom deployments."""

    module_id = "matomo"
    module_name = "Matomo"
    vendor = "InnoCraft Ltd (Matomo)"
    # Jurisdiction is per-instance for Matomo — see the ``(deployment) …``
    # ParamInfo each hit carries. Class-level fields stay blank so the
    # report doesn't bucket self-hosted instances under InnoCraft's NZ.
    legal_jurisdiction = ""
    data_residency = ""
    sovereignty_notes = ""
    # BASE = self-hosted Matomo (the deployment this project encourages,
    # and the proposal anchor): privacy 2.0 (durable _pk_id pseudonymous
    # profile, but under the operator's own control — rubric privacy 2.0);
    # security 0.0 + resilience 0.0 (operator-run, nothing external to
    # compromise or subpoena). The hosted variants this module also
    # matches (*.matomo.cloud / piwik.pro) are a contained third-party
    # vendor → privacy ~2.5 / security ~2.5 / resilience higher: a Phase-5
    # variant keyed on the hosted-suffix host match. Defaulting to the
    # self-hosted reading is the safe error — never over-penalise the
    # encouraged setup on mere presence.
    impact_rating = ImpactRating(privacy=2.0, security=0.0, resilience=0.0)
    impact_notes = {
        "privacy": "Builds a durable per-visitor profile, but on "
            "self-hosted infrastructure the operator controls — the data "
            "stays first-party.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if any(host.endswith(suffix) for suffix in _HOSTED_SUFFIXES):
            return True
        path = urlparse(event.url).path
        if any(path.endswith(suffix) for suffix in _PATH_SUFFIXES):
            return True
        params = event.query_params
        return "idsite" in params or "idSite" in params

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _classify(key)
            params.append(
                ParamInfo(
                    key=key, value=value, category=category, meaning=meaning,
                    privacy_impact=impact, event_index=event.event_id,
                )
            )
        params.append(_deployment_param(event))
        plugin_param = _plugin_param(event)
        if plugin_param is not None:
            params.append(plugin_param)
        mtm_param = _mtm_param(event)
        if mtm_param is not None:
            params.append(mtm_param)
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )


def _deployment_param(event: RequestEvent) -> ParamInfo:
    """Per-hit deployment-mode annotation.

    Hosted Matomo SaaS (matomo.cloud / innocraft.cloud / piwik.pro) is
    operated by InnoCraft Ltd in NZ with optional EU regions and US
    parent-company exposure. Everything else is a self-hosted instance
    controlled by whoever runs the server — the ``(infra) hosting``
    ParamInfo added by the runner names that operator's hosting provider.
    """
    if _is_hosted(event.host):
        return ParamInfo(
            key="(deployment) Matomo Cloud",
            value=event.host,
            category=CAT_OTHER,
            meaning=(
                "Matomo Cloud (hosted by InnoCraft Ltd, NZ). EU regions "
                "are available, but InnoCraft's US presence may expose "
                "the data to US CLOUD Act requests."
            ),
            privacy_impact=IMPACT_MEDIUM,
            event_index=event.event_id,
        )
    return ParamInfo(
        key="(deployment) self-hosted",
        value=event.host,
        category=CAT_OTHER,
        meaning=(
            "Self-hosted Matomo — data goes to the site operator running "
            "this server, not to InnoCraft. See the ``(infra) hosting`` "
            "ParamInfo for the actual ASN / country."
        ),
        privacy_impact=IMPACT_LOW,
        event_index=event.event_id,
    )


def _plugin_param(event: RequestEvent) -> ParamInfo | None:
    """HIGH-impact annotation for the HeatmapSessionRecording plugin.

    Only ``/plugins/HeatmapSessionRecording/`` is surfaced — it captures
    heatmaps (mouse position / clicks / scroll depth) plus full session
    replays of the visitor's interaction stream, which is meaningfully
    higher impact than baseline Matomo page-view analytics. Other Matomo
    premium plugins (FormAnalytics, AbTesting, MediaAnalytics) are
    intentionally not surfaced because no certain capture data was
    available when this was written.
    """
    path = urlparse(event.url).path
    if not path.startswith(_HSR_PLUGIN_PATH_PREFIX):
        return None
    return ParamInfo(
        key="(plugin) HeatmapSessionRecording",
        value=path,
        category=CAT_BEHAVIORAL,
        meaning=(
            "Matomo HeatmapSessionRecording plugin: captures heatmaps "
            "(clicks / mouse movement / scroll depth) and full session "
            "replays of the visitor's interactions on this page."
        ),
        privacy_impact=IMPACT_HIGH,
        event_index=event.event_id,
    )


def _mtm_param(event: RequestEvent) -> ParamInfo | None:
    """Annotation for a Matomo Tag Manager container script load.

    The container bootstrap (``/js/container_<id>.js``) carries no
    tracking parameters itself, but it is the client-side tag manager
    that can load further tags / trackers, so naming it explains why an
    otherwise param-less asset is attributed to Matomo.
    """
    path = urlparse(event.url).path
    if not _MTM_CONTAINER_RE.search(path):
        return None
    return ParamInfo(
        key="(tag manager) Matomo Tag Manager",
        value=path,
        category=CAT_TECHNICAL,
        meaning=(
            "Matomo Tag Manager container — client-side tag manager that "
            "can load additional tags / trackers on this page."
        ),
        privacy_impact=IMPACT_LOW,
        event_index=event.event_id,
    )
