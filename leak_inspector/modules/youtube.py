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

"""YouTube (embedded player) detector.

Recognizes the host cluster an embedded YouTube player touches:
``*.youtube.com``, ``*.youtube-nocookie.com``, ``*.ytimg.com``,
``*.googlevideo.com``, ``yt*.ggpht.com``, ``jnn-pa.googleapis.com``.
Player UI / CDN streaming internals are filtered before emission.
"""

from __future__ import annotations

import json
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


_HOST_SUFFIXES: tuple[str, ...] = (
    ".youtube.com",
    ".youtube-nocookie.com",
    ".ytimg.com",
    ".googlevideo.com",
)

_HOST_EXACT: frozenset[str] = frozenset({
    "youtube.com",
    "youtube-nocookie.com",
    "ytimg.com",
    "googlevideo.com",
    "jnn-pa.googleapis.com",
})

_GGPHT_SUFFIX = ".ggpht.com"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "v":     (CAT_CONTENT, "Video ID being viewed",                             IMPACT_MEDIUM),
    "docid": (CAT_CONTENT, "Video ID (telemetry form)",                         IMPACT_MEDIUM),
    "list":  (CAT_CONTENT, "Playlist ID",                                       IMPACT_MEDIUM),
    "pl":    (CAT_CONTENT, "Playlist ID (alternate)",                           IMPACT_MEDIUM),
    "index": (CAT_BEHAVIORAL, "Index within a playlist",                        IMPACT_LOW),
    "cpn":   (CAT_IDENTIFIER, "Content playback nonce — correlates events within one playback (not persistent across playbacks; see ``visitorData`` for the persistent visitor pseudonym)", IMPACT_MEDIUM),
    "ei":    (CAT_IDENTIFIER, "Encrypted event/session identifier",             IMPACT_MEDIUM),
    "vid":   (CAT_IDENTIFIER, "Visitor / session ID (varies by endpoint)",      IMPACT_MEDIUM),
    "embed_domain":    (CAT_CONTENT, "Domain hosting the embedded player",      IMPACT_MEDIUM),
    "widget_referrer": (CAT_CONTENT, "Page URL that embedded the player",       IMPACT_MEDIUM),
    "origin":          (CAT_CONTENT, "Embedding-page origin (CORS)",            IMPACT_MEDIUM),
    "host":            (CAT_CONTENT, "Player host context",                     IMPACT_LOW),
    "enablejsapi":     (CAT_TECHNICAL, "Iframe JS-API enabled flag",            IMPACT_LOW),
    "rd":              (CAT_TECHNICAL, "Redirect flag",                         IMPACT_LOW),
    "referrer":        (CAT_CONTENT, "Document referrer",                       IMPACT_MEDIUM),
    "el":       (CAT_BEHAVIORAL, "Page-type (embedded / leanback / detailpage)", IMPACT_LOW),
    "feature":  (CAT_BEHAVIORAL, "Feature context (e.g. youtu.be, share, button)", IMPACT_MEDIUM),
    "fexp":     (CAT_BEHAVIORAL, "Active feature experiments / A-B tests",      IMPACT_MEDIUM),
    "state":    (CAT_BEHAVIORAL, "Player state",                                IMPACT_LOW),
    "cmt":      (CAT_BEHAVIORAL, "Current media playback time (seconds)",       IMPACT_LOW),
    "vct":      (CAT_BEHAVIORAL, "Video current time",                          IMPACT_LOW),
    "et":       (CAT_BEHAVIORAL, "Elapsed time",                                IMPACT_LOW),
    "len":     (CAT_BEHAVIORAL, "Video length (seconds)",                       IMPACT_LOW),
    "vps":      (CAT_BEHAVIORAL, "Video player state",                          IMPACT_LOW),
    "splay":    (CAT_BEHAVIORAL, "Show-in-player flag",                         IMPACT_LOW),
    "volume":   (CAT_BEHAVIORAL, "Playback volume",                             IMPACT_LOW),
    "muted":    (CAT_BEHAVIORAL, "Mute state",                                  IMPACT_LOW),
    "lact":     (CAT_BEHAVIORAL, "Last activity timestamp (idle detection)",    IMPACT_LOW),
    "lct":      (CAT_BEHAVIORAL, "Last click timestamp",                        IMPACT_LOW),
    "vis":      (CAT_BEHAVIORAL, "Visibility state",                            IMPACT_LOW),
    "final":    (CAT_BEHAVIORAL, "Final event in playback",                     IMPACT_LOW),
    "autoplay": (CAT_BEHAVIORAL, "Autoplay setting",                            IMPACT_LOW),
    "autonav":  (CAT_BEHAVIORAL, "Auto-navigation setting",                     IMPACT_LOW),
    "c":          (CAT_TECHNICAL, "Client type (WEB / MWEB / EMBED / TVHTML5 / …)", IMPACT_LOW),
    "cver":       (CAT_TECHNICAL, "Client version",                             IMPACT_LOW),
    "cl":         (CAT_TECHNICAL, "Client revision",                            IMPACT_LOW),
    "cbr":        (CAT_TECHNICAL, "Browser name",                               IMPACT_LOW),
    "cbrver":     (CAT_TECHNICAL, "Browser version",                            IMPACT_LOW),
    "cos":        (CAT_TECHNICAL, "OS name",                                    IMPACT_LOW),
    "cosver":     (CAT_TECHNICAL, "OS version",                                 IMPACT_LOW),
    "cplayer":    (CAT_TECHNICAL, "Player type",                                IMPACT_LOW),
    "screenw":    (CAT_TECHNICAL, "Screen width",                               IMPACT_LOW),
    "screenh":    (CAT_TECHNICAL, "Screen height",                              IMPACT_LOW),
    "ctheme":     (CAT_TECHNICAL, "Player color theme",                         IMPACT_LOW),
    "gpu":        (CAT_TECHNICAL, "GPU identifier (fingerprint surface)",       IMPACT_LOW),
    "bwe":        (CAT_TECHNICAL, "Bandwidth estimate",                         IMPACT_LOW),
    "bat":        (CAT_TECHNICAL, "Battery status",                             IMPACT_LOW),
    "ns":         (CAT_TECHNICAL, "Namespace (always ``yt``)",                  IMPACT_LOW),
    "video_id":      (CAT_CONTENT,    "Video ID being viewed (alt form)",         IMPACT_MEDIUM),
    "session_token": (CAT_IDENTIFIER, "Per-session token (anti-CSRF / continuity)", IMPACT_MEDIUM),
    "forigin":       (CAT_CONTENT,    "Frame origin (embedding-page origin)",     IMPACT_MEDIUM),
    "euri":          (CAT_CONTENT,    "Embedding-page URL (full)",                IMPACT_MEDIUM),
    "user_intent":   (CAT_BEHAVIORAL, "User-intent classifier (click / autoplay / …)", IMPACT_MEDIUM),
    "aoriginsup":    (CAT_TECHNICAL,  "Allowed-origin supplemental flag",          IMPACT_LOW),
    "playerinfo": (CAT_TECHNICAL, "Player metadata blob",                       IMPACT_LOW),
    "consent":   (CAT_CONSENT, "Consent state",                                 IMPACT_LOW),
    "consent_v": (CAT_CONSENT, "Consent version",                               IMPACT_LOW),

    "iv_load_policy": (CAT_TECHNICAL, "Annotation visibility policy (3 = hide)", IMPACT_LOW),
    "rel":            (CAT_BEHAVIORAL, "Show related videos at end (0 = no)",  IMPACT_LOW),
    "controls":       (CAT_TECHNICAL, "Show player controls flag",              IMPACT_LOW),
    "loop":           (CAT_TECHNICAL, "Loop playback flag",                     IMPACT_LOW),
    "start":          (CAT_BEHAVIORAL, "Start position (seconds)",              IMPACT_LOW),
    "end":            (CAT_BEHAVIORAL, "End position (seconds)",                IMPACT_LOW),
    "hl":             (CAT_TECHNICAL, "Player UI language",                     IMPACT_LOW),
    "cc_lang_pref":   (CAT_TECHNICAL, "Caption language preference",            IMPACT_LOW),
    "cc_load_policy": (CAT_TECHNICAL, "Caption-loading policy",                 IMPACT_LOW),
    "fs":             (CAT_TECHNICAL, "Fullscreen-button visibility flag",      IMPACT_LOW),
    "modestbranding": (CAT_TECHNICAL, "Modest-branding flag",                   IMPACT_LOW),

    "event":      (CAT_BEHAVIORAL, "Stats event name (streamingstats, qoe, …)", IMPACT_MEDIUM),
    "plid":       (CAT_IDENTIFIER, "Per-playback session ID (paired with cpn)", IMPACT_MEDIUM),
    "fmt":        (CAT_TECHNICAL, "Selected video format ID",                   IMPACT_LOW),
    "seq":        (CAT_TECHNICAL, "Telemetry sequence number",                  IMPACT_LOW),
    "cplatform":  (CAT_TECHNICAL, "Client platform (DESKTOP / MOBILE / …)",     IMPACT_LOW),
    "cat":        (CAT_BEHAVIORAL, "Stats category (e.g. streaming)",           IMPACT_LOW),
    "view":       (CAT_TECHNICAL, "Viewport sample series",                     IMPACT_LOW),
    "vfs":        (CAT_TECHNICAL, "Video format sample series",                 IMPACT_LOW),
    "bh":         (CAT_TECHNICAL, "Buffer-health sample series",                IMPACT_LOW),
    "ctmp":       (CAT_TECHNICAL, "Connection tmp / diagnostic blob",           IMPACT_LOW),
    "qclc":       (CAT_TECHNICAL, "Quality-of-experience encoded blob",         IMPACT_LOW),

    "prettyPrint": (CAT_TECHNICAL, "JSON pretty-print flag",                    IMPACT_LOW),
    "alt":         (CAT_TECHNICAL, "Response-format alt (json / proto)",        IMPACT_LOW),
    "key":         (CAT_TECHNICAL, "API key for unauthenticated calls",         IMPACT_LOW),

    "sqp": (CAT_TECHNICAL, "Signed query parameters for thumbnail access",      IMPACT_LOW),
    "rs":  (CAT_TECHNICAL, "Signed-URL random salt",                            IMPACT_LOW),

    "ip":         (CAT_PII,        "Visitor IP address embedded in the signed video URL", IMPACT_HIGH),
    "expire":     (CAT_TECHNICAL, "URL-signature expiry timestamp",             IMPACT_LOW),
    "signature":  (CAT_TECHNICAL, "URL HMAC signature",                         IMPACT_LOW),
    "sparams":    (CAT_TECHNICAL, "Signed-parameter list (which keys the signature covers)", IMPACT_LOW),
    "id":         (CAT_IDENTIFIER, "Video stream ID (CDN form)",                IMPACT_MEDIUM),
    "itag":       (CAT_TECHNICAL, "Video format / quality stream ID",           IMPACT_LOW),
    "source":     (CAT_TECHNICAL, "CDN source label (e.g. ``goodput``)",        IMPACT_LOW),
    "range":      (CAT_TECHNICAL, "HTTP-range request bounds",                  IMPACT_LOW),
    "mm":         (CAT_TECHNICAL, "CDN management-server zone code",            IMPACT_LOW),
    "ms":         (CAT_TECHNICAL, "CDN media-server zone code",                 IMPACT_LOW),
    "mh":         (CAT_TECHNICAL, "CDN machine hash",                           IMPACT_LOW),
    "mn":         (CAT_TECHNICAL, "CDN machine name",                           IMPACT_LOW),
    "mt":         (CAT_TECHNICAL, "Manifest timestamp",                         IMPACT_LOW),
    "met":        (CAT_TECHNICAL, "Manifest expiry timestamp",                  IMPACT_LOW),
    "nh":         (CAT_TECHNICAL, "Next-host hint",                             IMPACT_LOW),
    "cps":        (CAT_TECHNICAL, "Content-protection signing flag",            IMPACT_LOW),
    "xpc":        (CAT_TECHNICAL, "Extra protected CDN parameter",              IMPACT_LOW),
    "requiressl": (CAT_TECHNICAL, "Require-SSL flag",                           IMPACT_LOW),
}


_SKIP_KEYS: frozenset[str] = frozenset({
    "rel", "controls", "loop", "fs", "modestbranding",
    "iv_load_policy", "cc_lang_pref", "cc_load_policy",
    "playsinline", "color", "mute", "playlist", "widgetid",
    "html5", "size", "of",
    "mv", "mvi", "pcm2cms", "rms", "initcwndbps", "bui", "spc",
    "vprv", "svpuc", "mime", "rqh", "gir", "clen", "dur", "lmt",
    "fmt", "itag", "range", "afmt", "vf", "afs",
    "mt", "met", "nh", "mh", "mn", "mm", "ms",
    "pl", "cps", "xpc", "requiressl", "source",
    "expire", "signature", "sparams",
    "fvip", "keepalive", "sefc", "txp", "n", "sig", "lsparams", "lsig",
    "alr", "rn", "rbuf", "pot", "ump", "srfvp", "aitags",
    "ver", "rt", "delay", "vm", "bwm", "mos", "epm", "rtn",
    "ptk", "pltype", "atr", "idpj", "ldpj", "dtm", "rti", "df", "st",
    "inview", "cr",
    "prettyPrint", "alt",
})


def _parse_youtubei_body(body: str | None) -> list[ParamInfo]:
    if not body:
        return []
    try:
        envelope = json.loads(body)
    except (ValueError, TypeError):
        return []
    if not isinstance(envelope, dict):
        return []

    extracted: list[ParamInfo] = []
    context = envelope.get("context") or {}
    if isinstance(context, dict):
        client = context.get("client") or {}
        if isinstance(client, dict):
            for json_key, label, category, meaning, impact in (
                ("clientName",    "(body) client_name",
                 CAT_TECHNICAL,   "YouTube client identifier (WEB / EMBED / MWEB / TVHTML5 / …)", IMPACT_LOW),
                ("clientVersion", "(body) client_version",
                 CAT_TECHNICAL,   "YouTube client version",                         IMPACT_LOW),
                ("hl",            "(body) language",
                 CAT_TECHNICAL,   "Visitor language preference",                    IMPACT_LOW),
                ("gl",            "(body) country",
                 CAT_TECHNICAL,   "Visitor country (derived from IP server-side)",  IMPACT_LOW),
                ("visitorData",   "(body) visitor_data",
                 CAT_IDENTIFIER,  "YouTube visitor data token (per-visitor pseudonym)", IMPACT_HIGH),
            ):
                value = client.get(json_key)
                if value:
                    extracted.append(ParamInfo(
                        key=label,
                        value=str(value),
                        category=category,
                        meaning=meaning,
                        privacy_impact=impact,
                        event_index=0,
                    ))

    events_list = envelope.get("events")
    if isinstance(events_list, list) and events_list:
        extracted.append(ParamInfo(
            key="(body) logged_event_count",
            value=str(len(events_list)),
            category=CAT_BEHAVIORAL,
            meaning="Number of distinct events shipped in this /youtubei/v1/log_event body",
            privacy_impact=IMPACT_MEDIUM,
            event_index=0,
        ))

    return extracted


@register
class YouTubeModule(TrackerModule):
    """Detect embedded YouTube player traffic across the YouTube host cluster."""

    module_id = "youtube"
    module_name = "YouTube (embedded player)"
    vendor = "Google LLC (YouTube)"
    legal_jurisdiction = "US"
    data_residency = "Global Google / YouTube CDN"
    sovereignty_notes = "Schrems II / US CLOUD Act / FISA 702 apply"
    # Embedded player: privacy 4.0 — the default embed sets persistent
    #   DoubleClick cookies and joins the visit to Google's ad profile,
    #   cross-site by design (rubric privacy 4.0); the youtube-nocookie
    #   variant is the mitigation (a Phase-5 variant). security 1.5
    #   (cross-origin iframe — sandboxed). resilience 3.0 (US Google;
    #   embedded video is a supporting feature with no easy EU swap —
    #   rubric 3.0).
    impact_rating = ImpactRating(privacy=4.0, security=1.5, resilience=3.0)
    impact_notes = {
        "privacy": "The default embed sets persistent DoubleClick cookies "
            "and joins the visit to Google's ad profile — the "
            "youtube-nocookie embed avoids this.",
        "security": "Runs in a cross-origin iframe — sandboxed.",
        "resilience": "Embedded video on US (Google) infrastructure, with "
            "no easy EU swap.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        if host in _HOST_EXACT:
            return True
        if any(host.endswith(suffix) for suffix in _HOST_SUFFIXES):
            return True
        if host.endswith(_GGPHT_SUFFIX):
            label = host[: -len(_GGPHT_SUFFIX)]
            first = label.rsplit(".", 1)[-1]
            return first.startswith("yt")
        return False

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            if key in _SKIP_KEYS:
                continue
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized YouTube parameter", IMPACT_LOW)
            )
            params.append(
                ParamInfo(
                    key=key, value=value, category=category, meaning=meaning,
                    privacy_impact=impact, event_index=event.event_id,
                )
            )
        path = urlparse(event.url).path
        if path.startswith("/youtubei/v1/"):
            for body_param in _parse_youtubei_body(event.request_body):
                body_param.event_index = event.event_id
                params.append(body_param)
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
