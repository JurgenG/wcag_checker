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

"""Consent-artifact decoders.

CMPs persist the visitor's consent decision in machine-readable
cookies. These decoders turn the persisted value into a
:class:`ConsentDecision` — the building block for classifying a
capture into the three consent states:

1. **no interaction** — no artifact exists (the bulk tool's
   pre-interaction captures are this state by construction);
2. **rejected / minimal** — artifact present, no non-essential
   category granted;
3. **accepted** — artifact present, at least one non-essential
   category granted.

Supported formats (each verified against a real capture):

* **Cookiebot** — ``CookieConsent`` cookie, a JS object literal:
  ``{...,necessary:true,preferences:false,statistics:false,
  marketing:false,method:'explicit',...}`` (doccle.be).
* **Cookie Script** — ``CookieScriptConsent`` cookie, JSON with an
  ``action`` of ``accept``/``reject`` and a JSON-encoded ``categories``
  string (cultuurkuur.be).
* **OneTrust** — ``OptanonConsent`` cookie, a querystring whose
  ``groups`` field flags each category code: ``C0001:1,C0002:0,…``.
  ``C0001`` is OneTrust's strictly-necessary group and never counts
  as a granted consent (colruyt.be).
* **EU Cookie Compliance** (Drupal GDPR module) — first-party
  ``cookie-agreed`` cookie: ``0`` = declined, non-zero (``1``/``2``)
  = agreed. Common on EU public-sector Drupal sites; recognised by
  the :mod:`..modules.eu_cookie_compliance` detector
  (``/modules/contrib/eu_cookie_compliance/`` asset path).
* **LCP/Icordis** (self-hosted, server-rendered) — no decodable
  cookie; the decision is the banner's form POST itself
  (``action=acceptall`` / ``action=decline``), read from the
  :mod:`..modules.lcp_icordis_consent` hit, not from storage
  (verified form markup: www.beernem.be capture). Interactive
  captures only — bulk captures never click.

Deliberately not decoded yet: **IAB TCF v2** ``euconsent-v2`` TC
strings — the bit-packed spec is published, but no local capture
carries one to verify against, and the house rule is to only build
on certain data. Sourcepoint's ``consentUUID`` alone (vrt.be) proves
an interaction happened but not what was chosen — callers must treat
such sessions as "unknown", never guess.

Decoders are pure functions: cookie value in, decision out, ``None``
for anything unparseable.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import parse_qs, unquote

#: Cookiebot's non-essential consent categories. ``necessary`` is
#: always true and never counts as a granted consent.
_COOKIEBOT_CATEGORIES: tuple[str, ...] = (
    "preferences", "statistics", "marketing",
)

#: OneTrust's strictly-necessary group code — always 1, never a
#: granted consent.
_ONETRUST_NECESSARY_GROUP = "C0001"

#: ParamInfo key prefixes proving a hit lands at a third-party vendor
#: despite a first-party-looking host (CNAME cloak / reverse proxy).
#: Mirrors the scoring module's override so a cloaked tracker still
#: counts as a consent offender.
_OVERRIDE_PREFIXES: tuple[str, ...] = ("(cname-cloak)", "(fp-proxy)")


@dataclass(frozen=True)
class ConsentDecision:
    """One decoded consent artifact.

    ``state`` is ``"accepted"`` when at least one non-essential
    category was granted, ``"rejected"`` otherwise. The absence of
    any artifact (state 1, "no interaction") is the *caller's*
    conclusion — a decoder can only speak when an artifact exists.
    """

    state: str                 # "accepted" | "rejected"
    source: str                # "cookiebot" | "cookie_script" | "onetrust"
    granted: tuple[str, ...]   # non-essential categories granted, sorted
    raw: str                   # decoded artifact value


def _decision(source: str, granted: list[str], raw: str) -> ConsentDecision:
    return ConsentDecision(
        state="accepted" if granted else "rejected",
        source=source,
        granted=tuple(sorted(granted)),
        raw=raw,
    )


def _decode_cookiebot(value: str) -> ConsentDecision | None:
    """Decode a Cookiebot ``CookieConsent`` JS-object-literal value.

    The value is not JSON (unquoted keys, single-quoted strings), so
    the category booleans are extracted directly rather than parsing
    the full literal.
    """
    flags: dict[str, bool] = {}
    for category in _COOKIEBOT_CATEGORIES:
        m = re.search(rf"\b{category}:(true|false)\b", value)
        if m is None:
            return None
        flags[category] = m.group(1) == "true"
    granted = [c for c, ok in flags.items() if ok]
    return _decision("cookiebot", granted, value)


def _decode_cookie_script(value: str) -> ConsentDecision | None:
    """Decode a Cookie Script ``CookieScriptConsent`` JSON value."""
    try:
        data = json.loads(value)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    action = data.get("action")
    if action not in ("accept", "reject"):
        return None
    granted: list[str] = []
    if action == "accept":
        # ``categories`` is a JSON-encoded *string* inside the JSON.
        try:
            categories = json.loads(data.get("categories", "[]"))
        except (json.JSONDecodeError, TypeError, ValueError):
            categories = []
        granted = [c for c in categories if isinstance(c, str)]
    # The action field is authoritative — an explicit accept is
    # state "accepted" even when the category list is empty.
    return ConsentDecision(
        state="accepted" if action == "accept" else "rejected",
        source="cookie_script",
        granted=tuple(sorted(granted)),
        raw=value,
    )


def _decode_onetrust(value: str) -> ConsentDecision | None:
    """Decode a OneTrust ``OptanonConsent`` querystring value."""
    groups_values = parse_qs(value).get("groups")
    if not groups_values:
        return None
    granted: list[str] = []
    for part in groups_values[0].split(","):
        code, _, flag = part.partition(":")
        code = code.strip()
        if not code or code == _ONETRUST_NECESSARY_GROUP:
            continue
        if flag.strip() == "1":
            granted.append(code)
    return _decision("onetrust", granted, value)


def _decode_eu_cookie_compliance(value: str) -> ConsentDecision | None:
    """Decode Drupal EU Cookie Compliance's ``cookie-agreed`` cookie.

    The value is a small integer: ``0`` means the visitor declined,
    any non-zero value (``1``/``2``) means they agreed. Non-integer
    values (e.g. an empty cookie, or the unrelated
    ``cookie-agreed-version`` content) decode to ``None`` — never a
    guess. The granted category names live in a separate
    ``cookie-agreed-categories`` cookie; the accept/decline state is
    fully determined here, so categories are not required.
    """
    text = value.strip()
    if not text.lstrip("-").isdigit():
        return None
    declined = int(text) == 0
    return ConsentDecision(
        state="rejected" if declined else "accepted",
        source="eu_cookie_compliance",
        granted=(),
        raw=value,
    )


#: Consent-artifact cookie names → decoder.
_DECODERS = {
    "CookieConsent": _decode_cookiebot,
    "CookieScriptConsent": _decode_cookie_script,
    "OptanonConsent": _decode_onetrust,
    "cookie-agreed": _decode_eu_cookie_compliance,
}

#: Cookie names that hold a decodable consent decision.
CONSENT_COOKIE_NAMES: frozenset[str] = frozenset(_DECODERS)


def decode_consent_artifact(name: str, value: str) -> ConsentDecision | None:
    """Decode one persisted consent artifact by cookie name.

    ``value`` may be the raw (URL-encoded) cookie value as stored in
    the bundle or the already-decoded form. Returns ``None`` for
    unknown cookie names and unparseable values — never guesses.
    """
    decoder = _DECODERS.get(name)
    if decoder is None or not value:
        return None
    return decoder(unquote(value))


#: Module IDs of CMPs whose persisted artifact the decoders above can
#: read. When one of these fired but no decodable artifact exists, the
#: visitor provably never decided — these CMPs persist nothing until a
#: choice is made.
_DECODABLE_CMP_MODULE_IDS: frozenset[str] = frozenset({
    "cookiebot", "cookie_script", "onetrust", "eu_cookie_compliance",
})


#: Module IDs of CMPs themselves. A CMP beacon firing before the
#: consent decision is not a violation — the CMP must run to draw the
#: banner and record the choice — so these are exempt from the
#: pre-consent / post-reject offender tally.
_CMP_MODULE_IDS: frozenset[str] = frozenset({
    "cookiebot", "cookie_script", "onetrust", "trustarc", "sourcepoint",
    "eu_cookie_compliance", "consentmanager", "cookieyes",
    "lcp_icordis_consent",
})


#: Module IDs whose *hit* carries the consent decision as a request
#: (LCP/Icordis: the banner is server-rendered HTML and persists only
#: an opaque server-set cookie — the decision form POST is the
#: machine-readable artifact). Maps the hit's ``action`` value to a
#: state; unknown values decode to nothing, never a guess.
_DECISION_POST_MODULE_IDS: frozenset[str] = frozenset({
    "lcp_icordis_consent",
})

_DECISION_POST_ACTIONS: dict[str, str] = {
    "acceptall": "accepted",
    "decline": "rejected",
}


@dataclass(frozen=True)
class ConsentState:
    """The capture's consent state, derived from persisted artifacts.

    ``state`` is one of:

    * ``"none"`` — a decodable CMP ran but the visitor never decided
      (the bulk tool's pre-interaction captures are this state);
    * ``"rejected"`` — decision artifact present, no non-essential
      category granted;
    * ``"accepted"`` — decision artifact present, at least one
      non-essential category granted;
    * ``"unknown"`` — no CMP we can decode (custom banner, TrustArc,
      Sourcepoint without a TCF string, or no banner at all).

    ``decided_at`` is the timestamp of the first storage snapshot
    containing a *decodable* decision — the moment the visitor chose.

    ``pre_decision_vendors`` are distinct third-party vendors that
    shipped a PII/identifier field *before* the decision (a violation
    regardless of the eventual choice). For state ``"none"`` every
    tracking vendor is pre-consent by construction. ``post_reject_vendors``
    are those that fired *after* an explicit reject — the starkest
    violation. ``unknown`` sessions leave both empty: no claim.

    ``consent_mode_signals`` are the distinct Google Consent Mode
    ``gcs`` values seen on the wire (``G100`` = storage denied,
    ``G111`` = granted) — independent corroboration of the decision.
    """

    state: str                      # "none" | "rejected" | "accepted" | "unknown"
    source: str | None = None       # decoder that produced the decision
    granted: tuple[str, ...] = ()   # non-essential categories granted
    decided_at: str | None = None   # ISO timestamp of the decision
    pre_decision_vendors: tuple[str, ...] = ()
    post_reject_vendors: tuple[str, ...] = ()
    consent_mode_signals: tuple[str, ...] = ()
    #: Display names of CMP modules that fired, decodable or not.
    #: Lets reports distinguish "banner present but its stored decision
    #: can't be read" (TrustArc / Sourcepoint → state ``unknown`` with
    #: names) from "no known CMP detected at all" (``unknown``, empty).
    cmp_names: tuple[str, ...] = ()


def _decode_decision(storage_snapshots) -> tuple[ConsentDecision | None, str | None]:
    """Return ``(final_decision, first_decision_timestamp)``.

    Walks snapshots in stream order; the decision moment is the first
    snapshot whose consent cookie *decodes* (mere presence is not
    enough — Cookie Script writes ``{"bannershown":1}`` before the
    visitor chooses). The final decodable value wins, matching browser
    cookie semantics.
    """
    first_ts: str | None = None
    last: ConsentDecision | None = None
    for event in storage_snapshots:
        if event.kind != "cookie":
            continue
        for entry in event.entries:
            name = entry.get("key", "")
            if name not in CONSENT_COOKIE_NAMES:
                continue
            decision = decode_consent_artifact(name, entry.get("value", ""))
            if decision is None:
                continue
            if first_ts is None:
                first_ts = event.timestamp
            last = decision
    return last, first_ts


def _decode_decision_posts(hits) -> tuple[ConsentDecision | None, str | None]:
    """Return ``(final_decision, first_decision_timestamp)`` from hits.

    Reads the ``action`` value off decision-POST hits (LCP/Icordis form
    submits). Mirrors :func:`_decode_decision`'s semantics: the final
    decodable decision wins (a visitor may decline, then accept via the
    manage page); the first one dates the decision moment. Unlike the
    snapshot boundary, ``hit.started_at`` is on the same clock as every
    other hit, so the pre/post split is exact.
    """
    decoded: list[tuple[str, ConsentDecision]] = []
    for hit in hits:
        if hit.module_id not in _DECISION_POST_MODULE_IDS:
            continue
        action = next(
            (p.value for p in hit.params if p.key == "action"), "",
        )
        state = _DECISION_POST_ACTIONS.get(action)
        if state is None:
            continue
        decoded.append((hit.started_at, ConsentDecision(
            state=state,
            source=hit.module_id,
            granted=(),
            raw=action,
        )))
    if not decoded:
        return None, None
    decoded.sort(key=lambda pair: pair[0])
    return decoded[-1][1], decoded[0][0]


def _offender_vendors(
    hits,
    is_tracking_hit,
    state: str,
    decided_at: str | None,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Split tracking-hit vendors into (pre-decision, post-reject) sets.

    No claim is made for ``unknown`` (no decodable decision) or
    ``accepted`` sessions. For accepted sessions the visitor consented
    and tracking bursts in a sub-second cluster around the click; the
    decision boundary is the *snapshot* carrying the decoded cookie,
    an upper bound on the real click, so a beacon that truly fired
    just after the accept can't be reliably told from one just before.
    Rather than risk naming a post-accept vendor as pre-consent, we
    assert nothing — the rejected / none states (where offenders fire
    well clear of the decision, or there is no decision at all) carry
    the compliance signal.
    """
    if state in ("unknown", "accepted"):
        return (), ()
    pre: set[str] = set()
    post: set[str] = set()
    for hit in hits:
        if not is_tracking_hit(hit):
            continue
        # No decision (state "none") → everything is pre-consent.
        if decided_at is None or hit.started_at < decided_at:
            pre.add(hit.module_name)
        elif state == "rejected":
            post.add(hit.module_name)
    return tuple(sorted(pre)), tuple(sorted(post))


def _consent_mode_signals(hits) -> tuple[str, ...]:
    """Distinct Google Consent Mode ``gcs`` values observed on the wire."""
    signals: set[str] = set()
    for hit in hits:
        for p in hit.params:
            if p.key == "gcs" and p.value:
                signals.add(p.value)
    return tuple(sorted(signals))


def derive_consent_state(
    storage_snapshots,
    hits,
    is_third_party_host,
) -> ConsentState:
    """Derive the session's consent state and compliance offenders.

    ``hits`` is the analysis's hit list; ``is_third_party_host`` is a
    predicate ``host -> bool``. A *tracking hit* is a third-party (or
    cloak/proxy-marked) hit, excluding the CMP modules themselves,
    that shipped at least one PII/identifier field.

    Without any decodable artifact: ``"none"`` when one of the
    decodable CMPs fired (those persist nothing until a choice),
    ``"unknown"`` otherwise — never guessed.
    """
    # Local import: keep this module free of a hard dependency on the
    # category constants' location (and avoid an import cycle).
    from ..modules.base import CAT_IDENTIFIER, CAT_PII

    def _is_tracking_hit(hit) -> bool:
        if hit.module_id in _CMP_MODULE_IDS:
            return False
        marked = any(
            p.key.startswith(_OVERRIDE_PREFIXES) for p in hit.params
        )
        if not marked and not is_third_party_host(hit.host):
            return False
        return any(
            p.category in (CAT_PII, CAT_IDENTIFIER) for p in hit.params
        )

    decision, first_ts = _decode_decision(storage_snapshots)
    if decision is None:
        # Self-hosted banners (LCP/Icordis) persist no decodable
        # artifact; their decision form POST is the artifact instead.
        decision, first_ts = _decode_decision_posts(hits)
    fired_module_ids = {hit.module_id for hit in hits}
    if decision is not None:
        state, source, granted = decision.state, decision.source, decision.granted
    elif fired_module_ids & _DECODABLE_CMP_MODULE_IDS:
        state, source, granted = "none", None, ()
    else:
        state, source, granted = "unknown", None, ()

    cmp_names = tuple(sorted({
        hit.module_name for hit in hits if hit.module_id in _CMP_MODULE_IDS
    }))
    pre, post = _offender_vendors(hits, _is_tracking_hit, state, first_ts)
    return ConsentState(
        state=state,
        source=source,
        granted=granted,
        decided_at=first_ts,
        pre_decision_vendors=pre,
        post_reject_vendors=post,
        consent_mode_signals=_consent_mode_signals(hits),
        cmp_names=cmp_names,
    )


__all__ = [
    "CONSENT_COOKIE_NAMES",
    "ConsentDecision",
    "ConsentState",
    "decode_consent_artifact",
    "derive_consent_state",
]
