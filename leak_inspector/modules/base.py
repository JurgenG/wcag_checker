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

"""Tracker module framework.

A *tracker module* recognizes outbound requests belonging to one specific
third-party service (GA4, Google Fonts, Clarity, ...). For each request it
matches, it produces a :class:`Hit` describing the request and a typed
:class:`ParamInfo` per parameter it observed.

Modules consume :class:`leak_inspector.events.RequestEvent` only. They do
not touch the bundle, the filesystem, or the network.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from ..events import RequestEvent
from ..impact import ImpactRating


# --- parameter categories --------------------------------------------------

CAT_PII = "pii"
CAT_IDENTIFIER = "identifier"
CAT_BEHAVIORAL = "behavioral"
CAT_HTTP_TRAFFIC = "http_traffic"
CAT_TECHNICAL = "technical"
CAT_CONSENT = "consent"
CAT_CONTENT = "content"
CAT_OTHER = "other"

#: Categories in their canonical reporting order (most → least sensitive).
#:
#: ``http_traffic`` covers the ambient request metadata (IP, Referer,
#: User-Agent, Cookie, …) that *every* external request discloses by
#: virtue of being made.
CATEGORIES: tuple[str, ...] = (
    CAT_PII,
    CAT_IDENTIFIER,
    CAT_BEHAVIORAL,
    CAT_HTTP_TRAFFIC,
    CAT_CONSENT,
    CAT_CONTENT,
    CAT_TECHNICAL,
    CAT_OTHER,
)


# --- privacy impact levels -------------------------------------------------

IMPACT_HIGH = "high"
IMPACT_MEDIUM = "medium"
IMPACT_LOW = "low"


# --- data shapes -----------------------------------------------------------


@dataclass
class ParamInfo:
    """One observed query/body parameter, classified by a tracker module."""

    key: str
    value: str
    category: str
    meaning: str
    privacy_impact: str
    event_index: int


@dataclass
class Hit:
    """One outbound request a module claimed.

    ``events`` holds the ``event_id`` of each :class:`RequestEvent` this
    hit covers. A fresh module emits a hit with a single event_id; the
    analysis dedup layer may roll multiple raw hits into one representative
    hit and extend the list.

    ``request_body`` and ``response_body`` are populated by the analysis
    runner from the source :class:`RequestEvent`. Modules are not
    expected to set these themselves; they're attached so reporters
    (and downstream tooling) can surface body content without having to
    re-traverse the bundle.
    """

    module_id: str
    module_name: str
    url: str
    host: str
    method: str
    response_status: int | None
    started_at: str
    params: list[ParamInfo] = field(default_factory=list)
    events: list[int] = field(default_factory=list)
    request_body: str | None = None
    response_body: str | None = None
    #: CDN / edge / vendor-own provider operating the CNAME tail for
    #: this hit's host, when one can be identified. ``None`` when the
    #: host has no CNAME hop or its tail is unknown.
    #: Populated by :func:`leak_inspector.analysis.analyze_events`.
    cdn_provider: "ProviderInfo | None" = None


# --- module interface ------------------------------------------------------


# --- module kinds ----------------------------------------------------------
#
# A module's *kind* distinguishes commercial trackers from public-sector
# services. Both kinds are still third-party data flows from the visitor's
# perspective, but the privacy implications and the report grouping are
# different (GDPR-bound EU government infra vs. e.g. a US ad network).

#: A commercial / private-sector tracker, analytics, ad-tech, or CDN.
MODULE_KIND_TRACKER = "tracker"

#: A public-sector / governmental service. Use ``government_level`` to
#: distinguish the level of government (European / federal / regional).
MODULE_KIND_GOVERNMENT = "government"

#: A para-governmental / publicly-funded entity that is not itself
#: government — typically a non-profit, intercommunal association, or
#: sector-specific public-service organisation operating on behalf of
#: government (publiq vzw, IMIO, Cultuurconnect, …). Data flows here
#: are public-sector-adjacent but the legal controller is a separate
#: entity, so the module's ``vendor`` field carries the identifying name.
MODULE_KIND_PARA_GOVERNMENT = "para_government"

#: Recognised values for :attr:`TrackerModule.government_level`. Empty
#: string means "not a government module" (the default).
GOVERNMENT_LEVELS: frozenset[str] = frozenset({
    "european",
    "federal_be",
    "regional_vlaanderen",
    "regional_wallonie",
    "regional_brussels_capital",
})


class TrackerModule:
    """Base class for tracker modules.

    Subclasses set the class-level identifiers + sovereignty attributes
    and implement :meth:`matches` and :meth:`parse`. Instances are
    stateless — the registry holds one shared instance per registered
    class.

    Sovereignty attributes (all optional, default empty):

    * ``vendor`` — legal entity that controls the data (e.g. "Microsoft
      Corporation"; may differ from ``module_name`` after acquisitions).
    * ``legal_jurisdiction`` — 2-letter ISO country code of the
      controller, or short label like ``"EU"`` for region-level entities.
      For EU users this answers "is data leaving the bloc?" — a US-based
      controller triggers Schrems II transfer concerns regardless of
      where the bytes physically sit.
    * ``data_residency`` — human-readable description of where the
      bytes typically land (e.g. "Microsoft Azure (region varies)",
      "Russia (Yandex data centers)", "Customer-controlled (self-hosted)").
    * ``sovereignty_notes`` — short note flagging non-obvious
      implications (CLOUD Act exposure, FISA 702 risk, etc.). Optional.

    Classification:

    * ``module_kind`` — :data:`MODULE_KIND_TRACKER` (default) or
      :data:`MODULE_KIND_GOVERNMENT`. Lets the report group public-sector
      third parties separately from commercial trackers.
    * ``government_level`` — only set when ``module_kind`` is
      ``"government"``. One of :data:`GOVERNMENT_LEVELS`.
    """

    module_id: ClassVar[str] = ""
    module_name: ClassVar[str] = ""

    vendor: ClassVar[str] = ""
    legal_jurisdiction: ClassVar[str] = ""
    data_residency: ClassVar[str] = ""
    sovereignty_notes: ClassVar[str] = ""

    #: Optional bucket label for the executive-summary vendor rollup.
    #: Defaults to empty, in which case the rollup uses ``vendor`` (with
    #: trailing ``" (...)"`` disambiguation stripped). Set this only when
    #: a module represents a deployment pattern that should NOT be
    #: collapsed with its parent vendor's other products — e.g. Google
    #: Tag First-Party Mode is a deliberate operator install distinct
    #: from a passive GA4 tag and warrants its own row.
    rollup_label: ClassVar[str] = ""

    module_kind: ClassVar[str] = MODULE_KIND_TRACKER
    government_level: ClassVar[str] = ""

    #: Curated Scoring-v2 impact triple — ``(privacy, security,
    #: resilience)``, 0.0–5.0 in half-point steps, rated against the 33
    #: criteria in ``docs/SCORING.md``. The one-line
    #: justification belongs in the module docstring, citing the rubric
    #: line. ``None`` = not yet rated (the sweep is roadmap Phase 3;
    #: completeness becomes a registry test at its gate).
    impact_rating: ClassVar[ImpactRating | None] = None

    #: Short report-facing explainer per domain — why this module costs
    #: what it does on ``"privacy"`` / ``"security"`` / ``"resilience"``.
    #: One per domain whose rating exceeds 1.0 (minor penalties stand on
    #: the label alone); surfaced in the report's penalty breakdown. A
    #: registry test enforces that every >1.0 domain has one.
    impact_notes: ClassVar[dict[str, str]] = {}

    def matches(self, event: RequestEvent) -> bool:
        """Return ``True`` if this module should handle ``event``."""
        raise NotImplementedError

    def parse(self, event: RequestEvent) -> Hit:
        """Build a :class:`Hit` from a request this module matched."""
        raise NotImplementedError

    def effective_rating(self, hits: list[Hit]) -> ImpactRating | None:
        """The Scoring-v2 rating for *this capture* (per-capture variant).

        ``hits`` are this module's :class:`Hit` objects in one capture.
        The default returns the base :attr:`impact_rating`; a subclass may
        override to select a *variant* when the capture shows a
        configuration that changes the impact — gated on wire-observable
        evidence only (the certainty rule: a setting we cannot see does
        not exist for scoring, so the base triple describes the product's
        documented default). An evasion-marked variant may only rate
        *higher* than the base (see ``docs/SCORING.md``,
        decision 5).
        """
        return self.impact_rating


# --- registry --------------------------------------------------------------

_REGISTRY: list[TrackerModule] = []


def register(cls: type[TrackerModule]) -> type[TrackerModule]:
    """Class decorator: instantiate the module and add it to the registry.

    Modules without a ``module_id`` are rejected — every registered module
    must be addressable by a stable identifier.
    """
    if not cls.module_id:
        raise ValueError(f"{cls.__name__} has no module_id; cannot register")
    if any(existing.module_id == cls.module_id for existing in _REGISTRY):
        raise ValueError(f"duplicate module_id: {cls.module_id!r}")
    _REGISTRY.append(cls())
    return cls


def all_modules() -> list[TrackerModule]:
    """Return every registered module instance, in registration order."""
    return list(_REGISTRY)


def detect(event: RequestEvent) -> TrackerModule | None:
    """Return the first registered module that matches ``event``, or ``None``.

    First-match-wins reflects the framework's contract: each request is
    "owned" by at most one tracker module.
    """
    for module in _REGISTRY:
        if module.matches(event):
            return module
    return None


def reset_registry() -> None:
    """Empty the registry. Intended for tests; do not call from production code."""
    _REGISTRY.clear()


__all__ = [
    "CAT_BEHAVIORAL",
    "CAT_CONSENT",
    "CAT_CONTENT",
    "CAT_HTTP_TRAFFIC",
    "CAT_IDENTIFIER",
    "CAT_OTHER",
    "CAT_PII",
    "CAT_TECHNICAL",
    "CATEGORIES",
    "Hit",
    "IMPACT_HIGH",
    "IMPACT_LOW",
    "IMPACT_MEDIUM",
    "ParamInfo",
    "TrackerModule",
    "all_modules",
    "detect",
    "register",
    "reset_registry",
]