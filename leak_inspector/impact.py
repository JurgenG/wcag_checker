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

"""Impact ratings — the unit of the Scoring-v2 model.

Every tracker module and every non-module signal carries one curated
:class:`ImpactRating`: ``(privacy, security, resilience)``, each
0.0–5.0 in half-point steps. The 33 evaluation criteria that give the
values meaning live in ``docs/SCORING.md``; the aggregation is
cumulative deduction per dimension, floored at zero.

This module is deliberately dependency-free (it sits below
``modules/``, ``report/`` and the posture packages) and holds:

* :class:`ImpactRating` — the validated triple.
* the **signal-rating registry** — non-module signals (header checks,
  cookie signals, DNS findings, …) declare their triple next to their
  own definition via :func:`register_signal_rating`; the scorer reads
  them back with :func:`signal_ratings`.
* :func:`ratings_overview_rows` — the generated overview of every
  rating (modules + signals). The table is *derived* from the
  registries, never hand-maintained; unrated modules appear with
  ``None`` values so the sweep's remaining work stays visible.
"""

from __future__ import annotations

from dataclasses import dataclass, fields

#: The 11 permitted values per domain: 0.0 … 5.0 in half-point steps.
VALID_IMPACT_VALUES: frozenset[float] = frozenset(
    n / 2 for n in range(0, 11)
)


@dataclass(frozen=True)
class ImpactRating:
    """One curated impact triple, validated at construction.

    Each value answers its domain's rubric question for *this* module
    or signal (see ``docs/SCORING.md``): what does it learn
    about the visitor (privacy), what attack surface does embedding it
    add (security), how much operator control does depending on it
    cost (resilience). 0.0 = no impact, 5.0 = disastrous; half-point
    steps only.
    """

    privacy: float
    security: float
    resilience: float

    def __post_init__(self) -> None:
        for f in fields(self):
            value = float(getattr(self, f.name))
            if value not in VALID_IMPACT_VALUES:
                raise ValueError(
                    f"{f.name} impact must be 0.0–5.0 in half-point "
                    f"steps, got {getattr(self, f.name)!r}"
                )
            object.__setattr__(self, f.name, value)


# --- signal-rating registry -----------------------------------------------------

#: ``signal_id -> ImpactRating`` for everything that costs points but is
#: not a tracker module. Populated at import time by the modules that
#: define the signals (Phase 4 of the roadmap).
_SIGNAL_RATINGS: dict[str, ImpactRating] = {}


def register_signal_rating(signal_id: str, rating: ImpactRating) -> None:
    """Declare a non-module signal's impact triple.

    Called once per signal, next to the signal's own definition.
    Raises :class:`ValueError` on duplicate registration — two owners
    for one signal is always a bug.
    """
    if signal_id in _SIGNAL_RATINGS:
        raise ValueError(f"signal rating already registered: {signal_id}")
    _SIGNAL_RATINGS[signal_id] = rating


def signal_ratings() -> dict[str, ImpactRating]:
    """A copy of the registered signal ratings (``signal_id -> rating``)."""
    return dict(_SIGNAL_RATINGS)


# --- generated overview ----------------------------------------------------------


def ratings_overview_rows(modules, signals) -> list[dict]:
    """Build the full ratings overview from the registries.

    ``modules`` is an iterable of registered tracker-module instances
    (``module_id`` / ``module_name`` / ``impact_rating``); ``signals``
    is a ``signal_id -> ImpactRating`` mapping. Returns one dict per
    entry, modules first, each kind sorted by id — deterministic, so
    the generated table diffs cleanly. Unrated modules appear with
    ``None`` values: during the rating sweep the table doubles as the
    worklist.
    """
    rows: list[dict] = []
    for module in sorted(modules, key=lambda m: m.module_id):
        rating = module.impact_rating
        rows.append({
            "kind": "module",
            "id": module.module_id,
            "name": module.module_name,
            "privacy": rating.privacy if rating else None,
            "security": rating.security if rating else None,
            "resilience": rating.resilience if rating else None,
        })
    for signal_id in sorted(signals):
        rating = signals[signal_id]
        rows.append({
            "kind": "signal",
            "id": signal_id,
            "name": signal_id,
            "privacy": rating.privacy,
            "security": rating.security,
            "resilience": rating.resilience,
        })
    return rows


__all__ = [
    "VALID_IMPACT_VALUES",
    "ImpactRating",
    "ratings_overview_rows",
    "register_signal_rating",
    "signal_ratings",
]
