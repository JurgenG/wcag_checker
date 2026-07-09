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

"""Debug reporter: surface third-party hosts no module claimed.

Aggregates :attr:`Analysis.untracked_requests` by host so the operator
can spot candidate trackers worth adding a module for. Each per-host
section is self-contained and intended to be pipeable into a Claude
Code session for module drafting.

"Third-party" is determined via :mod:`tldextract` against the bundle
manifest's ``base_domain``, with operator-family awareness from
:mod:`leak_inspector.analysis.operator_families`: a request whose
registrable domain differs from ``base_domain`` is third-party
*unless* the two domains belong to the same curated operator family
(e.g. ``s-microsoft.com`` collapses into ``microsoft.com``).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from io import StringIO
from typing import Any

from ..analysis import Analysis
from ..events import RequestEvent


_VALUE_MAX = 80


@dataclass
class UnknownHost:
    """Aggregated view of one third-party host that no module claimed."""

    host: str
    count: int = 0
    methods: Counter = field(default_factory=Counter)
    statuses: Counter = field(default_factory=Counter)
    sample_urls: list[tuple[str, str]] = field(default_factory=list)
    param_samples: dict[str, str] = field(default_factory=dict)
    first_initiator: str | None = None
    first_event_id: int | None = None
    first_timestamp: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Render as a plain dict for JSON output."""
        return {
            "host": self.host,
            "count": self.count,
            "methods": dict(self.methods),
            "statuses": {str(k): v for k, v in self.statuses.items()},
            "sample_urls": [
                {"method": m, "url": u} for m, u in self.sample_urls
            ],
            "param_samples": dict(self.param_samples),
            "first_initiator": self.first_initiator,
            "first_event_id": self.first_event_id,
            "first_timestamp": self.first_timestamp,
        }




def collect_unknown_hosts(analysis: Analysis) -> list[UnknownHost]:
    """Aggregate :attr:`Analysis.untracked_requests` into per-host summaries.

    Returns one :class:`UnknownHost` per distinct third-party host, sorted
    by hit count descending (so the most-frequent candidate surfaces first).
    """
    grouped: dict[str, UnknownHost] = {}

    for event in analysis.untracked_requests:
        if not analysis.is_third_party_host(event.host):
            continue
        entry = grouped.get(event.host)
        if entry is None:
            entry = UnknownHost(host=event.host)
            grouped[event.host] = entry
        _accumulate(entry, event)

    return sorted(grouped.values(), key=lambda h: (-h.count, h.host))


def _accumulate(entry: UnknownHost, event: RequestEvent) -> None:
    """Fold one event into the running per-host aggregate."""
    entry.count += 1
    entry.methods[event.method] += 1
    if event.response_status is not None:
        entry.statuses[event.response_status] += 1
    if len(entry.sample_urls) < 3:
        entry.sample_urls.append((event.method, event.url))
    for key, value in event.all_params.items():
        # Keep the FIRST observed value per key — keeps the dump
        # compact while still surfacing realistic values.
        entry.param_samples.setdefault(key, value)
    if entry.first_initiator is None and event.initiator:
        entry.first_initiator = event.initiator
    if entry.first_event_id is None:
        entry.first_event_id = event.event_id
        entry.first_timestamp = event.timestamp


def write_debug_report(analysis: Analysis) -> str:
    """Render the unknown-hosts dump as markdown.

    Output is a self-contained markdown document that can be piped into
    a Claude Code session to draft new tracker modules.
    """
    unknowns = collect_unknown_hosts(analysis)
    out = StringIO()

    out.write("# Unknown third-party hosts\n\n")
    out.write(
        f"Capture: `{analysis.manifest.target_url}` "
        f"(base_domain: `{analysis.manifest.base_domain}`)\n\n"
    )
    if not unknowns:
        out.write("No unclaimed third-party requests in this capture.\n")
        return out.getvalue()

    out.write(f"Total unknown hosts: **{len(unknowns)}**\n\n")
    out.write(
        "Paste any single section below into Claude Code to draft a new "
        "`leak_inspector` tracker module. Use `leak_inspector/modules/google_fonts.py` "
        "or `clarity.py` as a structural reference.\n\n"
    )
    out.write("---\n\n")

    for entry in unknowns:
        _write_host_section(out, entry)
        out.write("---\n\n")

    return out.getvalue()


def _write_host_section(out: StringIO, entry: UnknownHost) -> None:
    """Write one host's aggregated info as a markdown section."""
    out.write(f"## `{entry.host}`\n\n")
    out.write(f"- **Total hits:** {entry.count}\n")
    out.write(f"- **Methods:** {_format_counter(entry.methods)}\n")
    out.write(
        f"- **Status codes:** {_format_counter(entry.statuses) or '—'}\n"
    )
    if entry.first_event_id is not None:
        out.write(
            f"- **First seen:** event_id={entry.first_event_id} "
            f"at {entry.first_timestamp}\n"
        )
    if entry.first_initiator:
        out.write(f"- **First initiator:** `{entry.first_initiator}`\n")
    out.write("\n")

    out.write("**Sample URLs:**\n\n")
    for method, url in entry.sample_urls:
        out.write(f"- `{method} {url}`\n")
    out.write("\n")

    if entry.param_samples:
        out.write("**Observed parameter keys (with first observed value):**\n\n")
        for key in sorted(entry.param_samples):
            value = _truncate(entry.param_samples[key])
            out.write(f"- `{key}` = `{value}`\n")
        out.write("\n")


def _format_counter(counter: Counter) -> str:
    """Render a ``Counter`` as ``a=N, b=M`` in descending-count order."""
    return ", ".join(f"{k}={v}" for k, v in counter.most_common())


def _truncate(value: str, limit: int = _VALUE_MAX) -> str:
    """Cap parameter values so the markdown stays readable."""
    if len(value) <= limit:
        return value
    return value[: limit - 1] + "…"


__all__ = [
    "UnknownHost",
    "collect_unknown_hosts",
    "write_debug_report",
]
