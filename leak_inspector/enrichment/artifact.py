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

"""The enrichment artifact: schema + exact JSON round-trip.

Everything the live network contributes to a report is captured here
once, at enrichment time, and stored as the ``enrichment.json`` entry
inside the capture zip:

* **DNS posture** of the first-party domain (the full
  :class:`~leak_inspector.dns_posture.types.DNSPosture` tree),
* **transport posture** (HTTP/HTTPS probes of the landing host and
  its apex/www alternate),
* **CMS version probe** result (when a platform was fingerprinted),
* **per-host IP/ASN/geo info** for the self-hosted-collector hosts
  the analysis enriches (``host -> IPInfo | None``; ``None`` records
  an attempted-but-failed resolution so offline analysis doesn't
  mistake it for "never looked up"),
* ``enriched_at`` — the lookups' ISO-8601 UTC timestamp; reports
  display it so "posture as of <date>" is explicit.

Deserialization is *tolerant*: unknown keys are ignored (a newer
writer must not break an older reader) and missing fields take their
defaults (an older artifact stays readable). Round-trips of known
fields are exact — the offline analysis consumes these objects
through the same seams the live lookups used to fill.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, fields, is_dataclass
from typing import Any, get_args, get_origin, get_type_hints

from ..dns_posture.productivity import ProductivityProbe
from ..dns_posture.types import DNSPosture, IPInfo
from ..http_posture.probe import HostProbe, TransportPosture
from ..http_posture.security_txt import SecurityTxtProbe
from ..http_posture.tls import TLSPosture

#: Name of the artifact entry inside the capture zip.
ENRICHMENT_ZIP_ENTRY = "enrichment.json"

#: Version of the artifact's own contract (independent of the bundle
#: schema — the entry is additive, readers ignore unknown zip entries).
#: v2 added :attr:`Enrichment.section_timestamps` (per-section ages for
#: selective ``enrich --refresh <section>``); v1 artifacts read fine and
#: carry an empty map (readers fall back to ``enriched_at``). v3 added
#: :attr:`Enrichment.tls_posture` (the ``tls`` section); v1/v2 artifacts
#: read fine and carry ``None``.
ENRICHMENT_VERSION = 3

#: Canonical ids of the independently-refreshable enrichment sections,
#: in the order the producer runs them. Used as the keys of
#: :attr:`Enrichment.section_timestamps`, the producer's per-section
#: dispatch, and the CLI's ``--refresh`` choices — one source of truth.
ENRICHMENT_SECTIONS = (
    "dns", "transport", "tls", "cms-probe", "security-txt", "hosts",
)


@dataclass
class CMSVersionProbe:
    """Result of the active CMS version probe.

    ``version`` is ``None`` when the probe ran but found nothing (the
    version file may be hardened/removed — itself a useful signal);
    the whole object is ``None`` on the :class:`Enrichment` when no
    probeable platform was fingerprinted.
    """

    platform: str
    version: str | None = None
    probe_url: str = ""


@dataclass
class Enrichment:
    """All network-derived data for one capture, point-in-time."""

    version: int = ENRICHMENT_VERSION
    #: ISO-8601 UTC time of the last *full* enrichment — the baseline
    #: "posture as of <date>". A selective ``--refresh <section>`` leaves
    #: this untouched and updates only :attr:`section_timestamps`.
    enriched_at: str = ""
    #: Per-section last-probe times, keyed by :data:`ENRICHMENT_SECTIONS`
    #: id. Populated for every section on a full enrichment; a selective
    #: refresh updates only the re-probed section. Empty on v1 artifacts —
    #: readers fall back to :attr:`enriched_at`.
    section_timestamps: dict[str, str] = field(default_factory=dict)
    dns_posture: DNSPosture | None = None
    transport_posture: TransportPosture | None = None
    #: TLS-quality probe of the landing host (certificate validity/expiry,
    #: negotiated protocol/cipher, deprecated-protocol acceptance);
    #: ``None`` on artifacts that predate the probe (v1/v2).
    tls_posture: TLSPosture | None = None
    cms_probe: CMSVersionProbe | None = None
    #: RFC 9116 ``security.txt`` presence probe of the landing host;
    #: ``None`` on artifacts that predate the probe (or when the host
    #: could not be determined).
    security_txt: SecurityTxtProbe | None = None
    #: ``host -> IPInfo`` for enriched collector hosts; a ``None`` value
    #: records an attempted-but-failed resolution.
    host_ipinfo: dict[str, IPInfo | None] = field(default_factory=dict)
    #: Non-fatal lookup problems, in plain language (mirrors
    #: ``DNSPosture.errors`` at the artifact level).
    errors: list[str] = field(default_factory=list)


# --- serialization ------------------------------------------------------------


def _to_jsonable(value: Any) -> Any:
    """Recursively convert dataclasses / containers to JSON-able values."""
    if is_dataclass(value) and not isinstance(value, type):
        return {
            f.name: _to_jsonable(getattr(value, f.name))
            for f in fields(value)
        }
    if isinstance(value, dict):
        return {k: _to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_to_jsonable(v) for v in value]
    return value


def enrichment_to_json(enrichment: Enrichment) -> str:
    """Serialize an :class:`Enrichment` to the artifact's JSON form."""
    return json.dumps(_to_jsonable(enrichment), indent=2, sort_keys=True)


# --- deserialization -----------------------------------------------------------

#: ``DNSPosture.productivity_probes`` is annotated as a bare ``list``;
#: its element type can't be recovered from the hint, so it is pinned
#: here explicitly.
_UNTYPED_LIST_ELEMENTS: dict[tuple[type, str], type] = {
    (DNSPosture, "productivity_probes"): ProductivityProbe,
}


def _from_jsonable(hint: Any, value: Any) -> Any:
    """Recursively rebuild a value of type ``hint`` from JSON data."""
    if value is None:
        return None
    origin = get_origin(hint)
    if origin is not None:
        args = get_args(hint)
        # X | None — recurse on the non-None arm.
        if type(None) in args:
            inner = next(a for a in args if a is not type(None))
            return _from_jsonable(inner, value)
        if origin in (list, tuple):
            element = args[0] if args else Any
            return [_from_jsonable(element, v) for v in value]
        if origin is dict:
            value_hint = args[1] if len(args) == 2 else Any
            return {k: _from_jsonable(value_hint, v) for k, v in value.items()}
        return value
    if isinstance(hint, type) and is_dataclass(hint):
        return _dataclass_from_dict(hint, value)
    return value


def _dataclass_from_dict(cls: type, data: dict) -> Any:
    """Rebuild dataclass ``cls`` from ``data``, tolerantly.

    Unknown keys in ``data`` are ignored (forward compatibility);
    fields absent from ``data`` take their defaults (backward
    compatibility).
    """
    hints = get_type_hints(cls)
    kwargs: dict[str, Any] = {}
    for f in fields(cls):
        if f.name not in data:
            continue
        pinned = _UNTYPED_LIST_ELEMENTS.get((cls, f.name))
        if pinned is not None:
            kwargs[f.name] = [
                _dataclass_from_dict(pinned, v) for v in data[f.name]
            ]
        else:
            kwargs[f.name] = _from_jsonable(hints[f.name], data[f.name])
    return cls(**kwargs)


def enrichment_from_json(text: str) -> Enrichment:
    """Deserialize the artifact's JSON form back into an :class:`Enrichment`.

    Raises :class:`ValueError` on malformed JSON or a non-object
    top level. Unknown keys are ignored; missing fields take their
    defaults.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"malformed enrichment JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(
            f"enrichment JSON must be an object, got {type(data).__name__}"
        )
    return _dataclass_from_dict(Enrichment, data)


__all__ = [
    "ENRICHMENT_SECTIONS",
    "ENRICHMENT_VERSION",
    "ENRICHMENT_ZIP_ENTRY",
    "CMSVersionProbe",
    "Enrichment",
    "enrichment_from_json",
    "enrichment_to_json",
]
