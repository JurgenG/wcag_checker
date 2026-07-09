"""Owner + effort hints, keyed by Finding.kind.

The verdict layer attaches a small operational hint to selected
findings: who probably fixes this (web team / mail admin / etc.) and
roughly how much effort it costs (low / low-medium / medium / high).

Seeded conservatively. A finding kind is only seeded when:

* The Finding is actually emitted somewhere in ``_build_findings``
  today, AND
* The owner and effort are obvious from the technical content
  (a DNS-record change is "mail admin / low-medium"; a tracker leak
  pattern is "web team / low").

Unmapped kinds return ``None``; the renderer leaves those findings'
text unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ActionMetadata:
    """One finding's operational hint."""

    owner: str
    effort: str   # "low" | "low-medium" | "medium" | "high"


#: Keyed by ``Finding.kind`` slug.
ACTION_METADATA: dict[str, ActionMetadata] = {
    "dmarc_p_none": ActionMetadata(
        owner="mail admin",
        effort="low-medium",
    ),
}


def metadata_for(kind: str) -> Optional[ActionMetadata]:
    """Look up the metadata for one Finding.kind, or ``None`` if unseeded.

    Empty / falsy ``kind`` returns ``None`` so the default
    ``Finding.kind=""`` does not accidentally match an entry.
    """
    if not kind:
        return None
    return ACTION_METADATA.get(kind)


__all__ = ["ACTION_METADATA", "ActionMetadata", "metadata_for"]
