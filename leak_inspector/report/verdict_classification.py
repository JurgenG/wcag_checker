"""Curated classification map for the manager-facing verdict.

Each entry tags one vendor as ``expected`` (normal infrastructure for
the target audience), ``actionable`` (small fixes that improve privacy
posture), or ``strategic`` (a procurement or policy question, not a
quick fix). Unknown vendors render as ``unclassified`` so the verdict
is honestly partial rather than guessing.

Two distinct key kinds, intentionally separate:

* :data:`MODULE_VERDICTS` keyed by ``TrackerModule.module_id`` —
  matched exactly. Snake_case slug.
* :data:`VENDOR_VERDICTS` keyed by a substring of the human-readable
  vendor string produced by, e.g., the DNS-TXT verification scanner.
  Matched case-insensitively.

Seed contents are drawn from a real Belgian-municipality capture
(brecht.be). New entries land only when a real capture justifies them.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VendorVerdict:
    """One vendor's category + one-line plain-language explanation."""

    category: str   # "expected" | "actionable" | "strategic" | "unclassified"
    note: str


#: Sentinel returned for any key the operator has not yet classified.
#: Empty note so callers can detect unmapped entries.
_UNCLASSIFIED = VendorVerdict(category="unclassified", note="")


#: Vendors keyed by ``TrackerModule.module_id``. Exact-match lookup.
MODULE_VERDICTS: dict[str, VendorVerdict] = {
    "gov_flanders": VendorVerdict(
        category="expected",
        note=(
            "Vlaanderen widgets (Mijn Burgerprofiel, contact APIs) are "
            "standard for a Flemish municipal site."
        ),
    ),
    "google_fonts": VendorVerdict(
        category="actionable",
        note=(
            "Font files load from Google. Self-host the fonts to remove "
            "the third-party request to a US-jurisdiction provider."
        ),
    ),
}


#: Vendors keyed by a substring of the DNS-disclosed vendor string.
#: Case-insensitive substring match.
VENDOR_VERDICTS: dict[str, VendorVerdict] = {
    "Microsoft 365": VendorVerdict(
        category="strategic",
        note=(
            "Mail and collaboration run on Microsoft 365 (US "
            "jurisdiction: CLOUD Act, FISA 702). Acceptable depends on "
            "the data handled and the procurement policy."
        ),
    ),
    "Google": VendorVerdict(
        category="strategic",
        note=(
            "A Google verification token is published in DNS (typically "
            "Workspace or Search Console). US jurisdiction (CLOUD Act, "
            "FISA 702). Acceptable depends on the data handled and the "
            "procurement policy."
        ),
    ),
    "Apple": VendorVerdict(
        category="strategic",
        note=(
            "Apple services domain verification present (US "
            "jurisdiction: CLOUD Act, FISA 702). Acceptable depends on "
            "the use case."
        ),
    ),
}


def classify_module(module_id: str) -> VendorVerdict:
    """Look up a verdict by tracker-module id.

    Exact match. Returns the ``unclassified`` sentinel for any key not
    in :data:`MODULE_VERDICTS`. Never raises.
    """
    return MODULE_VERDICTS.get(module_id, _UNCLASSIFIED)


def classify_vendor(vendor: str) -> VendorVerdict:
    """Look up a verdict by DNS-disclosed vendor string.

    A key matches when **every whitespace-separated token in the key**
    appears as a case-insensitive substring of ``vendor`` (order-
    independent). So the seed key ``"Google Workspace"`` matches
    ``"Google (Workspace / Search Console)"``: the punctuation splits
    the words but both tokens are still present.

    Longest-key-first ordering means that if a future entry collides
    on a prefix (e.g. a generic ``"Google"`` next to ``"Google
    Workspace"``), the more specific one wins. Returns the
    ``unclassified`` sentinel when no key matches. Never raises.
    """
    if not vendor:
        return _UNCLASSIFIED
    lowered = vendor.lower()
    for key in sorted(VENDOR_VERDICTS, key=lambda k: len(k.split()), reverse=True):
        tokens = key.lower().split()
        if all(token in lowered for token in tokens):
            return VENDOR_VERDICTS[key]
    return _UNCLASSIFIED


__all__ = [
    "MODULE_VERDICTS",
    "VENDOR_VERDICTS",
    "VendorVerdict",
    "classify_module",
    "classify_vendor",
]
