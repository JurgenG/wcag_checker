"""Hard-EOL table + judgment for detected CMS versions.

Conservative by design (per CLAUDE.md "no speculation"): we only flag
versions whose end-of-life date is published by the upstream vendor
and is definitively in the past. No "behind current" or "outdated"
heuristics — those are judgment calls a tool can't reliably make.

Each entry's :class:`_EOLEntry` carries the EOL date and a one-line
explanation suitable for the report banner.

Sources:
* Drupal: https://www.drupal.org/about/core/policies/core-release-cycles/schedule
* Joomla: https://docs.joomla.org/Joomla_versions
* Magento / Adobe Commerce: Adobe Commerce / Magento Open Source LTS schedule

Deliberately descoped from v1:
* **TYPO3** — has a documented LTS schedule with both free-community
  and paid-ELTS support windows. Picking the right cutoff (community
  end vs. ELTS end) is a policy call and the published per-version
  dates need verification against ``typo3.org`` before encoding.
  TYPO3 is still passively detected and the version is surfaced when
  meta-generator carries it; only the EOL flag is missing.
* **WordPress** — WordPress's security-backport policy makes single-
  version EOL judgments unreliable; intentionally not shipped here.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date
from typing import Optional

from .detect import CMSFingerprint


@dataclass(frozen=True)
class _EOLEntry:
    """One EOL fact: ``<platform> <version-prefix>`` reached EOL on ``date``."""

    platform: str
    version_prefix: str    # major-only prefix match: "7" matches "7", "7.99", "7.0.1"
    eol_date: date
    note: str              # report-ready one-line explanation


#: Documented end-of-life dates. Each entry is a single hard fact.
_EOL_TABLE: tuple[_EOLEntry, ...] = (
    _EOLEntry(
        platform="Drupal",
        version_prefix="7",
        eol_date=date(2025, 1, 5),
        note=(
            "Drupal 7 reached end-of-life on 2025-01-05. No further "
            "security updates from the Drupal Association."
        ),
    ),
    _EOLEntry(
        platform="Drupal",
        version_prefix="8",
        eol_date=date(2021, 11, 2),
        note=(
            "Drupal 8 reached end-of-life on 2021-11-02. No further "
            "security updates."
        ),
    ),
    _EOLEntry(
        platform="Drupal",
        version_prefix="9",
        eol_date=date(2023, 11, 1),
        note=(
            "Drupal 9 reached end-of-life on 2023-11-01. No further "
            "security updates."
        ),
    ),
    _EOLEntry(
        platform="Joomla",
        version_prefix="3",
        eol_date=date(2023, 8, 17),
        note=(
            "Joomla 3.x reached end-of-life on 2023-08-17. No further "
            "security updates."
        ),
    ),
    _EOLEntry(
        platform="Joomla",
        version_prefix="4",
        eol_date=date(2025, 10, 17),
        note=(
            "Joomla 4.x reached end-of-life on 2025-10-17. No further "
            "security updates; upgrade to Joomla 5."
        ),
    ),
    _EOLEntry(
        platform="Magento",
        version_prefix="1",
        eol_date=date(2020, 6, 30),
        note=(
            "Magento 1.x reached end-of-life on 2020-06-30. Adobe ended "
            "official support; PCI-compliant alternatives required."
        ),
    ),
)


def is_eol_past(platform: str, version: Optional[str], *, today: date) -> bool:
    """Return ``True`` if ``platform`` ``version`` is past its documented EOL.

    Matches by major-version prefix: ``"7"`` matches ``"7"``, ``"7.99"``,
    ``"7.0.1"``. Unknown platforms or unmappable versions return ``False``
    rather than guess.
    """
    if not version:
        return False
    entry = _lookup(platform, version)
    if entry is None:
        return False
    return today >= entry.eol_date


def apply_eol_judgment(
    fp: Optional[CMSFingerprint], *, today: date,
) -> Optional[CMSFingerprint]:
    """Stamp the EOL flag + explanatory note onto a fingerprint, if applicable.

    Returns ``None`` unchanged when no fingerprint was detected.
    Otherwise returns a copy with ``is_eol`` / ``eol_note`` set when
    the version is past a documented EOL date, untouched otherwise.
    """
    if fp is None:
        return None
    entry = _lookup(fp.name, fp.version)
    if entry is None or today < entry.eol_date:
        return fp
    return replace(fp, is_eol=True, eol_note=entry.note)


def _lookup(platform: str, version: Optional[str]) -> Optional[_EOLEntry]:
    """Find the EOL entry matching ``platform`` and ``version`` (by major prefix)."""
    if not version:
        return None
    major = version.split(".", 1)[0]
    for entry in _EOL_TABLE:
        if entry.platform == platform and entry.version_prefix == major:
            return entry
    return None


__all__ = ["apply_eol_judgment", "is_eol_past"]
