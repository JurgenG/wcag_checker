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

"""Enrichment: the live-network phase of the pipeline.

Runs once, immediately after capture (or retrofitted via
``leak-inspector enrich``), and stores its results as the
``enrichment.json`` entry *inside* the capture zip — DNS posture,
transport posture, CMS version probe, per-host IP/ASN/geo info, all
timestamped. Analysis and reporting then work fully offline,
consuming the stored artifact instead of probing the network.

Boundary: this package reads bundles and uses :mod:`..dns_posture`,
:mod:`..http_posture` and :mod:`..cms`. It never imports
:mod:`..analysis` or :mod:`..modules`.
"""

from .artifact import (
    ENRICHMENT_SECTIONS,
    ENRICHMENT_VERSION,
    ENRICHMENT_ZIP_ENTRY,
    CMSVersionProbe,
    Enrichment,
    enrichment_from_json,
    enrichment_to_json,
)

__all__ = [
    "ENRICHMENT_SECTIONS",
    "ENRICHMENT_VERSION",
    "ENRICHMENT_ZIP_ENTRY",
    "CMSVersionProbe",
    "Enrichment",
    "enrichment_from_json",
    "enrichment_to_json",
]
