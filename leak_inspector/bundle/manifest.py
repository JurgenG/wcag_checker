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

"""Bundle manifest schema.

A manifest is the bundle's public API. Capture writes it; analysis reads
it. The ``bundle_schema`` field is the version of this contract — readers
refuse bundles they do not know how to interpret.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

#: Schema version this code knows how to write and read.
BUNDLE_SCHEMA_VERSION = 1

#: Canonical tool identifier embedded in every bundle.
TOOL_NAME = "leak_inspector"


class ManifestError(ValueError):
    """Raised when a manifest is missing required fields or fails validation."""


_REQUIRED_FIELDS = (
    "bundle_schema",
    "tool",
    "tool_version",
    "session_id",
    "started_at",
    "ended_at",
    "target_url",
    "base_domain",
    "browser",
    "profile",
)


@dataclass
class Manifest:
    """Bundle metadata.

    Field names and types mirror the on-disk JSON. See PROJECT.md for the
    canonical schema description.

    ``target_url`` is what the operator passed on the command line.
    ``landing_url`` is where the browser actually ended up after the
    initial-page redirect chain settled — for sites that redirect the
    bare apex to a marketing host (``museumpas.be`` → ``museumpassmusees.be``),
    the two differ. ``base_domain`` is computed from ``landing_url`` when
    present so the third-party / first-party classifier uses the
    operator's *actual* host. ``landing_url`` is optional: old bundles
    without the field still parse, and capture pre-redirect-tracking
    versions of the tool leave it empty.
    """

    bundle_schema: int
    tool: str
    tool_version: str
    session_id: str
    started_at: str
    ended_at: str
    target_url: str
    base_domain: str
    browser: dict[str, str]
    profile: str
    landing_url: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return the manifest as a JSON-serializable dict."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Manifest":
        """Build a :class:`Manifest` from a parsed JSON dict.

        Raises :class:`ManifestError` if required fields are missing or
        if the schema version is one this code does not understand.
        """
        missing = [f for f in _REQUIRED_FIELDS if f not in data]
        if missing:
            raise ManifestError(
                f"manifest missing required field(s): {', '.join(missing)}"
            )

        schema = data["bundle_schema"]
        if schema != BUNDLE_SCHEMA_VERSION:
            raise ManifestError(
                f"unsupported bundle_schema {schema!r}; "
                f"this build understands {BUNDLE_SCHEMA_VERSION}"
            )

        browser = data["browser"]
        if not isinstance(browser, dict):
            raise ManifestError("manifest 'browser' must be an object")

        return cls(
            bundle_schema=schema,
            tool=data["tool"],
            tool_version=data["tool_version"],
            session_id=data["session_id"],
            started_at=data["started_at"],
            ended_at=data["ended_at"],
            target_url=data["target_url"],
            base_domain=data["base_domain"],
            browser=dict(browser),
            profile=data["profile"],
            landing_url=data.get("landing_url", ""),
        )


__all__ = [
    "BUNDLE_SCHEMA_VERSION",
    "Manifest",
    "ManifestError",
    "TOOL_NAME",
]