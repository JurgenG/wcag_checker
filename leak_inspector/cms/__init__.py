"""CMS / web-platform fingerprinting.

Identifies the content-management system or hosted platform behind a
captured site using highly-specific signals (vendor headers, well-
known URL paths, platform-specific cookies). Per CLAUDE.md only
"certain" matches ship — signatures that effectively cannot
false-positive on a non-platform site.

Version detection is best-effort: surfaced when the platform exposes
it (header, meta-generator tag, asset query string), left as ``None``
otherwise.
"""

from __future__ import annotations

from .detect import CMSFingerprint, detect_cms

__all__ = ["CMSFingerprint", "detect_cms"]
