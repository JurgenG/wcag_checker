# wcag_checker — record a real human-driven browsing session and audit
# the visited pages for WCAG 2.2 accessibility conformance.
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

"""Translate user-facing text into the operator's chosen language.

English is the source language: user-facing strings are written in
English in the code and passed through :func:`tr`, which looks them up
in the catalog of the requested language and fills in ``{named}``
placeholders. Every other language has a catalog module in this package
(``nl`` …) whose ``MESSAGES`` maps English source text to its
translation and whose ``CRITERION_NAMES`` maps WCAG success-criterion ids
to their official titles in that language.

Strings defined as constants and translated later are wrapped in
:func:`N_`, a no-op marker, so the catalog-completeness test finds them.

Pure: no I/O, no driver. Imported by every layer that renders text.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import Mapping

from . import nl

#: The language the source strings are written in.
SOURCE_LANG = "en"

#: The language used when the operator does not choose one.
DEFAULT_LANG = "nl"

#: Supported languages, by ISO 639-1 code.
LANGUAGES: tuple[str, ...] = ("en", "nl")

#: Translation catalogs per non-source language.
CATALOGS: Mapping[str, Mapping[str, str]] = MappingProxyType({"nl": nl.MESSAGES})

#: Official WCAG 2.2 success-criterion titles per non-source language.
CRITERION_NAMES: Mapping[str, Mapping[str, str]] = MappingProxyType(
    {"nl": nl.CRITERION_NAMES}
)


def N_(text: str) -> str:
    """Mark ``text`` as translatable without translating it; returns it as-is."""
    return text


def tr(lang: str, text: str, /, **params: object) -> str:
    """Return ``text`` in ``lang`` with ``{name}`` placeholders filled in.

    ``text`` is the English source string. It is looked up in the
    catalog for ``lang``; English, or a string without a translation,
    is returned in English. ``params`` fill the placeholders with
    :meth:`str.format`; without params the text is returned verbatim, so
    literal braces need no escaping.
    """
    template = CATALOGS.get(lang, {}).get(text, text)
    return template.format(**params) if params else template


def criterion_name(lang: str, criterion_id: str, english_name: str) -> str:
    """Return the official title of a WCAG criterion in ``lang``.

    Falls back to ``english_name`` for English or an unknown id.
    """
    return CRITERION_NAMES.get(lang, {}).get(criterion_id, english_name)


def check_lang(lang: str) -> str:
    """Return ``lang`` if supported, else raise :class:`ValueError`."""
    if lang not in LANGUAGES:
        raise ValueError(
            f"unsupported language {lang!r}; choose from {', '.join(LANGUAGES)}"
        )
    return lang


__all__ = [
    "CATALOGS",
    "CRITERION_NAMES",
    "DEFAULT_LANG",
    "LANGUAGES",
    "N_",
    "SOURCE_LANG",
    "check_lang",
    "criterion_name",
    "tr",
]
