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

"""GeoLite2-Country mmdb lookup + on-demand download helper.

The mmdb file is not bundled in the repo — it must be downloaded once
from MaxMind using the user's free license key. The ``leak-inspector
update-geoip`` CLI subcommand wraps :func:`download_geoip_db`; at
analysis time :func:`open_country_reader` opens whatever mmdb the
user has cached and returns a tiny adapter with one method,
:meth:`CountryReader.country`.

If no mmdb is present, lookups return empty strings — every other
DNS-posture field still works, only the country labels go blank.
"""

from __future__ import annotations

import io
import os
import tarfile
import urllib.request
from pathlib import Path


_DEFAULT_CACHE_PATH = Path.home() / ".cache" / "leak_inspector" / "GeoLite2-Country.mmdb"
_ENV_OVERRIDE = "LEAK_INSPECTOR_GEOIP_DB"
_DOWNLOAD_URL = (
    "https://download.maxmind.com/app/geoip_download"
    "?edition_id=GeoLite2-Country&suffix=tar.gz&license_key={key}"
)


def cached_db_path() -> Path:
    """Where the mmdb is expected to live.

    Honours the ``LEAK_INSPECTOR_GEOIP_DB`` environment variable; falls
    back to ``~/.cache/leak_inspector/GeoLite2-Country.mmdb``.
    """
    override = os.environ.get(_ENV_OVERRIDE)
    if override:
        return Path(override).expanduser()
    return _DEFAULT_CACHE_PATH


class CountryReader:
    """Tiny wrapper over a maxminddb reader exposing one method.

    Hides the underlying library so callers don't need to handle
    :exc:`AddressNotFoundError` themselves and so the rest of the
    package can be tested without the C extension installed.
    """

    def __init__(self, reader) -> None:  # ``maxminddb.Reader``; left untyped
        self._reader = reader

    def country(self, ip: str) -> tuple[str, str]:
        """Return ``(iso_code, english_name)`` or ``("", "")``."""
        try:
            record = self._reader.get(ip)
        except (ValueError, KeyError):
            return "", ""
        if not isinstance(record, dict):
            return "", ""
        country = record.get("country") or record.get("registered_country") or {}
        if not isinstance(country, dict):
            return "", ""
        iso = str(country.get("iso_code") or "")
        names = country.get("names") or {}
        name = ""
        if isinstance(names, dict):
            name = str(names.get("en") or "")
        return iso, name

    def close(self) -> None:
        try:
            self._reader.close()
        except Exception:  # pragma: no cover -- defensive
            pass


def open_country_reader(path: Path | None = None) -> CountryReader | None:
    """Open the GeoLite2-Country mmdb at ``path``.

    Returns ``None`` if the file is absent, unreadable, or the
    ``maxminddb`` package is not installed. Callers treat ``None`` as
    "geo unavailable" and fall back to ASN-only attribution.
    """
    db_path = path or cached_db_path()
    if not db_path.exists():
        return None
    try:
        import maxminddb
    except ImportError:
        return None
    try:
        reader = maxminddb.open_database(str(db_path))
    except Exception:
        return None
    return CountryReader(reader)


# --- download helper -------------------------------------------------------


class GeoIPDownloadError(RuntimeError):
    """Raised when the GeoLite2 mmdb cannot be downloaded or extracted."""


def download_geoip_db(
    license_key: str,
    destination: Path | None = None,
    *,
    timeout: float = 60.0,
) -> Path:
    """Fetch the GeoLite2-Country mmdb from MaxMind and cache it.

    MaxMind ships the database as a ``.tar.gz`` archive containing one
    versioned directory. We extract the ``.mmdb`` from that directory
    and write it to ``destination`` (or :func:`cached_db_path` by
    default), creating parent directories as needed.

    Returns the absolute path the file was written to. Raises
    :exc:`GeoIPDownloadError` on any failure — caller (CLI) renders
    the message and exits.
    """
    if not license_key:
        raise GeoIPDownloadError(
            "MaxMind license key is required. Set $MAXMIND_LICENSE_KEY or pass --key."
        )

    target = destination or cached_db_path()
    target.parent.mkdir(parents=True, exist_ok=True)

    url = _DOWNLOAD_URL.format(key=license_key)
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            payload = response.read()
    except urllib.error.HTTPError as exc:
        if exc.code in (401, 403):
            raise GeoIPDownloadError(
                "MaxMind rejected the license key — verify $MAXMIND_LICENSE_KEY."
            ) from exc
        raise GeoIPDownloadError(
            f"MaxMind download failed (HTTP {exc.code}): {exc.reason}"
        ) from exc
    except urllib.error.URLError as exc:
        raise GeoIPDownloadError(f"network error downloading mmdb: {exc.reason}") from exc

    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as tar:
            mmdb_member = next(
                (m for m in tar.getmembers() if m.name.endswith(".mmdb")),
                None,
            )
            if mmdb_member is None:
                raise GeoIPDownloadError("no .mmdb file found inside the downloaded archive")
            extracted = tar.extractfile(mmdb_member)
            if extracted is None:
                raise GeoIPDownloadError("could not extract the mmdb from the archive")
            target.write_bytes(extracted.read())
    except tarfile.TarError as exc:
        raise GeoIPDownloadError(f"corrupt MaxMind archive: {exc}") from exc

    return target


__all__ = [
    "CountryReader",
    "GeoIPDownloadError",
    "cached_db_path",
    "download_geoip_db",
    "open_country_reader",
]
