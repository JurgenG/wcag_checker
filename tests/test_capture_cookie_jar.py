"""Tests for full cross-domain cookie-jar capture via WebDriver BiDi.

``driver.get_cookies()`` (classic WebDriver) returns only cookies scoped
to the top-level document's domain, so third-party tracker cookies — set
on e.g. ``.linkedin.com`` while browsing ``egovselect.be`` — never reach
the bundle. BiDi ``storage.getCookies`` with no filter enumerates the
*whole* jar across every domain. These tests pin the mapping from BiDi
``StorageCookie`` objects to the snapshot dict shape and assert that the
captured snapshot now carries those third-party cookies, while a driver
without BiDi storage still falls back cleanly to ``get_cookies()``.
"""

from __future__ import annotations

from selenium.webdriver.common.bidi.storage import (
    BytesValue,
    GetCookiesResult,
    StorageCookie,
)

from leak_inspector.capture.storage import (
    _full_cookie_jar,
    _storage_cookie_to_dict,
    capture_snapshot,
)


class _FakeStorage:
    """Stand-in for ``driver.storage`` (the BiDi storage module)."""

    def __init__(self, cookies):
        self._cookies = cookies

    def get_cookies(self, filter=None, partition=None):
        return GetCookiesResult(cookies=list(self._cookies), partition_key=None)


class _FakeDriver:
    """Selenium driver stand-in, optionally exposing BiDi ``.storage``."""

    def __init__(self, url, *, cookies=None, jar=None, has_storage=True):
        self.current_url = url
        self._cookies = cookies or []
        if has_storage:
            self.storage = _FakeStorage(jar or [])

    def execute_script(self, _script):
        return {"local": {}, "session": {}, "cookie": ""}

    def get_cookies(self):
        return self._cookies


def _li_cookie() -> StorageCookie:
    return StorageCookie(
        name="bcookie",
        value="v=2&abc",
        domain=".linkedin.com",
        path="/",
        http_only=False,
        secure=True,
        same_site="none",
        expiry=1900000000,
    )


# --- mapping: StorageCookie -> snapshot dict --------------------------------


def test_storage_cookie_to_dict_maps_fields() -> None:
    out = _storage_cookie_to_dict(_li_cookie())
    assert out == {
        "name": "bcookie",
        "value": "v=2&abc",
        "domain": ".linkedin.com",
        "path": "/",
        "httpOnly": False,
        "secure": True,
        "sameSite": "none",
        "expiry": 1900000000,
    }


def test_storage_cookie_to_dict_unwraps_bytesvalue() -> None:
    """``StorageCookie.value`` may arrive wrapped in a BiDi ``BytesValue``."""
    cookie = StorageCookie(name="x", value=BytesValue("string", "plain"), domain="a.be")
    assert _storage_cookie_to_dict(cookie)["value"] == "plain"


# --- _full_cookie_jar -------------------------------------------------------


def test_full_cookie_jar_returns_all_domains() -> None:
    driver = _FakeDriver("https://egovselect.be/", jar=[_li_cookie()])
    jar = _full_cookie_jar(driver)
    assert jar is not None
    assert [c["domain"] for c in jar] == [".linkedin.com"]


def test_full_cookie_jar_none_without_bidi_storage() -> None:
    """A driver with no ``.storage`` must yield ``None`` so the caller falls back."""
    driver = _FakeDriver("https://egovselect.be/", has_storage=False)
    assert _full_cookie_jar(driver) is None


# --- capture_snapshot integration -------------------------------------------


def test_capture_snapshot_includes_third_party_cookies() -> None:
    """The headline behaviour: a third-party ``.linkedin.com`` cookie set
    while browsing ``egovselect.be`` now lands in the snapshot's jar."""
    driver = _FakeDriver(
        "https://egovselect.be/nl",
        cookies=[],  # classic get_cookies sees nothing third-party
        jar=[_li_cookie()],
    )
    snap = capture_snapshot(driver)
    domains = {c["domain"] for c in snap["cookies"]}
    assert ".linkedin.com" in domains


def test_capture_snapshot_merges_first_party_and_jar() -> None:
    """First-party ``get_cookies()`` and the cross-domain jar are merged and
    deduped, so a first-party cookie present in both appears once."""
    fp = {"name": "CookieConsent", "value": "yes", "domain": "egovselect.be",
          "path": "/", "httpOnly": False, "secure": True}
    jar = [
        StorageCookie(name="CookieConsent", value="yes", domain="egovselect.be",
                      path="/", http_only=False, secure=True),
        _li_cookie(),
    ]
    driver = _FakeDriver("https://egovselect.be/", cookies=[fp], jar=jar)
    snap = capture_snapshot(driver)
    keys = [(c["domain"], c["name"]) for c in snap["cookies"]]
    assert keys.count(("egovselect.be", "CookieConsent")) == 1
    assert (".linkedin.com", "bcookie") in keys


def test_capture_snapshot_falls_back_to_get_cookies_without_bidi() -> None:
    """Without BiDi storage, behaviour is unchanged: first-party only."""
    fp = {"name": "sid", "value": "1", "domain": "egovselect.be", "path": "/"}
    driver = _FakeDriver("https://egovselect.be/", cookies=[fp], has_storage=False)
    snap = capture_snapshot(driver)
    assert snap["cookies"] == [fp]