"""Detect self-hosted consent banners from captured page-source markup.

Third-party-hosted CMPs (Cookiebot, OneTrust, …) persist a decodable
decision artifact, so :mod:`leak_inspector.analysis.consent` reads them
directly. A large share of EU public-sector sites instead run a
**self-hosted, server-rendered** banner: no vendor host, the decision
lives first-party, and there is no machine-readable artifact to decode.
Those sites otherwise report "no known consent banner" — understating
that they *do* ask for consent. This module recognises such banners from
the saved page-source HTML so they can be named (presence, not decision).

Currently recognises two banner families, each with a signature derived
from real captures (not raw server HTML — curl-derived signatures do
not survive rendering):

* **LCP / Icordis** (ASP.NET-Core CMS, Belgian municipalities; from a
  real ``www.beernem.be`` capture): a server-rendered accept/decline
  ``<form>`` whose submit buttons carry
  ``name="action" value="acceptall|decline"``, corroborated by a
  ``cookie-compliance`` (or its typo'd ``cookie-complicance``) class.
  The ``name="action"`` form POST is the load-bearing signal: it both
  survives DOM rendering and distinguishes LCP from JS/cookie CMPs
  that share ``cookie-compliance`` class naming but never POST a
  decision. The button *class* names (``btn-cookie-accept``) are not
  relied on — on the real markup ``btn-cookie-accept`` sits on the
  "manage cookies" link, not the accept button.
* **Drupal EU Cookie Compliance** (from real ``www.anderlecht.be`` /
  ``www.leuven.be`` captures): the module's JS injects a banner whose
  module-owned ``eu-cookie-compliance-banner`` class appears in a real
  ``class`` attribute, corroborated by the ``id="sliding-popup"``
  container or the ``eu-cookie-compliance-default-button`` agree
  button. This is the fallback for the ~⅔ of Drupal sites where JS
  aggregation hides the ``/modules/contrib/eu_cookie_compliance/``
  asset path the request-side detector keys on. Requiring a real
  ``class`` attribute matters: some sites (sjtn.brussels) carry the
  banner template only as escaped JSON inside ``Drupal.settings``
  without ever injecting it — config is not a banner. LCP markup
  reuses ``eu-cookie-compliance-more-button``, so the *banner* class
  (which LCP never has) is the disambiguator in this direction.
"""

from __future__ import annotations

import re
from typing import Iterable

#: Name surfaced for the LCP / Icordis self-hosted banner.
LCP_ICORDIS_BANNER = "self-hosted consent banner (LCP/Icordis)"

#: The accept/decline submit buttons — the primary, disambiguating signal
#: (attribute order tolerated). ``acceptall`` / ``decline`` are LCP's own
#: action values.
_ACTION_BUTTON = re.compile(
    r'name=["\']action["\'][^>]*value=["\'](?:acceptall|decline)["\']'
    r'|value=["\'](?:acceptall|decline)["\'][^>]*name=["\']action["\']',
    re.I,
)

#: Corroborating class — matches both ``cookie-compliance`` and the
#: typo'd ``cookie-complicance`` seen in the wild.
_COMPLIANCE_CLASS = re.compile(r'cookie-compl[ia]', re.I)

#: Name surfaced for the Drupal EU Cookie Compliance banner. Must equal
#: the ``eu_cookie_compliance`` module's ``module_name`` so the
#: asset-path detection and this markup fallback feed one deduplicated
#: ``cmp_names`` entry (test-pinned).
EU_COOKIE_COMPLIANCE_BANNER = "EU Cookie Compliance (Drupal)"

#: The module-owned banner class in a *real* ``class`` attribute — the
#: primary signal. The attribute anchor excludes the banner template
#: embedded as escaped JSON in ``Drupal.settings`` (``class=\\u0022…``),
#: where the banner was never injected into the DOM.
_ECC_BANNER_CLASS = re.compile(
    r'class=["\'][^"\']*\beu-cookie-compliance-banner', re.I,
)

#: Corroborators: the module's banner container or its agree button.
_ECC_CORROBORATOR = re.compile(
    r'id=["\']sliding-popup["\']'
    r'|class=["\'][^"\']*\beu-cookie-compliance-default-button',
    re.I,
)


def detect_self_hosted_banners(htmls: Iterable[str | None]) -> list[str]:
    """Return the names of self-hosted consent banners found in ``htmls``.

    ``htmls`` is the page-source HTML of each saved screenshot (``None`` /
    empty entries are skipped). The result is deduplicated and order is
    by first detection. Empty when no recognised banner is present.
    """
    documents = [html for html in htmls if html]
    names: list[str] = []
    if _detect_lcp_icordis(documents):
        names.append(LCP_ICORDIS_BANNER)
    if _detect_eu_cookie_compliance(documents):
        names.append(EU_COOKIE_COMPLIANCE_BANNER)
    return names


def _detect_lcp_icordis(htmls: Iterable[str]) -> bool:
    """True when any document carries the LCP/Icordis banner signature."""
    return any(
        _ACTION_BUTTON.search(html) and _COMPLIANCE_CLASS.search(html)
        for html in htmls
    )


def _detect_eu_cookie_compliance(htmls: Iterable[str]) -> bool:
    """True when any document carries the rendered Drupal ECC banner."""
    return any(
        _ECC_BANNER_CLASS.search(html) and _ECC_CORROBORATOR.search(html)
        for html in htmls
    )
