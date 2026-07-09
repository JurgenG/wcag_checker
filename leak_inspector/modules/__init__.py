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

"""Tracker modules.

Each module knows which requests belong to a particular tracker
(GA4, Google Fonts, Clarity, ...) and parses them into a structured
:class:`~leak_inspector.modules.base.Hit` with per-parameter
categorization. Importing this package registers all bundled modules
via their ``@register`` decorators.
"""

from .base import (
    CAT_BEHAVIORAL,
    CAT_CONSENT,
    CAT_CONTENT,
    CAT_HTTP_TRAFFIC,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_PII,
    CAT_TECHNICAL,
    CATEGORIES,
    GOVERNMENT_LEVELS,
    Hit,
    IMPACT_HIGH,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    MODULE_KIND_GOVERNMENT,
    MODULE_KIND_PARA_GOVERNMENT,
    MODULE_KIND_TRACKER,
    ParamInfo,
    TrackerModule,
    all_modules,
    detect,
    register,
)

# Side-effect imports: each module file calls ``@register`` at import time.
from . import act_on  # noqa: F401
from . import addtoany  # noqa: F401
from . import adform  # noqa: F401
from . import adroll  # noqa: F401
from . import adobe_fonts  # noqa: F401
from . import adobe_helix_rum  # noqa: F401
from . import adobe_marketing_cloud  # noqa: F401
from . import amazon_ad_system  # noqa: F401
from . import app360  # noqa: F401
from . import appnexus  # noqa: F401
from . import apple_maps  # noqa: F401
from . import apple_pay  # noqa: F401
from . import azure_application_insights  # noqa: F401
from . import azure_cdn  # noqa: F401
from . import baidu_tongji  # noqa: F401
from . import bidswitch  # noqa: F401
from . import bidtellect  # noqa: F401
from . import bing_maps  # noqa: F401
from . import bing_uet  # noqa: F401
from . import bombora  # noqa: F401
from . import bootstrapcdn  # noqa: F401
from . import browsealoud  # noqa: F401
from . import chathive  # noqa: F401
from . import clarity  # noqa: F401
from . import cloudflare_cdn  # noqa: F401
from . import cloudflare_turnstile  # noqa: F401
from . import cloudflare_web_analytics  # noqa: F401
from . import cloudflare_zaraz  # noqa: F401
from . import cloudfront  # noqa: F401
from . import commanders_act  # noqa: F401
from . import consentmanager  # noqa: F401
from . import contentsquare  # noqa: F401
from . import cookie_script  # noqa: F401
from . import cookiebot  # noqa: F401
from . import cookieyes  # noqa: F401
from . import criteo  # noqa: F401
from . import duda  # noqa: F401
from . import eu_cookie_compliance  # noqa: F401
from . import eulerian  # noqa: F401
from . import eyeota  # noqa: F401
from . import ezoic  # noqa: F401
from . import facebook_pixel  # noqa: F401
from . import flexmail  # noqa: F401
from . import font_awesome  # noqa: F401
from . import fullstory  # noqa: F401
from . import ga4  # noqa: F401
from . import google_ads  # noqa: F401
from . import google_cdn  # noqa: F401
from . import google_first_party_mode  # noqa: F401
from . import google_fonts  # noqa: F401
from . import google_maps  # noqa: F401
from . import googletagmanager  # noqa: F401
from . import gstatic  # noqa: F401
from . import hcaptcha  # noqa: F401
from . import hotjar  # noqa: F401
from . import hubspot  # noqa: F401
from . import icordis  # noqa: F401
from . import id5  # noqa: F401
from . import imagekit  # noqa: F401
from . import imgix  # noqa: F401
from . import index_exchange  # noqa: F401
from . import integral_ad_science  # noqa: F401
from . import jimdo  # noqa: F401
from . import jitsi  # noqa: F401
from . import jquery_cdn  # noqa: F401
from . import jsdelivr  # noqa: F401
from . import keyade  # noqa: F401
from . import lcp_icordis_consent  # noqa: F401
from . import letsgocity  # noqa: F401
from . import linkedin_insight  # noqa: F401
from . import liveramp  # noqa: F401
from . import lotame  # noqa: F401
from . import magnite  # noqa: F401
from . import mailchimp  # noqa: F401
from . import mailjet  # noqa: F401
from . import mapbox  # noqa: F401
from . import matomo  # noqa: F401
from . import mediago  # noqa: F401
from . import microsoft_bookings  # noqa: F401
from . import microsoft_forms  # noqa: F401
from . import microsoft_office_config  # noqa: F401
from . import microsoft_onecdn  # noqa: F401
from . import microsoft_telemetry  # noqa: F401
from . import myfonts  # noqa: F401
from . import nativo  # noqa: F401
from . import onetrust  # noqa: F401
from . import oniroco  # noqa: F401
from . import openstreetmap  # noqa: F401
from . import openx  # noqa: F401
from . import oracle_eloqua  # noqa: F401
from . import osm_community  # noqa: F401
from . import oswald  # noqa: F401
from . import outbrain  # noqa: F401
from . import piano_analytics  # noqa: F401
from . import plausible  # noqa: F401
from . import polyfill_fastly  # noqa: F401
from . import pubmatic  # noqa: F401
from . import quantcast  # noqa: F401
from . import readspeaker  # noqa: F401
from . import recaptcha  # noqa: F401
from . import sentry  # noqa: F401
from . import smart_adserver  # noqa: F401
from . import snowplow  # noqa: F401
from . import statsig  # noqa: F401
from . import sourcepoint  # noqa: F401
from . import squarespace  # noqa: F401
from . import surveymonkey  # noqa: F401
from . import taboola  # noqa: F401
from . import tapad  # noqa: F401
from . import tiktok  # noqa: F401
from . import tinymce  # noqa: F401
from . import trade_desk  # noqa: F401
from . import tribalfusion  # noqa: F401
from . import triplelift  # noqa: F401
from . import trustarc  # noqa: F401
from . import tubemogul  # noqa: F401
from . import unpkg  # noqa: F401
from . import userway  # noqa: F401
from . import webflow  # noqa: F401
from . import webtrekk_mapp  # noqa: F401
from . import weebly  # noqa: F401
from . import wix_platform  # noqa: F401
from . import wizaly  # noqa: F401
from . import wordpress_com  # noqa: F401
from . import wonderpush  # noqa: F401
from . import x_ads  # noqa: F401
from . import yahoo_ads  # noqa: F401
from . import yandex_metrica  # noqa: F401
from . import youtube  # noqa: F401
from . import zendesk  # noqa: F401
from . import zyro  # noqa: F401

# Governmental third-party detectors — registered AFTER all trackers
# so that more-specific tracker modules win on hosts where a government
# entity also runs analytics (e.g. ``matomo.bosa.be`` resolves to Matomo,
# not to "Federal Belgian government"). Order within the group follows
# geographic / political scope: EU first, then federal Belgian, then
# the three regional governments.
from . import gov_european_union  # noqa: F401
from . import gov_federal_belgium  # noqa: F401
from . import gov_flanders  # noqa: F401
from . import gov_wallonia  # noqa: F401
from . import gov_brussels  # noqa: F401

# Para-governmental third parties — publicly-funded non-profits /
# intercommunal associations / sector-specific service organisations
# that are not formally part of government. Registered AFTER all
# trackers so that a tracker running on a paragov host wins (e.g.
# ``plausible.imio.be`` stays classified as Plausible, not IMIO).
from . import paragov_belnet  # noqa: F401
from . import paragov_cultuurconnect  # noqa: F401
from . import paragov_imio  # noqa: F401
from . import paragov_publiq  # noqa: F401
from . import paragov_smals  # noqa: F401
from . import paragov_uvcw  # noqa: F401
from . import paragov_vvsg  # noqa: F401

# Catch-all detectors — MUST be imported last. First-match-wins means
# any module appearing here would shadow more specific Google-product
# modules (recaptcha, google_ads, google_maps, …) which all match
# subsets of google.com / googleapis.com. ``google_apis`` is the
# googleapis.com residual catch-all — after google_fonts / google_cdn /
# google_maps so those win on their specific hosts.
from . import google_apis  # noqa: F401
from . import google_misc  # noqa: F401

__all__ = [
    "CAT_BEHAVIORAL",
    "CAT_CONSENT",
    "CAT_CONTENT",
    "CAT_HTTP_TRAFFIC",
    "CAT_IDENTIFIER",
    "CAT_OTHER",
    "CAT_PII",
    "CAT_TECHNICAL",
    "CATEGORIES",
    "GOVERNMENT_LEVELS",
    "Hit",
    "IMPACT_HIGH",
    "IMPACT_LOW",
    "IMPACT_MEDIUM",
    "MODULE_KIND_GOVERNMENT",
    "MODULE_KIND_PARA_GOVERNMENT",
    "MODULE_KIND_TRACKER",
    "ParamInfo",
    "TrackerModule",
    "all_modules",
    "detect",
    "register",
]
