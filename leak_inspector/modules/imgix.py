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

"""Imgix image-CDN detector.

Imgix is a multi-tenant image-transform CDN. Each customer gets a
sub-domain of the form ``<customer>.imgix.net``. The image filename is
in the path; the transform is in the query string.
"""

from __future__ import annotations

from ..events import RequestEvent
from ..impact import ImpactRating
from .base import (
    CAT_CONTENT,
    CAT_IDENTIFIER,
    CAT_OTHER,
    CAT_TECHNICAL,
    Hit,
    IMPACT_LOW,
    IMPACT_MEDIUM,
    ParamInfo,
    TrackerModule,
    register,
)


_HOST_SUFFIX = ".imgix.net"
_HOST_EXACT = "imgix.net"


_PARAMS: dict[str, tuple[str, str, str]] = {
    "w":         (CAT_TECHNICAL, "Output width (pixels)",                       IMPACT_LOW),
    "h":         (CAT_TECHNICAL, "Output height (pixels)",                      IMPACT_LOW),
    "max-w":     (CAT_TECHNICAL, "Maximum output width",                        IMPACT_LOW),
    "max-h":     (CAT_TECHNICAL, "Maximum output height",                       IMPACT_LOW),
    "fit":       (CAT_TECHNICAL, "Fit mode (crop / clip / fill / max …)",       IMPACT_LOW),
    "crop":      (CAT_TECHNICAL, "Crop strategy (edges / faces / focalpoint …)", IMPACT_LOW),
    "ar":        (CAT_TECHNICAL, "Output aspect ratio",                         IMPACT_LOW),
    "dpr":       (CAT_TECHNICAL, "Device pixel ratio",                          IMPACT_LOW),
    "fp-x":      (CAT_TECHNICAL, "Focal-point X",                               IMPACT_LOW),
    "fp-y":      (CAT_TECHNICAL, "Focal-point Y",                               IMPACT_LOW),
    "fp-z":      (CAT_TECHNICAL, "Focal-point zoom",                            IMPACT_LOW),
    "rect":      (CAT_TECHNICAL, "Region rectangle (x,y,w,h)",                  IMPACT_LOW),
    "auto":      (CAT_TECHNICAL, "Automatic optimizations (compress / format / enhance)", IMPACT_LOW),
    "fm":        (CAT_TECHNICAL, "Output format (webp / avif / jpg / png …)",   IMPACT_LOW),
    "q":         (CAT_TECHNICAL, "Output quality",                              IMPACT_LOW),
    "lossless":  (CAT_TECHNICAL, "Lossless-compression flag",                   IMPACT_LOW),
    "cs":        (CAT_TECHNICAL, "Color space",                                 IMPACT_LOW),
    "bg":        (CAT_TECHNICAL, "Background color",                            IMPACT_LOW),
    "blur":      (CAT_TECHNICAL, "Gaussian-blur amount",                        IMPACT_LOW),
    "px":        (CAT_TECHNICAL, "Pixelate amount",                             IMPACT_LOW),
    "sat":       (CAT_TECHNICAL, "Saturation",                                  IMPACT_LOW),
    "bri":       (CAT_TECHNICAL, "Brightness",                                  IMPACT_LOW),
    "con":       (CAT_TECHNICAL, "Contrast",                                    IMPACT_LOW),
    "exp":       (CAT_TECHNICAL, "Exposure",                                    IMPACT_LOW),
    "monochrome": (CAT_TECHNICAL, "Monochrome tint color",                      IMPACT_LOW),
    "sharp":     (CAT_TECHNICAL, "Sharpening amount",                           IMPACT_LOW),
    "rot":       (CAT_TECHNICAL, "Rotation (degrees)",                          IMPACT_LOW),
    "flip":      (CAT_TECHNICAL, "Flip direction (h / v / hv)",                 IMPACT_LOW),
    "trim":      (CAT_TECHNICAL, "Trim-edge mode",                              IMPACT_LOW),
    "border":    (CAT_TECHNICAL, "Border (width,color)",                        IMPACT_LOW),
    "border-radius": (CAT_TECHNICAL, "Border-radius",                           IMPACT_LOW),
    "padding":   (CAT_TECHNICAL, "Padding (px)",                                IMPACT_LOW),
    "mark":      (CAT_TECHNICAL, "Watermark image URL",                         IMPACT_LOW),
    "markw":     (CAT_TECHNICAL, "Watermark width",                             IMPACT_LOW),
    "markh":     (CAT_TECHNICAL, "Watermark height",                            IMPACT_LOW),
    "markalign": (CAT_TECHNICAL, "Watermark alignment",                         IMPACT_LOW),
    "marka":     (CAT_TECHNICAL, "Watermark alpha (opacity)",                   IMPACT_LOW),
    "markpad":   (CAT_TECHNICAL, "Watermark padding",                           IMPACT_LOW),
    "txt":       (CAT_CONTENT,   "Text overlay (rendered onto the image)",      IMPACT_MEDIUM),
    "txt-font":  (CAT_TECHNICAL, "Text-overlay font",                           IMPACT_LOW),
    "txt-size":  (CAT_TECHNICAL, "Text-overlay font size",                      IMPACT_LOW),
    "txt-color": (CAT_TECHNICAL, "Text-overlay color",                          IMPACT_LOW),
    "txt-align": (CAT_TECHNICAL, "Text-overlay alignment",                      IMPACT_LOW),
    "txt-pad":   (CAT_TECHNICAL, "Text-overlay padding",                        IMPACT_LOW),
    "txt-line":  (CAT_TECHNICAL, "Text-overlay line height",                    IMPACT_LOW),
    "txt-fit":   (CAT_TECHNICAL, "Text-overlay fit mode",                       IMPACT_LOW),
    "txt-clip":  (CAT_TECHNICAL, "Text-overlay clip mode",                      IMPACT_LOW),
    "txt-shad":  (CAT_TECHNICAL, "Text-overlay shadow",                         IMPACT_LOW),
    "ixlib":     (CAT_TECHNICAL, "Imgix JS client identifier + version",        IMPACT_LOW),
    "ixid":      (CAT_IDENTIFIER, "Imgix anonymous request identifier",         IMPACT_LOW),
    "s":         (CAT_TECHNICAL, "URL HMAC signature (signed Imgix URLs)",      IMPACT_LOW),
    "v":         (CAT_TECHNICAL, "Cache-bust version tag",                      IMPACT_LOW),
    "expires":   (CAT_TECHNICAL, "Signed-URL expiry timestamp",                 IMPACT_LOW),
    "maxwidth":  (CAT_TECHNICAL, "Custom max-width parameter (operator-defined)", IMPACT_LOW),
}


@register
class ImgixModule(TrackerModule):
    """Detect imgix image-CDN traffic."""

    module_id = "imgix"
    module_name = "Imgix"
    vendor = "Imgix, Inc."
    legal_jurisdiction = "US"
    data_residency = "Imgix global CDN (Fastly-backed)"
    sovereignty_notes = "US CLOUD Act applies; no analytics product, but every image fetch leaks visitor IP + UA + Referer + asset path"
    # Image CDN: privacy 1.0 (presence leak), security 0.5 (non-executable
    #   static images — rubric 0.5), resilience 2.0 (US, cosmetic asset
    #   host, pure habit-dependency — rubric 2.0).
    impact_rating = ImpactRating(privacy=1.0, security=0.5, resilience=2.0)
    impact_notes = {
        "resilience": "A US-controlled image CDN for assets that could be "
            "served from EU/own infrastructure.",
    }

    def matches(self, event: RequestEvent) -> bool:
        host = event.host.lower()
        return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized Imgix transform parameter", IMPACT_LOW)
            )
            params.append(
                ParamInfo(
                    key=key, value=value, category=category, meaning=meaning,
                    privacy_impact=impact, event_index=event.event_id,
                )
            )
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status, started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
