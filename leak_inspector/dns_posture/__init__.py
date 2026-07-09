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

"""Standalone DNS-posture analysis for the capture's first-party domain.

Independent of the browsing session: takes a registrable domain and
queries DNS for the records that disclose sovereignty (A/AAAA → ASN
and geo; NS → DNS provider; MX → inbox provider), email security
(SPF, DMARC, DKIM, BIMI, MTA-STS, TLS-RPT), transport security
(DNSSEC, CAA, HTTPS/SVCB), and self-disclosed third-party SaaS
relationships (well-known TXT-verification fingerprints).

The single entry point :func:`lookup` returns a :class:`DNSPosture`
record. Every nested resolver is soft-fail: missing or timed-out
records leave the corresponding field empty rather than aborting the
overall lookup, so a partial network outage still produces a useful
report.
"""

from __future__ import annotations

from .orchestrator import lookup
from .types import (
    BIMIRecord,
    CAARecord,
    DKIMSelector,
    DMARCRecord,
    DNSPosture,
    DNSSECStatus,
    HostRecord,
    HTTPSRecord,
    IPInfo,
    MTASTSStatus,
    NameserverRecord,
    SPFRecord,
    TLSRPTStatus,
    TXTVerification,
)

__all__ = [
    "BIMIRecord",
    "CAARecord",
    "DKIMSelector",
    "DMARCRecord",
    "DNSPosture",
    "DNSSECStatus",
    "HostRecord",
    "HTTPSRecord",
    "IPInfo",
    "MTASTSStatus",
    "NameserverRecord",
    "SPFRecord",
    "TLSRPTStatus",
    "TXTVerification",
    "lookup",
]