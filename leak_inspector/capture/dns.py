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

"""CNAME chain resolution for cloaking detection.

A "CNAME-cloaked" tracker is one served from a first-party-looking
subdomain (e.g. ``metrics.example.com``) that resolves via a CNAME
record to a third-party tracker collector (e.g. ``custom-eulerian.
eulerian.net``). The browser sees a first-party host; the actual data
goes to a third party. This module fetches each captured hostname's
CNAME chain so the analyzer can match the chain tail against the
tracker-module hostname suffixes — catching cloaking that wire-level
data alone is blind to.

Resolution is best-effort. DNS failures (NXDOMAIN, timeout, network
unavailable) return a single-element chain containing just the input
hostname, so the analyzer's downstream logic always has *something* to
match against.

Resolution is performed once per session at capture-finalization time,
not at analysis time, because DNS records change over time and the
chain as it stood **when the visitor's browser connected** is the
ground truth the bundle should preserve.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.exception
import dns.resolver


#: Per-query DNS timeout in seconds. dnspython's default of 5s is too
#: generous for batch resolution at session-end — we'd rather skip a
#: slow host than block bundle finalization on it.
_DEFAULT_TIMEOUT = 2.0

#: Maximum CNAME chain depth. Real chains are typically 1-3 hops; we
#: cap at 8 to guard against pathological or self-referential records.
_MAX_DEPTH = 8


def resolve_cname_chain(
    hostname: str, timeout: float = _DEFAULT_TIMEOUT
) -> list[str]:
    """Follow CNAME records from ``hostname`` to the canonical name.

    Returns the resolved chain as a list, starting with the input host
    and ending at the first name that has no further CNAME (the
    canonical target). For a hostname that already has no CNAME the
    chain is a single-element list ``[hostname]``.

    Network / DNS failures (NXDOMAIN, timeout, resolver unreachable)
    are treated as "we don't know" — the chain stops at the last
    successfully-resolved name and the caller still gets a valid list.
    """
    chain: list[str] = [hostname]
    current = hostname

    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    for _ in range(_MAX_DEPTH):
        try:
            answers = resolver.resolve(current, "CNAME")
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
        ):
            break
        if not answers:
            break
        target = str(answers[0].target).rstrip(".").lower()
        if not target or target == current:
            break
        chain.append(target)
        current = target

    return chain


def collect_chains(
    hostnames: list[str] | set[str],
    timeout: float = _DEFAULT_TIMEOUT,
    max_workers: int = 10,
) -> dict[str, list[str]]:
    """Resolve CNAME chains for every name in ``hostnames``, in parallel.

    Returns a dict mapping each input hostname to its resolved chain.
    Hostnames that fail entirely (any exception escapes) still appear
    in the result with their own single-element chain as fallback —
    callers never have to handle missing keys.

    Deduplication: if ``hostnames`` contains the same name multiple
    times (e.g. from a Counter), only one DNS query is fired.
    """
    unique = {h.strip().lower() for h in hostnames if h and h.strip()}
    chains: dict[str, list[str]] = {}
    if not unique:
        return chains

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(resolve_cname_chain, host, timeout): host
            for host in unique
        }
        for future in as_completed(futures):
            host = futures[future]
            try:
                chains[host] = future.result()
            except Exception:
                chains[host] = [host]

    return chains


__all__ = [
    "collect_chains",
    "resolve_cname_chain",
]
