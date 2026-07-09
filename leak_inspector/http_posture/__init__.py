"""HTTP/HTTPS transport-posture analysis for the captured site.

Probes the captured site's host(s) over both HTTP and HTTPS to surface
hygiene issues an auditor would expect to be checked:

* HTTPS broken on the captured host → HIGH-risk finding.
* HTTP doesn't redirect to HTTPS → MEDIUM-risk finding.
* HTTP not served (HTTPS-only) → LOW-risk mention.
* Apex and www variants both serve content independently → LOW mention.
* Only one of apex/www resolves → MEDIUM-risk finding.

Probing happens at analysis time — the captured bundle stays pristine.
"""

from __future__ import annotations

from .probe import HostProbe, TransportPosture, probe_transport

__all__ = ["HostProbe", "TransportPosture", "probe_transport"]
