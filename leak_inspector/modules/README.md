# Writing a new tracker module

A tracker module teaches `leak_inspector` to recognize one vendor's
requests and label the parameters those requests carry. Each module
is one Python file in this directory, a subclass of
[`TrackerModule`](base.py), discovered via an import in
[`__init__.py`](__init__.py).

## The contract

```python
from ..events import RequestEvent
from .base import (
    CAT_IDENTIFIER, CAT_OTHER,
    Hit, IMPACT_HIGH, IMPACT_LOW, IMPACT_MEDIUM,
    ParamInfo, TrackerModule,
    register,
)


@register
class MyVendorModule(TrackerModule):
    # --- identity (required) ---
    module_id   = "my_vendor"             # stable filename-shaped key
    module_name = "My Vendor"             # human-readable display label

    # --- vendor / sovereignty metadata (required for report rollups) ---
    vendor               = "My Vendor Inc."
    legal_jurisdiction   = "US"           # 2-letter ISO code, or "EU"
    data_residency       = "..."          # one-line factual statement
    sovereignty_notes    = "..."          # CLOUD Act / FISA / PIPL note

    def matches(self, event: RequestEvent) -> bool:
        return event.host.lower().endswith(".myvendor.com")

    def parse(self, event: RequestEvent) -> Hit:
        params: list[ParamInfo] = []
        for key, value in event.all_params.items():
            category, meaning, impact = _PARAMS.get(
                key, (CAT_OTHER, "Unrecognized My Vendor parameter", IMPACT_LOW)
            )
            params.append(ParamInfo(
                key=key, value=value, category=category,
                meaning=meaning, privacy_impact=impact,
                event_index=event.event_id,
            ))
        return Hit(
            module_id=self.module_id, module_name=self.module_name,
            url=event.url, host=event.host, method=event.method,
            response_status=event.response_status,
            started_at=event.timestamp,
            params=params, events=[event.event_id],
        )
```

- `@register` adds the class to the global registry at import time.
- `matches()` must be **cheap** and **side-effect-free** — the
  dispatcher calls it on every captured request.
- `parse()` runs only after `matches()` returned true.
- `event.all_params` merges URL query string with form-encoded POST
  body. For JSON / multipart / base64 bodies, read
  `event.request_body` directly.

### Register the module

Add the import to [`__init__.py`](__init__.py). The dispatcher walks
the registry in **import order** and the **first** matching module
wins, so when scopes overlap, narrower goes first. The bundled
catch-all `google_misc` is imported last in `__init__.py` and has an
explanatory comment — broader modules follow the same pattern.

Within an equivalence class of disjoint hostname patterns (the common
case — `*.adnxs.com` doesn't compete with `*.eulerian.net`), import
alphabetically so the "added a new module" diff is one line in a
predictable place.

## Classification taxonomy

Every `ParamInfo` carries a **category** and a **privacy_impact**.
These power the report's severity-scored findings, the per-vendor
rollup, and the JSON contract.

| Category | What goes here |
|---|---|
| `CAT_PII` | Email / phone / name / address / DOB / IP / signed-in user ID. |
| `CAT_IDENTIFIER` | Visitor pseudonyms, session IDs, ad cookie values, cross-vendor sync tokens. |
| `CAT_BEHAVIORAL` | Event names, ecommerce values, engagement times, experiment buckets. |
| `CAT_CONTENT` | Page URL, document title, referrer, embedded text. |
| `CAT_TECHNICAL` | Screen / viewport / language / SDK version / plugin probes. |
| `CAT_CONSENT` | IAB TCF strings, GPP, Google consent mode, anonymize-IP flags. |
| `CAT_HTTP_TRAFFIC` | Reserved for the ambient HTTP surface — do not use in `_PARAMS`. |
| `CAT_OTHER` | Fallback for keys you observed but can't honestly label. |

| Impact | When |
|---|---|
| `IMPACT_HIGH` | Direct PII, persistent visitor pseudonyms, cross-site cookies. |
| `IMPACT_MEDIUM` | Per-customer IDs, event payloads, referrer URLs, fingerprint bits. |
| `IMPACT_LOW` | Versions, cache-busters, technical plumbing. |

## A worked example: Outbrain

[`outbrain.py`](outbrain.py) is the simplest full-featured reference
(~120 lines, single vendor, multi-host, no body parsing).

```python
_HOST_SUFFIX = ".outbrain.com"
_HOST_EXACT  = "outbrain.com"

def matches(self, event: RequestEvent) -> bool:
    host = event.host.lower()
    return host == _HOST_EXACT or host.endswith(_HOST_SUFFIX)
```

A suffix match catches `tr.outbrain.com`, `amplify.outbrain.com`,
`widgets.outbrain.com`, … in one rule.

```python
_PARAMS: dict[str, tuple[str, str, str]] = {
    # --- customer / pixel identifiers ---
    "marketerId":   (CAT_IDENTIFIER, "Outbrain marketer / advertiser ID",   IMPACT_MEDIUM),
    "obApiKey":     (CAT_IDENTIFIER, "Outbrain Amplify API key",            IMPACT_MEDIUM),
    # --- behavioral / event payload ---
    "name":         (CAT_BEHAVIORAL, "Event name (PAGE_VIEW, …)",           IMPACT_MEDIUM),
    # --- page / content ---
    "permalink":    (CAT_CONTENT,    "Page canonical URL",                  IMPACT_MEDIUM),
    # --- consent ---
    "gdpr":         (CAT_CONSENT,    "GDPR-applies flag",                   IMPACT_LOW),
}
```

A flat dict keyed by parameter name maps to `(category, meaning, impact)`.
`parse()` looks each key up; missing keys fall through to the
`CAT_OTHER` catch-all so values still appear in the report. Use
header comments to mark sections — entries land in batches after a
fresh capture, and grouping keeps them sortable.

## Data-driven discovery workflow

**Don't guess at field meanings.** Per `CLAUDE.md`:

> If you don't have enough information online or are not able to
> reliably/certain create a module, don't speculate. Only base your
> modules on certain data.

A missing label is honest; a wrong label corrupts every downstream
report.

### 1. Capture a real session

```bash
python -m leak_inspector capture https://site-that-uses-the-vendor.example \
    --out captures/sample.zip
```

Browse normally so the vendor's JavaScript fires.

### 2. Find the unclassified hosts

```bash
python -m leak_inspector analyze captures/sample.zip
```

Your future module's hostname should appear in the
`Unclassified third-party hosts` section.

### 3. Inspect the requests

```bash
unzip -d /tmp/inspect captures/sample.zip
python <<'PY'
import json
from urllib.parse import urlparse, parse_qs
from collections import defaultdict

host_substr = "your-vendor.com"
by_endpoint = defaultdict(list)
with open("/tmp/inspect/events.jsonl") as f:
    for line in f:
        e = json.loads(line)
        if e.get("type") != "request":
            continue
        p = e["payload"]
        if host_substr not in (p.get("host") or ""):
            continue
        by_endpoint[(p["host"], urlparse(p["url"]).path, p["method"])].append(p)

for (host, path, method), reqs in sorted(by_endpoint.items()):
    print(f"\n--- {method} {host}{path}  ({len(reqs)} reqs)")
    qs = parse_qs(urlparse(reqs[0]["url"]).query, keep_blank_values=True)
    print(f"  query keys: {sorted(qs.keys())}")
    body = reqs[0].get("request_body") or ""
    if body:
        print(f"  body[:300]: {body[:300]}")
    for k, v in qs.items():
        print(f"    {k:20s} = {v[0][:60]!r}")
PY
```

### 4. Label what you can defend

For each key, ask:

- Is the meaning documented (vendor docs, OpenRTB spec, IAB TCF spec, …)?
- Does the captured value confirm the name? `tv=js-3.1.6` is
  plausibly "tracker version"; `tv=view7-28hs` is something else
  entirely (real situation, caused a Snowplow false positive — see
  [`snowplow.py`](snowplow.py)'s `_EVENT_CODES`).
- If you can't defend it, leave it out. The catch-all still surfaces
  the key and value.

Record unknowns in a comment so the next person doesn't reinvent the
investigation:

```python
# NOTE: observed but not labeled — values resist naming:
#   - ``happid``: 10-digit numeric (role unknown)
#   - ``pvt``: ``n`` (single char, role unknown)
```

See [`contentsquare.py`](contentsquare.py) for an example.

### 5. Verify

Re-analyze and check your module fires:

```bash
python -m leak_inspector --list-modules | grep my_vendor
python -m leak_inspector analyze captures/sample.zip --format json | \
  python -c "import json,sys; d=json.load(sys.stdin); \
             print('hits:', sum(1 for t in d['trackers'] if t['module_id']=='my_vendor'))"
```

A first-pass module should resolve most of its vendor's requests
with non-`Unrecognized` labels. Heavy `Unrecognized` rates mean a
missed endpoint or wrong hostname suffix.

## Common patterns

**Multi-host with regional subdomains** —
[`contentsquare.py`](contentsquare.py). One suffix per host family:

```python
_HOST_SUFFIXES: tuple[str, ...] = (".clicktale.net", ".contentsquare.net")

def matches(self, event):
    host = event.host.lower()
    return any(host.endswith(s) for s in _HOST_SUFFIXES)
```

**JSON / structured POST body** —
[`snowplow.py`](snowplow.py) (tp2 envelope) and
[`azure_application_insights.py`](azure_application_insights.py).
Parse inside `parse()`, emit one `ParamInfo` per logical field,
prefix the keys with `(body) ` so the transport leg is explicit.

**Path-encoded parameters** — [`adobe_marketing_cloud.py`](adobe_marketing_cloud.py).
Adobe demdex's `/ibs:dpid=771&dpuuid=…` has no `?` separator:

```python
def _parse_demdex_ibs_path(path: str) -> list[tuple[str, str]]:
    if not path.startswith("/ibs:"):
        return []
    return parse_qsl(path[len("/ibs:"):], keep_blank_values=True)
```

**Stronger detection than hostname alone** —
[`snowplow.py`](snowplow.py) combines four signals (canonical paths,
hosted suffixes, parameter signature, body schema marker) and trips
on any of them. Use when a vendor's collector may be CNAME-aliased
to a fully custom domain or when two vendors collide on a path
family.

**Host-plus-path matching** — [`google_ads.py`](google_ads.py)
claims `www.google.{tld}` only for ad-specific paths so it doesn't
shadow Google search.

**Asset-only modules** — [`adobe_helix_rum.py`](adobe_helix_rum.py).
SDK CDNs with no tracking params on the URL: match the host, return
a `Hit` with empty params. Still attributes the request away from
the unclassified section.

## House style

- **Module docstring** should answer three questions: (1) what
  vendor/product, including acquisitions ("Contentsquare (incl.
  legacy ClickTale + Hotjar)"); (2) which hosts are recognized and
  each one's role; (3) what's special about the privacy story
  (HIGH-impact fields, self-hostability, anything not obvious from
  the dict).

- **Sovereignty metadata is required**, not optional. `vendor`,
  `legal_jurisdiction`, `data_residency`, `sovereignty_notes` feed
  the executive summary's jurisdiction tally and HIGH-impact-by-vendor
  rollup. Without them the report's sovereignty story breaks for your
  module's hits.

- **Keep `_PARAMS` flat.** Section-header comments, not nested dicts.

- **PII-channel labelling: by what's documented, not worst-case.** A
  publisher-supplied passthrough field could *theoretically* contain
  PII, but if observed values are UUIDs or codes, label by what the
  field actually is and what observed values show.

- **`CAT_IDENTIFIER` means *visitor* identifier.** A value that is
  identical for every visitor — property / measurement / container /
  pixel / account IDs, public site keys and API keys, partner / DSP /
  network company IDs, widget / form / list / campaign / placement
  config IDs — carries no visitor data and classifies as
  `CAT_TECHNICAL` / `IMPACT_LOW`. Anything that *varies* with the
  visitor or their activity (visitor pseudonyms, session / page-load /
  per-event correlation IDs, click IDs, sync payloads, fingerprints)
  stays `CAT_IDENTIFIER`. When a field's scope is uncertain, keep it
  `CAT_IDENTIFIER` — downgrades require certainty.

- **Don't shadow ambient fields.** `(http) ip`, `(http) referer`,
  `(http) cookie`, and `(set-cookie) <name>` are added by the
  analyzer's cross-cutting passes. Don't redefine them in `_PARAMS`.

## Deliberately not covered (no certain fingerprint)

Per the project rule "only base modules on certain data", these
known first-party-trick vendors have **no module** because no
reliable browser-visible fingerprint is publicly documented:

- **Meta Conversions API Gateway** — the gateway appliance's event
  endpoint paths are not publicly documented, and the
  `capig.<site>` subdomain is a setup *suggestion*, not a wire
  guarantee. Without a documented path/payload shape, any detector
  would be speculation. (Pure server-side CAPI — site backend →
  Meta — is invisible to a browser capture by design.)
- **TraceDock** — its CNAME tails are four rotating AWS ELB
  domains (NextDNS blocklist); not stable enough to pin.
- **Awin / Tradedoubler** — affiliate first-party tracking exists,
  but no stable canonical cloaking domains are documented in the
  NextDNS blocklist.

Revisit if a primary source (vendor doc, captured HAR in
`captures/`) pins the fingerprint.
