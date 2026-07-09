# leak_inspector

Record what data a website (and the third parties it loads) leaks about
a user during a real, human-driven browsing session and then run pluggable
tracker modules over the recording to classify and report on those
leaks at three levels: board-ready executive summary, vendor-by-vendor
detail, and per-request drill-down.

The tool drives a real Firefox window via Selenium + WebDriver BiDi.
You browse manually; the tool captures the session, writes a
self-contained bundle to disk, and analyzes it offline.

## A BeLibre project

leak_inspector is a [BeLibre](https://belibre.be) project. Its purpose
is to give Belgian and European site operators a concrete, evidence-
based way to measure how much visitor data their websites hand off to
vendors outside EU jurisdiction — the kind of observation digital-
sovereignty decisions need to rest on, instead of assumption. Every
detector module flags vendor jurisdiction (EU / US / UK / …) and
extra-territorial exposure (CLOUD Act, FISA 702, Schrems II) so the
report can be read as a sovereignty audit, not just a tracker tally.
BeLibre can also put you in touch with experts who can help interpret
the findings and build a remediation roadmap.

## What you get

Each analysis produces a **report document** that all four output
formats render from:

- **Composite score** — `Total: N/100  ·  🛡️ R  🔐 S  🕶️ P`, the
  geometric mean of resilience / security / privacy, each 0–100
  each. Full rubric in [`docs/SCORING.md`](docs/SCORING.md).
- **Executive summary** — 🔴/🟡/🟢-scored findings (session replay,
  CNAME cloaking, extra-territorial vendor exposure, persistent
  tracking cookies, PII channels, …), with a tied list of
  recommended actions mapped to GDPR articles.
- **Detailed findings** — HIGH-impact tracking rolled up by vendor;
  CNAME-cloak alias table; vendor-jurisdiction tally (EU flag for
  member states); top trackers by privacy impact.
- **Unclassified third-party hosts** — third party links for which currently no .
  analysis module exists. If relevant, feel free to submit a proposal.
- **Per-tracker drill-down** — for each fired module: stat row,
  harvested-fields summary, every representative hit with its
  classified parameter table.

75 detector modules ship today. See the [module list](#detector-coverage).

## Install

See [INSTALL.md](INSTALL.md) for the step-by-step install guide
(Windows, macOS, Linux — no prior experience assumed).

Requirements at a glance: Python ≥ 3.10 and a venv. **Firefox is
optional** — both geckodriver *and* Firefox itself are auto-fetched by
Selenium Manager on first capture if they're not already installed
(the browser lands in a user-space cache, no admin rights needed; the
tool prints a one-time "downloading ~80 MB" notice before it starts).
A system Firefox, when present, is used as-is. Runtime deps pulled by
`pip install -e .`: `selenium>=4.20` (WebDriver BiDi), `tldextract>=5.1`
(first-/third-party classification), `dnspython>=2.4` (CNAME chain
resolution), `maxminddb>=2.5` (optional ASN/country enrichment),
`pillow>=10` (lossless-webp report screenshots).

## Quick start

```bash
# 1. Capture: opens Firefox, you browse, close the window when done.
python -m leak_inspector capture https://example.com --out captures/example.zip

# 2. Analyze: render the report.
python -m leak_inspector analyze captures/example.zip
```

That's the whole workflow. The capture step launches Firefox with
stealth-tuned preferences (so trackers see a normal browser, not an
automation rig), subscribes to WebDriver BiDi network / log /
navigation events, snapshots client-side storage on every URL change,
and resolves a CNAME chain for every hostname touched. Closing the
browser window finalises the bundle — and immediately runs the
**enrichment** phase: DNS posture, HTTP/HTTPS transport probes, a TLS
quality probe (certificate validity/expiry, negotiated protocol,
deprecated-protocol acceptance), a CMS version probe, an RFC 9116
`security.txt` presence check and per-host IP/ASN/geo lookups, stored
*inside* the bundle as a timestamped `enrichment.json`. The recorded network
posture is therefore contemporaneous with the browsing session, and
everything after capture works fully offline.

The analyze step replays the bundle offline through the tracker
modules, applies dedup, and emits a report — no network. A bundle
captured before the enrichment phase existed (or on a machine that
was offline at capture close) can be retrofitted any time:

```bash
python -m leak_inspector enrich captures/example.zip                       # one-time retrofit
python -m leak_inspector enrich captures/example.zip --refresh             # re-probe every section
python -m leak_inspector enrich captures/example.zip --refresh cms-probe   # re-probe one section
```

`--refresh` takes an optional section — one of `dns`, `transport`,
`tls`, `cms-probe`, `security-txt`, `hosts` — to re-probe just that one (handy
after changing a single detector, e.g. the CMS version probe). The
bundle's other sections and its baseline `enriched_at` are left
untouched; the re-probed section records its own timestamp, so a
mixed-age posture states each section's true age instead of pretending
the whole posture is from one moment. Bare `--refresh` re-probes
everything.

## Output formats

```bash
python -m leak_inspector analyze bundle.zip                           # ANSI text (default)
python -m leak_inspector analyze bundle.zip --format html  > r.html   # standalone HTML (data: URIs)
python -m leak_inspector analyze bundle.zip --format html  -o r.html  # report + sibling PNG files
python -m leak_inspector analyze bundle.zip --format json  > r.json   # structured (schema v2)
python -m leak_inspector analyze bundle.zip --format markdown_summary > r.md
python -m leak_inspector analyze bundle.zip --format markdown_detailed > r.md   # +per-hit tables
python -m leak_inspector analyze bundle.zip --format pdf -o r.pdf      # branded cover + full report (needs the [pdf] extra)
```

All formats render from the same in-memory `ReportDocument`. The JSON
output is the canonical serialization of that document — anything you
see in text, markdown, or HTML is derivable from the JSON.

**Screenshots.** To stdout (`>`), html/markdown reports stay
self-contained — screenshots are inlined as base64 `data:` URIs. With
`-o FILE`, screenshots are instead written as sibling files next to
the report and referenced by relative filename:
`<stem>.post-load.webp` for the end-of-session capture and
`<stem>.shot_<host>_<HHMMSS>.webp` for each operator-triggered
screenshot. Either way the bundle's archival PNGs are converted to
**lossless webp** (same pixels — they're evidence — at roughly a
third of the size).

### CLI reference

```
python -m leak_inspector capture <URL> --out <PATH.zip> [--profile <DIR>]
python -m leak_inspector enrich <PATH.zip> [--refresh [dns|transport|tls|cms-probe|security-txt|hosts]]
python -m leak_inspector analyze <PATH.zip> [--format text|json|html|markdown_summary|markdown_detailed|pdf]
                                            [--out FILE | -o FILE] [--no-color] [--verbose] [--debug]
python -m leak_inspector diff <A.zip> <B.zip>
                                            [--label-a NAME] [--label-b NAME]
                                            [--format text|json|html|markdown]
                                            [--out DIR | --stdout]
                                            [--no-color]
python -m leak_inspector --list-modules
```

- `--profile DIR` — record against an existing Firefox profile (mutated
  in place; copy first if you need isolation). Default: fresh temp profile.
- `--no-color` — disable ANSI color (auto-disabled when stdout isn't a TTY).
- `--verbose` — text reporter adds source `event_id` list per representative.
- `--debug` — text reporter appends per-unclassified-host drill-down
  (sample URLs + observed params) at the end, for drafting new tracker modules.
- `--list-modules` — print every registered module id + display name and exit.

Exit codes: `0` success, `1` usage error, `2` runtime error,
`3` missing capture dependencies, `130` Ctrl-C during capture.

## Scoring

Every analyzed site gets a single 0–100 score under the report
header, composed of three 0–100 dimensions:

```
Total: 66 / 100  ·  🛡️ 81  🔐 64  🕶️ 54
```

Each third party (a **module**) and each adverse posture fact (a
**signal**) carries a curated **impact rating** — `(privacy, security,
resilience)`, each 0–5 — saying how much harm it does per domain. For a
capture, every fired module + signal **deducts** its impact; the
per-domain penalties **cumulate**; and each dimension's summed penalty
is mapped through a **logistic curve** to its 0–100 score.

- **🛡️ Resilience** — exposure to actors outside the operator's legal
  control: foreign-jurisdiction vendors, US-owned mail / hosting,
  platform lock-in.
- **🔐 Security** — attack surface: missing hardening headers (CSP,
  HSTS, …), end-of-life platform, unpinned third-party code, missing
  Subresource Integrity, weak DMARC / DNSSEC.
- **🕶️ Privacy** — data leaving to third parties and whether it does so
  lawfully: cross-site trackers, identifiers, session replay, and
  consent violations (tracking before the decision / after a reject).

The total combines them by **geometric mean** — `³√(R × S × P)`, all
three 0–100. Two properties fall out:

1. **Both ends are asymptotic.** A penalty-free dimension reaches 99
   (perfection — 100 — is never printed); any penalty keeps you ≥ 1
   (rock-bottom — 0 — is never printed either). The curve is steepest
   in the middle, so that is where most discrimination happens.
2. **Imbalance penalises itself.** One rotten dimension drags the cube
   root down — a sovereign, well-secured site that is a privacy
   disaster cannot hide behind its two good dimensions.

Example outputs across real captures:

| Site | 🛡️ | 🔐 | 🕶️ | Total |
|---|---:|---:|---:|---:|
| `kifkif.be` (Plausible only) | 98 | 93 | 97 | **96** |
| `brecht.be` (Belgian municipality, Drupal) | 97 | 91 | 97 | **95** |
| `nbb.be` | 95 | 91 | 93 | **93** |
| `kbc.be` (Adobe Experience Cloud + AppNexus) | 81 | 64 | 54 | **66** |
| `aalst.be` (Meta Pixel + Google Ads, US infra) | 47 | 50 | 61 | **52** |
| `awel.be` (tracking before consent) | 16 | 5 | 33 | **14** |
| `doccle.be` (14 trackers; reject-then-track) | 2 | 1 | 1 | **1** |

The detailed report itemises every `(detail, −penalty)` pair behind
each dimension score, so a low number always points directly at what to
fix. Below the scorecard, a **Biggest win** line names the single
deduction whose removal helps most (e.g. *"Remove or replace Adobe
Experience Cloud (−4 privacy)"*).

The full model (the 0–5 impact rubric, per-capture variants like GA4
Consent Mode, the signal catalog, the logistic parameters and
calibration history) lives in [`docs/SCORING.md`](docs/SCORING.md).

## What the report looks like

```
==============================================================================
BeLibre Automatic Leak Inspector : awel.be
target:     https://awel.be
landed at:  https://awel.be/
==============================================================================

Total: 14 / 100  ·  🛡️ 16  🔐 5  🕶️ 33
resilience · security · privacy — 🛡️ Meta (Facebook) Pixel −3.5, Google Analytics 4 −3, Google Tag Manager −2.5, +8 more;
🔐 Google Tag Manager −3, Google Analytics 4 −2.5, Meta (Facebook) Pixel −2.5, +14 more;
🕶️ Meta (Facebook) Pixel −4, Google Analytics 4 −3, Google reCAPTCHA −3, +7 more
Biggest win: Remove or replace Meta (Facebook) Pixel (−4 privacy)

Consent: banner shown, no choice recorded

Executive summary
──────────────────────────────────────────────────────────────────────────────
  🔴 2 vendors sent personal data before the visitor made any choice. Fired
     pre-consent: Google Analytics 4, Meta (Facebook) Pixel. …
  🔴 5 vendors under extra-territorial jurisdiction (Schrems II / CLOUD Act /
     FISA 702 exposure). 5× US (Google LLC, Meta Platforms, Inc., …)
  🟡 2 unclassified third-party hosts.
  🟢 2 additional first-party domains visited (sittool.net, watwat.be).

RECOMMENDED ACTIONS
  1. Confirm a DPIA (GDPR Art. 35) covers session-replay recording …
  2. Audit the cookie banner — confirm tracking cookies are not set before consent …
  3. Verify SCCs + Transfer Impact Assessments on file for each US vendor …
  4. Review each PII field against data-minimization (GDPR Art. 5(1)(c)) …
  5. Investigate each unclassified host …

DETAILED FINDINGS
  HIGH-impact tracking by vendor:
    Google LLC  [Google Analytics 4, Google Fonts, YouTube]
      pii         ip
      identifier  cid, ecid, visitor_data
      http_traffic (set-cookie) VISITOR_INFO1_LIVE, (set-cookie) __Secure-YNID, …
      content     text
    Snowplow Analytics Ltd  [Snowplow Analytics]
      identifier  duid
  Vendor jurisdictions: 11× 🇺🇸 US (Google LLC, +) · 1× 🇪🇺 CZ · 1× 🇪🇺 LT · 1× 🇬🇧 UK · 1× 🇪🇺 FR
  Trackers fired:      15 modules · 167 requests (93 unique after dedup)
  Third-party hosts:   28 touched · 27 claimed, 1 unclassified
  Top by impact:       YouTube (14H/74M/34×), GA4 (8H/23M/4×), Snowplow (4H/40M/4×)
```

The HTML format additionally surfaces:
- Hover tooltips on field codes (field meaning), vendor names
  (sovereignty: jurisdiction + residency + notes), category labels
  (one-sentence description), CNAME alias rows (cloaking explained).
- Collapsible per-tracker `<details>` blocks for the representative-hit drill-down.

## Detector coverage

Tracker modules are registered today, grouped roughly by category:

- **Analytics & RUM** — GA4 (incl. UA legacy), Matomo, Snowplow, Yandex
  Metrica (+ WebVisor), Adobe Experience Cloud (Analytics / Audience
  Manager / Advertising Cloud / DTM), Cloudflare Web Analytics, Azure
  Application Insights, Adobe Helix RUM, Bing UET.
- **Session replay / behavioral** — Microsoft Clarity, Hotjar,
  FullStory, Contentsquare (incl. ClickTale + Hotjar via CSQ CDN).
- **Ads & demand-side** — Google Ads / DoubleClick, Meta (Facebook)
  Pixel, LinkedIn Insight Tag, AppNexus / Xandr, Mediago (Bytedance),
  Outbrain, Integral Ad Science (IAS), Baidu Tongji.
- **CAPTCHA / consent** — Google reCAPTCHA, hCaptcha, Cloudflare
  Turnstile, OneTrust, Cookiebot, Cookie Script, consentmanager,
  CookieYes, LCP/Icordis self-hosted banner (decision form POST).
- **CRM / marketing automation** — HubSpot, Mailchimp, Mailjet.
- **Tag management** — Google Tag Manager.
- **Maps / embeds** — Google Maps, Bing Maps, Apple Maps, OpenStreetMap,
  YouTube (embedded player), Zendesk widget.
- **Asset CDNs** — Google Fonts, gstatic, Google CDN / Hosted Libraries,
  Cloudflare cdnjs, jsDelivr, Imgix, Icordis/LCP (EU municipal CMS).
- **Error / observability** — Sentry.
- **Catch-all** — generic `google.com` for endpoints not claimed by
  more-specific Google modules.

`python -m leak_inspector --list-modules` prints the registered set.

### Cross-cutting analysis

Beyond per-module attribution, the analyzer applies three cross-cutting
passes on every captured request:

- **Ambient HTTP-traffic** — visitor IP, Referer, Cookie, User-Agent,
  Client Hints, GPC/DNT all show as `(http) X` rows.
- **`Set-Cookie` attribute parsing** — each cookie a vendor sets surfaces
  with its name, lifetime (derived from `Max-Age` or `Expires`),
  `SameSite`/`Secure`/`HttpOnly`/`Partitioned`/`Domain` attributes. The
  combination drives a privacy-impact rating: `Partitioned` → LOW
  (CHIPS-bound), `SameSite=None + >30 days` → HIGH (cross-site
  persistent), etc.
- **CNAME-cloak detection** — at capture time the recorder resolves the
  CNAME chain for every unique hostname seen. At analysis time, if no
  module claims a request via its on-the-wire host, the canonical name
  at the end of the chain is re-tested against every module. A match
  attributes the hit with a HIGH-impact `(cname-cloak)` row showing
  `alias → canonical`. Catches first-party-aliased third-party trackers
  (Eulerian, AT Internet, Adobe DTM-CNAMEd setups, etc.) that wire-only
  inspection misses.

## Using the library

The CLI is the recommended entry point, but every layer is usable from
Python. Three common patterns:

### Read a bundle

```python
from leak_inspector.bundle import BundleReader

with BundleReader("captures/example.zip") as bundle:
    print(bundle.manifest.target_url, bundle.manifest.session_id)
    for event in bundle.events():
        print(event.event_id, event.type, event.timestamp)

    bundle.storage("example.com")    # parsed storage/<host>.json
    bundle.script("deadbeef")        # raw bytes of scripts/<sha256>
    bundle.cname_chains              # dict[host, [chain, …]]
```

### Run analysis programmatically

```python
from leak_inspector import modules                # registers detectors
from leak_inspector.analysis import analyze_bundle
from leak_inspector.report import write_text_report

analysis = analyze_bundle("captures/example.zip")
print(write_text_report(analysis, color=False))

for rep in analysis.representative_hits():
    print(rep.module_id, rep.url, [(p.key, p.category) for p in rep.params])
```

### Build the report document directly

If you want the structured data (e.g. to feed a dashboard, CMP sync,
or CI gate), skip the renderer and walk the document tree:

```python
from leak_inspector.analysis import analyze_bundle
from leak_inspector.report import build_report_document

document = build_report_document(analyze_bundle("captures/example.zip"))

for finding in document.executive_summary.findings:
    print(finding.severity, finding.headline)

for vendor in document.executive_summary.high_impact_by_vendor:
    print(vendor.vendor_label, len(vendor.modules), "modules")

for cloak in document.executive_summary.cname_cloaks:
    print(f"{cloak.alias} → {cloak.canonical}")
```

The document's JSON-serializable shape is the same one
`--format json` emits. See `leak_inspector/report/document.py` for the
full schema (schema_version = 3).

## Architecture

- **Events** — `leak_inspector.events`. Normalized dataclasses for every
  bundle event type. Both capture and analysis speak in these; tracker
  modules never see raw dicts.
- **Bundle** — `leak_inspector.bundle`. Schema-versioned manifest +
  zipped directory layout. Reader and writer are pure I/O.
  ```
  capture-<ISO-timestamp>.zip
  ├── manifest.json
  ├── events.jsonl
  ├── cname_chains.json                          # resolved at capture-end (if available)
  ├── screenshot.png                             # post-load page screenshot
  ├── screenshot_<host>_<HHMMSS>.png             # operator-triggered (Ctrl+Alt+S; zero or more)
  ├── storage/<host>.json
  └── scripts/<sha256>
  ```
- **Capture** — `leak_inspector.capture`. Launches Firefox with stealth
  prefs, subscribes to BiDi events, snapshots client-side storage on a
  pre-navigation callback and after every URL change, resolves CNAME
  chains at session-end, finalises the bundle when the browser window
  closes.
- **Analysis** — `leak_inspector.analysis`. Iterates bundle events,
  dispatches each `RequestEvent` to the matching tracker module via
  the registry. When no module matches the on-the-wire host, the
  CNAME chain tail is re-tested as fallback. Three cross-cutting
  passes (ambient HTTP, Set-Cookie attributes, CNAME cloaks)
  decorate every hit.
- **Modules** — `leak_inspector.modules`. 74 pluggable detectors.
  Each parameter is categorized (pii, identifier, behavioral, content,
  technical, consent, http_traffic, other) with a privacy-impact
  rating (HIGH / MEDIUM / LOW).
- **Report** — `leak_inspector.report`. Single source of truth in
  `ReportDocument` built once by `report/builder.py`. JSON, text,
  markdown, and HTML reporters all walk the document — they don't
  re-derive from `Analysis`.

Boundaries: `capture/` only writes bundles, `analysis/` only reads
bundles, `bundle/` is shared and depends on neither.

## First capture walkthrough

```bash
# 1. Activate the venv (one-time-per-shell).
. .venv/bin/activate

# 2. Capture: opens Firefox; browse normally; close the window when done.
python -m leak_inspector capture https://news-site.example \
    --out captures/news-site.zip

# 3. Read the report in your terminal:
python -m leak_inspector analyze captures/news-site.zip

# 4. Or render as HTML and open in a browser (tooltips, expandable sections):
python -m leak_inspector analyze captures/news-site.zip --format html > report.html
xdg-open report.html       # or `open` on macOS
```

## Comparing two captures

The canonical use case: capture the same site twice with different
consent choices (reject vs accept), then ask the tool what the accept
path actually unlocks. The ``diff`` subcommand consumes two bundles
and emits a structured comparison.

```bash
# 1. Capture twice — close the cookie banner the second time.
python -m leak_inspector capture https://example.com --out captures/reject.zip
python -m leak_inspector capture https://example.com --out captures/accept.zip

# 2. Diff. For html/markdown, three files land in <stem_a>_vs_<stem_b>/
#    in the current directory: the diff plus a full single-site report
#    for each side, with the diff embedding relative links to the
#    two side reports for drill-down.
python -m leak_inspector diff captures/reject.zip captures/accept.zip \
                              --label-a reject --label-b accept \
                              --format html
# → reject_vs_accept/diff.html
# → reject_vs_accept/reject.report.html
# → reject_vs_accept/accept.report.html

# 3. Pick a custom output directory:
python -m leak_inspector diff a.zip b.zip --format html --out audit/diff/

# 4. Force stdout (skip the directory):
python -m leak_inspector diff a.zip b.zip --format html --stdout > diff.html
```

What the diff surfaces:

- **Severity-aware headline** — "*'accept' adds 6 new vendors; 4 new
  distinct personal-data fields; 6 new tracking cookies; 3 vendors
  no longer firing.*" The headline names the visitor-side impact, not
  just the vendor count.
- **Personal-data field delta** — distinct ``(vendor, category, key)``
  triples that start (or stop) leaking, deduplicated so the same
  cookie sent on 100 beacons counts once.
- **Cookie delta** — cookies present in one capture but not the other,
  matched by ``(name, host)``.
- **Browser-storage delta** — ``localStorage`` / ``sessionStorage``
  keys unique to one side, matched by ``(origin, kind, key)``.
- **Module, host, finding deltas** — vendors that fired only in one
  capture, hosts that appeared / disappeared, executive findings that
  changed.
- **Hidden extraterritorial infrastructure** carried through —
  picks up new first-party-host CNAME chains that route through
  US-jurisdiction CDNs.
- **Bundle-mismatch warning** — if A and B target different sites
  (different ``base_domain``), the diff fires a warning banner at the
  top so the comparison is read as the apples-to-oranges output it is.

**Format defaults:** ``html`` and ``markdown`` auto-derive an output
directory (``<stem_a>_vs_<stem_b>/`` in CWD) so the diff and its two
side reports stay together. ``text`` defaults to stdout (terminal use
case); ``json`` defaults to stdout (machine consumption). Pass
``--out DIR`` to override, or ``--stdout`` to force stdout for
html/markdown.

## Screenshots during capture

Every capture stores one **post-load screenshot** of the page (taken right
after `driver.get()` returns) at the bundle root as `screenshot.png`. The
HTML report embeds it near the top so you can see what the visitor saw.

During a visible-mode (non-headless) capture you can also take **ad-hoc
screenshots at any moment** by pressing **`Ctrl+Alt+S`**
(Linux/Windows) / **`Ctrl+Option+S`** (macOS). Each press writes a
`screenshot_<host>_<HHMMSS>.png` into the bundle and the HTML report
renders the lot as a small gallery captioned with the host and time.

The shortcut is `Ctrl+Alt+S` rather than the more obvious `Ctrl+Shift+S`
because Firefox binds `Ctrl+Shift+S` to its own built-in screenshot tool
in most builds and `preventDefault` from a page handler cannot override
Firefox's chrome shortcuts.

Mechanism: a tiny preload script (added via BiDi `script.addPreloadScript`)
installs a capture-phase `keydown` listener that fires `fetch` to a
reserved `.invalid` host; the capture layer intercepts that one request,
takes the screenshot, and suppresses the request itself so it never
appears in `events.jsonl`. No console wiring, no localhost server, no
browser extension.

## Bulk scanning

For sovereignty audits across a list of sites instead of one at a time,
`bulk-tool/run.py` reads `<dataset>/domains.csv`, captures each URL
unattended (page load + 1 s settle, then close), and writes a per-URL
HTML report into `<dataset>/reports/` (or a directory of your choice
via `--out DIR`), with screenshots as lossless-webp sidecars using the
same naming as `analyze -o`. After the batch it generates a single
`index.html` overview that ranks the cleanest and worst sites and
aggregates the most common findings across the dataset; rebuild just
the overview with `python bulk-tool/overview.py <dataset>`.

```bash
python bulk-tool/run.py bulk-tool/datasets/belgium
python bulk-tool/run.py bulk-tool/datasets/belgium --out audits/belgium-2026-06/
```

## License

GNU General Public License v3 or later (GPL-3.0-or-later). See
[`LICENSE`](LICENSE) for the canonical text. Anyone who receives this
program in source or binary form is granted the four freedoms of the
GPL (run, study, share, modify); derivative works must remain under
the same license.

## Limits and non-goals

- **Headless or scripted browsing** — out of scope. The value is real
  human sessions; trackers behave differently against automation.
- **Non-Firefox browsers** — Firefox + WebDriver BiDi is the only
  supported capture engine.
- **Server-side leak detection** — the browser cannot see leaks that
  pass through the first-party server before reaching a third party
  (server-side GTM, Cloudflare Zaraz, Server-Side Tagging). Documented
  blind spot.
- **Response-body capture** — threat model is data flowing *out*; what
  came back is rarely informative for leak analysis and inflates bundle
  size.
- **Always-on monitoring** — leak_inspector is a one-session-at-a-time
  tool. Extension-style continuous capture is not a planned feature.
- **Active blocking or mitigation** — analysis only. The tool surfaces
  leaks; it doesn't prevent them.
- **CNAME chain rotation** — chains are resolved once at capture-end
  and stored in the bundle. Re-analysing a months-old bundle uses the
  chain as it stood when the capture ran, not current DNS. Intentional
  — the bundle should preserve the state at capture time.
