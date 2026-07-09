# leak_inspector — project guide

This document is the starting point for a developer joining the
project. It is enough, on its own, to take the codebase from its
current scaffolded state to a working **v1.0**.

`README.md` is the short pitch; `CLAUDE.md` is the code-standards
contract; this file is the implementation plan.

---

## What this project is

`leak_inspector` is a measurement tool for understanding how websites
and their third parties collect data about a person.

The workflow is:

1. A developer (or researcher) launches the tool, which opens a real
   Firefox window driven by Selenium.
2. The user **manually** browses a target site — clicking, scrolling,
   logging in, accepting/refusing cookies, whatever scenario is under
   study. The tool does not script the browsing.
3. While the user browses, the tool records every outbound request,
   every change to browser storage, and every script the site loads.
4. When the session ends, the tool writes a self-contained, versioned
   **capture bundle** to disk.
5. A separate analysis stage reads the bundle, runs **tracker modules**
   over it, and produces a human-readable report plus a JSON dump.

Capture and analysis are decoupled. A bundle is a frozen artifact; an
analysis can be re-run against the same bundle as modules evolve.

---

## v1.0 — what a developer is building

Three components, in this order:

```
┌──────────────┐     bundle.zip      ┌──────────────┐    report.{txt,json}
│   capture    │ ─────────────────▶  │   analysis   │ ─────────────────▶
│  (Selenium)  │                     │   (modules)  │
└──────────────┘                     └──────────────┘
```

### Package layout

The scaffolding is already in place:

```
leak_inspector/
├── PROJECT.md
├── README.md
├── CLAUDE.md
├── pyproject.toml
├── leak_inspector/
│   ├── __init__.py
│   ├── cli.py                 # entrypoint: console script `leak-inspector`
│   ├── capture/               # Selenium + BiDi recording
│   ├── bundle/                # bundle read/write, schema, event model
│   ├── analysis/              # iterates events, dispatches to modules
│   ├── modules/               # tracker modules (ga4, google_fonts, clarity)
│   └── report/                # text + json reporters
└── tests/
    └── fixtures/
```

The `bundle` package owns the event-model dataclasses and the
on-disk format; both capture (which writes) and analysis (which
reads) depend on it.

The CLI entrypoint is registered in `pyproject.toml` as
`leak-inspector = "leak_inspector.cli:main"`.

---

## The bundle format (the contract)

A bundle is a zipped directory. Capture writes it; analysis reads it.
Nothing else crosses the boundary.

```
<label>-<ISO-timestamp>.zip
├── manifest.json
├── events.jsonl
├── storage/
│   └── <origin>.json          # one file per origin observed
└── scripts/
    └── <sha256>               # raw script bodies, content-addressed
```

### `manifest.json`

Schema-versioned metadata. Treat the schema version as the bundle's
public API.

```json
{
  "bundle_schema": 1,
  "tool": "leak_inspector",
  "tool_version": "0.1.0",
  "session_id": "2026-05-22T10-40-12Z-9f3a",
  "label": "news-site",
  "started_at": "2026-05-22T10:40:12Z",
  "ended_at":   "2026-05-22T10:47:55Z",
  "target_url": "https://example.com",
  "base_domain": "example.com",
  "browser": {"name": "firefox", "version": "..."},
  "profile": "fresh"            // or "user:<path>"
}
```

### `events.jsonl`

One JSON object per line. Append-only during capture, ordered by
`timestamp`. Each event has at minimum:

| Field        | Description                                              |
|--------------|----------------------------------------------------------|
| `event_id`   | Monotonic counter, unique within the bundle.             |
| `timestamp`  | ISO-8601 UTC.                                            |
| `type`       | See event types below.                                   |
| `context_id` | BiDi browsing-context id (which tab/frame).              |
| `payload`    | Event-specific object.                                   |

Event types (v1.0):

- `navigation` — top-level navigations.
- `request` — outbound HTTP request. Payload includes `method`, `url`,
  `host`, `headers`, `request_body` (text or null), `initiator` (best
  effort from BiDi), `response_status`, `response_mime`,
  `response_headers`. Response **bodies** are not captured.
- `websocket_open` / `websocket_message` / `websocket_close`.
- `storage_snapshot` — emitted at navigation boundaries and session
  end. Payload is `{origin, kind: "local"|"session"|"cookie", entries:
  [{key, value}]}`. The full snapshot lives in `storage/<origin>.json`;
  the event references it by origin.
- `script_load` — a script was loaded. Payload includes `url` and
  `sha256` (the file body is stored in `scripts/<sha256>`).
- `log` — `console.*`, JS errors, BiDi log entries.

Modules consume this event stream. They do **not** read raw Selenium
objects and do **not** touch the filesystem directly.

### `storage/<origin>.json`

The full state of `localStorage`, `sessionStorage`, and
`document.cookie` for one origin at one moment, plus a `captured_at`
timestamp. There may be multiple snapshots per origin across the
session; they are distinguished by timestamp within the file.

### `scripts/<sha256>`

Raw script bodies, content-addressed. Capture stores each script once,
no matter how many times the site loads it. v1.0 stores them but does
not yet analyze them.

---

## Component 1 — capture (`leak_inspector.capture`)

### Driver setup

Use Selenium + geckodriver against a real Firefox install. Required
preferences:

- `dom.webdriver.enabled = false` — hide the automation flag.
- Disable `marionette`-leaking heuristics where possible.
- Do not enable headless mode. The user is supposed to see and drive
  the browser.

Profile selection:

- **Default:** fresh, temporary profile, deleted on session end. This
  isolates the capture from the developer's real browsing history.
- **Opt-in:** `--profile <path>` to point at an existing Firefox
  profile, for "what does this site leak about me logged in" runs.

### BiDi subscriptions

WebDriver BiDi is the **only** capture mechanism in v1.0. No mitmproxy,
no extensions. Subscribe to:

- `network.beforeRequestSent`
- `network.responseStarted`
- `network.responseCompleted`
- `network.fetchError`
- `browsingContext.navigationStarted` /
  `browsingContext.fragmentNavigated`
- `log.entryAdded`
- WebSocket events (`network.*` covers these in current BiDi).

For each event, normalize the BiDi payload into the bundle's event
schema and append to the `events.jsonl` writer.

Request **and** response bodies are captured via BiDi's data-collector
mechanism (``network.addDataCollector``) with a configurable per-body
size cap (default 256 KB). This is required for tracker analysis —
analytics endpoints like Clarity, Sentry, HubSpot forms, and Snowplow
ship the payload that matters in POST bodies; capturing only URL +
headers gives a misleadingly thin picture of what data the site is
sending. Bodies that exceed the size cap are truncated browser-side
to bound bundle size; raise the cap for full session-replay capture
at the cost of bundle size.

### Storage snapshot

`localStorage` / `sessionStorage` / `document.cookie` are not visible
via BiDi network events. Capture them by injecting JavaScript:

```python
driver.execute_script("""
    return {
        local:   Object.fromEntries(Object.entries(localStorage)),
        session: Object.fromEntries(Object.entries(sessionStorage)),
        cookie:  document.cookie,
    };
""")
```

Cookies with `HttpOnly` set will not appear via `document.cookie`. Use
`driver.get_cookies()` in addition to capture the HTTP-visible ones.

Snapshot triggers:

- Immediately before every navigation (catches what the previous page
  wrote).
- Immediately after every navigation has settled.
- On session end.

Per-origin: iterate the origins the page has touched. For the simple
v1.0 case, snapshot the top-level document's origin plus any same-tab
navigated origins.

### Recorder

Orchestrates a session:

1. Build the driver.
2. Open a BiDi session, attach all subscriptions.
3. Open a writer for `events.jsonl`.
4. Navigate to the target URL.
5. Block on the user closing the browser (or pressing Ctrl-C in the
   CLI). While blocked, events flow into the writer asynchronously.
6. On exit: take a final storage snapshot, hand off to the bundle
   writer, clean up the temp profile.

---

## Component 2 — bundle (`leak_inspector.bundle`)

The shared contract between capture and analysis. Owns:

- **Event dataclasses.** One class per event `type` from the spec
  above, plus a base `Event` and a `parse_event(dict) -> Event`
  factory. Modules consume these dataclasses, never raw dicts.
- **Manifest dataclass.** Mirrors the `manifest.json` schema; includes
  the `bundle_schema` constant the rest of the code reads.
- **Writer.** Given a working directory, validates the manifest, zips
  it, deletes the working directory. Fails loudly if a required field
  is missing rather than producing a broken bundle.
- **Reader.** Opens a bundle zip, parses `manifest.json`, streams
  `events.jsonl` line by line yielding parsed `Event` objects. Storage
  snapshot files are loaded lazily on demand (a module that doesn't
  care about storage shouldn't pay for it).

Keep `capture` and `analysis` strictly downstream of `bundle`. No
type defined in `capture` should appear in `analysis` and vice
versa — they meet only in `bundle`.

---

## Component 3 — analysis (`leak_inspector.analysis`)

### Module framework (`modules/base.py`)

Salvage the proven shapes from the previous `har_inspector` codebase:

- `ParamInfo` (key, value, category, meaning, privacy_impact,
  event_index).
- `Hit` (module_id, module_name, url, host, method, response_status,
  started_at, params, events).
- Category constants (`CAT_PII`, `CAT_IDENTIFIER`, `CAT_BEHAVIORAL`,
  `CAT_CONSENT`, `CAT_CONTENT`, `CAT_TECHNICAL`, `CAT_OTHER`).
- A `register()` / `all_modules()` / `detect()` global registry.

The module interface for v1.0:

```python
class TrackerModule(ABC):
    module_id: str
    name: str
    vendor: str

    def matches(self, event: RequestEvent) -> bool: ...
    def parse(self, event: RequestEvent) -> Hit: ...
```

The bundled v1.0 modules — `ga4`, `google_fonts`, `clarity` — port
from the old codebase by swapping `HarRequest` for `RequestEvent`
and mapping field names. The parameter dictionaries inside each
module do not change.

### Runner

Iterate the bundle's event stream. For each `RequestEvent`, call
`detect()` and dispatch to the matching module. Collect `Hit`s into an
`Analysis` result holding:

- Per-module hit lists.
- Unique parameter keys per module.
- Category counts per module.
- A first-party / third-party classification for every host observed,
  derived from the manifest's `base_domain` via `tldextract` (already
  a dependency in `pyproject.toml`) to handle public suffixes correctly.

### Dedup rule (reporting only)

> Collapse repeat hits by `(module_id, endpoint, param-key-set,
> event-type)`. A new endpoint, a new param key, a new event type, or
> a new module triggers a fresh full report entry.

Implement this in the analysis layer as a "representative hit"
picker, not in the modules themselves. The raw event stream and full
hit list stay accessible in the JSON output for drill-down.

---

## Component 4 — report (`leak_inspector.report`)

Two reporters, both reading the same `Analysis` object:

- `text.py` — terminal output with optional ANSI color. One section
  per module: total hits, unique param keys, category breakdown, one
  representative hit per endpoint with every parameter classified.
- `json_reporter.py` — machine-readable, includes the full un-deduped
  hit list so downstream tooling can drill in.

---

## CLI (`leak_inspector.cli`)

The `pyproject.toml` already exposes the entrypoint as
`leak-inspector`. The README documents the surface; for v1.0,
implement these subcommands:

```bash
# Capture a session. Opens Firefox, waits for the user to finish.
leak-inspector capture --label news-site \
    [--url https://example.com] \
    [--out captures/] \
    [--profile /path/to/firefox/profile]

# Analyze a previously captured bundle.
leak-inspector analyze captures/news-site-2026-05-22T10-40-00Z.zip \
    [--format text|json] [--no-color] [--verbose]

# Compare two captures (e.g. consent granted vs refused).
leak-inspector diff full.zip minimal.zip [--format text|json]

# List registered tracker modules.
leak-inspector modules
```

The `diff` command reports, per module, which parameter keys appeared
only in the first bundle, only in the second, and in both — mirroring
the diff behavior of the old `har_inspector`. It is implemented in the
analysis layer by running each bundle through the same pipeline and
comparing the resulting `Analysis` objects.

No flags beyond these in v1.0. Resist the urge to add watch mode,
batch mode, or live-tail — they are not on the v1.0 list.

---

## Definition of done for v1.0

A v1.0 build must satisfy all of the following:

1. `leak-inspector capture --label X --url <url>` opens a real Firefox
   window, lets a user browse, and on exit writes a valid bundle zip.
2. The bundle contains a parseable `manifest.json`, at least one
   `request` event, at least one `storage_snapshot` event, and at
   least one entry in `storage/<origin>.json`.
3. `leak-inspector analyze <bundle.zip>` runs the three bundled
   modules (`ga4`, `google_fonts`, `clarity`) and produces both text
   and JSON reports without error against a real capture of a site
   known to use those trackers.
4. `leak-inspector diff full.zip minimal.zip` reports per-module
   parameter-key diffs.
5. The dedup rule above is applied to the text report.
6. The `dom.webdriver.enabled = false` stealth pref is confirmed by
   running against `https://bot.sannysoft.com/` (or equivalent) and
   observing that automation indicators do not trip.
7. A fresh profile is used by default; passing `--profile` honors the
   given profile path.

---

## v1.1 — identifier propagation (outline)

Goal: detect when an identifier stored in `localStorage`,
`sessionStorage`, or a cookie subsequently appears in an outbound
third-party request.

Approach, at a glance:

- Extend the event-stream consumer to keep a per-origin map of
  observed storage values.
- For each outbound `RequestEvent`, scan the URL, headers, and body
  for matches against known stored values (allow encoding variants:
  raw, URL-encoded, base64).
- Surface matches in reports as a "propagation" finding linking
  source storage key → destination host/endpoint.

No new bundle fields required — v1.1 is purely an analysis-side
change on top of v1.0 captures.

---

## v1.2 — CNAME cloaking detection (outline)

Goal: flag requests whose apparently first-party hostname is in fact
a CNAME alias of a known tracker.

Approach, at a glance:

- Ship a bundled CNAME blocklist (community-maintained lists exist;
  pick one with a compatible license).
- During capture, additionally record the resolved CNAME chain per
  observed host. Selenium does not expose this directly; resolve via
  a Python DNS library at capture time.
- Add a `dns` event type to the bundle schema; bump
  `bundle_schema` to 2 and keep loader compatibility for v1 bundles.
- In analysis, mark hits whose host appears in the blocklist's
  cloak-target set.

---

## Explicit non-goals

These are deliberately out of scope and should not be added without
discussion:

- Headless or scripted browsing.
- Browsers other than Firefox.
- Always-on monitoring or active blocking.
- Server-side leak detection (server-side GTM, Zaraz, server-side
  forwarding). These are a known browser-side blind spot; reports
  may flag *likely* server-side forwarding but cannot confirm it.
- Mobile or native apps.
- A Firefox WebExtension. The Python-via-Selenium path is the chosen
  approach; a parallel JS codebase is not justified.

---

## Working on this codebase

Code standards are owned by [CLAUDE.md](./CLAUDE.md). The short
version: PEP 8 + PEP 257 + type hints, small focused modules, no
speculative abstractions, ask when scope is ambiguous.