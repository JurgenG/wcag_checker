# CLAUDE.md

Guidelines for Claude when working in this repository.

## This project

The goal of this project is to record a real, human-driven browsing
session in Firefox and analyze what data the visited website (and the
third parties it loaded) collected about the user.

If you don't have enough information online or are not able to reliably certain create a module, don't speculate. Only base your modules on certain data.

Architecture:

- **Capture** (`leak_inspector/capture/`) — Selenium + Firefox driven
  via geckodriver, using WebDriver BiDi for event subscription. Stealth
  prefs hide automation so trackers fire normally. The user clicks
  around manually; the tool records.
- **Bundle** (`leak_inspector/bundle/`) — capture writes a
  self-contained, schema-versioned JSON bundle (`manifest.json` +
  `events.jsonl` + `storage/<origin>.json` + `scripts/<sha256>`), zipped
  on export.
- **Enrichment** (`leak_inspector/enrichment/`) — the live-network
  phase, run once right after capture (or retrofitted via
  `leak-inspector enrich`): DNS posture, transport probes, CMS
  version probe, `security.txt` presence, per-host IP/ASN/geo.
  Results are stored *inside* the
  bundle zip as `enrichment.json`, timestamped, so the posture is
  contemporaneous with the browsing session.
- **Analysis** (`leak_inspector/analysis/`) — iterates bundle events,
  dispatches to tracker modules, derives first-party vs third-party
  via Public Suffix List. Strictly offline: all network-derived data
  comes from the stored enrichment; un-enriched bundles analyze fine
  but carry no posture (reports say so).
- **Modules** (`leak_inspector/modules/`) — pluggable tracker detectors
  that classify each parameter by category (PII, identifier,
  behavioral, technical, consent, content, other).
- **Report** (`leak_inspector/report/`) — text + JSON. Repeat hits are
  deduplicated by `(module, endpoint, parameter-key-set, event-type)`;
  the raw stream remains available for drill-down.
- **TDD** (`tests/`) — Using test driven development, we build tests for every new feature that gets added.

Boundaries to keep clean:

- `capture/` writes bundles. It does not import `analysis/` or
  `modules/`.
- `enrichment/` reads bundles and writes the bundle's enrichment
  entry. It imports `dns_posture/`, `http_posture/` and `cms/`, never
  `analysis/` or `modules/`. The CLI orchestrates capture→enrich;
  `capture/` itself stays network-analysis-free.
- `analysis/` reads bundles (including the stored enrichment). It
  does not import `capture/` and never touches the network.
- `bundle/` is shared by all, depends on none of them
  (`bundle/reader`'s enrichment accessor lazily imports only the pure
  `enrichment.artifact` data module — acyclic).

Explicit non-goals: headless/scripted browsing, browsers other than
Firefox, always-on monitoring, active blocking, server-side leak
detection.

## Code standards

- Adhere to Python PEP standards, in particular:
  - **PEP 8** — code style (naming, indentation, line length, imports).
  - **PEP 257** — docstring conventions.
  - **PEP 484 / PEP 604** — type hints; annotate public functions and methods.
  - **PEP 20** (Zen of Python) — prefer simple, explicit, readable code.
- Use a consistent formatter/linter style (e.g. `black`, `ruff`, or `flake8`) if one is already configured in the project; do not introduce new tooling without asking.
- Write modular code, prefer small functions over large blobs

## Documentation

- Every module, public class, and public function gets a docstring (PEP 257).
- Docstrings describe **purpose, inputs, outputs, and side effects** — not implementation details that the code already shows.
- Keep inline comments rare and reserved for non-obvious *why*, not *what*.
- Update relevant docs (README, module docstrings) when behavior or interfaces change.
- Create/use TODO.md in the project root when new tasks are added to a queue.
- Create/use SBOM.md to maintain an SBOM and comment on the key processes

## Modular development

- Build small, focused modules with clear single responsibilities.
- Keep functions short; extract helpers when a function does more than one thing.
- Separate concerns: parsing, business logic, I/O, and presentation live in distinct modules.
- Prefer pure functions where practical; isolate side effects.
- Public interfaces should be minimal and explicit; avoid leaking internals.

## Scope discipline

- **Do only what is asked.** Do not add features, options, configuration, abstractions, or "nice-to-haves" that were not requested.
- No speculative generality — no hooks, plugin systems, or extension points for hypothetical future needs.
- No unrequested refactors. If you spot something worth changing, mention it and wait for direction.
- No extra error handling, logging, retries, or validation beyond what the task requires or what is needed at real system boundaries.
- Prefer editing existing files over creating new ones.

## When in doubt, ask

- If requirements are ambiguous, the desired scope is unclear, or there are multiple reasonable approaches with meaningful trade-offs, **ask a clarifying question before writing code**.
- Surface assumptions explicitly rather than silently choosing.
- It is always better to ask one short question than to deliver the wrong thing.
