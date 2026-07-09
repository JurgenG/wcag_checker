# TODO

Open work, grouped by priority. Shipped work is removed — the git
history documents it. Add items when they're acknowledged but not yet
built; move items between tiers when priorities shift.

## P0 — Scoring v2: per-module impact ratings (roadmap, 2026-06-12)

The major overhaul agreed in `docs/SCORING.md` (rubric + six
decisions live there — read it first). Every module and every
non-module signal carries a curated `(privacy, security, resilience)`
impact triple, 0–5 in half-points; dimensions become
`max(0, 10 − Σ impacts)`; the geometric-mean composite stays. All work
happens on a dedicated branch (`scoring-v2`); the old math keeps
working on `master` until the switchover phase merges. Each phase is
tests-first and leaves the suite green.

- [x] **Phase 1 — rating substrate** (done 2026-06-12, branch
  `scoring-v2`). `leak_inspector/impact.py` (dependency-free, sits
  below `modules/`/`report/`): validated frozen `ImpactRating` triple
  (0–5, half-steps); `TrackerModule.impact_rating: ImpactRating |
  None` (single triplet attribute — supersedes the three-attribute
  sketch); signal registry (`register_signal_rating` /
  `signal_ratings`, duplicate-raises); `ratings_overview_rows`
  generator (modules first, sorted, unrated shown as `None` gaps so
  the table doubles as the Phase-3 worklist). Eight base anchors from
  the proposal pinned in `test_impact_anchors.py` — skip-while-unrated
  so each activates the moment its family pass lands; the ninth (GA4
  FP-Mode variant) is pinned by Phase 5. Tests:
  `test_impact_rating.py`, `test_impact_anchors.py`.

- [x] **Phase 2 — aggregation engine** (done 2026-06-12, branch
  `scoring-v2`). `report/score_v2.py`, pure, alongside the v1 math
  (nothing rewires `compute_score`): `Deduction` rows →
  `compute_score_v2` with `max(0, 10 − Σ impacts)` per domain,
  v1-identical geometric-mean total, caps as lower-only ceilings
  (tightest wins, binding cap recorded on the result);
  `module_deductions(hits, registry)` dedups per distinct module
  (once regardless of hit count, per *product* not per vendor) and
  returns unrated ids separately so coverage gaps never score as
  harmless. Each `DimensionResult` carries its own
  largest-first `(label, amount)` deduction list — the raw material
  for Phase 6's rationale strings. Tests: `test_score_v2.py`
  (16 synthetic cases incl. the documented composite examples
  (6,6,6)→60 and (10,4,6)→62).

- [x] **Phase 3 — module rating sweep** (done 2026-06-13; all 6
  families below shipped — 98/98 modules rated). Assign triples + a
  one-line justification in each module's docstring, citing the rubric
  line. Order by corpus weight:
  - [x] 3a — Google family (done 2026-06-12). Rated all 10:
    ga4 (3/2.5/3), googletagmanager (1.5/3/2.5 — code-loader), google_ads
    (4/2.5/3.5), google_misc (1/2/2), google_fonts (1/1/2 — CSS, so
    security 1.0 not 0.5), gstatic (1/2/2), google_cdn (1/2.5/2),
    google_maps (1.5/2/2.5), recaptcha (3/2/2.5 — fingerprinting),
    google_first_party_mode (4.5/2.5/3 — evasion overrides; realizes the
    proposal's 9th worked example as a module base rating, no Phase-5
    variant needed). Each carries a rubric-citing justification comment.
    Anchor note: google_fonts security pinned 1.0 (conscious change from
    the proposal's 0.5 — it serves a stylesheet).
  - [x] 3b — session replay + social/ads majors (done 2026-06-12).
    Rated 9: clarity (4.5/3.5/2.5), hotjar (4.5/3.5/1.5),
    fullstory (4.5/3.5/2.5), contentsquare (4.5/3.5/1.5) — all
    session-replay = privacy 4.5 (indiscriminate capture) + security
    3.5 (input-capture by design), resilience split US 2.5 vs EU 1.5;
    facebook_pixel (4/2.5/3.5), linkedin_insight (4/2.5/3),
    bing_uet (4/2.5/3), criteo (4/4/1.5 — SSP sync hub → security 4.0,
    EU vendor → resilience 1.5), outbrain (4/2.5/2.5). Conscious anchor
    change: hotjar resilience 2.5→1.5 (EU vendor must beat US replay
    vendors on the jurisdiction-driven resilience axis; the worked
    example misfiled it). 19/98 modules rated.
  - [x] 3c — ad-exchange / ID long tail (done 2026-06-12). Rated 14.
    SSP/DMP shared shape privacy 4.0 + security 4.0 (OpenRTB / cookie-sync
    = transitive fourth parties), resilience by jurisdiction: US 2.5
    (appnexus, pubmatic, openx, magnite, lotame, quantcast, mediago[CN
    same high-risk class]), CA-adequacy 1.5 (index_exchange), EU 1.5
    (adform). Specials: liveramp 5.0/3.0/2.5 (RampID = person-level
    identity from hashed PII → the one privacy-5.0 in 3c), id5 4.0/3.0/1.5
    (universal ID, UK adequacy, library not auction hub), adobe_marketing_
    cloud 4.0/4.0/3.0 (demdex ID-sync hub — the anchor), ezoic 4.0/4.0/3.0
    (monetization stack), integral_ad_science 3.0/2.5/2.5 (verification,
    not audience-building). 33/98 modules rated; only matomo, icordis,
    polyfill_fastly anchors remain (later passes).
  - [x] 3d — EU / self-hosted / public sector (done 2026-06-12).
    Rated 20. Self-hosted analytics (the encouraged posture):
    matomo 2/0/0 + snowplow 2/0/0 (operator-run pseudonymous
    profile), plausible 1.5/0/0 (cookieless). icordis 0.5/0.5/0.5
    (operator's own EU asset host — anchor). oswald 2.5/1.5/1.0 (EU
    chat). Form-harvesting → privacy 5.0 (email PII ships out):
    mailjet 5/2.5/1.0 (EU), mailchimp + hubspot 5/2.5/3.0 (US CRM).
    gov_* (5) + paragov_* (7) all 1/1/0.5 — EU public-sector deps, the
    most sovereign external dependency (resilience 0.5). Phase-5 note
    left in matomo/plausible: hosted-suffix variants raise
    security/resilience. 53/98 rated; only polyfill_fastly anchor left.
  - [x] 3e — CDNs, utility + CMPs (done 2026-06-13). Rated 27.
    Asset CDNs (presence-leak privacy 1.0, security by content type):
    jsdelivr 1/2.5/1 (EU), cloudflare_cdn 1/2.5/2, adobe_fonts 1/1/2
    (CSS), imgix 1/0.5/2 (images). Observability (privacy 1.5 technical):
    sentry, azure_app_insights, adobe_helix_rum, cloudflare_web_analytics
    1/2/2 (cookieless). CAPTCHA: hcaptcha 2/1.5/2.5, turnstile 1.5/1.5/2.5
    (sandboxed). cloudflare_zaraz 1.5/3/2.5 (tag loader). Maps:
    apple/bing 1.5/2/2.5, openstreetmap 1.5/1/1.5 (the open alt, rated
    below). youtube 4/1.5/3 (embed = DoubleClick cookies). apple_pay
    1.5/1.5/2.5, zendesk 2.5/2.5/2.5. polyfill_fastly 1/4.5/2 (the
    failed-governance anchor). CMPs: self-hosted lcp_icordis_consent +
    eu_cookie_compliance 0.5/0/0 (encouraged); EU-hosted cookiebot/
    cookie_script/consentmanager 1.5/2.5/1, cookieyes 1.5/2.5/1.5 (UK);
    US onetrust/sourcepoint 1.5/3/2.5 (vendor-script loaders), trustarc
    1.5/2.5/2.5. All 50 anchors now active (zero skips). 80/98 rated;
    the 18 left are exactly the 3f set.
  - [x] 3f — CNAME-cloak vendors + ad-tech/foreign-analytics long
    tail (done 2026-06-13). Rated 18, completing the sweep (98/98).
    CNAME-cloak (privacy 4.5 evasion-override, security 2.5):
    eulerian/keyade/wizaly/commanders_act/piano_analytics 4.5/2.5/1.5
    (EU), webtrekk_mapp 4.5/2.5/2.5 (US analytics), act_on/oracle_eloqua
    4.5/2.5/3.0 (US marketing-automation outreach). Ad-tech: SSP/exchange
    shape 4/4/2.5 (amazon_ad_system, trade_desk, triplelift, tubemogul,
    yahoo_ads); pixels taboola 4/2.5/1.5 (IL adequacy), tiktok 4/2.5/2.5
    (CN), x_ads 4/2.5/3.0 (social). Foreign analytics baidu_tongji +
    yandex_metrica 3/2.5/3.0 (CN/RU measurement layer; yandex WebVisor =
    Phase-5 replay variant). **Gate flipped:** new
    `test_every_registered_module_carries_a_rating` — a module added
    without a triple now fails. All 58 anchors green.

- [x] **Phase 4 — non-module signal ratings** (done 2026-06-13,
  branch `scoring-v2`). `leak_inspector/signals.py`: a declarative
  `SIGNAL_CATALOG` of 21 non-module signals, each the *adverse* fact
  with a rubric-cited triple — the 11 v1 posture checks (as their
  failing form: https_broken S3, csp_missing S1, dmarc_weak S1, the
  rest S0.5; dnssec split S0.5/R0.5; referrer_policy dual P0.5/S0.5),
  plus eol_platform S5, missing_sri_script S1 / _stylesheet S0.5,
  security_txt_missing S0.5, us_mail/us_hosting R0.5, and the consent/
  cookie signals persistent_xs_cookie P3, forwarded_tracking_cookie
  P1, pre_consent_tracking P4, post_reject_tracking P5. Self-registers
  via idempotent `register_all()`; the generated overview is now
  119 rows (98 modules + 21 signals) — the whole vocabulary in one
  table. **Application semantics deferred to Phase 6** (cap-vs-
  deduction for the consent/EOL signals; dedup of cookie signals
  against the vendor module that set them) — documented per-signal.
  Numbers are rubric-honest; Phase-6 calibration may rescale. Tests:
  `test_signal_ratings.py` (catalog well-formedness, axis placement,
  registry round-trip, reaches `compute_score_v2`, overview).

- [x] **Phase 5 — variant ratings** (done 2026-06-13, branch
  `scoring-v2`). `TrackerModule.effective_rating(hits)` hook — default
  returns the base triple; a subclass selects a variant from its own
  hits, gated on wire-observable evidence (certainty rule). `GA4Module`
  is the first variant product: any cloak/proxy-marked hit →
  `_EVASION_RATING` (privacy 4.5, override only ever raises); else every
  observable `gcs` reporting `G100` → `_CONSENT_DENIED_RATING` (privacy
  1.5, snippet/measurement-dependency unchanged); else base 3.0. No
  observable `gcs` → base. `score_v2.module_deductions` now groups a
  module's own hits and deducts its `effective_rating` (with a
  base-rating fallback so rating-only stand-ins keep working).
  **Validated on real fixtures**: doccle-reject (all G100) → privacy
  1.5; doccle-accept (mixed G100/G111) → base 3.0. Further variants
  (hosted-vs-self-hosted analytics, youtube-nocookie, yandex WebVisor,
  advanced-matching pixels) are seeded as in-code notes, to add when a
  real capture demonstrates each. Tests: `test_impact_variants.py`.

- [x] **Phase 6 — switchover + calibration + merge** (done
  2026-06-13). Calibration settled the four open decisions:
  consent signals fire **per offending vendor** (cumulate); **no
  caps** (the logistic + cumulation reproduce the v1 cap effect);
  cookie/consent signals are **not** deduped against the setting
  module (firing pre/post-consent is an additional wrong); logistic
  **p50=14 / s=3.5** with **ceil display** (clean reaches ~95, printed
  bounds 1–99). 6a: `build_deductions` assembler (modules + signals
  from real facts, certainty-gated). 6b: `build_score_view` wired into
  the builder; `ScoreView`/`DimensionView` keep the renderer/bulk
  interface (0–100); rationale names top deductions, "Biggest win" =
  largest-impact deduction; a per-detail penalty breakdown renders in
  text/markdown/html. 6c: snapshot repinned to the v2 document score
  (operator-signed-off: brecht 95, nbb 93, kbc 66, aalst 52,
  cultuurkuur 2, doccle 1); `docs/SCORING.md` rewritten, README
  scorecards updated. 6d: predicates moved into `score_v2.py`, the v1
  `score.py` + its test files deleted, all consumers repointed.
  Logistic model + calibration tool (`tools/score_v2_preview.py`)
  landed alongside. Suite: 3035 passed.

**P0 complete** — all six phases shipped on `scoring-v2`; merging to
master.

## P2 — planned: needs a small capture / enrichment / placement change


- [x] **NIS2 / CyberFundamentals email + DNS posture signals** (done
  2026-06-23). Four new `signals.py` entries scored from the
  already-collected DNS posture, mapped to NIS2 Art. 21(2)(g)/(h) and
  the CCB CyberFundamentals baseline: `spf_weak` (S0.5, missing or
  `+all`/`?all`), `caa_missing` (S0.5), `mta_sts_missing` (S0.5,
  MX-gated — inbound-only), `dns_single_nameserver` (R0.5, exactly one
  NS; zero = not measured). Wired in `score_v2._signal_deductions`
  (DNS block), certainty-gated. **Corpus-measured before rating**
  (`tools`-free probe over the 8 snapshot fixtures): `spf_weak` and
  `dns_single_nameserver` fire 0/8 (latent guards — every fixture has
  an acceptable SPF qualifier and ≥2 NS); `caa_missing` + `mta_sts_
  missing` are the score-movers. Snapshot re-pinned (operator-signed-
  off): brecht 76→74, kbc 41→40, aalst 24→23, doccle-reject total 1
  (sec 6→5); **nbb unchanged — it publishes both CAA and MTA-STS**.
  Single-MX deliberately NOT scored (a single managed-provider MX is
  redundant behind the name — certain-data rule). TLS-RPT left
  surface-only (pure telemetry, redundant with MTA-STS). Tests:
  `test_score_v2_assembler.py` (emission + gating), snapshot re-pin.

- [x] **CyberFundamentals / NIS2 report view** (done 2026-06-23).
  `leak_inspector/report/nis2.py`: a pure `build_cyberfundamentals_view`
  that re-groups the observable technical controls into five
  operator-facing areas — Encryption in transit `[Art.21(2)(h)]`, Email
  security `[(g)/(h)]`, DNS security & resilience `[(c)/(h)]`, Web
  hardening `[(g)]`, Vulnerability disclosure `[(e)]` — each control
  reported ok / fail / not-deployed (surface-only, e.g. TLS-RPT) /
  not-assessed (certainty rule: un-probed data never reads as fail).
  Verdicts reuse the score_v2 predicates so the baseline and the
  scorecard never disagree. Carried on `ReportDocument.cyberfundamentals`,
  built in `builder._build_cyberfundamentals`, serialized via `asdict`
  (nested frozen dataclasses), rendered in text/markdown/html. Framing:
  CyberFundamentals-first, NIS2 noted, "indicator not a conformity
  assessment" stated in every format. Tests: `test_nis2_view.py`
  (grouping, status verdicts, MX-gating, surface-only, counts, doc+JSON
  wiring). Framing/taxonomy were operator-signed-off.

- [ ] **CSP directive analysis — operator-declared allowlist** (idea,
  2026-06-23; data already captured). We store the raw
  `Content-Security-Policy` header but only check it for *presence*
  (`_csp_present`). Parsing the host-source directives — especially
  `script-src` (declared code-trust surface), and `img-src` /
  `style-src` / `connect-src` — yields three insights: (1) which
  third-party/tracker hosts are *operator-sanctioned* (present in the
  allowlist = deliberate integration, cross-referenceable against the
  tracker modules); (2) *latent* third parties allowed but not loaded
  this session (widens coverage beyond observed traffic, still
  certain-data because it's a fact in a captured header); (3) weak-CSP
  findings (`*`, `https:`, `'unsafe-inline'`, `'unsafe-eval'` in
  `script-src`) that feed the Web-hardening area of the baseline view.
  **Discipline:** a CSP entry is *permission*, not evidence of data
  leaving — frame strictly as "operator-declared allowlist," never as a
  leak. Caveat: nonce/hash-only and report-only CSPs name no domains, so
  coverage is partial. Effort: a CSP parser + a finding/placement
  decision (likely alongside the unclassified-host / supply-chain view);
  no new capture.

- [ ] **Security-header executive-summary findings** (placement
  decision). The 11 security-header checks surface via the
  security-section rationale + `compute_top_action`, but not as
  findings. Architectural note: `derive_findings` takes a
  `TransportPosture` while the header data lives on
  `Analysis.security_headers`; Analysis-derived findings already live
  in `report/builder.py` — decide placement when picked up (NOT
  `http_posture/findings.py` as first sketched).

- [ ] **Iframe storage capture** (deferred to v1.3; **unlocks IAB TCF
  v2 consent decoding**). v1.0 snapshots top-level-origin storage only.
  Sourcepoint / Didomi / Quantcast CMPs write the `euconsent-v2` TC
  string into CMP-iframe storage, so those sites classify "unknown"
  today. Capturing iframe storage + decoding the TC string converts
  the largest CMP family into real reject/accept states. (The TCF
  decoder was deliberately not built: no in-reach capture carries a
  decodable TC string to verify against — certain-data rule.)

## PDF output as a supported file format
- [x] **Analyze can export the report to a PDF file** (done 2026-06-13).
  `analyze --format pdf -o report.pdf` renders the existing HTML report
  through WeasyPrint (HTML→PDF) with a branded cover page: BeLibre logo,
  the site URL, the project source link (codeberg), the capture date,
  and the disclaimer. The body is the full detailed report, including
  the per-dimension penalty breakdown and the "How the score is
  calculated" derivation. `leak_inspector/report/pdf.py` (cover +
  HTML-assembly are pure/testable; the WeasyPrint call is lazy with an
  install-pointing error if absent). WeasyPrint is the optional `[pdf]`
  extra (needs native libs: cairo/pango/gdk-pixbuf). PDF is binary →
  requires `-o`. Tests: `test_report_pdf.py`, `test_cli_pdf.py`
  (render gated skip-if-absent). Verified end-to-end: 75-page PDF, cover
  page 1 carries all required elements.

## P3 — backlog

- [ ] **Cross-cutting "ID-sync chain" finding.** Many unclassified
  hosts appear in `?redir=` chains hopping out of `dpm.demdex.net`
  (Adobe AAM). A single finding surfacing the chain itself (rather
  than each hop individually) would compress the report — likely more
  value per effort than classifying each sync partner below.

- [ ] **Niche tracker modules — Adobe AAM ID-sync partners.**
  Single-hit cookie-sync partners observed in the AAM chain. One-per-vendor
  modules following `leak_inspector/modules/README.md` + the test pattern in
  `tests/test_modules_ga4.py`. The three verified against a *local* capture
  (`captures/apple-max.zip`) are built; the rest are **not present in any
  local capture** (the referenced `microsoft-max.zip` no longer carries
  them), so they stay deferred per the certain-data rule — revisit when a
  capture demonstrates each (and note several are defunct).
  - [x] Exponential Interactive (Tribal Fusion) — `*.tribalfusion.com`
    (module `tribalfusion`, 2026-06; KB page in Ad-tech)
  - [x] Nativo (formerly PostRelease) — `*.postrelease.com`
    (module `nativo`, 2026-06; KB page in Ad-tech)
  - [x] bttrack.com — confirmed = **Bidtellect, Inc.** (US native DSP/DMP)
    (module `bidtellect`, 2026-06; KB page in Ad-tech)
  - [ ] InnovId — `ag.innovid.com` (video advertising / measurement) — not in local captures
  - [ ] OwnerIQ — `*.owneriq.net` — not in local captures
  - [ ] FlashTalking (Mediaocean) — `*.flashtalking.com` — not in local captures
  - [ ] Magnite CTV (formerly SpotX) — `*.spotxchange.com` — not in local captures
  - [ ] Adentifi — `*.adentifi.com` — not in local captures (likely defunct)
  - [ ] Reson8 — `*.reson8.com` — not in local captures (likely defunct)
  - [ ] Media6Degrees — `*.media6degrees.com` — not in local captures (now Dstillery)

- [ ] **RPKI route-origin validation** (resilience; from the OpenKAT
  review). No `rpki` check exists in `dns_posture/`. Clearest missing
  resilience signal — can the hosting / mail IPs be BGP-hijacked? Fits
  the existing per-host IP/ASN enrichment; needs an external
  ROA/validity data source (certain-data rule: skip the signal when
  validity can't be resolved, like the US-ownership deductions).
  Licence note if porting OpenKAT logic: EUPL-1.2 is GPLv3-compatible
  iff our licence stays plain GPLv3 (not "or later"); keep EUPL
  notices and record in `SBOM.md` — though in practice the reusable
  asset is rule logic / thresholds, not drop-in files.

- [ ] **DNS-posture extras** (skipped for v1):
  - [ ] Full DNSSEC validation chain — currently a presence-check only
    (DS at parent + DNSKEY in zone); full validation needs a
    validating resolver and per-record signature verification.
  - [ ] MTA-STS policy-file fetch — only the TXT advertisement at
    `_mta-sts.<domain>` is checked; the policy at
    `https://mta-sts.<domain>/.well-known/mta-sts.txt` is not parsed.
  - [ ] DANE / TLSA records — rare in the wild; requires DNSSEC.
  - [ ] Reverse-DNS (PTR) lookups on resolved IPs — marginal signal.

- [ ] **TLS version / weak-protocol security checks.** Blocked on data:
  neither the transport probe nor the bundle captures TLS
  version/cipher today; needs a capture/enrichment extension first.

- [ ] **`facebook_pixel` `o` parameter semantics.** Different semantics
  on `/tr` (4-digit numeric, undocumented) vs `/b.php` (0/1 flag);
  currently falls through to `CAT_OTHER`. Investigate `/tr` semantics.

## Gated — explicit decision required before starting

### Chromium support

Gate: explicitly reversing the "Firefox only" non-goal in CLAUDE.md —
don't start it casually. Motivation was operator browser
*availability*, which Firefox auto-provisioning (shipped) already
solves; Chromium remains only as a fidelity lens. The analysis layer
is already browser-agnostic (bundles record `browser.name/version`);
the cost concentrates in capture fidelity and score comparability:

- [ ] Phase 1 — capture-only behind `--browser chromium`: driver
  factory, profile handling, BiDi subscription. Bundles stamped;
  **no score** on Chromium bundles initially (or score with a visible
  browser tag) — every coefficient and snapshot was calibrated on
  Firefox captures.
- [ ] Phase 2 — stealth validation, empirical: compare tracker sets
  Firefox-vs-Chromium on known captures. Chromium's automation
  detection is an arms race (navigator.webdriver, --enable-automation,
  CDP-presence detection by anti-bot scripts); an
  undetected-but-actually-detected capture silently produces wrong
  reports, violating the "only base on certain data" rule.
- [ ] Phase 3 — BiDi behavioral parity: response-body capture,
  storage-snapshot timing, redirect-event ordering all differ between
  the two BiDi implementations; the consent pass leans on snapshot
  cadence and needs per-browser re-validation.
- [ ] Phase 4 — score comparability decision: Firefox ships ETP by
  default, Chromium blocks nothing — same site, different tracker
  sets, different scores. Decide: browser-qualified scores
  ("58/100 in Firefox") vs recalibration. Bulk-tool rankings must
  never silently mix browsers.

## Ongoing — grows as new captures land

- [ ] More verdict-classification seeds. Each new vendor seed needs a
  real-data justification (a capture where the vendor appears) before
  encoding.
- [ ] More `Finding.kind` slugs as findings get added or refined.