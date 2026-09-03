# Changelog

## [v4.6.34](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.34) — Third whitebox benchmark challenge (SSTI) (2026-09-02)

### Added
- **A third whitebox benchmark challenge (`whitebox-ssti`) widens source-to-runtime validation to server-side template injection.** With `whitebox-cmdi` (RCE) and `whitebox-sqli` now solving within the standard benchmark deadline, this adds an equivalent SSTI challenge so the source-to-runtime bridge is exercised across a third injection class. Its vulnerable preview route (`/internal/preview`, which renders a concatenated user parameter through `render_template_string`) is **not linked from any page**, so black-box crawling cannot reach it and solving it requires the bridge: scan the source, discover the route and the co-located template sink (which the code scanner types as a template sink → SSTI), attribute the sink to that handler, probe the route live, then prove the injection with the classic `{{7*7}}` → `49` evaluation. Operator-only benchmark tooling; the shipped binary is unchanged (releases build only `./cmd/xalgorix`).

## [v4.6.33](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.33) — Whitebox guidance teaches the source-to-runtime bridge (2026-09-02)

### Changed
- **The whitebox methodology briefing now drives the agent through the source-to-runtime bridge instead of describing the old hand-crafted flow.** The bridge shipped over v4.6.23–v4.6.32 (`scan_source_sinks`, `scan_source_routes`, `probe_hypothesis`, auto-seeding at scan start, and the `verify_sqli`/`verify_xss`/`verify_oob` confirmers) was fully built, but the whitebox briefing the agent reads at scan start still described the pre-bridge methodology — `code_search` a sink, trace it by hand, then hand-craft an exploit — and never mentioned the auto-seeded ledger or the new tools. A benchmark diagnostic showed the cost: with the correlated source→route hypothesis already sitting in the ledger from iteration 1, the agent spent its early budget black-box crawling (chasing a reflected XSS) and only reached the seeded SQL-injection route late, missing an 8-minute deadline it clears comfortably when it works the seeded lead first. The live-target modes (whitebox, and provision-and-DAST) now tell the agent to WORK THE SEEDED LEDGER FIRST: `claim_next_hypothesis` the top correlated source→route lead, `probe_hypothesis` it to confirm it is live, then CONFIRM the class deterministically with `verify_sqli` (error-based SQLi), `verify_xss` (browser-executed XSS), or `verify_oob` (blind RCE/SQLi/SSRF/XXE) — widening to broad black-box crawling only after the seeded leads are worked. The source-review mode (no live target) is unchanged. The guidance text was also refactored behind a pure `whiteboxGuidanceText` helper so it is unit-tested directly.

## [v4.6.32](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.32) — Deterministic error-based SQL injection confirmer (verify_sqli) (2026-09-02)

### Added
- **`verify_sqli` confirms error-based SQL injection in one call — the SQLi counterpart of `verify_xss`.** The source-to-runtime bridge (`scan_source_sinks` → `scan_source_routes` → `probe_hypothesis`) gets the agent to a reachable route that a source SQLi sink flows into, but PROVING the injection still relied on the model hand-crafting a quote payload, reading the response, and recognizing a DBMS error — several turns of scarce budget for a class black-box scanners already miss most (the `whitebox-sqli` benchmark took ~12 min to land it manually, and missed at 8 min). The new tool takes a ledger `hypothesis_id` (a source-route/authenticated-endpoint hypothesis) or a `url`, plus the `parameter` to test, and issues three scope-gated requests: a benign baseline, a single-quote payload that breaks SQL syntax, and a doubled-quote payload that re-balances it. It confirms error-based SQLi when a DBMS error (`You have an error in your SQL syntax`, `ORA-#####`, `SQLSTATE`, `PG::…`, `SQLite`, `unclosed quotation mark`) appears on the broken request but **not** on the benign baseline — rejecting always-on error pages outright. When the balanced request recovers (no error) it reports the classic break/recover signature at high confidence; when it still errors (some apps/WAFs error on any quote) it confirms at lower confidence. On success it records exploit-proven evidence in the shared ledger and tells the agent to report it as High CWE-89; it does not auto-report. DBMS-error detection reuses the same signatures as the reporting impact-gate (shared `LooksLikeSQLError`), so the confirmer and the gate never drift. Safety: it resolves the target host internally and therefore always scope-checks it (refusing the operator's own machine/listener), uses the scan's session auth, does not follow redirects, honors the request-rate policy and cancellation, and is disabled in passive mode.

## [v4.6.31](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.31) — Error-based SQL injection recognized as valid High proof (2026-09-02)

### Fixed
- **A reflected DBMS error is now treated as valid proof of error-based SQL injection instead of being silently dropped.** The `whitebox-sqli` benchmark (v4.6.30) surfaced a false negative: an agent could inject a quote, get back a database error that proves the injection point (`You have an error in your SQL syntax`, `ORA-#####`, `SQLSTATE`, `PG::…SyntaxError`, `SQLite error`), and still never file the finding. Three things conspired against it. (1) The agent prompt contradicted itself — one rule accepted a DB error as SQLi proof while the evidence standard listed "an error string" as *not* an outcome and the depth-first checklist omitted DB errors entirely, so the agent judged its own proof insufficient. (2) The reporting `checkClaimConsistency` C:H gate rejected a High/`C:H` error-based finding because a lone DB error carries no data-obtained marker. (3) The DBMS-error signatures were absent from the concrete-impact indicators, so error-based SQLi was auto-downgraded and never tagged exploit-proven. All three are fixed: the prompt now names a provoked DBMS error as a concrete error-based SQLi outcome (CWE-89) to report as High without extracting data; the C:H gate is SQLi-aware (a SQLi finding whose proof carries a native SQLi/DBMS-error signal satisfies C:H); and the DBMS-error signatures are recognized as concrete impact so the finding is tagged exploit-proven and the verifier can auto-confirm. A proven injection point is reported as High even when the PoC only triggered a database error rather than dumping rows. The SQLi carve-out is scoped to SQLi findings, so other classes still require real data-obtained evidence for C:H.

## [v4.6.30](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.30) — Second whitebox benchmark challenge (SQLi) (2026-09-02)

### Added
- **Second whitebox benchmark challenge (`whitebox-sqli`) widens source-to-runtime validation to a second injection class.** The `whitebox-cmdi` challenge (v4.6.27) proved the source-to-runtime bridge end-to-end for command injection; this adds an equivalent SQL-injection challenge so the bridge is exercised across classes rather than one. Its vulnerable reporting route (`/internal/report`, which concatenates a user parameter straight into a raw `SELECT`) is **not linked from any page**, so — as with `whitebox-cmdi` — black-box crawling can't reach it and solving it requires the bridge: scan the source, discover the route and the co-located SQLi sink, attribute the sink to that handler, probe the route live, then prove the injection. Operator-only benchmark tooling; the shipped binary is unchanged (releases build only `./cmd/xalgorix`).

## [v4.6.29](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.29) — Handler-span route↔sink correlation (2026-09-02)

### Changed
- **Source route↔sink correlation now attributes a sink to its enclosing handler, not the whole file.** When source auto-seeding types a route by a co-located dangerous sink, it previously matched *any* sink anywhere in the same file — so in a multi-route file every route was typed with the same (often unrelated) vuln class. The first whitebox benchmark run showed this: all three routes in the challenge's `app.py` were typed `rce` even though only `/internal/run-check` actually contains the `os.popen` sink. Correlation now uses the route's handler span — a sink at line L is attributed to the route whose declaration is the nearest one at or above L (bounded by the next route declaration below it) — so only the route that genuinely reaches a sink is class-typed and prioritized; the others seed as ordinary attack-surface (`idor`) leads. This keeps `probe_hypothesis` and exploitation focused on the route that actually reaches the dangerous code.

## [v4.6.28](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.28) — Route-discovery precision fix (2026-09-02)

### Fixed
- **Source route discovery no longer mistakes ordinary `.get()`/`.post()` calls for HTTP routes.** The Express/Koa route pattern matched `<anything>.get("…")`, so common non-router calls — `request.args.get('host')`, `dict.get('key')`, `session.get('token')` — were scooped up as bogus route hypotheses (the first whitebox benchmark run seeded 4 routes for a 3-route app; the extra one was a "route" named `host` harvested from `request.args.get('host')`). The receiver is now restricted to router-like names (`app`, `router`, `routes`, `route`, `api`, `srv`, `server`, `mux`, `koa`, `fastify`), so only real route declarations are seeded — keeping the ledger and `probe_hypothesis` focused on genuine attack surface. Gin/Echo routers, which use upper-case method calls (`r.GET(...)`), are matched by the separate Go-router pattern and are unaffected. Surfaced by the v4.6.27 whitebox benchmark.

## [v4.6.27](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.27) — Whitebox benchmark challenge for the source-to-runtime bridge (2026-09-02)

### Added
- **A whitebox benchmark challenge that measures the source-to-runtime bridge end-to-end.** The benchmark harness could only measure black-box detection; the whitebox capability shipped over the last four releases (`scan_source_sinks`, `scan_source_routes`, `probe_hypothesis`, and auto-seeding at scan start) had no benchmark to prove it works. A `Challenge` can now carry a `SourceFiles` source tree, which the harness materializes to a temp directory and hands to the scan as the target's source repo (the real runner wires it via `SetSourceRepo`). The new `whitebox-cmdi` challenge is a small app whose command-injectable route is **not linked from any page** — black-box crawling cannot reach it, so solving it (class RCE) genuinely requires the bridge: scan the source, discover the route and the `os.popen` sink in the same file, probe it live, then exploit it. This is operator-only benchmark tooling; the shipped binary is unchanged (releases build only `./cmd/xalgorix`).

## [v4.6.26](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.26) — Auto-seed the ledger from whitebox source at scan start (2026-09-02)

### Changed
- **Whitebox source now auto-seeds the ledger at scan start — the source-to-runtime bridge fires from iteration 1.** The three whitebox tools (`scan_source_sinks`, `scan_source_routes`, `probe_hypothesis`) only ran if the model chose to call them, so a scan with source attached could spend early iterations black-box-crawling before the code was ever examined. Now, as soon as the source is resolved, the scan sweeps it for dangerous sinks and HTTP routes and seeds the ledger with the resulting hypotheses — dangerous sinks (`file:line`), reachable routes (real HTTP paths), and the route↔sink correlations (a route whose handler file has a dangerous sink is seeded class-typed and higher-confidence) — exactly as an uploaded OpenAPI/HAR context already auto-seeds the surface. The specialists get concrete, source-derived leads to `probe_hypothesis` and exploit from the first iteration instead of rediscovering them. Deterministic, bounded (per-sweep caps), and idempotent (the ledger dedups), so it never floods or duplicates; a no-op when no source is configured.

## [v4.6.25](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.25) — Touch the live target from a seeded hypothesis (probe_hypothesis) (2026-09-02)

### Added
- **`probe_hypothesis` closes the source-to-runtime loop: it touches the live target from a seeded hypothesis.** `scan_source_sinks` finds the dangerous code and `scan_source_routes` gives it a reachable path, but until now nothing acted on that path — the model had to hand-craft every request. The new tool takes a ledger hypothesis that carries a real HTTP path (a `source-route` hypothesis, or an ingested/authenticated endpoint), resolves it against the scan target, issues **one** baseline request, and records the response as evidence — turning a guessed route into a confirmed lead. A live `2xx` raises confidence and moves the hypothesis to `testing`; `401/403` flags it as a prime `authz_matrix` target; a `404`/connection failure marks it `blocked` so the scheduler stops spending budget on routes that aren't deployed. It uses the scan's session auth automatically (so authenticated routes are probed authenticated) and does not follow redirects (a `3xx` to `/login` is itself a signal). Safety: because the tool resolves the target host internally (the agent-loop scope gate keys off tool arguments and can't see it), it always scope-checks the resolved host with the same operator-machine guard `authz_matrix` uses and refuses loopback/RFC1918/the dashboard listener; it reuses the existing scope-agnostic request path, honors the scan's request-rate policy and cancellation, and is disabled in passive mode. Source-location (`file:line`) endpoints from `scan_source_sinks` are skipped — they carry no HTTP path.

## [v4.6.24](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.24) — Give source-discovered sinks a reachable HTTP path (scan_source_routes) (2026-09-02)

### Added
- **`scan_source_routes` completes the source-to-runtime bridge: it gives source-discovered sinks a reachable HTTP path.** `scan_source_sinks` (v4.6.23) finds the dangerous code (a sink at `file:line`), but a `file:line` is not something the runtime tools can request. The new tool extracts HTTP route declarations from the attached source across the common frameworks (Flask/FastAPI, Django, Express, Spring, Go routers, Rails) and seeds each into the shared ledger as a hypothesis with a **real, reachable path** — including internal/admin routes a black-box crawler never reaches. It then correlates routes with sinks by handler-file co-location: a route whose file also contains a dangerous sink is seeded **class-typed** (by the worst sink class present) at higher confidence with a data-flow note linking the two, turning "there is an rce sink somewhere" into "`POST /admin/exec` reaches it — attack it." Uncorrelated routes seed as authz/attack-surface (`idor`) leads. Seeding is bounded (max 40 per sweep) and idempotent (dedup by vuln class + path), and the tool degrades to a black-box fallback when no source is configured. Specialists `claim_next_hypothesis` and request the route on the live target to prove the vuln.

## [v4.6.23](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.23) — Bridge whitebox source to runtime (scan_source_sinks) (2026-09-02)

### Added
- **`scan_source_sinks` bridges whitebox source to runtime exploitation.** Black-box recon finds routes; whitebox search finds the dangerous code behind them — but nothing connected the two automatically. The new tool sweeps the attached source tree for dangerous sinks (RCE/command injection, SQLi, SSRF, file I/O→LFI, template→SSTI, deserialization, open redirect) using the same curated patterns as `code_search`, then seeds each hit into the shared ledger as a source→sink hypothesis tagged with its `file:line` and a `source-sink:` data-flow note — the first automated populator of `Hypothesis.DataFlow`. Each sink class is mapped to its canonical vuln class (e.g. `cmdi`→`rce`, `fileio`→`lfi`, `template`→`ssti`); discovery-only classes (secrets, auth, crypto) are deliberately not seeded. Seeding is bounded (max 40 hypotheses per sweep) and idempotent (dedup by class + `file:line`, so re-running adds nothing), and when no source is configured the tool degrades to a black-box fallback message. Specialists can then `claim_next_hypothesis` and trace each sink back to a reachable route to prove it on the live target — the first step toward source-to-runtime exploitation.

## [v4.6.22](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.22) — Stop dropping browser-confirmed XSS as a false positive (2026-09-01)

### Fixed
- **The false-positive gate no longer rejects a browser-confirmed XSS as "reflection only."** When `verify_xss` proves execution in a real browser, it emits a machine-generated proof — `Browser-confirmed XSS: a dialog:alert dialog carrying the nonce "…" fired while loading …` — but that phrasing matched none of the gate's execution markers, while the reflected payload the agent includes (`<script>`, `onerror=`) tripped the reflection-only check, so a genuinely proven XSS was dropped (and had to be re-reported, sometimes landing as needs-manual-verification). The gate now recognizes the verifier's execution tokens (and dialog/console/DOM signal kinds), so a browser-confirmed XSS passes through to the independent verifier instead of being discarded. Surfaced by the first benchmark baseline run.

## [v4.6.21](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.21) — Benchmark scoring, robustness, and a per-challenge timeout (2026-09-01)

### Changed
- **Benchmark scoring is now class-based.** Each challenge app hosts exactly one vulnerability, so a finding of the expected class against it counts as solved; the previous exact-endpoint requirement wrongly failed a correct detection when the agent proved the bug on a different path (e.g. reflected XSS confirmed at `/?q=` rather than a declared `/search`). Path precision is a separate concern from class detection, which is what the benchmark measures.
- **Per-challenge wall-clock timeout.** `bench.RunWithTimeout` (and a `-timeout` flag on `xalgorix-bench`, default 8m) bound each challenge scan and mark timeouts on the scorecard, so a wandering or stuck scan can no longer hang the whole run; partial findings gathered before the deadline are still scored.

### Fixed
- **IDOR challenge no longer panics on non-`/api/orders/` paths** (it sliced the prefix off every request path) and now serves a small index linking to a concrete object so the endpoint is discoverable by the crawler.

## [v4.6.20](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.20) — More benchmark challenges (SSRF, SSTI, LFI, command injection) (2026-09-01)

### Added
- **Four more benchmark challenge classes.** The benchmark harness now covers SSRF (an internal-target fetch returns cloud-metadata-like secrets), SSTI (a `{{7*7}}` expression evaluates to `49`), LFI/path traversal (`../../etc/passwd` returns passwd-like content), and command injection (a shell metacharacter yields `uid=0(root)`), on top of the existing reflected XSS, IDOR, open redirect, and error-based SQLi. Each challenge simulates the dangerous outcome rather than performing a real fetch/exec/file-read, so the set stays hermetic and safe while presenting a crisp, detectable signal. All four map to existing scoring classes, so `xalgorix-bench` now measures eight classes.

## [v4.6.19](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.19) — Benchmark harness (measure detection per class) (2026-09-01)

### Added
- **A benchmark harness to measure detection, per vulnerability class.** New `internal/bench` package hosts a set of deliberately vulnerable, self-contained challenge apps (reflected XSS, IDOR, open redirect, error-based SQLi to start) and deterministically scores a scan's findings against the expected class and endpoint — so the effect of a change on real detection can be measured instead of assumed. The heavy agent run is injected as a `ScanFunc`, keeping the challenge apps, scoring, and aggregation fully unit-tested without any model calls. A new operator command, `xalgorix-bench`, wires the real agent and prints a per-class scorecard; it needs `XALGORIX_LLM`/`XALGORIX_API_KEY` and makes live calls, so it is a local tool and not part of the shipped release. This is the first step toward the repeatable evaluation the roadmap requires before any parity claim; the challenge set is intentionally small and will grow.

## [v4.6.18](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.18) — CWE-aware duplicate detection (2026-09-01)

### Changed
- **Duplicate detection now falls back to the CWE when a finding's title doesn't name its class.** The near-duplicate check keys on vulnerability class, which it inferred from title/description keywords — so a finding worded without the class name (e.g. "Unauthenticated contact creation" that is really stored XSS, tagged CWE-79) escaped class-based dedup and paid for its own full verification. When no keyword is present, the finding's CWE is now mapped to the class, so same-class findings on the same endpoint collapse as intended. The mapping is limited to high-confidence, common CWEs; an unmapped CWE with no keyword still yields no class, so the fallback never over-merges distinct findings.

## [v4.6.17](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.17) — Deterministic claiming of the next hypothesis (2026-09-01)

### Added
- **`claim_next_hypothesis` turns the evidence ledger into a real work queue.** The shared ledger already ranked untested hypotheses by confidence, but picking and assigning one was left to free-form model choice — so an agent could skip the strongest lead, and two parallel specialists could grab the same target. The new tool atomically claims the highest-confidence *queued* hypothesis (optionally scoped to a `vuln_class` lane), assigns it to the calling agent, and moves it to `testing` in one locked step — then hands back its next action and baseline. Specialists are now directed to claim their lane with it instead of eyeballing the ledger, so scheduling is deterministic and collision-free, and the coordinator provably works the most promising leads first.

## [v4.6.16](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.16) — Precision: dedup object-ID variants before verification (2026-09-01)

### Changed
- **Findings that are the same bug across different object IDs are now recognized as one.** Duplicate detection compared endpoints literally, so `/orders/1042`, `/orders/2087`, and `/orders/<uuid>` looked like three distinct findings — each one paying for a full independent verification pass and landing as a separate report. Deduplication now templates opaque per-object id segments (pure numbers, UUIDs, long hex/ObjectIds) to a placeholder when comparing endpoints, so object-id variants of the same endpoint collapse into a single finding. The templating is conservative (version segments like `v1`/`v2` and named paths are never collapsed) and applies only to the duplicate-comparison key — the stored and reported endpoint keeps the real id so the PoC stays reproducible. Because every dedup path (report gates and child→parent merge) shares this logic, it also cuts redundant, expensive verifier runs — precision over volume.

## [v4.6.15](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.15) — Two-account IDOR/BOLA from a second ingested session (2026-09-01)

### Added
- **`ingest_har` can now register a SECOND account (`role=b`) for true two-account IDOR/BOLA.** Proving broken object-level authorization needs two real identities: one user's session reaching another user's objects. Capture a HAR while logged in as a second user and run `ingest_har path=… role=b` — its session is registered as role B (a dedicated store that is deliberately *not* auto-applied to `http_request`, since role B is the "other user" identity used on purpose). `authz_matrix` then uses that ingested session as role B (when no operator second account is configured, mirroring how role A already falls back to an ingested session), replaying each request as role A, role B, and anonymous to flag any of role A's resources that role B can reach. Role-B ingestion registers credentials only — it does not seed the ledger, since role B is a comparison identity, not new attack surface.

## [v4.6.14](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.14) — Uploaded context seeds the hypothesis ledger (2026-09-01)

### Changed
- **Uploaded scan-context artifacts now seed the hypothesis ledger, not just a briefing.** When a scan starts with an OpenAPI/Swagger spec, HAR, Postman collection, or Burp export, Xalgorix already parsed it into a normalized endpoint surface and registered any captured session — but the endpoints only appeared as a passive text briefing. They now also become bounded, role-scoped authorization hypotheses (the prime IDOR/BOLA surface) in the shared ledger, so the operator-supplied surface directly drives `authz_matrix` and the evidence-driven specialists instead of relying on the model to re-derive targets from prose. Role is `authenticated` when the artifact carried a live session, otherwise `anonymous`. Seeding is deduplicated (by class/endpoint/parameter/role) and bounded, so it never floods the scheduler or double-counts across sub-agents. This mirrors what `ingest_har` does mid-scan, now applied to every context upload at scan start.

## [v4.6.13](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.13) — Ingested session drives the authorization matrix (2026-09-01)

### Changed
- **An ingested authenticated session now powers `authz_matrix` directly.** When a scan's credentials come from a logged-in HAR (`ingest_har`) rather than a separately configured operator account, `authz_matrix` now adopts that session as role A. Previously the HAR seeded IDOR/BOLA hypotheses but the matrix meant to test them saw only anonymous access and refused to run — so the authenticated surface never got exercised. Role A is the operator account when one is configured (unchanged, deterministic precedence) and otherwise the ingested session, closing the loop from `ingest_har` → session auth → cross-identity access-control testing.

## [v4.6.12](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.12) — Authenticated-context ingestion from HAR (2026-09-01)

### Added
- **`ingest_har` starts a scan from a real logged-in session.** Point it at a HAR captured while authenticated and it (1) registers the session credentials it carries (Authorization / Cookie / API-key headers) so subsequent `http_request` and `authz_matrix` calls are authenticated, and (2) seeds the ledger with the HAR's authenticated endpoints — the prime IDOR/BOLA surface — as role-scoped (`role=authenticated`) authorization hypotheses for the specialist to work. A new `internal/har` parser extracts the exercised endpoints (static assets skipped), their query/body parameters, and the session headers, with host-scope filtering. This gives Xalgorix the authenticated business-logic surface that unauthenticated crawling never reaches.

## [v4.6.11](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.11) — Auto-link reported findings to their ledger hypothesis (2026-09-01)

### Added
- **`report_vulnerability` accepts an optional `hypothesis_id`.** When the agent reports a finding that proves a ledger hypothesis (its id comes straight from `authz_matrix` / `verify_xss` / `verify_oob` / `record_hypothesis`), the finding is linked to that hypothesis and the hypothesis is marked proven on a successful report — closing the loop the precision finish-gate enforces without a separate `add_hypothesis_evidence` call. The link is deterministic (the agent names the exact id, no fuzzy matching) and best-effort: an empty or unknown id is a silent no-op, so it can never fail a valid report.

## [v4.6.10](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.10) — Out-of-band blind-vulnerability verification (2026-09-01)

### Added
- **`verify_oob` confirms blind vulnerabilities via the OAST oracle and records them in the ledger.** After minting a callback with `oob_callback` and planting it in a target-side payload, `verify_oob` polls the token and applies a class-aware verdict: SSRF requires an assessed non-scanner HTTP interaction, while blind RCE / command injection / XXE / SQL injection are confirmed by any genuine non-scanner callback (HTTP or a DNS lookup of the unique token). Confirmed results are recorded as role-scoped ledger evidence, giving Xalgorix a deterministic proof path for the classes that leave no in-band signal — directly targeting the blind-injection gap where autonomous scanners are weakest.

## [v4.6.9](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.9) — Broader XSS execution verification (console + DOM oracles) (2026-09-01)

### Added
- **`verify_xss` now confirms execution via console calls and DOM markers, not just dialogs.** The headless browser captures `console.*` API output as execution signals, and the verifier also reads DOM markers (`document.title` / `window.name`) after navigation. A payload can therefore prove execution by firing a dialog, by logging the nonce to the console (useful when a filter strips `alert()`), or by mutating a DOM marker to the nonce — extending confirmed XSS coverage to non-dialog and DOM-only sinks while keeping the same "proof of execution, not reflection" bar.

## [v4.6.8](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.8) — Evidence-driven multi-agent assessments (2026-09-01)

Scan-scoped parallel specialists coordinated by a durable hypothesis/evidence ledger, plus deep-testing tools for the vulnerability classes autonomous scanners are weakest at (broken authorization, XSS).

### Added
- **Scan-scoped multi-agent assessments.** Coordinator-led parallel specialists are enabled by default: full assessments split mature reconnaissance into two or three non-overlapping, hypothesis-driven roles (authorization/business logic, injection/server-side behavior, and source/data-flow or client/API analysis). `spawn_agent`, `check_agent`, and `wait_agent` are always available, and the root finish gate requires every running or completed delegation to be collected before the scan can finish.
- **Durable, scan-shared hypothesis/evidence ledger.** A new typed ledger on the scan context records every attack hypothesis (vulnerability class, endpoint, parameter, role/data-flow, preconditions, baseline, confidence, status, and next action) with append-only evidence. It is deduplicated, memory-bounded, and persisted atomically to `ledger.json`, so the coordinator and every specialist read and write one shared graph that survives restart/resume. New agent tools `record_hypothesis`, `add_hypothesis_evidence`, `update_hypothesis`, and `read_ledger` operate on it.
- **The ledger drives scheduling.** Once reconnaissance produces a plan, the ledger is seeded with a hypothesis per candidate class. Delegation is ledger-driven: the coordinator assigns disjoint, contract-bound work to deterministic specialist profiles — authorization/business-logic, injection/server-side, and client/source — each carrying an explicit evidence contract (baseline + concrete proof; out-of-band callbacks for blind classes; browser-confirmed execution for XSS/DOM) and a stopping rule.
- **Multi-role authorization matrix (`authz_matrix`).** Replays a single request as every configured identity — the primary session (role A), a second account (role B) when the scan has one, and anonymous — and reports the access-control differential. When a lower-privileged identity receives the same successful response as the authorized one, that is broken access control (IDOR/BOLA for a second user, auth bypass/BFLA for anonymous). It enforces scope (never probes the operator's own machine) and the per-scan request-rate policy, and records role-scoped hypotheses with the differential as evidence.
- **Browser-backed XSS execution verification (`browser_action command=verify_xss`).** The headless browser now records JavaScript dialogs as execution signals; the new action navigates a payload that raises a dialog carrying a unique nonce and confirms XSS only when that dialog actually fires — proof of execution rather than mere reflection. Confirmed results are recorded as browser-confirmed XSS evidence in the ledger.
- Injection/server-side and client/source specialist profiles now point at `authz_matrix` and `verify_xss` in their evidence contracts, so specialists produce the required proof automatically.

### Fixed
- **A scan could finish with proven work unreported.** A precision finish-gate now blocks completion while any hypothesis is marked proven but has no linked finding, requiring the agent to file it (and link the finding) or downgrade it. The gate is bounded so it can never deadlock a scan, and it complements the existing coverage gate rather than replacing it.
- **Concurrent scans could cross-wire sub-agents.** The delegation runner, agent map, concurrency semaphore, stop flag, and cleanup path were process-global. Constructing another root or child overwrote the runner; cleanup could clear another live scan; streamed partial results used the internal agent ID instead of the coordinator-visible delegation ID; and reset did not cancel a child already inside `Run`. Each root now owns a cancellable `agentsgraph.Graph`, descendants share only that graph, worker slots are per scan, partial/final evidence uses one stable ID, and shutdown waits briefly for children before persisting and deleting scan stores.
- **Parallel reports could borrow the wrong Verifier LLM client.** Verifiers were selected through one mutable callback per scan context, so a newly constructed child could replace the callback used by its siblings. `report_vulnerability` now captures the reporting agent's independent verifier in its own tool registry; parallel hunters block on their own verifier client and cannot overwrite or race a sibling's validation loop.
- **Delegated agents multiplied per-scan resource caps.** Each child previously received fresh duration, iteration, token, and tool-call counters, so a coordinator plus three specialists could consume roughly four times the configured caps. The graph now shares one scan budget: the root starts the wall clock once, agent iterations and tool-call batches atomically reserve the remaining allowance, and token deltas aggregate across agent clients.

## [v4.6.7](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.7) — Manual instance capacity (2026-09-01)

### Fixed
- **Explicit instance capacity was still reduced by adaptive RAM admission.** When `XALGORIX_MAX_INSTANCES` is set, it now defines the authoritative number of concurrent scan instances instead of acting only as an upper bound on a smaller RAM-derived estimate. Adaptive RAM admission remains the default when the variable is unset, heavy tools remain resource-throttled, and the critical disk floor still blocks new work.

## [v4.6.6](https://github.com/xalgorix/xalgorix/releases/tag/v4.6.6) — Concurrent admission and restart recovery (2026-09-01)

### Fixed
- **Healthy scans could remain pending even above the configured instance cap.** The RAM admission model calculated how many *additional* scans fit in currently available memory, but compared that number as though it were the total concurrency ceiling. As running scans consumed RAM, the UI could report an impossible state such as six running with `Max 5`, and new work stayed pending despite `XALGORIX_MAX_INSTANCES=20`. Admission and resource telemetry now add the already-running instances back to remaining RAM headroom, while still enforcing the manual cap and critical RAM/disk safety floors. Newly admitted scans temporarily reserve their estimated slot until their allocations are reflected in host telemetry, so a burst of pending jobs cannot all spend the same RAM snapshot. The Instances resource card now shows total capacity, running instances, and available slots separately.

## [v4.6.5](https://github.com/xalgord/xalgorix/releases/tag/v4.6.5) — Opt-in scan-completion notifications (2026-08-30)

### Added
- **Completion-summary control for Discord and Telegram.** `XALGORIX_NOTIFY_SCAN_COMPLETE` lets operators opt in to queue-level and report-level scan-completion summaries. It defaults to `false`; per-vulnerability alerts are unchanged.

### Fixed
- **Race-safe live notification updates.** Runtime setting changes are synchronized, and regression coverage verifies both enabled and disabled delivery paths.

### Documentation
- Documented the new setting in the README and architecture guide and regenerated the embedded Web UI assets.

## [v4.6.4](https://github.com/xalgord/xalgorix/releases/tag/v4.6.4) — macOS ARM64 and multi-architecture images (2026-08-29)

### Added
- Added native macOS ARM64 release support and multi-architecture container images.

## [v4.6.3](https://github.com/xalgord/xalgorix/releases/tag/v4.6.3) — Token usage and hosted-cost guidance (2026-08-27)

### Added
- The CLI now reports LLM token usage when a scan ends and explains which model costs are covered by the hosted service.

### Documentation
- Added a direct comparison of self-hosted and hosted Xalgorix, including operational responsibilities and cost tradeoffs.

## [v4.6.2](https://github.com/xalgord/xalgorix/releases/tag/v4.6.2) — MiniMax native web search (2026-08-26)

### Added
- MiniMax-backed scans now use MiniMax's native `web_search` capability.

## [v4.6.1](https://github.com/xalgord/xalgorix/releases/tag/v4.6.1) — Evidence integrity hardening (2026-08-24)

### Fixed
- Reporting rejects fabricated or unreachable non-findings and no longer treats a description as proof of exploitation.

## [v4.6.0](https://github.com/xalgord/xalgorix/releases/tag/v4.6.0) — Brand refresh and UX milestone (2026-08-23)

### Added
- Replaced the legacy opaque mark with a transparent vector logo and regenerated the favicon, dashboard, login, and README assets.
- Added persisted Light, Dark, and System dashboard themes with no-flash startup behavior.
- Added multi-file Postman uploads so a collection and environment can be supplied together, with variables and authentication resolved into the seeded attack surface.

### Compatibility
- No breaking changes; existing installations can upgrade in place.

## [Unreleased] — Provider model selector

### Added
- **Provider model selection across authentication methods.** Settings now renders one reusable model field for API-key, OAuth, and credential-free providers. Saved values retain the canonical `provider/model` routing prefix.
- **Live provider model discovery.** Providers with compatible OpenAI, Anthropic, Gemini, or Ollama model-list endpoints automatically load the models available to the selected credential. Discovery runs server-side and keeps credentials out of the browser. The built-in catalog no longer hardcodes model examples; providers without discovery support use explicit manual entry.
- **Novita AI provider.** The built-in catalog now includes Novita's OpenAI-compatible API endpoint and API-key authentication, with models loaded dynamically from Novita's API.

## [Unreleased] — Provider-specific CLI credential errors

### Fixed
- **Codex sign-in incorrectly reported missing Claude credentials.** Both CLI-reuse drivers previously returned the Claude-specific `auth.ErrNotFound` sentinel, so OAuth completion responded with `claude cli credentials not found` when the Codex credential was unavailable. Codex now returns a dedicated sentinel and the API responds with `codex cli credentials not found`. The sign-in modal also identifies the expected Codex credential path and read-only Docker mount.

## [Unreleased] — Per-scan live guidance

### Added
- **Operators can guide an agent while its scan is running.** The individual scan Events tab now includes a per-instance message composer with focused guidance suggestions, keyboard submission, delivery feedback, and responsive layout. Messages are routed to the exact running `instance_id`, queued for the agent's next iteration without interrupting its active work, and then surface in the same instance event stream. The WebUI client response type now also matches the existing `/api/chat` response contract.

## [Unreleased] — Markdown rendering in finding details

### Fixed
- **Finding text rendered raw Markdown in the dashboard.** The finding detail dialog showed `description`, `impact`, `technical_analysis`, and `remediation` as plain text, so the LLM-emitted Markdown (`##` headings, `**bold**`, fenced code, lists) appeared as literal characters. Added a small dependency-free Markdown renderer (`webui/src/components/markdown.tsx`) and use it for all non-code sections; the full description now renders as its own section. Code fields (PoC script, exploitation proof, suggested fix) stay verbatim in `<pre>`.

## [Unreleased] — Recognize command-injection RCE as proven

### Fixed
- **Genuine OS command-injection RCE was flagged "manual verification needed"** despite proof of root command execution. A critical `/uptime/{flag}` finding (CVSS 9+) whose proof showed `whoami`→`root`, `uname -a`→`… x86_64 GNU/Linux`, `uptime`→`load average …`, and full source-code disclosure was tagged `needs-manual-verification`. Cause: the concrete-impact detector (`HasConcreteImpact` and the reproduced-/concrete-impact indicator lists) only recognized command execution via `id`/`cat /etc/passwd`-style output (`uid=`, `gid=`, `root:`, `/etc/passwd`); it did not recognize `whoami`, `uname`, `uptime`, or Windows command output, so neither the independent Verifier's auto-confirm nor the `exploit-proven` classification fired. Added high-signal command-execution markers (`gnu/linux`, `load average`, `nt authority\`, `volume serial number`, `windows ip configuration`, `microsoft windows [version`) to both lists. Such findings are now `verified`/`exploit-proven` (Verified=true) instead of flagged for manual review. Regression: `TestHasConcreteImpact_RecognizesCommandExecutionOutput`.

## [Unreleased] — Phase-progress accuracy

### Fixed
- **Phase progress jumped to a late phase during reconnaissance** (e.g. showed "8. IDOR / BAC" at iteration 4 while still fingerprinting). `inferCurrentPhase` mapped ubiquitous HTTP tokens in tool arguments to methodology phases — `authorization` → 8, `cookie` → 4, `login`/`session` → 5, `/api/`/`graphql` → 9 — but those appear in ordinary requests on nearly every target (an authenticated scan sends an `Authorization` header from its first recon request), so the bar false-jumped immediately. Those keyword heuristics are removed; phases without a dedicated tool signal now advance only via the agent's explicit phase narration. Additionally, the reported phase is now **monotonic** (progress only moves forward) so it no longer bounces backward when the autonomous agent revisits recon between exploit attempts. Regression guard in `TestInferCurrentPhase_*`.

## [Unreleased] — "Exploit-proven" verification state

### Fixed
- **Proven findings were being flagged "manual verification needed."** When the independent Verifier returned an *inconclusive* verdict (ran out of turn/time budget, hit an LLM error, or the class needs state/timing/OOB it lacks), the finding was tagged `needs-manual-verification` regardless of the strength of its own proof — so a proven RCE whose exploitation proof shows `uid=0(root)`, or a SQLi that dumped rows, was presented as unverified. The verification dimension now has three states: `verified` (independently reproduced by the Verifier), **`exploit-proven`** (Verifier inconclusive/absent, but the finding's OWN proof contains a concrete exploitation outcome per `HasConcreteImpact` — command output, extracted data, OOB callback, SQL extraction, cloud-metadata), and `needs-manual-verification` (no concrete proof yet). `Verified` is now true for both `verified` and `exploit-proven`, so reports no longer stamp proven findings "UNVERIFIED — manual review required." Regression: `TestReportVuln_IndependentVerifierGate/inconclusive_with_concrete_first-party_proof_is_EXPLOIT-PROVEN`.

## [Unreleased] — Internal refactor: decompose web/agent god-files

### Changed
- **Behavior-preserving decomposition of the two largest files** into cohesive, single-purpose files within their existing packages. No logic changed (verified: top-level declaration sets identical vs the prior revision, and code content byte-identical except two removed stale orphan comments; build/vet/gofmt/golangci-lint clean, tests + `-race` green).
  - `internal/web/server.go` 8865 → 3187 LOC, split into `auth_session`, `ws_hub`, `queue_state`, `orchestrator`, `uploads`, `notify`, `scan_session`, `chat`, `schedules`, `scan_list`, `scan_query`, `scan_record`, `legacy_import`.
  - `internal/agent/agent.go` 4028 → 1422 LOC, split into `agent_prompt`, `agent_ratepolicy`, `agent_messages`, `agent_guard`.

## [Unreleased] — Report accuracy vs severity filter (customer feedback)

### Fixed
- **Report omitted findings the live severity filter hid.** When a scan was launched with a `severity_filter` (e.g. only show `critical` live), a vulnerability below that threshold was dropped from `sess.record.Vulns` entirely — so it never reached the on-disk `scan.json` or the PDF report. Customers saw "report shows no findings, but the logs show findings, even critical." The severity filter is now a **display/broadcast gate only**: every vuln the agent reports is always persisted to the scan record (and thus the report + `/api/findings`), and the filter only suppresses the real-time WebSocket broadcast and Discord/Telegram notification. `report_vulnerability` event handling in `internal/web/server.go` no longer wraps persistence in the `if allowed` block. Regression tests: `TestReportPersistsBelowFilterVulns`, `TestAppendVulnSummaryUniqueIsFilterAgnostic`.

## [Unreleased] — Telegram bot notifications (#157)

### Added
- **Telegram bot notifications** as a first-class notification channel alongside Discord. Operators configure a bot token + chat ID (`XALGORIX_TELEGRAM_BOT_TOKEN`, `XALGORIX_TELEGRAM_CHAT_ID`, `XALGORIX_TELEGRAM_MIN_SEVERITY`) and receive the same lifecycle and finding notifications Discord already receives: scan started, vulnerability found (severity-gated), scan finished, the completed PDF report delivered via `sendDocument`, and service restart/stop events. Telegram and Discord are independent and can be enabled together or separately.
  - New `sendTelegram` / `sendTelegramWithFile` helpers in `internal/web/server.go` mirror `sendDiscord` / `sendDiscordWithFile` (fire-and-forget goroutine, 30s timeout, `safe.Recover` boundary, early-return when unconfigured). Text messages use HTML parse_mode; the PDF report is attached as a `sendDocument` multipart upload. Telegram logical `ok:false` responses (HTTP 200 with an error body) are logged without crashing the scan.
  - The outbound host is pinned to `api.telegram.org` over HTTPS (not operator-configurable) so an attacker-influenced base URL cannot create an SSRF surface.
  - The bot token is `Sensitive: true` in the settings registry and never returned by any `/api/...` response; only a `telegram_configured` boolean is surfaced on scan records (mirrors the existing `discord_webhook_configured` redaction pattern verified in `server_test.go`).
  - Settings → Notifications tab now has a Telegram card (bot token, chat ID, minimum severity) and the Integrations page has a Telegram bot card.
  - v1 is global-only (no per-scan Telegram override); per-scan parity with Discord is tracked as a future follow-up.

## [Unreleased] — Loop-breaker for repeated identical tool calls

### Fixed
- **Endless loop on repeated identical tool calls (#158).** The agent could spin indefinitely, regenerating the same tool call (most commonly `terminal_execute`) with identical arguments and an identical failing result — observed reaching iteration 2106+ with no progress. Stuck detection in `internal/agent/hooks.go` only accumulated for `browser_action` and `web_search`; the default branch of `hookStuckTracker` reset all stuck counters for every other tool, so a loop on `terminal_execute` (or any non-browser/search tool) never tripped a nudge or force-skip and ran until `MaxIterations` (default 0 = unlimited) or process kill.
  - New `ScanState` fields track consecutive identical `(tool, args)` and consecutive byte-identical tool outputs; these counters are deliberately NOT reset by `OnHealthyResponse` (a "healthy" response re-issuing the same call is exactly the loop).
  - New thresholds `RepeatCallSoftNudge=3`, `RepeatCallHardSkip=5`, `RepeatResultHardSkip=4`.
  - `hashToolArgs()` (order-independent FNV-64a) and `resultFingerprint()` detect identical `(tool, args)` and identical output across iterations.
  - `hookStuckTracker`'s default branch now counts consecutive identical calls; `add_note`/`read_notes` are excluded so legitimate note-taking between identical test calls doesn't reset the counter.
  - New `hookResultRepeatTracker` on `OnToolResult` counts byte-identical outputs (ignores `add_note`/`read_notes`/`finish`).
  - `hookStuckNudge` force-skips + nudges ahead of the browser hard-limit on repeated identical call (soft/hard) and repeated identical output; counters reset after firing.

### Notes
- No change to `agent.go` (existing `ForceSkip`→skip / `Nudge`→user-message machinery already consumes the result) and no change to the `MaxIterations` default (legitimate wildcard scans run thousands of iterations).
- Known follow-up, not fixed here: the three block branches in `agent.go` (`shouldBlockForActivityPolicy` / `shouldBlockForPhaseRestriction` / `shouldBlockForOutOfScope`, ~L1547-1581) still do not increment any stuck counter.

## [Unreleased]

### Added
- **`POST /api/restart`** — schedules a graceful backend restart from the dashboard/API. The restart never interrupts active work: it waits until the scanner is idle (no running/pending/paused/queued/starting instances, no in-progress scan, no leased tool processes) before restarting, then in-flight scans auto-resume. Shares the same `scannerIdle` gate and restart-when-idle watcher as the existing `xalgorix --restart-when-idle` (SIGUSR1) path. Returns `{ "status": "scheduled"|"already_pending", "idle": <bool> }`. Inherits the existing auth + CSRF stack as a mutating route.

## [Unreleased] — Runtime-editable provider catalog and OAuth flows

### Added
- **Runtime-editable provider catalog** at `~/.xalgorix/data/providers.json`. The file ships empty: there are no baked-in defaults, no startup writes, and no auto-fetch. Operators populate it through the dashboard or the new HTTP API. Catalog reads/writes use atomic temp-rename with `0600` file mode and a parent dir `chmod 0700`; corrupt JSON is treated as empty for `List` and refuses every `Create`/`Update`/`Delete` until the file is fixed.
- **Four OAuth flows** for storing per-provider credentials, all coalesced through a single `Driver` registry and a `TokenSink` that serializes refreshes per `(provider, profileId)`:
  - `pkce`: loopback redirect on `127.0.0.1:<ephemeral>` with PKCE S256 plus a paste-fallback that activates automatically when `XALGORIX_BIND` resolves to a non-loopback address.
  - `device_code` (RFC 8628): polls the token endpoint at the server-supplied interval, honors `slow_down`, and surfaces `408` on `expires_in` timeout.
  - `setup_token`: posts an operator-supplied bearer to the configured `tokenEndpoint` and persists the resulting profile.
  - `claude_cli_reuse`: read-only import of the Claude CLI credential file; mtime + SHA-256 of the source file are unchanged after import.
- **Operator-triggered openclaw catalog import** via `POST /api/providers/import-openclaw`. HTTPS-only, skip-on-collision merge with a per-entry `outcomes` envelope. Upstream non-2xx responses bubble up as a `502` envelope and the on-disk catalog is left untouched.
- **Per-scan `provider_profile` field** on `ScanRequest`. The web layer's `resolveScanCredentials` resolves the routing precedence `provider_profile → catalog default → legacy env`, with explicit `api_key` overrides forcing API-key auth. Unknown profile keys fail fast with `400` before any scan goroutine spawns.
- **One-time legacy migration banner.** When `XALGORIX_LLM` (or `XALGORIX_API_KEY`) is set and both `providers.json` / `auth-profiles.json` are absent or empty, the dashboard offers a one-click migration that materializes a `legacy` catalog entry plus a `legacy:default` API-key profile and drops a `.legacy-providers-migrated` sentinel. The importer never modifies `~/.xalgorix.env`.
- **New HTTP routes** under the existing auth + CSRF stack:
  - `GET/POST /api/providers`, `PUT/DELETE /api/providers/{id}`, `POST /api/providers/import-openclaw`
  - `GET/POST /api/providers/migrate-legacy` and `GET /api/providers/migrate-legacy/status`
  - `GET /api/auth/profiles`, `POST /api/auth/profiles/api-key`, `POST /api/auth/profiles/oauth/start`, `POST /api/auth/profiles/oauth/complete`, `POST /api/auth/profiles/{key}/refresh`, `DELETE /api/auth/profiles/{key}`
  All credential strings (`apiKey`, `accessToken`, `refreshToken`) are masked via `maskAuthCredential` on every response while metadata (`expiresAt`, `scopes`, `tokenType`, `requiresReauth`, `apiBaseOverride`) round-trips unmasked.
- **Settings → Providers tab** in the dashboard composing the catalog editor, profile list with per-flow OAuth modal (loopback / device / paste shapes), openclaw import button, and the legacy migration banner.

### Changed
- The LLM client now resolves outbound endpoints through a composite resolver: when the catalog is non-empty it routes through `catalogResolver`; when the catalog is empty and `XALGORIX_LLM` matches the legacy provider shape it falls back to `legacyResolver`; otherwise requests fail with a config error. The header-application matrix lives in a single `(HeaderStyle × AuthMethod)` switch covering OpenAI / Anthropic (`anthropic-version: 2023-06-01`) / Gemini (`x-goog-api-key`) for both API-key and OAuth-bearer auth.

### Notes
- The env-file path keeps working unchanged for existing operators: setting `XALGORIX_LLM` and `XALGORIX_API_KEY` continues to drive scans without touching the catalog or profile store. Catalog and profile writes never modify `~/.xalgorix.env`.
- `/oauth/callback` is intentionally not registered on the dashboard mux — loopback callbacks land on per-flow ephemeral listeners owned by the `pkce` driver.

### See also
Spec: `.kiro/specs/provider-catalog-and-oauth/`

## [Unreleased] — Concurrency model: RAM-only admission

### Changed
- **Scan admission now derives concurrency purely from RAM headroom.** `EffectiveMaxInstances` no longer mixes CPU load and disk pressure into the slot count. CPU saturation throttles scans (the kernel time-slices) but doesn't crash them, so gating new scans on CPU only reduced total throughput. Disk consumption is bursty, not reserved up front; disk now acts as a yes/no admission gate that refuses new scans only when free space is below the critical floor (`XALGORIX_DISK_CRITICAL_MB`, default 1 GB).
- **Per-tool CPU throttling is unchanged** and still lives in the tool-lease layer (`tryAcquireToolLease`), where it correctly queues heavy subprocess launches without blocking scan admission.
- **Dashboard layout.** The "Max N · scan budget · tool cap" caption moved from under the DISK FREE tile to under HOST MEMORY, where the underlying constraint actually lives. DISK FREE now describes its own role.
- **Admission rationale** strings (`/api/status`, the dashboard) only mention dimensions that actually gate admission (RAM and disk-critical). Pre-cleanup, an "instances 4/4 — CPU critical: load X" message was misleading because admission proceeded regardless of CPU.

### Removed
- `XALGORIX_SCAN_CPU_LOAD` env var and its associated `perScanCPULoad` / `autoScanCPULoad` plumbing, the `Capacity().ScanCPULoad` field, the `scan_cpu_load` field on `/api/status`, and the matching settings UI row. The knob hadn't influenced admission since it was a stealth no-op; setting it now logs a one-time deprecation notice on startup.
- Internal `cpuInstanceCapacity` helper (no callers after the refactor).
- Internal `hostMatchesLocalInterface` helper (dead code; `isBlockedTarget` now routes through `ipsMatchLocalInterface`).
- The `level` parameter on `effectiveMaxInstancesForStats` (it was unused after the refactor).

### Fixed
- `effectiveMaxInstancesForStats` no longer calls `memoryInstanceCapacity` twice on the same `stats` snapshot.

## v4.4.19 — Scope guard hardening v2

### Fixed
- **URL-in-query-param bypass closed.** `scopeHostTokenSplit` in `internal/agent/agent.go` now also breaks tokens on `=`, `?`, `#`, and `@`, and a new `extractEmbeddedURLs` sweep pulls every `http://` / `https://` substring out of an arg value before the separator pass. An OOS host smuggled inside a redirect query parameter (e.g. `https://in-scope.example/redirect?next=https://oos.example/path`), a userinfo form (`user@oos.example`, `https://user:pass@oos.example/`), or any of the new delimiters now surfaces as a standalone token and the gated tool call is rejected.
- **Per-arg scan length capped at 8 KiB.** A new `argScanLimitBytes = 8192` constant plus `truncateForScopeScan` helper bound how much of any single Arg_Value the agent-side guard tokenizes. Values ≤ 8 KiB still walk the same path byte-for-byte; values larger than 8 KiB are silently truncated at the largest UTF-8 rune-boundary offset ≤ 8192. The cap never short-circuits to a reject — oversize args fall through to the existing allow path on length alone.
- **Single DNS lookup per `isBlockedTarget` call.** `isBlockedTarget` in `internal/web/server.go` now parses the host as a `net.IP` literal first, otherwise issues exactly one `net.LookupHost` (via a package-level `lookupHost` shim for testability), and threads the resolved IP slice into both the self-listener check (new internal helper `ipsMatchLocalInterface`) and the private-range check. DNS failure preserves the prior `return false` (allow) verdict.
- **OOS hostnames in `add_note` are redacted, not leaked.** A new `(*Agent).redactOutOfScopeHosts` method mirrors the gated tokenization path and substitutes the literal marker `[redacted: out-of-scope host]` for every OOS host span in the `key` and `value` arguments of `add_note`. The agent loop applies redaction in place immediately before `shouldBlockForOutOfScope`, so notes can no longer launder OOS hostnames through `read_notes` on the next iteration. Gated tools continue to reject rather than redact.

### See also
Spec: `.kiro/specs/scope-guard-hardening-v2/requirements.md`

## [Unreleased]

### Breaking changes

#### Default workspace moved to `~/.xalgorix/data/`

The default location for scan output, notes, schedules, and other generated artefacts moved from `$CWD` (the directory the binary was launched from) to `~/.xalgorix/data/`. This is the single most visible part of the stability + workspace-isolation release.

**To retain previous behavior**, run:
```
export XALGORIX_DATA_DIR=$(pwd)
```

A `[MIGRATION]` warning is emitted at startup when legacy markers (`notes.json`, `_schedules/`, `vulnerabilities.json`, or `YYYY-MM-DD/scan-*` directories) are detected in `$CWD` and `XALGORIX_DATA_DIR` is unset.

### Added
- `XALGORIX_LLM_MAX_INFLIGHT`: caps concurrent outbound LLM calls (default: `4 × EffectiveMaxInstances`, minimum 1).
- Health endpoint counters: `panics_recovered`, `path_rejections`, `watchdog_kills`, `admission_refusals`, `llm_inflight_cap`, `data_dir`, `allow_list`, `read_deny`.
- Path_Policy boundary check: every filesystem-touching tool now writes only into `~/.xalgorix/data/`, `~/.xalgorix/`, or `/tmp/`.
- Read-policy: filesystem-touching tools may now READ anywhere on the host (system wordlists, payload directories, `/etc/services`, etc.) so agents can use shared assets without copying them into the workspace. A built-in deny-list still rejects reads of sensitive paths (`~/.ssh`, `~/.aws`, `~/.gnupg`, `/etc/shadow`, `/etc/sudoers`, `/proc/kcore`, etc.). Set `XALGORIX_READ_DENY_LIST` (colon-separated) to extend the defaults. The active deny-list is exposed as `read_deny` on `/api/status`.
- Browser tool now acquires Tool_Leases and applies process memory limits.
- Recovery for tool panics, scheduler ticks, HTTP handler panics, and ScanContext close panics.

### Fixed
- Python and terminal tools no longer leak `.tmp/`, `.cache/`, `.config/`, `.local/` directories into `$CWD`. They now create those scratch dirs under the active scan directory or `~/.xalgorix/data/`.
- Tool stdout/stderr now bounded to 1 MB / 512 KB respectively (prevents OOM from runaway output).

### See also
Spec: `.kiro/specs/xalgorix-stability-and-workspace-isolation/requirements.md`

## [Unreleased] — Findings consistency and pagination

### Fixed
- **Findings page no longer truncated to 30 scans.** The Findings dashboard now enumerates every scan on disk and paginates the union with controls for page size [25, 50, 100, 200] (default 50). Findings deduplicate across runs by `(target, endpoint, title, severity)`, with the surviving row linking to the most recent producing scan.
- **Counter flicker eliminated.** The Findings and Overview totals widgets keep prior data during refetches (`keepPreviousData`), so the visible total no longer drops to zero between background polls.
- **Counter monotonicity per scan.** A new `effectiveVulnCount(inst, sess)` helper consolidates the previous triple-source `inst.VulnCount` assignments. Counters now read in-memory while the scan is running and on-disk after teardown — they never visibly drop without a delete.
- **Panic-safe persistence of child findings.** `reporting.PromoteToParent` is invoked on every successful `report_vulnerability` so a child scan's findings reach the parent aggregate immediately. Combined with `MergeVulnsToContext` running in the deferred `cleanup()`, parent records survive child agent panics.

### Added
- **`/api/findings/summary` endpoint.** Returns severity counts derived from on-disk scan records, with an `as_of` timestamp and `etag` for cheap polling. Polled by the WebUI every 10s; honors `If-None-Match` for `304 Not Modified` responses.
- **`vulns_persisted` field in `/api/status`.** Stable on-disk total alongside the existing `vulns` (in-memory) field. Additive change — no breaking change for existing clients.
- **Legacy `~/xalgorix-data/` import.** On first server start after this release, scan records under `~/xalgorix-data/` are non-destructively copied into `cfg.DataDir`. A sentinel file `.legacy-imported` prevents repeated walks. The legacy directory is preserved; you may manually `rm -rf ~/xalgorix-data` after verifying the import via the WebUI banner and Findings page.

### Notes
- The legacy import is intentionally manual to undo. Automation here is out of scope.
- The previous spec's `safe.Recover` wrappers already contain agent-goroutine panics to a single scan; the panic that motivated this work no longer crashes the whole server even before the persistence fixes land. This bugfix focuses on counter and pagination correctness.
