# NVD Watch — project context for Claude Code

## What this is
NVD Watch is Will Davis's AI-Augmented Policy Project for Intro to Tech Policy (Pardee RAND, MTP). It is a public, weekly-updated scorecard of the U.S. vulnerability warning system (the NIST National Vulnerability Database and the CISA KEV catalog). It ships with a ≤3-page policy brief and an AI collaboration log.

## The policy question
> Does NIST's April 2026 triage leave exploited vulnerabilities without product data (CPE) when defenders need it, and would a published re-check rule plus quarterly performance metrics close that gap at a cost NIST can absorb?

Framing line: *NIST prioritizes by who uses the software, or confirmed attacks. We propose re-checking the rest when attack signals rise, and publishing whether it works.*

## Syllabus requirements (all three deliverables are graded)
1. **Artifact** built with AI tools, beyond what one person could build unaided in a quarter (real data pipeline + interactive site).
2. **Policy brief**, max 3 pages: background, challenges and opportunities, recommendations for identified stakeholders.
3. **AI collaboration log**: models used, key prompts and iterations, where AI failed or fabricated, how claims were verified. See `docs/ai-collaboration-log.md`; keep adding entries.

## Settled decisions (don't relitigate without a reason)
- **The gap is product data (CPE), not severity scores.** 94.5% of non-rejected CVEs in our pull carry some CVSS: 77.8% from the CNA that published the record, most of the rest from CISA's Vulnrichment (ADP), 2.8% from NIST (OIG: nearly 80% of CVE Program *participants* include scores). Use the non-rejected denominator; the 91.0% / 2.7% figures counted Rejected records; OIG's own specialists produced the same CVSS vector in only 8 of 69 double-scored CVEs (12%), so scoring is inconsistent even among experts. Don't attack the "stop re-scoring" half of NIST's policy.
- **KEV is the gate.** For most software, CPE comes only after a KEV listing. Median CVE-to-KEV lag rose 6 → 9 → 12 → 14 days (2023–2026, Barracuda); our own recomputation of Barracuda's population gives 4 → 7 → 10 → 9 (2026 to Nov 6). See `docs/data-notes.md`. Federally used software (e.g., PHP2Shell) gets CPE without waiting for KEV.
- **EPSS is a re-check trigger, not an intake screen.** EPSS crossed 0.10 before KEV in only 19% of cases, but led by ~201 days when it did. Move any CVE without CPE (Not Scheduled, Awaiting, Received) into the KEV queue, under the existing one-business-day goal, when max(EPSS, KEV, LEV) — NIST CSWP 41 — crosses a published threshold, or CISA SSVC marks exploitation PoC/Active.
- **The ask is a rule change, not new money.** **Measured directly (Nov 7, `scripts/research/recheck_volume.py`; reproduced Nov 8 on fresh feeds):** at EPSS ≥ 0.10 the rule re-queues **303 stock CVEs once** (no CPE, Not Scheduled / Awaiting / Received, not KEV; 443 at 0.05; 3,384 at 0.01), then **~11–28 a month**, mostly CVEs over 90 days old. At 45 analyst-minutes and $120/h: ~$27K once and ~$30K/yr at 28 a month (~$5K–$40K/yr across 11–28 a month and 20–60 minutes), 0.6% of the ~5,000/month NIST has never exceeded (an OIG observation, not a NIST-stated ceiling). Lead with share of capacity. Compare with the OIG's ~$800K over two years (~$400K/yr, our division) from minimizing re-scoring, which NIST contests. NIST already stopped routine re-scoring in April 2026, so the OIG figure is a **scale comparison, not spare money**. The page shows both parts (from `data/processed/recheck_measured.json`, dated Nov 7); the simulator default is the highest month, 28. See `docs/research/notes/open_items_recheck_volume.md`. **Retired:** the Floodline-based ~16–46 a month and ~$8K–$66K/yr (Floodline: ~0.09% of new CVEs cross EPSS 10% by day 30; that figure counted mostly new CVEs that already had CPE, and matched the measured total only by coincidence), and before it "250–470 CVEs/month, $270K–$510K/yr" (Floodline's "2.7 per 1,000" misread as 2.7%; see `docs/data-notes.md`). Other triggers' volumes (SSVC, LEV) and their recall on KEV CVEs: `docs/red-team-nov7-response.md`.
- **Stakeholders (brief):** NIST; CISA (as KEV owner *and* CVE sponsor — the CNA product-data ask goes here); Congress (Appropriations, Science, Homeland Security; GAO review request; NDAA CVE-codification vehicle). Context: FIRST (EPSS), MITRE/CVE Board, FedRAMP PMO, SLTT governments/MS-ISAC, commercial vendors, ENISA, AI labs.
- **Answer NIST RFI question 7(e)** (91 FR 52042, Aug 12, 2026): "What metrics should be considered to track and evaluate the success of the NVD?"

## Scope — final
One scorecard page with four sections:
1. **The gap** — CPE coverage by priority tier/status, computed by us from the NVD API, definitions shown.
2. **The gate** — CVE-to-KEV lag trend; PHP2Shell as the worked example.
3. **The fix and its cost** — re-check rule simulator (CVEs/month, % of capacity, cost range vs. OIG offset; minutes-per-CVE as a 20/45/60 range, labeled as an assumption).
4. **Who should act** — recommendations + five quarterly metrics.

**Out of scope (cut on purpose):** wildfire/hero map, funnel chart, separate lifecycle tracker, Siemens S7 case (one sentence in the brief), CNA-vs-NIST score disagreement view, GitLab, cve.now, formal verification, forum monitoring.

## Decided Nov 8 after red-team round 6 (supersedes conflicting lines above and below)
Full reasoning: `docs/red-team-nov7-response.md` §7; brief structure: `docs/brief-outline.md`.
- **NIST ask has three parts.** 1A automated day-0 CPE: pass through CNA-supplied `cpes` and assign provisional, product-level CPE on exact vendor:product dictionary matches (29.1% of window CVEs without CPE, 3,849 of 13,207, Nov 7 pull; `automated_mapping.json`). 1B daily **EPSS ≥ 0.05** re-check backstop (443 once, 8–30 a month, ~$32K/yr; show 0.10 beside it). 1C quarterly reporting.
- **The 25%-recall stopping rule is rejected.** EPSS is a weak pre-KEV warning (22 of 172; 4 of 51 under v5); its job is the non-KEV stock. The ~105 / ~95 "expected exploitation" figures are EPSS's own summed probabilities, not validation; metric 5's hit rate is the test.
- **Gap framing:** "The backlog began Feb 2024. Readiness was about half before the April triage and about half after; the triage turned a backlog into standing policy." Never "the triage caused the gap". Cohorts "plateau"; never "permanent" or "abandonment".
- **PHP2Shell is a contrast case** (federal tier, CPE 2 h 44 min after publication; KEV 1–2 days after the first exploitation report). Exploitation was not reported Oct 21.
- **Congress vehicle:** CJS appropriations report language plus the Thompson–Lofgren GAO request (June 6, 2025). RFI comments closed Oct 13, 2026; no NIST response as of Nov 8.
- **EPSS v5 feature loss** stays an open hypothesis; the 12 unscored v5 KEV CVEs were one day old (timing).

## The five quarterly metrics (revised Nov 8; freeze these definitions)
1. Pre-KEV readiness: share of KEV additions public before listing that had CPE before listing, at ≥ 1 and ≥ 7 days public.
2. CPE coverage by publication-month cohort (any source; NIST-sourced), by observable tier: KEV status and NVD status.
3. Median and 90th-percentile time to enrichment, by the same observable tiers.
4. Compliance with NIST's one-business-day KEV enrichment goal (NVD change history; clock starts at the later of KEV listing and NVD publication).
5. Re-queue counts, time-to-enrichment after re-queue, and hit rate (re-queued CVEs later in KEV or exploited).
Reporting rules (not metrics): a change log of NVD status-category definitions (changed Apr 15, 2026); counts by priority tier (NIST does not publish its tier assignments); nvd@nist.gov request volume and turnaround. The site's section 4 shows this set (Nov 8).

### Nov 7 set (superseded)
1. Share of new CVEs with CPE (any source; NIST-sourced), by observable tier: KEV status and NVD status. NIST does not publish its tier assignments; publishing them is a recommendation.
2. Median and 90th-percentile time to enrichment, by the same observable tiers.
3. Compliance with NIST's one-business-day KEV enrichment goal (NVD change history; clock starts at the later of KEV listing and NVD publication).
4. Re-queue counts and time-to-enrichment after re-queue.
5. A change log of NVD status-category definitions (they changed on Apr 15, 2026).

## Data sources (all free)
- NVD API 2.0: `https://services.nvd.nist.gov/rest/json/cves/2.0` (pub date windows ≤120 days; request an API key; NIST's own metrics carry `source: "nvd@nist.gov"`).
- CISA KEV JSON: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- FIRST EPSS API: `https://api.first.org/data/v1/epss` (batch `cve=` lists).
- Starter script: `scripts/fetch_sample.py` (untested against live endpoints — run it first and fix as needed).

## Rules for working on this project
- **Never invent data.** Anything illustrative is labeled "illustrative" on the page. Every number on the site traces to a query or a cited source.
- **Verify before citing.** Prefer primary sources (NIST, OIG, Federal Register, FIRST, CISA). Mark single-source or vendor-sourced figures (VulnCheck, Volerion, CSA, Barracuda all have interests).
- **Log AI failures as they happen** in `docs/ai-collaboration-log.md` (fabrications, wrong dates, unfindable sources, overstated framing).
- **Keep it simple.** Will prefers simple, concise solutions and wants the reasoning explained, not just working code.
- Tech stack preference: Python (requests, pandas) for the pipeline → JSON → one static HTML page. Weekly rebuild runs as a scheduled GitHub Action (`.github/workflows/rebuild.yml`, Mondays 12:47 UTC; live since Nov 8, 2026).

## Related tools (don't duplicate)
RogoLabs (Jerry Gamblin, https://rogolabs.net) publishes free, open-source CVE tools. Positioning: **RogoLabs measures the CVE ecosystem (volume, CNAs, suppliers); NVD Watch measures NIST's own performance and prices a policy rule. No public tool measures CPE coverage by NIST priority tier, time to enrichment, KEV-goal compliance, or re-queues.**
- **CVE.ICU** (https://cve.icu): raw CVE counts only. Link to it for volume; don't build volume charts.
- **CVE Floodline** (https://cvefloodline.org; repo github.com/RogoLabs/cvefloodline.org, Apache-2.0): each day's CVE cohort re-scored against the dated EPSS archive at day 0/7/30/90. Treats a low day-one score as "provisional, not safe," which is our re-check (not intake) design. We reuse its published `data/floodline.json` (one number: share crossing EPSS 10% by day 30) via `fetch_floodline()` in `scripts/fetch_sample.py`, attributed on the page.
- **CNA Scorecard** (https://cnascorecard.org) and **CNAPulse** (https://cnapulse.org): CNA record quality and publishing activity. Cite for the CNA data-quality point; don't build a CNA view.
- **SADP Tracker** (https://rogolabs.github.io/SADP-Tracker/index.html): the CVE Program's Supplier ADP pilot. Siemens (from Apr 14, 2026) and Red Hat (from Jun 30, 2026) have added affected-product data to 3,349 unique CVEs (3,391 records) as of Nov 7, 2026. A partial, non-NIST path to product data; it fills CVE's `affected` field, not CPE.

## Known open items
- **KEV: goal met, readiness not (Nov 7 pull; Nov 8 pull: goal 29 of 30, readiness still 10 of 23):** all 35 CVEs added to KEV Oct 8 – Nov 7 (any publication year) met the one-business-day goal or are pending, all by NIST. But of the 23 that were public before listing (and not enriched pre-triage), only 10 had CPE beforehand; several got it within minutes of the KEV event (`scripts/kev_enrichment.py`). "When defenders need it" = before the KEV listing. Keep readiness and the goal separate. At-risk example: CVE-2026-59774 (Gitea, Not Scheduled, EPSS 0.28, not confirmed exploited).
- Coverage figures: our first pull (Nov 7, 2026, 30 days) shows 22.6% of non-rejected CVEs with CPE (Nov 8 pull: 22.3%). The page now updates weekly, so cite figures with their pull date and take them from one `data/history/` folder; see `docs/data-notes.md`. Vendor figures (Volerion ≈50%, CSI 8.4%) are now context, not headline.
- NVD API status values differ from display labels: API `Deferred` = "Not Scheduled", `Awaiting Analysis` = "Awaiting Enrichment", `Analyzed` = "Enriched". Use display labels on the page, API values in code.
- The NVD API now returns CNA `affected` data (free-text vendor/product). 94% of CVEs have it; the gap is *standardized* CPE, not any product data. Say "CPE" or "scanner-matchable product identifiers", never "no product data".
- Re-check volume (researched Nov 7; `docs/research/notes/open_items_recheck_volume.md`):
  - **Day 90:** Floodline can never supply it (90-day rolling window, point-in-time scores). Our own Jun 15 – Jul 14 cohort (8,376): ever ≥ 0.10 rose from 0.263% by day 30 to 0.442% by day 90, but only 7 lack CPE and are not in KEV (~14/month). One cohort only.
  - **Stock:** 76,217 CVEs without CPE in Deferred / Awaiting / Received, none in KEV (29,017 Not Scheduled published before Mar 1, confirming the ~29,000). One-time load 303 at ≥ 0.10. Monthly flow ~11–28 at 0.10, checked against change history. The NVD API has no `vulnStatus` filter; the census used the yearly JSON feeds.
  - Still open: LEV and SSVC trigger volumes, a second day-90 cohort, flow stability under one EPSS model.
- **EPSS is v5** (model `v2026.06.15`, publishing since Jun 15, 2026; FIRST data page and archive file headers), not v4. NVD CVSS metrics are an input; FIRST does not say whether vendor/product features come from NVD CPE or CNA `affected`. Does v5 rank unenriched CVEs worse? Unmeasured anywhere; a test design is in the research note. Pilot: of 13 KEV CVEs without CPE before listing, 1 was at EPSS ≥ 0.10 the day before (small n, not a test).
- No per-CVE enrichment cost exists; cost figures are crude upper bounds.
- **AI framing (settled Nov 7):** AI accelerates a capacity problem that predates it (backlog from early 2024; NIST's Apr 15 notice cites 263% growth 2020–2025 and does not mention AI). AI appears in the brief only as why-now, cost of waiting, pipeline pressure, and the future test (RFI title). Add an AI source only if it changes a metric or a recommendation (e.g., published accuracy of AI-assisted enrichment, or a credible share of new CVEs that are AI-found). See `docs/project-plan.md`.
- **Legacy share:** of 2026's KEV additions, 30 of 285 (10.5%) were published 4+ years before listing (`kev_lag.json` legacy_by_year; 9.6 / 11.3 / 14.3% for 2023–25). CVE age, not code age. Don't call the re-check stock "legacy": ~45,000 of its 76,217 were published after Apr 15, 2026.
- PHP2Shell (CVE-2026-109618, -109619): honeypot attempt Oct 17 (success unclear), patch and NVD publication Oct 21, NIST CPE Oct 21 (same day), exploitation reported Oct 24–25 (BleepingComputer only), KEV Oct 26. It shows KEV listing lag, not CPE waiting on KEV.
- Source checks: see `docs/source-verification.md`. NIST's AI enrichment tool is named in its Aug 12, 2026 blog but unreleased; don't name it on the page or in the brief (nothing to measure). Cite RFI questions 1(b) and 3(b) instead. GPT-6 Cyber figures are press-reported (CyberScoop, Nov 5). Ivanti "6–12 days" is cut.

## Where things are
- `docs/handoff.md` — **start here in a new session**: current state, how to run everything, what's next in order, gotchas
- `PRODUCT.md` — product truth for design work (Impeccable); `DESIGN.md` — the visual system as built
- `.github/workflows/rebuild.yml` — weekly pull, build, commit (github-actions[bot]) and Pages deploy; `pages.yml` deploys on ordinary pushes. Run `git pull` before local work after a Monday
- `scripts/fetch_sample.py` — data pull (reads `NVD_API_KEY` from `.env`; `--from-raw` reprocesses without fetching)
- `scripts/kev_enrichment.py` — NVD change history for each KEV CVE in the sample: first CPE date vs KEV listing (readiness, metric 1; KEV goal, metric 4). Run after `fetch_sample.py`, before `build_site.py`; the build exits without its output
- `data/history/YYYY-MM-DD/` — each pull's `summary.json` and `kev_enrichment.json`, written by `build_site.py`; `scripts/stability.py` prints readiness and KEV-goal x of n per pull, with min/max (decides point vs range in the brief)
- `scripts/kev_lag.py` — median CVE-to-KEV lag by year for the section 2 chart (writes `data/processed/kev_lag.json`; `build_site.py` draws the chart, its caption date and the highlight's lag sentence from it, and stops if it is missing; run it before the build to refresh them)
- `scripts/cost_model.py` — the re-check cost rule in one place: constants (5,000 peak, OIG $400K, $120/h, 20/45/60 min), money format, verdict wording. `build_site.py` renders from it and writes it into the page and `site/data/cost_model.json`; `site/cost.js` repeats only the arithmetic for the browser (`app.js` simulator, `story.js`). After changing either, run `python scripts/check_cost_model.py` (Node) to confirm both print the same strings
- `site/story.html`, `site/story.js` — "The data in 3D" scroll story, one dot per CVE; reads `site/data/*.json` at runtime. The scorecard itself stays 2D (see DESIGN.md, The 2D Rule)
- Branches `prototype/3d-variants` (chose the story page) and `prototype/scorecard-figures` (3D scorecard figures, rejected) — throwaway prototypes; not for main
- `scripts/research/osv_orphans.py` — CVEs without CPE that no OSV package advisory covers ("orphaned"); reads the OSV ecosystem exports (~3.1 GB, download first; see its docstring), writes `data/processed/osv_orphans.json`. The section 1 orphan row appears only while that file matches the current pull's window
- `scripts/build_site.py` — renders `site/index.html` from `site/template.html` + `data/processed/summary.json`; edit the template, never index.html
- `docs/data-notes.md` — what each pull showed, caveats, status-name mapping. Read its **Current conclusions** list first; older sections that were revised are marked Superseded
- `docs/project-plan.md` — full plan, recommendations, roadmap
- `docs/brief-outline.md` — 3-page brief skeleton
- `docs/ai-collaboration-log.md` — log, seeded with entries so far
- `docs/sources.md` — key sources with links
- `docs/source-verification.md` — verdict per claim (Nov 7, 2026), what each source actually says
- `docs/research/` — evidence review report + raw research notes
- `docs/learning/` — primer and drill pages (open in a browser), video list
- `design/mockups/` — earlier scorecard mockups (reference only)
