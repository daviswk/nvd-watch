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
- **The gap is product data (CPE), not severity scores.** 91% of CVEs in our pull carry some CVSS (OIG: nearly 80% of CVE Program *participants* include scores); OIG's own specialists produced the same CVSS vector in only 8 of 69 double-scored CVEs (12%), so scoring is inconsistent even among experts. Don't attack the "stop re-scoring" half of NIST's policy.
- **KEV is the gate.** For most software, CPE comes only after a KEV listing. Median CVE-to-KEV lag rose 6 → 9 → 12 → 14 days (2023–2026, Barracuda); our own recomputation of Barracuda's population gives 4 → 7 → 10 → 9 (2026 to Nov 6). See `docs/data-notes.md`. Federally used software (e.g., PHP2Shell) gets CPE without waiting for KEV.
- **EPSS is a re-check trigger, not an intake screen.** EPSS crossed 0.10 before KEV in only 19% of cases, but led by ~201 days when it did. Re-queue stalled / "Not Scheduled" CVEs when max(EPSS, KEV, LEV) — NIST CSWP 41 — crosses a published threshold, or CISA SSVC marks exploitation PoC/Active.
- **The ask is a rule change, not new money.** Re-check volume is measured, not assumed: CVE Floodline shows ~0.09% of new CVEs cross EPSS 10% by day 30 (27 of 28,618, Aug–Nov 2026; an earlier window showed 0.27%), which on our ~17,000 CVEs/30 days is ~16–46 re-queues a month, well under 1% of the ~5,000/month NIST has never exceeded (an OIG observation, not a NIST-stated ceiling), ~$8K–$66K/yr at 20–60 analyst-minutes and $120/h, vs. the OIG's ~$800K over two years (~$400K/yr, our division) from minimizing re-scoring, which NIST contests. NIST already stopped routine re-scoring in April 2026, so the OIG figure is a **scale comparison, not spare money**; lead with share of capacity. The earlier "250–470 CVEs/month, $270K–$510K/yr" came from reading Floodline's "2.7 per 1,000" as 2.7%; it is retired (see `docs/data-notes.md`). A lower threshold (0.05, 0.01) raises the volume; the simulator lets readers try it.
- **Stakeholders (brief):** NIST; CISA (as KEV owner *and* CVE sponsor — the CNA product-data ask goes here); Congress (Appropriations, Science, Homeland Security; GAO review request; NDAA CVE-codification vehicle). Context: FIRST (EPSS), MITRE/CVE Board, FedRAMP PMO, SLTT governments/MS-ISAC, commercial vendors, ENISA, AI labs.
- **Answer NIST RFI question 7(e)** (91 FR 52042, Aug 12, 2026): "What metrics should be considered to track and evaluate the success of the NVD?"

## Scope — final
One scorecard page with four sections:
1. **The gap** — CPE coverage by priority tier/status, computed by us from the NVD API, definitions shown.
2. **The gate** — CVE-to-KEV lag trend; PHP2Shell as the worked example.
3. **The fix and its cost** — re-check rule simulator (CVEs/month, % of capacity, cost range vs. OIG offset; minutes-per-CVE as a 20/45/60 range, labeled as an assumption).
4. **Who should act** — recommendations + five quarterly metrics.

**Out of scope (cut on purpose):** wildfire/hero map, funnel chart, separate lifecycle tracker, Siemens S7 case (one sentence in the brief), CNA-vs-NIST score disagreement view, GitLab, cve.now, formal verification, forum monitoring.

## The five quarterly metrics (freeze these definitions)
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
- Tech stack preference: Python (requests, pandas) for the pipeline → JSON → one static HTML page. Weekly rebuild via a scheduled GitHub Action is the stretch goal.

## Related tools (don't duplicate)
RogoLabs (Jerry Gamblin, https://rogolabs.net) publishes free, open-source CVE tools. Positioning: **RogoLabs measures the CVE ecosystem (volume, CNAs, suppliers); NVD Watch measures NIST's own performance and prices a policy rule. No public tool measures CPE coverage by NIST priority tier, time to enrichment, KEV-goal compliance, or re-queues.**
- **CVE.ICU** (https://cve.icu): raw CVE counts only. Link to it for volume; don't build volume charts.
- **CVE Floodline** (https://cvefloodline.org; repo github.com/RogoLabs/cvefloodline.org, Apache-2.0): each day's CVE cohort re-scored against the dated EPSS archive at day 0/7/30/90. Treats a low day-one score as "provisional, not safe," which is our re-check (not intake) design. We reuse its published `data/floodline.json` (one number: share crossing EPSS 10% by day 30) via `fetch_floodline()` in `scripts/fetch_sample.py`, attributed on the page.
- **CNA Scorecard** (https://cnascorecard.org) and **CNAPulse** (https://cnapulse.org): CNA record quality and publishing activity. Cite for the CNA data-quality point; don't build a CNA view.
- **SADP Tracker** (https://rogolabs.github.io/SADP-Tracker/index.html): the CVE Program's Supplier ADP pilot. Siemens (from Apr 14, 2026) and Red Hat (from Jun 30, 2026) have added affected-product data to 3,349 unique CVEs (3,391 records) as of Nov 7, 2026. A partial, non-NIST path to product data; it fills CVE's `affected` field, not CPE.

## Known open items
- **KEV CVEs are covered fast (Nov 7 pull):** 17 of 18 KEV CVEs got CPE within one business day, all by NIST (`scripts/kev_enrichment.py`). The claim is about CVEs *before or outside* KEV, not KEV CVEs lacking CPE. "When defenders need it" = by the KEV listing date. At-risk example: CVE-2026-59774 (Gitea, Not Scheduled, EPSS 0.28, not confirmed exploited).
- Coverage figures: our first pull (Nov 7, 2026, 30 days) shows 22.6% of non-rejected CVEs with CPE; see `docs/data-notes.md`. Vendor figures (Volerion ≈50%, CSI 8.4%) are now context, not headline.
- NVD API status values differ from display labels: API `Deferred` = "Not Scheduled", `Awaiting Analysis` = "Awaiting Enrichment", `Analyzed` = "Enriched". Use display labels on the page, API values in code.
- The NVD API now returns CNA `affected` data (free-text vendor/product). 94% of CVEs have it; the gap is *standardized* CPE, not any product data. Say "CPE" or "scanner-matchable product identifiers", never "no product data".
- Re-check volume now comes from CVE Floodline's day-30 crossing rate (see Related tools). Still open: the day-90 horizon (not yet observable in Floodline's window), crossings from the older Not Scheduled stock (which Floodline's 90-day window does not cover), and the SSVC / third-party-evidence triggers, none of which the estimate counts. It is a lower bound.
- Does EPSS v4 accuracy degrade on unenriched CVEs? Unmeasured.
- No per-CVE enrichment cost exists; cost figures are crude upper bounds.
- PHP2Shell (CVE-2026-109618, -109619): honeypot attempt Oct 17 (success unclear), patch and NVD publication Oct 21, NIST CPE Oct 21 (same day), exploitation reported Oct 24–25 (BleepingComputer only), KEV Oct 26. It shows KEV listing lag, not CPE waiting on KEV.
- Source checks: see `docs/source-verification.md`. V-etalon is confirmed by NIST's Aug 12, 2026 blog (in development). GPT-6 Cyber figures are press-reported (CyberScoop, Nov 5). Ivanti "6–12 days" is cut.

## Where things are
- `docs/handoff.md` — **start here in a new session**: current state, how to run everything, what's next in order, gotchas
- `PRODUCT.md` — product truth for design work (Impeccable); `DESIGN.md` — the visual system as built
- `scripts/fetch_sample.py` — data pull (reads `NVD_API_KEY` from `.env`; `--from-raw` reprocesses without fetching)
- `scripts/kev_enrichment.py` — NVD change history for each KEV CVE in the sample: first CPE date vs KEV listing (harm metric, metric 3). Run after `fetch_sample.py`, before `build_site.py`; the build exits without its output
- `scripts/kev_lag.py` — median CVE-to-KEV lag by year for the section 2 chart (writes `data/processed/kev_lag.json`; `build_site.py` copies it to `site/data/` for the story page; the SVG values in the template are copied by hand)
- `site/story.html`, `site/story.js` — "The data in 3D" scroll story, one dot per CVE; reads `site/data/*.json` at runtime. The scorecard itself stays 2D (see DESIGN.md, The 2D Rule)
- Branches `prototype/3d-variants` (chose the story page) and `prototype/scorecard-figures` (3D scorecard figures, rejected) — throwaway prototypes; not for main
- `scripts/build_site.py` — renders `site/index.html` from `site/template.html` + `data/processed/summary.json`; edit the template, never index.html
- `docs/data-notes.md` — what each pull showed, caveats, status-name mapping
- `docs/project-plan.md` — full plan, recommendations, roadmap
- `docs/brief-outline.md` — 3-page brief skeleton
- `docs/ai-collaboration-log.md` — log, seeded with entries so far
- `docs/sources.md` — key sources with links
- `docs/source-verification.md` — verdict per claim (Nov 7, 2026), what each source actually says
- `docs/research/` — evidence review report + raw research notes
- `docs/learning/` — primer and drill pages (open in a browser), video list
- `design/mockups/` — earlier scorecard mockups (reference only)
