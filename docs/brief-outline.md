# Policy brief outline (≤ 3 pages)

**Title (working):** Re-check, Then Measure: Closing the Product-Data Gap in the National Vulnerability Database

**Spine:** NIST's triage has a front door (KEV) but no side door. Add the side door (re-check rule), then measure whether both doors work (five metrics). *Test every section against this sentence; cut what doesn't serve it.*

**BLUF** (≤ 120 words: the three asks and the price; if they don't fit, scope is still too wide)
> _[empty: write last]_

**Word budget:** P1 ~400 · P2 ~450 + 1 figure · P3 ~400 (≈1,250 words total).

**Number labels:** [stable] = yearly or one-time measurements that won't move week to week; [volatile] = 30-day-window shares that move every pull; [fragile] = small n, may swing. Report fragile numbers as a range if `scripts/stability.py` shows them swinging.

**Jargon allowlist:** CPE, KEV, EPSS. Everything else in plain words (e.g. CNA → "the organizations that write CVE records"; enrichment → "adding product data"; CVSS → "severity score"). *Open: CVE itself is not on the list; define it once on first use or add it.*

**Lead with measurement, not failure.** No one publishes how quickly NIST attaches product data to CVEs; here are the numbers. Once CISA lists a CVE as exploited, NIST meets its own goal. The gap is before and outside KEV. The brief must stand alone without the site (#17) and work whatever the weekly data shows.

## Page 1 — Background (~400 words)
- **Why now** — *emerging-tech hook (assignment requirement).* **Settled framing (Nov 7):** AI accelerates a capacity problem that already existed; it did not cause it. AI appears in four roles only: why now, why waiting is costly, pressure on the pipeline, the future test. Do not say "AI-driven surge." Drop the CyberScoop/OpenAI line (press-reported, adds nothing the metrics use).
  > **DRAFT (~150 words; page 1 is already at budget, cut while writing):** NIST's capacity problem predates AI. Its backlog began in early 2024, when a support contract lapsed (OIG), and its April 2026 notice blames a 263% rise in submissions from 2020 to 2025, without mentioning AI. AI is now speeding it up. New CVEs in the NVD rose from 5,143 in January 2026 to 17,481 in October [stable] (our count); Google's threat intelligence team reports monthly disclosures doubled from January to August, and, like FIRST, credits much of the growth to other causes such as bulk Linux kernel CVEs and advisory backfills. FIRST also finds the actionable share (in KEV or above EPSS 10%) flat. Waiting is getting costlier: RAND found an off-the-shelf AI agent, prompted by people with no cyber expertise, solved each of its hacking challenges in under an hour for under $20 in total. Maintainers of curl and the Linux kernel report a flood of real, AI-found bugs. NIST asked how to modernize the NVD in the age of AI. Our answer: whatever AI changes, measure it publicly.
  Sources: OIG-26-020-I; NIST Apr 15, 2026 notice ("increased 263% between 2020 and 2025"); GTIG Sep 30, 2026 (5,045 → 10,740, Jan–Aug); FIRST Jun 15, 2026 (GHSA +449%, VulnCheck +3,119%, actionable burden "completely flat"); RAND RR-A3892-2 (CTF challenges, "less than US$20" over all of them; the agent was Claude Code, disclose); Stenberg Oct 22, 2026 ("high volume, high quality"); Torvalds via Tom's Hardware, May 18, 2026 ("almost entirely unmanageable"). **Not** "about $16" (earlier drill figure; RAND's summary says under $20 and the PDF was not readable this pass).
- What the NVD does, and why CPE is what lets scanners tell an organization it is affected.
- NIST's April 15, 2026 triage: KEV, federal, and EO 14028 critical software first; everything else waits.
- Definition (#21): CPE arrives "when defenders need it" if it is there **before** CISA confirms exploitation (the KEV listing). Readiness is scored apart from NIST's one-business-day goal after listing; never let one number stand for both.
- KEV lag, one sentence: median days from CVE publication to KEV listing rose from 4 (2023) to 10 (2025), 9 in 2026 to Nov 6 [stable] (our count, `scripts/kev_lag.py`; Barracuda reports 6 → 14, vendor).

## Page 2 — Challenges and opportunities (~450 words + 1 figure)
**Figure:** status breakdown of new CVEs, with CPE share per status (Not Scheduled 40.8% [volatile] of new CVEs, 0% with CPE). Source: site section 1 table.

**Three findings**
1. **After KEV, NIST performs; before it, CPE mostly isn't there.** Goal: 34 of 35 [fragile] KEV additions Oct 8 – Nov 7 had CPE within one business day, all from NIST. Readiness: only 10 of 23 [fragile] had CPE before the listing. Defender's view only: NVD users did not see CPE for the other 13 until CISA listed them (don't claim NIST starts from scratch at the listing). Arithmetic → footnote.
2. **Before KEV, nothing re-checks.** 22.6% [volatile] of new CVEs have CPE; 40.8% [volatile] are Not Scheduled, and they stay that way: 37.9% [stable, one snapshot] of the Apr 15 – Jun 15 cohort is still Not Scheduled five months later. Example: CVE-2026-59774 (Gitea), Not Scheduled, no CPE, EPSS 0.28 on Nov 7 [volatile]; at risk, *not* confirmed exploited (we checked only KEV).
3. **KEV is late and narrow.** It lists after attacks begin (PHP2Shell: KEV nine days after the first attempt; PHP got CPE on day one as federal software, so it shows listing lag, not the CPE gap) and catches a fraction of exploitation (VulnCheck 884 vs CISA 245 in 2025 [stable]; vendor figure, different rules).

**Context (one line each)**
- The gap is standardized identifiers, not product information: CNAs name a product for 94.0% [volatile] of new CVEs, but 71.3% [volatile] have that and no CPE.
- Who bears it: state and local governments, hospitals, small businesses — those that can't buy commercial product data.
- Limits: counts are CVEs, not risk (#22); some threats never get a matchable CVE (one sentence: Aug 2026 Siemens S7 advisory listed no CVE IDs).

**Won't AI make this obsolete?** (durability; one paragraph, here or before the recommendations)
  > **DRAFT (~170 words; over budget):** AI may cut certain bugs in new code sharply, but not to zero. Anthropic used Claude to prove 239 fuzzing entry points in 123 open-source libraries free of crashes, and its own limits section says "formally verified" does not mean "bug-free": the proofs cover specific properties (no crashes on inputs under 64 MB) under specific assumptions (single-threaded, static RISC-V binaries). AI systems also bring new flaw classes; RAND counts 31, many only partly patchable. Meanwhile old code stays in service. Zero-days in RAND's sample went undiscovered for 6.9 years on average, and industrial control systems get vendor minor updates only every 178 days on average. AI is finding new flaws in that old code (GitLab CVE-2026-110264 reaches back to version 7.0, released June 2014), and old CVEs are still being exploited: 30 of 285 KEV additions in 2026 [stable] were published four or more years earlier. The bottleneck moves from writing patches to deploying them, which depends on knowing what you run. That is the job of a public, scanner-matchable product record, whoever keeps it.
  Sources: Anthropic, "LLMs are making formal software verification feasible at a much larger scale," Oct 22, 2026 (vendor; the project uses Claude, disclose); RAND RR-A4983-1 (Jul 30, 2026); RR-1751 (6.9 years is zero-day *undisclosed* lifespan, ~200 cases); RR-A1888-2 (178 days = average interval between ICS vendor minor updates, not deployment); NVD CVE-2026-110264 and GitLab v7.0.0 tag (Jun 20, 2014); `kev_lag.json` legacy_by_year. **Dropped:** PHP2Shell "back to PHP 5.4" (CNA lists 8.2+, NVD CPE 7.3+). **Softened:** point (c) "the CVEs least likely to be enriched" has no data behind it; not claimed.

**Opportunities**
- EPSS leads KEV by ~201 days when it leads at all [stable, vendor: Barracuda], so it is a re-check trigger, not an intake screen. Its precision on unenriched CVEs is unmeasured; say so.
- NIST already designed the trigger (CSWP 41) and answers to its own RFI question on metrics (7(e)); NVD Watch is a working answer.

## Page 3 — Recommendations (~400 words)
**One headline ask per stakeholder**
1. **NIST:** adopt and publish a re-check rule — any CVE without CPE moves into the KEV queue when its EPSS crosses a published threshold — and report five quarterly metrics on both doors, including quarterly counts by tier.
   - Inside the metrics ask: **label which enrichments were AI-assisted** (provenance in the record), so every metric can be split by source. Why, one sentence: a tool can't grade itself, and speed isn't accuracy. Ties to RFI questions 1(b) (human review, "over-reliance on AI") and 3(b) ("transparency and auditability in AI-driven prioritization"). Don't name NIST's tool; nothing is released to measure.
   - Falsifiable line: "If AI-assisted enrichment scales, coverage should rise and time to enrichment should fall. These metrics will show whether it does."
2. **CISA:** as CVE Program sponsor, phase in machine-matchable product data in CVE records, largest vendor CNAs first.
3. **Congress:** make the five metrics the yardstick for oversight, in the GAO review House members requested and in any bill that codifies the CVE program; no new money.

**Cost box:** a one-time load of 303 CVEs [stable] ($12K–$36K once), then 11–28 a month [stable] (0.2–0.6% of NIST's ~5,000/month peak output, OIG; ~$5K–$40K a year). For scale only, not spare money: the OIG valued the re-scoring NIST stopped at ~$400K a year (NIST disputes it). Full derivation → footnote.

**Liveness as evidence:** the metrics are already computed weekly from public APIs (NVD Watch), so publishing them is cheap for NIST.

**Alternatives considered** (no prose; one "why not" each)
- Restore full enrichment — ~17,000 CVEs a month [volatile] against a ~5,000 peak; NIST already chose triage.
- Commercial enrichment — leaves out exactly the organizations that can't pay.
- Push upstream to CNAs only — right long-term (the CISA ask), but slow, risks small CNAs publishing less, and does nothing for the 76,217 [stable] CVEs already set aside.
- Status quo — CPE keeps waiting on KEV, which is late and narrow.

**What would change the recommendation (#5):** if high-EPSS Not Scheduled CVEs get CPE within a few weeks without a rule, the ask shrinks to the metrics. If NIST stopped meeting its KEV goal, KEV compliance would come first.

**RAND (#10), one sentence:** RAND has not studied the NVD directly; this applies RAND frameworks (incentives, accountability, continuous measurement), and EPSS's lineage includes RAND-affiliated authors.

## Footnote / site only
- Future work (one sentence): estimating installed-base lifetimes and code age from the affected-version ranges in CVE records. The site's legacy share counts CVE age, not code age.
Not in the brief body. Footnote where a reader needs it; otherwise link to the site.

*Sub-asks moved off Page 3*
- NIST: log every re-queue; freeze metric definitions; publish each CVE's priority tier (KEV, federal, EO 14028, none). OPSEC objection: per-CVE "federal" tags reveal what agencies run, and a combined "federal or EO 14028" flag still leaks; hence quarterly counts by tier in the headline ask. Until then, metrics 1–2 use observable tiers (KEV status, NVD status).
- NIST: re-queue into the KEV queue under the existing one-business-day goal; moving to the back of Awaiting would not help. Triggers beyond EPSS: KEV, LEV (CSWP 41), CISA SSVC PoC/Active, credible third-party reports.
- CISA as KEV owner: publish listing lag by month; set a review clock for credible third-party exploitation reports. Build the CNA ask on the Supplier ADP pilot.
- Congress: Appropriations, Science, Homeland Security committees; the June 2025 GAO request (no GAO product yet); FY2027 NDAA texts have no CVE codification.

*Detail moved out of the body*
- Readiness arithmetic: 35 additions − 6 listed on or before the day NVD published them − 6 with CPE from before the triage = 23 [fragile]. Of the 13 without CPE before listing, 4 got it within two hours of NVD logging the listing; NVD's KEV event is its own sync time, not CISA's.
- Runner-up CVEs: CVE-2026-77690 (ManageEngine, EPSS 0.16 [volatile], Awaiting — why the rule covers every status); CVE-2026-111357 (public 15 days, CPE 89 minutes after the KEV event); CVE-2026-41709 (public 90 days, CPE the day after).
- LEV / SSVC / SADP / purl / GCVE / EU vulnerability database details. SADP: Siemens and Red Hat added product data to 3,349 CVEs [volatile] (SADP Tracker, Nov 7); it fills `affected`, not CPE. Distributed enrichment complements the NVD, which stays the free baseline FedRAMP and PCI reference.
- Full cost derivation: measured from the whole NVD stock Nov 7, 2026 (`scripts/research/recheck_volume.py`, `data/processed/recheck_measured.json`), EPSS 10%. Stock 76,217 [stable] (no CPE, not KEV). One-time 303 ≈ 6% of one peak month. Monthly 11, 12, 23, 28 in four 30-day windows Jul 10 – Nov 6, change history included; mostly CVEs over 90 days old. 20–60 analyst-minutes at $120/h; simulator default 28 → ~$30K/yr at 45 min ($13K–$40K). OIG: ~$800K over two years ≈ $400K/yr; the rule is ~1–10% of that, a scale comparison. Left out (push it up): LEV, SSVC, third-party triggers; at 5%, 443 once; at 1%, 3,384 once and a few hundred a month. Five months under one EPSS model (v5). The earlier 16–46/month is superseded (`data-notes.md`).
- The five metric definitions (site section 4; CLAUDE.md, frozen).
- Coverage figures in circulation (≈50% Volerion, 8.4% CSI) differ by definition and window; status labels changed Apr 15, 2026.
- KEV-lag biases (#6): grouping by year added mixes in old CVEs listed late (up); the current year is incomplete (down).

## Data snapshot
- Snapshot tag: `brief-v1` (created at submission, not now)
- Pull date / CVE window: _TBD_
- Disclaimer: "Figures on the live site will differ; this brief uses the [date] snapshot."
- Cite the tag for numbers; cite the live site for the tracker ("updated weekly").

## Checks before submitting
- [ ] Every number matches the `brief-v1` tag (`summary.json`, `kev_enrichment.json`, `recheck_measured.json` at that tag), not the live site
- [ ] Fragile numbers reported as a range if they swing (`python scripts/stability.py`)
- [ ] Every number carries its label in this outline; volatile ones are dated in the brief
- [ ] Only CPE, KEV, EPSS used as unexplained acronyms
- [ ] BLUF ≤ 120 words; each page within its word budget; under 3 pages including the figure
- [ ] Vendor-sourced figures are attributed
- [ ] Each number in the brief has a "how verified" note in the AI log (#20)

## Later (at submission, not now)
- `git tag brief-v1 && git push origin brief-v1`; fill in **Data snapshot**; add a "Brief data snapshot" link on the site pointing to the tagged data.
