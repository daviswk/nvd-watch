# Policy brief outline (≤ 3 pages)

**Title (working):** Re-check, Then Measure: Closing the Product-Data Gap in the National Vulnerability Database

**Spine (revised Nov 8 after red-team round 6):** NIST's triage has a front door (KEV) but no side door. Fill what can be filled automatically (CNA-supplied CPE and exact dictionary matches), add a cheap side door for the rest (EPSS re-check), then measure whether both doors work (five metrics). *Test every section against this sentence; cut what doesn't serve it.*

**Framing line for the gap (Will, Nov 8):** "The backlog began Feb 2024. Readiness was about half before the April triage and about half after; the triage turned a backlog into standing policy." Never say the April triage *caused* the readiness gap (`kev_trigger_recall.json` → `m1_readiness_by_period`: 9 of 18 Oct–Nov 2025, 8 of 16 Jan–Feb 2026, 16 of 29 now).

**BLUF** (≤ 120 words: the three asks and the price; if they don't fit, scope is still too wide)
> _[empty: write last]_

**Word budget:** P1 ~400 · P2 ~450 + 1 figure · P3 ~400 (≈1,250 words total).

**Number labels:** [stable] = yearly or one-time measurements that won't move week to week; [volatile] = 30-day-window shares that move every pull; [fragile] = small n, may swing. Report fragile numbers as a range if `scripts/stability.py` shows them swinging.

**Jargon allowlist:** CPE, KEV, EPSS. Everything else in plain words (e.g. CNA → "the organizations that write CVE records"; enrichment → "adding product data"; CVSS → "severity score"). *Open: CVE itself is not on the list; define it once on first use or add it.*

**Lead with measurement, not failure.** No one publishes how quickly NIST attaches product data to CVEs; here are the numbers. Once CISA lists a CVE as exploited, NIST meets its own goal. The gap is before and outside KEV. The brief must stand alone without the site (#17) and work whatever the weekly data shows.

## Page 1 — Background (~400 words)
- **Why now** — *emerging-tech hook (assignment requirement).* **Settled framing (Nov 7):** AI accelerates a capacity problem that already existed; it did not cause it. AI appears in four roles only: why now, why waiting is costly, pressure on the pipeline, the future test. Do not say "AI-driven surge." Drop the CyberScoop/OpenAI line (press-reported, adds nothing the metrics use).
  > **DRAFT (~150 words; page 1 is already at budget, cut while writing):** NIST's capacity problem predates AI. Its backlog began in early 2024, when a support contract lapsed (OIG), and its April 2026 notice blames a 263% rise in submissions from 2020 to 2025, without mentioning AI. AI is now speeding it up. New CVEs in the NVD rose from 5,143 in January 2026 to 17,481 in October [stable] (our count); Google's threat intelligence team reports monthly disclosures doubled from January to August, and, like FIRST, credits much of the growth to other causes such as bulk Linux kernel CVEs and advisory backfills. FIRST also finds the actionable share (in KEV or above EPSS 10%) flat. Waiting is getting costlier: RAND found an off-the-shelf AI agent, prompted by people with no cyber expertise, solved each of its hacking challenges in under an hour for under $20 in total. Maintainers of curl and the Linux kernel report a flood of real, AI-found bugs. NIST asked how to modernize the NVD in the age of AI. Our answer: whatever AI changes, measure it publicly.
  **Nov 8 revision (Will): keep it to 2–3 sentences, two forces.** (1) Noise inflates the denominator: FIRST forecasts ~66K CVEs for 2026 (68K in its metadata; cite one); GTIG counts ~5,000 Linux kernel CVEs Jan–Aug 2026 (~145 a week), which it attributes to the kernel CNA's assignment policy, with zero exploited zero-days among them; only 0.23% of 2026 CVEs were seen exploited (GTIG). (2) Speed compresses the response time: exploited CVEs still rose in absolute terms, 10.5 → 18 a month (GTIG; say "count", since FIRST's "flat" is a ratio); RAND RR-A3892-2's agent solved each of three hacking tests in under an hour; GTIG's one timing example, BeyondTrust CVE-2026-1731, was exploited within 4 days of disclosure. **Don't say** "N-days in minutes" (no source measures it), don't cite DARPA AIxCC for offense (it found and patched bugs), don't call kernel CVEs "CYA", don't use "59,000 a year" (not in our sources). **COI:** lead with GTIG and RAND; cite RAND as a RAND study (disclose that the agent was Claude Code in the footnote); no Glasswing in the body.
  Sources: OIG-26-020-I; NIST Apr 15, 2026 notice ("increased 263% between 2020 and 2025"); GTIG Sep 30, 2026 (5,045 → 10,740, Jan–Aug); FIRST Jun 15, 2026 (GHSA +449%, VulnCheck +3,119%, actionable burden "completely flat"); RAND RR-A3892-2 (CTF challenges, "less than US$20" over all of them; the agent was Claude Code, disclose); Stenberg Oct 22, 2026 ("high volume, high quality"); Torvalds via Tom's Hardware, May 18, 2026 ("almost entirely unmanageable"). **Not** "about $16" (earlier drill figure; RAND's summary says under $20 and the PDF was not readable this pass).
- What the NVD does, and why CPE is what lets scanners tell an organization it is affected.
- NIST's April 15, 2026 triage: KEV, federal, and EO 14028 critical software first; everything else waits.
- Definition (#21): CPE arrives "when defenders need it" if it is there **before** CISA confirms exploitation (the KEV listing). Readiness is scored apart from NIST's one-business-day goal after listing; never let one number stand for both.
- KEV lag, one sentence: median days from CVE publication to KEV listing rose from 4 (2023) to 10 (2025), 9 in 2026 to Nov 6 [stable] (our count, `scripts/kev_lag.py`; Barracuda reports 6 → 14, vendor).

## Page 2 — Challenges and opportunities (~450 words + 1 figure)
**Figure (decided Nov 8): monthly cohort maturation bar** (`data/processed/coverage_by_month.json`, `.svg`; S6). One bar per publication month, CPE share vs Not Scheduled share. It separates queue lag from the plateau: the rolling 30-day window is at 22.3% CPE (Nov 8 pull), the Aug–Oct 2026 cohorts at 26–34%, the Apr–Jul 2026 cohorts at 55–68% with 28–43% Not Scheduled. Say "plateau", not "permanent" or "abandonment": Not Scheduled CVEs can be re-queued. Caveat for the caption: Not Scheduled was already 28–50% in the Nov 2024 – Feb 2026 cohorts, and status definitions changed Apr 15, 2026, so the figure can't date when parking began. Snapshot: NVD yearly feeds, Nov 8 [one snapshot]. The status-table figure (0% CPE in Not Scheduled, true by definition) moves to the site.

**Three findings**
1. **After KEV, NIST performs; before it, CPE mostly isn't there.** Goal: 34 of 35 [fragile] KEV additions Oct 8 – Nov 7 had CPE within one business day, all from NIST *(number drift: the Nov 8 pull, Oct 9 – Nov 8, shows 29 of 29 resolved, 1 pending; use the figure at the `brief-v1` tag)*. Readiness: only 10 of 23 [fragile] had CPE before the listing (same in both pulls so far, but the two windows share 30 of 31 days, so that is not a stability check; see `scripts/stability.py`). Defender's view only: NVD users did not see CPE for the other 13 until CISA listed them (don't claim NIST starts from scratch at the listing). Arithmetic → footnote. Of the 13, the day before listing: 5 Not Scheduled (each moved there 1–2 days after publication), 5 Awaiting Enrichment, 2 Received, 1 unknown (`parked_before_kev.json`) — half parked, half queued; all got CPE about a business day after listing, as the triage is designed. Readiness at ≥ 1 and ≥ 7 days public: 10 of 23 and 8 of 14 [fragile]; median 6 days public without CPE (publication to listing, not exploitation to listing).
2. **Before KEV, nothing re-checks.** 22.6% [volatile] of new CVEs have CPE; 40.8% [volatile] are Not Scheduled *(Nov 8 pull: 22.3% and 40.9%; use the `brief-v1` tag)*. 37.9% [one snapshot] of the Apr 15 – Jun 15 cohort is still Not Scheduled five months later (a single measurement; no test yet of whether Not Scheduled CVEs stay that way). Example: CVE-2026-59774 (Gitea), Not Scheduled, no CPE, EPSS 0.28 on Nov 7 [volatile]; at risk, *not* confirmed exploited (we checked only KEV).
3. **KEV is a confirmation list: late and narrow by design.** Late: CISA's SSVC "active" value is logged only 0.7–1.7 hours before NVD's KEV event, so it is part of the listing, not a warning. PHP2Shell is a **contrast case, not a KEV-gate failure**: as federally used software it got NIST CPE 2 h 44 min after NVD published it (Oct 21, 14:17 → 17:01 UTC), yet KEV listed it Oct 26, 1–2 days after the first public exploitation report (Oct 24–25, BleepingComputer only). The Oct 17 honeypot hit predates disclosure; don't count lag from it, and don't date exploitation to Oct 21. CVEs that did wait on KEV for CPE: the 13 in finding 1. Narrow: KEV held 1,228 of ~260,000 CVEs in Dec 2024 (~0.5%), while CSWP 41's LEV estimates ~1,006 of 66,125 EPSS-v3-scored CVEs (1.5%) were likely exploited, and several hundred CVEs with LEV near 1.0 were not on the KEV lists NIST tested (NIST CSWP 41, May 2025). VulnCheck logged 884 CVEs with first-time exploitation evidence in 2025 (518 vendors) vs CISA's 245 (99 vendors) [stable; vendor, broader evidence rules]. KEV's criteria (CVE ID, evidence of active exploitation, clear remediation) are not limited to federal software; BOD 22-01 binds agencies, not the catalog's scope. **Dropped:** "KEV misses 22–39%" (not in CSWP 41 or any source we hold).

**Context (one line each)**
- The gap is standardized identifiers, not product information: CNAs name a product for 94.0% [volatile] of new CVEs, but 71.3% [volatile] have that and no CPE.
- Who is blind without CPE (#9, scoped): package scanners match language and distro packages through package advisories (Trivy never uses NVD for detection); Grype matches unknown software and binaries only through NVD CPE. In a random sample of 10 CVEs without CPE or an OSV advisory (n = 10, checked in Tenable, GitHub advisories and WPScan only): 2 WordPress plugins covered by WPScan; 1 covered by a Tenable FreeBSD package plugin (MySQL Router); 5 vendor or appliance products with no detection in those sources (IBM MQ, WatchGuard Fireware OS, Mitsubishi Electric GENESIS, SOCFortress CoPilot, NetEase Youdao LobsterAI); 2 open-source packages (signalk-server on npm, SurrealDB on crates.io) with only unreviewed GitHub advisories and no package coordinates, so package scanners had nothing to match either. Commercial scanners not checked. Don't include "operating systems" (distro feeds cover them).
- Who bears it: state and local governments, hospitals, small businesses — those that can't buy commercial product data.
- Severity scores are not the gap: 94.5% [volatile] of new CVEs carry one (77.8% from the CNA, most of the rest from CISA's Vulnrichment); NIST scored 2.8%. Use the non-rejected base, never 91%.
- Federal demand already exists: FedRAMP's 2026 rules (mandatory Dec 7, 2026) require cloud providers to evaluate every detected vulnerability for whether it is "likely exploitable" (VER-EVA-ELX) and internet-reachable (VER-EVA-EIR). That evaluation starts with detection, and scanners detect by product data. FedRAMP's "LEV" is its own contextual term (Likely Exploit*able*), **not** NIST CSWP 41's Likely Exploit*ed* Vulnerabilities; FedRAMP cites no EPSS, NVD or CPE, so "needs CPE" is our inference.
- Limits: counts are CVEs, not risk (#22); some threats never get a matchable CVE (one sentence: Aug 2026 Siemens S7 advisory listed no CVE IDs).

**Won't AI make this obsolete?** (durability; one paragraph, here or before the recommendations)
  > **DRAFT (~170 words; over budget):** AI may cut certain bugs in new code sharply, but not to zero. Anthropic used Claude to prove 239 fuzzing entry points in 123 open-source libraries free of crashes, and its own limits section says "formally verified" does not mean "bug-free": the proofs cover specific properties (no crashes on inputs under 64 MB) under specific assumptions (single-threaded, static RISC-V binaries). AI systems also bring new flaw classes; RAND counts 31, many only partly patchable. Meanwhile old code stays in service. Zero-days in RAND's sample went undiscovered for 6.9 years on average, and industrial control systems get vendor minor updates only every 178 days on average. AI is finding new flaws in that old code (GitLab CVE-2026-110264 reaches back to version 7.0, released June 2014), and old CVEs are still being exploited: 30 of 285 KEV additions in 2026 [stable] were published four or more years earlier. The bottleneck moves from writing patches to deploying them, which depends on knowing what you run. That is the job of a public, scanner-matchable product record, whoever keeps it.
  Sources: Anthropic, "LLMs are making formal software verification feasible at a much larger scale," Oct 22, 2026 (vendor; the project uses Claude, disclose); RAND RR-A4983-1 (Jul 30, 2026); RR-1751 (6.9 years is zero-day *undisclosed* lifespan, ~200 cases); RR-A1888-2 (178 days = average interval between ICS vendor minor updates, not deployment); NVD CVE-2026-110264 and GitLab v7.0.0 tag (Jun 20, 2014); `kev_lag.json` legacy_by_year. **Dropped:** PHP2Shell "back to PHP 5.4" (CNA lists 8.2+, NVD CPE 7.3+). **Softened:** point (c) "the CVEs least likely to be enriched" has no data behind it; not claimed.

**Opportunities**
- **Much of the gap can be filled without analysts.** Of 13,207 window CVEs without NVD CPE (Nov 7 pull), 1,430 (10.8%) already carry unvalidated CNA-supplied `cpes` in the CVE record, and 2,846 (21.5%) name a vendor and product that exactly match a CPE dictionary pair; together 3,849 (29.1%, overlap 427) [volatile] (`automated_mapping.json`). The dictionary matches are provisional, product-level CPE without version ranges. Price: no per-CVE analyst time, plus a QA sample.
- EPSS leads KEV by ~201 days when it leads at all [stable, vendor: Barracuda], so it is a re-check trigger, not an intake screen. As a pre-KEV warning it is weak: at ≥ 0.05 it fired the day before listing for 22 of 172 KEV CVEs without CPE (2025–26), 4 of 51 under EPSS v5 (`kev_trigger_recall.json`). Its main job is the non-KEV stock (see Page 3).
- **EPSS v5 (#17), report honestly:** at ≥ 0.10, 13 of 88 scored CVEs under v4 vs 2 of 39 under v5 (different cohorts). The 12 unscored v5 CVEs were each listed one day after publication, before EPSS's daily run scored them: a timing artifact, not lost features. Whether v5 under-scores CVEs without CPE (77.7% of the Nov 8 window) is an **open hypothesis**, not a finding.
- NIST already designed the trigger (CSWP 41) and answers to its own RFI question on metrics (7(e)); NVD Watch is a working answer.

## Page 3 — Recommendations (~400 words)
**One headline ask per stakeholder**
1. **NIST (three parts, decided Nov 8):**
   - **1A. Automated day-0 CPE.** Pass through CNA-supplied `cpes` and assign provisional, product-level CPE where the CNA's vendor and product exactly match the dictionary: up to 29.1% of the CVEs now without CPE [volatile], no per-CVE analyst time, plus a QA sample.
   - **1B. Daily EPSS ≥ 0.05 re-check backstop.** Any CVE still without CPE (Not Scheduled, Awaiting, Received) moves into the KEV queue when its EPSS reaches 0.05. Show 0.05 and 0.10 side by side (cost box). Its main job is the non-KEV stock: by EPSS's own summed 30-day probabilities, the one-time load holds ~105 CVEs expected to see exploitation activity at 0.05 (~95 at 0.10). Those are the model's estimates, not independent validation; hence the hit-rate test in metric 5. `trigger_table.json` shows why broader triggers break the budget: EPSS ≥ 0.01 ~$707K/yr, LEV ≥ 0.10 ~$353K/yr, SSVC PoC ~$2.49M/yr (max monthly flow, 45 min).
   - **1C. Quarterly reporting:** the five metrics below, plus enrichment counts by priority tier and the volume and turnaround of enrichment requests to nvd@nist.gov (today email-only, "as resources allow", no published data).
   - Inside the metrics ask: **label which enrichments were AI-assisted** (provenance in the record), so every metric can be split by source. Why, one sentence: a tool can't grade itself, and speed isn't accuracy. Ties to RFI questions 1(b) (human review, "over-reliance on AI") and 3(b) ("transparency and auditability in AI-driven prioritization"). Don't name NIST's tool; nothing is released to measure.
   - Falsifiable line: "If AI-assisted enrichment scales, coverage should rise and time to enrichment should fall. These metrics will show whether it does."
2. **CISA:** as CVE Program sponsor, require structured `cpes` or `packageURL` in CVE records for the ~71% that 1A can't fill, where CNA strings don't match the dictionary; build on the Supplier ADP pilot, largest vendor CNAs first.
3. **Congress:** Commerce-Justice-Science appropriations report language directing NIST to publish the quarterly metrics and tier and request counts; make them the yardstick in the GAO review that House Homeland Security and Science ranking members Thompson and Lofgren requested (June 6, 2025 letter). No new money. Timing: NIST's RFI comments closed Oct 13, 2026, with no published NIST response as of Nov 8, so the evidence arrives while NIST is weighing the comments.

**Cost box (EPSS ≥ 0.05, with 0.10 beside it; 45 analyst-minutes at $120/h, range 20–60 min):**

| | ≥ 0.05 | ≥ 0.10 |
|---|---|---|
| One-time load | 443 CVEs, ~$40K ($18K–$53K) | 303 CVEs, ~$27K ($12K–$36K) |
| Monthly flow | 8–30, ~$32K/yr at 30 ($4K–$43K) | 11–28, ~$30K/yr at 28 ($5K–$40K) |
| Share of ~5,000/month peak | 0.16–0.6% | 0.22–0.56% |
| KEV CVEs caught before listing (2025–26 / v5) | 22 of 172 / 4 of 51 | 15 of 172 / 2 of 51 |
| EPSS-expected exploitation in the load, 30 days | ~105 | ~95 |

[stable except the flow, measured in four 30-day windows Jul 10 – Nov 6.] For scale only, not spare money: the OIG valued the re-scoring NIST stopped at ~$400K a year (NIST disputes it). Full derivation → footnote.

**Liveness as evidence:** the metrics are already computed weekly from public APIs (NVD Watch), so publishing them is cheap for NIST.

**Alternatives considered** (no prose; one "why not" each)
- Restore full enrichment — ~17,000 CVEs a month [volatile] against a ~5,000 peak; NIST already chose triage.
- Commercial enrichment — leaves out exactly the organizations that can't pay.
- Push upstream to CNAs only — right long-term (the CISA ask), but slow, risks small CNAs publishing less, and does nothing for the 76,217 [stable] CVEs already set aside.
- Status quo — CPE keeps waiting on KEV, which is late and narrow.

**What would change the recommendation (#5):** if high-EPSS Not Scheduled CVEs get CPE within a few weeks without a rule, the ask shrinks to 1A and the metrics. If NIST stopped meeting its KEV goal, KEV compliance would come first. **Hit-rate test (replaces the overnight 25%-recall stopping rule, rejected Nov 8):** metric 5 tracks how many re-queued CVEs later reach KEV or show exploitation; NIST tunes or retires the threshold on that evidence.

**The five quarterly metrics (revised Nov 8; replaces the Nov 7 frozen set):**
1. Pre-KEV readiness: share of KEV additions public before listing that had CPE before listing, at ≥ 1 and ≥ 7 days public.
2. CPE coverage by publication-month cohort (any source; NIST-sourced), split by observable tier (KEV status, NVD status).
3. Median and 90th-percentile time to enrichment, by the same tiers.
4. Compliance with the one-business-day KEV goal (clock: later of listing and NVD publication).
5. Re-queues: counts, time to enrichment after re-queue, and hit rate (later KEV listing or exploitation).
Reporting rules, not metrics: publish a change log of status-category definitions (they changed Apr 15, 2026), counts by priority tier, and nvd@nist.gov request volume and turnaround.

**Why NIST must publish what NVD Watch already computes (#15):** outsiders can measure lag and coverage only after the fact, and can't see two things at all: which tier triggered an enrichment, and how many enrichment requests NIST receives, accepts or declines. Analogy only: Polley's Pardee RAND dissertation (RGSD-A1954-1, 2022) found the Vulnerabilities Equities Process debate "largely rooted in uninformed opinion" without public data.

**RAND (#10), one sentence:** RAND has not studied the NVD directly; this applies RAND frameworks (incentives, accountability, continuous measurement), and EPSS's lineage includes RAND-affiliated authors. Optional clause, as an analogy only: Polley's Pardee RAND dissertation on the Vulnerabilities Equities Process (2022; Romanosky on the committee) found that without public data the debate was "largely rooted in uninformed opinion", the same reason to publish tier counts. It studies zero-day retention, not NVD triage, so it supports transparency, not the rule.

## Footnote / site only
- Future work (one sentence): estimating installed-base lifetimes and code age from the affected-version ranges in CVE records. The site's legacy share counts CVE age, not code age.
Not in the brief body. Footnote where a reader needs it; otherwise link to the site.

*Sub-asks moved off Page 3*
- NIST: log every re-queue; freeze metric definitions; publish each CVE's priority tier (KEV, federal, EO 14028, none). OPSEC objection: per-CVE "federal" tags reveal what agencies run, and a combined "federal or EO 14028" flag still leaks; hence quarterly counts by tier in the headline ask. Until then, metrics 1–2 use observable tiers (KEV status, NVD status).
- NIST: re-queue into the KEV queue under the existing one-business-day goal; moving to the back of Awaiting would not help. Triggers beyond EPSS: KEV, LEV (CSWP 41), CISA SSVC PoC/Active, credible third-party reports.
- CISA as KEV owner: publish listing lag by month; set a review clock for credible third-party exploitation reports. Build the CNA ask on the Supplier ADP pilot.
- Congress: Appropriations, Science, Homeland Security committees; the June 2025 GAO request (no GAO product yet); FY2027 NDAA texts have no CVE codification.

*Detail moved out of the body*
- Readiness arithmetic: 35 additions − 6 listed on or before the day NVD published them − 6 with CPE from before the triage = 23 [fragile] *(Nov 7 pull; Nov 8 pull: 30 − 6 − 1 = 23)*. Of the 13 without CPE before listing, 4 got it within two hours of NVD logging the listing; NVD's KEV event is its own sync time, not CISA's.
- Runner-up CVEs: CVE-2026-77690 (ManageEngine, EPSS 0.16 [volatile], Awaiting — why the rule covers every status); CVE-2026-111357 (public 15 days, CPE 89 minutes after the KEV event); CVE-2026-41709 (public 90 days, CPE the day after).
- LEV / SSVC / SADP / purl / GCVE / EU vulnerability database details. SADP: Siemens and Red Hat added product data to 3,349 CVEs [volatile] (SADP Tracker, Nov 7); it fills `affected`, not CPE. Distributed enrichment complements the NVD, which stays the free baseline FedRAMP and PCI reference.
- Full cost derivation: measured from the whole NVD stock Nov 7, 2026 (`scripts/research/recheck_volume.py`, `data/processed/recheck_measured.json`), EPSS 10%. Stock 76,217 [stable] (no CPE, not KEV). One-time 303 ≈ 6% of one peak month. Monthly 11, 12, 23, 28 in four 30-day windows Jul 10 – Nov 6, change history included; mostly CVEs over 90 days old. 20–60 analyst-minutes at $120/h; simulator default 28 → ~$30K/yr at 45 min ($13K–$40K). OIG: ~$800K over two years ≈ $400K/yr; the rule is ~1–10% of that, a scale comparison. Left out (push it up): LEV, SSVC, third-party triggers; at 5%, 443 once; at 1%, 3,384 once and a few hundred a month. Five months under one EPSS model (v5). The earlier 16–46/month is superseded (`data-notes.md`).
- The five metric definitions (Page 3 above; CLAUDE.md; site section 4, updated Nov 8).
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
