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
- **Why now** — *emerging-tech hook (assignment requirement).* New CVEs in the NVD rose from 5,143 in January 2026 to 17,481 in October [stable] (our count, NVD API; `data-notes.md`, Verification pulls). Google's threat intelligence team (GTIG, Sep 30, 2026) sees "emerging signals" that AI is contributing to vulnerability discovery, but does **not** attribute the rise to AI: it names other drivers, such as about 5,000 Linux kernel CVEs Jan–Aug and vendor disclosure cycles. OpenAI officials told CyberScoop (Nov 5) its new model found 81+ novel Firefox bugs (press-reported). Frame: AI is one force raising volume and likely to raise it further; the capacity gap began earlier (February 2024 contract lapse, OIG). Do not say "AI-driven surge."
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

**Opportunities**
- EPSS leads KEV by ~201 days when it leads at all [stable, vendor: Barracuda], so it is a re-check trigger, not an intake screen. Its precision on unenriched CVEs is unmeasured; say so.
- NIST already designed the trigger (CSWP 41) and answers to its own RFI question on metrics (7(e)); NVD Watch is a working answer.

## Page 3 — Recommendations (~400 words)
**One headline ask per stakeholder**
1. **NIST:** adopt and publish a re-check rule — any CVE without CPE moves into the KEV queue when its EPSS crosses a published threshold — and report five quarterly metrics on both doors, including quarterly counts by tier.
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
