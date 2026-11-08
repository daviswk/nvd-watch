# Red-team round 6: overnight response (Nov 7–8, 2026)

Session: Claude Opus 5.5 (Claude Code), branch `redteam-nov7`. Task spec: `docs/red-team-nov7.md`. Will was asleep, so no questions were asked; where the spec left room for interpretation, the reading taken is noted under **Readings taken** below. Every number below traces to a script in `scripts/research/` and its output in `data/processed/`, unless it is labelled otherwise. Small n is given as counts.

## 1. Top 5 results

1. **The gap predates the April triage, at about the same size.**
   - Before the triage, about half of the public-before-listing KEV CVEs had CPE before CISA listed them: 9 of 18 (Oct 8 – Nov 7, 2025) and 8 of 16 (Jan 8 – Feb 7, 2026).
   - Today it is 16 of 29, or 10 of 23 under the page's rule.
   - For CVEs at most 90 days old at listing, it was 2 of 10 and 3 of 8 then, against 7 of 20 now.
2. **The EPSS ≥ 0.10 trigger catches about 1 harm case in 11.**
   - Of 172 KEV CVEs (2025 – Nov 7, 2026) that were public without CPE before listing, it fired for 15 the day before listing.
   - Under EPSS v5 the count drops to 2 of 51 (13 of 98 under v4). In the current window it is 1 of 13.
   - LEV adds 2 cases. Every trigger combined (EPSS 0.10, LEV 0.10, SSVC ≥ 24 h ahead) reaches 21 of 172.
3. **The "better" triggers either arrive with KEV or flood the queue.**
   - CISA's SSVC "active" is logged 0.7–1.7 hours before NVD's KEV event, so it is part of the listing, not a warning ahead of it.
   - SSVC "poc" already marks 15,870 of the 76,217 stock CVEs, and adds ~1,500–2,300 a month (up to 46% of NIST's peak monthly output).
   - LEV ≥ 0.10 means 2,972 once, then 165–327 a month.
4. **The 13 were half parked, half queued.**
   - The day before CISA listed them: 5 were Not Scheduled, 5 Awaiting Enrichment, 2 Received, 1 unknown (not enriched).
   - Their median time public without CPE was 6 days.
   - A side door exists: email nvd@nist.gov, "as resources allow". NIST publishes no criteria, no goal and no counts for it.
5. **Some CPE could be produced automatically, and young windows understate coverage.**
   - Of the window's 13,207 CVEs without NVD CPE:
     - 21.5% name a CNA vendor and product that exactly match a CPE dictionary pair;
     - 10.8% already carry CNA-supplied `cpes`, which NVD does not use.
   - Post-triage monthly cohorts that are 4–7 months old now have 55–68% CPE, not 22%.
   - Each post-triage cohort is still 28–41% Not Scheduled.

## 2. Decisions for Will

### 2a. Does the EPSS-only headline ask survive M3?

**The evidence** (`data/processed/trigger_table.json`; recall from `kev_trigger_recall.json`; volumes from `recheck_measured.json`, `trigger_volume.json` and the Nov 8 re-run of `recheck_volume.py`; costs from `cost_model.py` at 45 analyst-minutes and $120/h):

**How to read the table:**
- **Recall:** among public-before-listing KEV CVEs without CPE before listing, whether the trigger fired before NVD logged the KEV listing.
- **EPSS:** the score dated the day before listing. 25 of the 172 had no score that day: 12 under v5, 10 under v4, 3 under v3.
- **SSVC** recall can be dated only from Jun 16, 2026, when NVD's change history began logging SSVC. Its denominator is therefore the 51 v5-era cases.
- **One-time load and flow:** measured on the stock of 76,217 CVEs (no CPE, Not Scheduled / Awaiting / Received, not KEV).
- **Benefit:** the sum of current EPSS over the one-time load. That is the expected number of those CVEs with exploitation **activity** in the next 30 days. EPSS is a 30-day probability of exploitation activity, not of compromise.

| Trigger | Recall, 2025–26 | v4 era | v5 era | One-time load | Cost once | Monthly flow | Cost/yr at top of flow | Share of 5,000/mo | Expected CVEs with activity, 30 d (load) |
|---|---|---|---|---|---|---|---|---|---|
| EPSS ≥ 0.10 (headline) | 15 of 172 | 13 of 98 | 2 of 51 | 303 | $27K | 11–28 | $30K | 0.6% | 95 |
| EPSS ≥ 0.05 | 22 of 172 | 18 of 98 | 4 of 51 | 443 | $40K | 8–30\* | $32K | 0.6% | 105 |
| EPSS ≥ 0.01 | 36 of 172 | 24 of 98 | 12 of 51 | 3,384 | $305K | 183–655\* | $707K | 13.1% | 158 |
| LEV ≥ 0.10 (from EPSS; approx.) | 17 of 172 | 15 of 98 | 2 of 51 | 2,972 | $267K | 165–327 | $353K | 6.5% | 139 |
| SSVC poc/active ≥ 24 h before listing | — | not dateable | 5 of 51 | 15,870 | $1.43M | 1,515–2,307\*\* | $2.49M | 46.1% | 120 |
| SSVC poc/active, any time before | — | not dateable | 19 of 51 | 15,870 | $1.43M | 1,515–2,307\*\* | $2.49M | 46.1% | 120 |
| EPSS 0.10 or LEV 0.10 or SSVC ≥ 24 h | 21 of 172 | 15 of 98 | 6 of 51 | 17,893 | — | — | — | — | 204 |

Table notes:
- \* Stock crossers only, without the change-history correction applied at 0.10. The correction adds 2–7 a month.
- \*\* Flow is dated by the SSVC `timestamp`, which is the latest evaluation. CISA sometimes back-dates it (CVE-2026-76418 reads Oct 28 but was set to "active" on Oct 29), so the flow is approximate.
- Of the 19 SSVC hits, 14 were "active" values logged 0.7–1.7 h before the KEV event.
- In the v3 era (Jan 1 – Mar 16, 2025), no trigger fired for any of 23 cases. v3 scores for new CVEs sat around 0.0004–0.01.

**Recommendation: a stopping rule.**

> Keep a trigger in the headline ask only if, on KEV CVEs without CPE before listing, it fires ≥ 1 day before listing for at least **25%** of cases, at fewer than **100 re-queues a month** on the stock (2% of NIST's 5,000/month peak).

Why these values:
- **25%:** at that rate the rule would catch at least one in four of the cases the brief is about.
- **100 a month:** about 4× the measured EPSS 0.10 flow, still a rounding error in NIST's capacity.

**No trigger passes.**
- EPSS 0.10: 8.7% recall at 28 a month.
- EPSS 0.01: 21% at up to 655 a month.
- The union of all triggers: 12%.

**If the rule fails,** demote the re-check from the headline to a cheap backstop: "re-queue at EPSS 0.10; it costs 0.6% of capacity and would have caught about 1 in 11". Make the headline ask what the data supports:
1. Publish readiness (CPE before KEV listing) and re-queue metrics quarterly.
2. Ingest the CPE that CNAs already supply, and auto-map exact vendor:product matches as provisional CPE (see 2d).

This changes the argument, so it is Will's call; nothing in the brief outline's asks was changed.

**Before deciding, note the limits:**
- n is small: 51 in the v5 era.
- The current model looks worse than v4 (2 of 51 against 13 of 98).
- Whether EPSS v5 under-scores unenriched CVEs is still untested. It is an open item in `CLAUDE.md`, and this result raises its priority.

### 2b. Does M1 support "the April triage caused the gap"?

**No. Recommend "the gap persists", and say it predates the triage.**

| Period (KEV listing dates) | KEV adds | Not public before listing (excluded) | Readiness, all public before listing | CVEs ≤ 90 days old at listing | Page rule (excludes pre-triage CPE) |
|---|---|---|---|---|---|
| Oct 8 – Nov 7, 2025 (pre-triage) | 20 | 2 | 9 of 18 | 2 of 10 | 9 of 18 (rule n/a) |
| Jan 8 – Feb 7, 2026 (pre-triage) | 21 | 5 | 8 of 16 | 3 of 8 | 8 of 16 (rule n/a) |
| Oct 8 – Nov 7, 2026 (under triage) | 35 | 6 | 16 of 29 | 7 of 20 | 10 of 23 (6 excluded) |

Caveats:
- The pre-triage periods fall in NVD's 2024–26 backlog, not in a "normal" year.
- Each period has 16–29 cases.
- Within this noise, readiness neither collapsed nor improved.

Source: `kev_trigger_recall.json` → `m1_readiness_by_period`. The rules are `kev_enrichment.py`'s, plus the legacy correction under §4c (it removed 8 false "no CPE" cases, none in these three periods).

### 2c. Does M2 support the side-door story, or is it a queue-speed story?

**Both, about evenly. The waits were short.**

| Status the day before listing (fkie-cad NVD mirror) | Count | CVEs |
|---|---|---|
| Not Scheduled (`Deferred`) | 5 | CVE-2026-110447, -106931, -119977, -105133, -105134 (public 3–10 days) |
| Awaiting Enrichment | 5 | CVE-2026-110936, -111357, -111497, -21589, -41709 (-41709 public 90 days) |
| Received | 2 | CVE-2026-102764, -114625 (public 1 day each) |
| Unknown | 1 | CVE-2026-76418: no mirror version before listing; NVD change history shows only "New CVE Received" and ADP updates, so not enriched |

What it means:
- Five were parked, so a request or re-check could have reached them.
- Seven were simply in the queue, so the issue there is queue speed.
- The 5 parked CVEs were Not Scheduled within days of publication, and each got CPE within one business day of listing.

**Recommendation:** present the 13 as "not enriched in time", with the split, rather than as parked. Source: `data/processed/parked_before_kev.json`.

### 2d. Should automated mapping (S1) be added as an alternative, or replace the CISA ask?

**Add it as an alternative; don't replace the CISA ask.**
- An exact vendor:product match covers 21.5% (2,846 of 13,207), and it gives a product, not version ranges.
- CNA-supplied `cpes` cover 10.8% (1,430).
- Together that is at most about a third. Most CNA records still lack a dictionary-matching product name, which is the upstream data-quality problem the CISA (CVE sponsor) ask targets.

A concrete low-cost NIST ask: *"display CNA-supplied CPE and exact-match provisional CPE, labelled as such, for Not Scheduled CVEs."*

Source: `data/processed/automated_mapping.json`.
- Rule: lower-case and spaces → `_`; nothing else.
- The CVE Record Format's `product.cpes` field was confirmed in the schema at CVEProject/cve-schema.
- `packageURL` appears on 14.4%.

### 2e. Metric set: add readiness? Drop or merge metric 5?

**Recommendation (a proposal; the five definitions are unchanged):**
- **Add readiness** (share of KEV-listed CVEs that had CPE before listing, among those public ≥ 1 day; report ≥ 7 days alongside). It is the defender-facing measure, and the only one the data shows failing.
- **Fold metric 3** (one-business-day goal) into it as a second line. It is met: 29 of 29 resolved, 1 pending, on Nov 8.
- **Merge metric 5** (status-definition change log) into the reporting rules as a standing requirement rather than a performance metric.
- Metric 1 by NVD status is partly definitional, since Not Scheduled means 0% CPE by construction. Report it by age cohort instead, as in the S6 figure.

## 3. Pushback status (points 1–19)

| # | Point | Status | What settles it |
|---|---|---|---|
| 1 | EPSS caught 1 of 13; better triggers demoted; LEV derives from EPSS | **Addressed** | 1 of 13 reproduced (CVE-2026-111497, EPSS 0.36). Over 2025–26: 15 of 172. LEV adds 2. SSVC is not better: "active" arrives with KEV, and "poc" floods the queue. `trigger_table.json` |
| 2 | Cost priced on 0.10 only | **Addressed** | Every trigger priced, once and per year: §2a table |
| 3 | No benefit estimate | **Addressed** | Expected CVEs with exploitation activity in 30 days, per trigger: 95 for the 303 at EPSS 0.10 ($27K once). `trigger_volume.json` |
| 4 | A side door already exists | **Addressed (confirmed)** | NVD status page: "Requests may be made…"; Apr 15 notice: email nvd@nist.gov; no goal, no counts. `docs/research/notes/redteam_nov7_request_channel.md` |
| 5 | Missing automated mapping; `has_cpe` ignores CNA CPE | **Addressed (measured; page unchanged)** | 21.5% exact match; 10.8% CNA `cpes`. `has_cpe` reads NVD `configurations` only, which is what scanners using NVD see. `automated_mapping.json` |
| 6 | No pre-triage baseline | **Addressed** | §2b: 9 of 18, 8 of 16 vs 16 of 29 / 10 of 23 |
| 7 | Findings 1 and 2 not shown to be the same CVEs | **Addressed** | §2c: 5 of 13 were Not Scheduled before listing. `parked_before_kev.json` |
| 8 | Readiness sensitive to public-days cutoff; harm in days unstated | **Addressed** | 10 of 23 at ≥ 1 day; 8 of 14 at ≥ 7 days. Days public without CPE: median 6, max 90. `kev_trigger_recall.json` → `s3_current_listed_cohort` |
| 9 | Scanner dependence rests on one blog post | **Partly** | Grype matches unknown software and binaries only through NVD CPE. Trivy does not use NVD for detection at all. Ten random orphans: 3 have any public detection (2 WPScan, 1 FreeBSD package plugin for MySQL Router); 7 have none. Commercial scanners not checked. `redteam_nov7_scanners.md`, §5 below |
| 10 | 0% CPE in Not Scheduled is definitional; 22% is a young window | **Partly (figure proposed)** | Post-triage cohorts 4–7 months old are at 55–68% CPE. `coverage_by_month.json` and `.svg` (S6). Brief outline flags the definitional point |
| 11 | "They stay that way" rests on one snapshot | **Partly** | Phrase dropped from the outline. Cross-section: Apr–Jul 2026 cohorts are still 28–41% Not Scheduled now. One snapshot; no panel test |
| 12 | PHP2Shell undercuts "KEV is late"; lag fell in 2026; BOD 22-01 | **Partly** | PHP2Shell wording fixed: KEV 1–2 days after the first public report. Lag 10 → 9 already shown on the page. BOD 22-01 scope argument not addressed |
| 13 | AI "why now" vs its sources; FIRST's flat burden; COI citations | **Not** | Argument and sourcing, outside tonight's measurement scope |
| 14 | Readiness not a metric; metric 1 definitional; metric 3 met; metric 5 a log | **Partly (proposal)** | §2e |
| 15 | Outsiders can compute metrics 1–3 | **Not** | Argument. Our data shows what outsiders cannot see: NIST's tier assignments, and the request channel's volume (M5) |
| 16 | NIST ask is four asks; no Congress vehicle; RFI closed | **Not** | Argument. M5 confirms that no request data is published |
| 17 | EPSS threshold unstable across versions; flow fell 28 → 12 | **Partly** | Recall split by model (v4 13 of 98, v5 2 of 51). Flow re-measured, same 11–28. Displacement cost not estimated |
| 18 | Overlapping windows make stability look narrow | **Addressed** | `stability.py` prints the overlap (Nov 7 vs Nov 8 share 30 of 31 days) and the non-overlapping range (1 window so far) |
| 19 | Readiness n doesn't grow | **Addressed** | `data/history/kev_cumulative.json` (union of all pulls; 35 CVEs, 10 of 23 so far), written by `kev_enrichment.py` each run |

## 4. What changed, what went wrong, what is open

### 4a. Commits on `redteam-nov7`

| Commit | What |
|---|---|
| `0a3afd2` | Task spec added. This commit also, by mistake, carries the deletion of `site/data/osv_orphans.json` (see 4b) |
| `9500f73` | Page: KEV goal as "x of y resolved, z pending"; OSV source line only with the orphan row; build deletes a stale `osv_orphans.json`; `index.html` re-rendered from the committed Nov 8 data (4 lines change) |
| `89f8abb` | `kev_enrichment.py` writes `data/history/kev_cumulative.json`; `stability.py` reports overlap, non-overlapping windows and the union |
| `648608d` | Doc fixes: CLAUDE.md re-check bullet; evidence-review CNA-CPE line; handoff; brief-outline PHP2Shell, 37.9% and number drift |
| `22273fe` | Research scripts and outputs (M1–M4, S1, S3, S6), M5 and S2 notes |
| (this commit) | This report and the AI-log rows |

**Readings taken:**
- **M3 "no pre-triage CPE".** For CVEs without CPE before listing, a pre-triage CPE could only come after listing, so excluding them would drop most 2025 listings for no reason. I read the condition as already implied by "no CPE before listing".
- **"Rebuild with `--from-raw`".** The raw file exists, but it is the Nov 7 pull, while the committed data is the Nov 8 bot pull. Rebuilding from it would roll the page back a day and fail the KEV cross-check. So I rendered the template from the committed Nov 8 data in a scratch copy and diffed it against the live build: only the four intended lines changed. The next scheduled run (Mon Nov 9, 12:47 UTC) will render it again from fresh data.
- **The cumulative file lives in `data/history/`,** because the weekly workflow commits that folder, and I was not to touch the workflow.
- **S1 used the Nov 7 local CSV** (window Oct 8 – Nov 7), since the Nov 8 CSV is not committed.
- **S2 used the Nov 7 `osv_orphans.json`** (not re-run; the OSV exports are ~3 GB and the window moved by one day). Ten orphans were drawn with `random.seed(20261107)`.
- **LEV is evaluated on a 30-day grid** anchored at the evaluation date (recall) or at Nov 7 (stock), with all weights 1. That approximates CSWP 41, which anchors at the first score date. The stock grid mixes EPSS models v2022–v2026.

### 4b. What I got wrong along the way

- **A slow line in my S1 script.** `automated_mapping.py` first rebuilt a 150,000-entry vendor set for every affected entry. It ran past 10 minutes; I stopped it and fixed it, and the run then took 34 s.
- **Commit hygiene.** The `git rm` of `site/data/osv_orphans.json` was staged before a failed command and landed in the spec commit (`0a3afd2`), not the page commit. I left it, because history rewrites are off-limits.
- **FIRST API.** The API answers HTTP 422 ("listNoResults") when no requested CVE has a score that day. My recall script crashed on the first such date; it now treats 422 as "no score".
- **A pipeline limitation I would have repeated.** `kev_enrichment.py` takes the first "CPE Configuration" change-history event as the first CPE. For CVEs analysed before NVD's change history logged details (e.g. CVE-2010-3765, CVE-2009-0238), the original analysis is an "Initial Analysis" event with no details, so the rule dates their CPE to a 2026 re-analysis. In the 2025–26 KEV set this made 8 old CVEs look "without CPE before listing". The research scripts correct for it. `kev_enrichment.py` itself is **not** changed. It doesn't affect the current 10 of 23, but an old CVE entering KEV would be miscounted. **Proposed fix:** count a pre-listing "Initial Analysis" with empty details as CPE. Your call, since it changes page logic.
- **Chat claims this session tested:**
  - The CVE Record Format has `affected[].cpes`: confirmed (schema `product.cpes`); used by 10.8%.
  - The fkie-cad mirror carries `vulnStatus`: confirmed, with a version per change. One CVE (CVE-2026-76418) had no version before listing.
  - The 1-vs-7-day recount: confirmed, 10 of 23 and 8 of 14.
  - Contradicted: the implication in point 1 that SSVC is a better trigger. Its "active" value is set about an hour before the KEV event, and "poc" covers 21% of the stock.

### 4c. Still open

- Whether EPSS v5 under-scores unenriched CVEs. More urgent now: v5-era recall is 2 of 51, against 13 of 98 under v4.
- SSVC dating before Jun 16, 2026: NVD's change history has no SSVC events before then. Dating it would need cisagov/vulnrichment git history.
- The SSVC monthly flow is approximate (timestamp = latest evaluation).
- Exact CSWP 41 LEV with daily scores. The approximation's recall is 17 vs 15 for EPSS alone.
- The `kev_enrichment.py` legacy-analysis fix (4b).
- Commercial scanners (Tenable, Qualys, Rapid7) in the harm chain. One Tenable plugin was seen in the sample.
- Displacement cost of re-queues (point 17), BOD 22-01 scope (point 12), and the argument-level points 13, 15 and 16.
- The live request-channel test is Will's to do: email nvd@nist.gov asking to schedule CVE-2026-59774 (Gitea; Not Scheduled; EPSS 0.28 on Nov 7), log the send time, then watch its NVD change history. That gives the first data point for metric 4.
- A second non-overlapping weekly window arrives around Dec 7, 2026.

## 5. S2 detail: ten random orphans (Nov 7 window), checked Nov 8

| CVE | Product | Public detection |
|---|---|---|
| CVE-2026-94676 | Tainacan (WordPress plugin) | WPScan entry |
| CVE-2026-16437 | Mitsubishi Electric GENESIS | none |
| CVE-2026-61708 | SOCFortress CoPilot | none |
| CVE-2026-101783 | Oracle MySQL Router | Tenable plugin 374531 (a FreeBSD package check) |
| CVE-2026-109339 | SurrealDB (Rust crate) | none (only an unreviewed GHSA, no package) |
| CVE-2026-118690 | signalk-server (npm) | none (only an unreviewed GHSA, no package) |
| CVE-2026-11376 | IBM MQ | none |
| CVE-2026-112014 | NetEase Youdao LobsterAI | none |
| CVE-2026-104745 | Customer Email Verification for WooCommerce (WP) | WPScan entry |
| CVE-2026-93865 | WatchGuard Fireware OS | none |

How these were checked:
- Tenable's `/cve/<id>/plugins` tab.
- GitHub's advisory API (`cve_id=`, reviewed and unreviewed).
- WPScan, for the two WordPress plugins.

**Verdict on the harm chain.** For 7 of 10 orphans no public scanner detection exists. For those, the only standard machine-matchable route would be NVD CPE, which Grype uses for unknown software and Trivy never uses. WordPress plugins are covered by WPScan's own database, so missing CPE matters less for them. The chain "no CPE → scanners miss it" holds for appliances and enterprise products, not for everything. Say "for vendor products without package advisories".

## 6. AI collaboration log

Two new rows, dated Nov 7–8, at the end of *Entries from Claude Code* in `docs/ai-collaboration-log.md`:

1. The red-team critique (claude.ai chat).
2. This overnight session.

## 7. Will's decisions and follow-up (Nov 8)

Will answered §2 in two rounds; Claude checked each answer against the data and sources and pushed back where it didn't hold. The settled versions are in `docs/brief-outline.md` and `CLAUDE.md` ("Decided Nov 8").

| § | Decision | Changed in review |
|---|---|---|
| 2a | Reject the 25%-recall stopping rule; EPSS's job is the non-KEV stock. Backstop at **EPSS ≥ 0.05** (0.10 shown beside it). Metric 5 hit rate is the test | The 95 / 105 "expected" figures are EPSS's own summed probabilities, labelled as such. "~1 in 11 future KEVs" was the 2025–26 mix; under v5 it is 2 of 51 at 0.10, 4 of 51 at 0.05. **"KEV misses 22–39%" (attributed to CSWP 41) dropped:** not in CSWP 41 or our sources; replaced by CSWP 41's own figures (KEV 1,228 entries, Dec 2024; ~1,006 of 66,125 likely exploited; several hundred LEV ≈ 1.0 not in KEV) and VulnCheck 884 vs 245 |
| 2b | "The backlog began Feb 2024. Readiness was about half before the April triage and about half after; the triage turned a backlog into standing policy." | Not "April locked it in": Not Scheduled was already 28–50% of the Nov 2024 – Feb 2026 cohorts, and status definitions changed Apr 15. Readiness was measured only from Oct 2025 |
| 2c | "Half parked, half queued" | The 5 Not Scheduled were moved there 1–2 days after publication (fkie mirror); they got CPE as the triage is designed, not as a correction |
| 2d | S1 becomes NIST Recommendation 1A; CISA keeps the structured-data ask for the rest | **Measured the deduplicated union: 3,849 of 13,207 (29.1%), overlap 427** (`automated_mapping.py` re-run, counts reproduced). "Unvalidated CNA-supplied cpes"; "provisional, product-level CPE without version ranges"; "no per-CVE analyst time, plus a QA sample" |
| 2e | Cohort maturation bar replaces the status figure; readiness becomes metric 1; status change log becomes a reporting rule | Aug–Oct 2026 cohorts are at 26–34% CPE (22.3% is the rolling window). "Plateau", not "abandonment" |
| #9 | Scanner claim scoped to vendor products without package advisories | 2 of the 7 "none" are npm and Rust packages with only unreviewed GitHub advisories, so package scanners miss them too. Checked in three sources only |
| #12 | PHP2Shell as a contrast case | **Corrected Will's date:** exploitation was first reported Oct 24–25, not Oct 21 (Oct 21 is publication and CPE). Median 6 days is publication to listing |
| #13 | Two-force why-now, 2–3 sentences, GTIG and RAND first | Dropped "59,000 a year", "N-days in minutes", AIxCC as offense, "CYA" |
| #15 | Polley as analogy (RGSD-A1954-1) | — |
| #16 | CJS report language; Thompson–Lofgren GAO request (June 6, 2025) | Dropped "bipartisan May 2024 letter" (not found; the 2025 letter is from two Democratic ranking members) and "2027 operational roadmap" (no source) |
| #17 | v4 → v5 drop reported, feature loss an open hypothesis | The 12 unscored v5 CVEs were each one day old at listing: timing, not lost features. Scored recall 2 of 39 vs 13 of 88 |

**`kev_enrichment.py` legacy fix applied (approved by Will).** `is_cpe_event()` now counts an "Initial Analysis" event with no details as the first CPE. No year cutoff: the empty-details condition already identifies these CVEs. Checked against the cached change history of the 180 research cases: it flips exactly the 8 known legacy CVEs (CVE-2007-0671 … CVE-2014-6278), all listed before the current window, so the page's 10 of 23 is unchanged. Takes effect at the next weekly pull.

**Site section 4 updated (Will approved):** the five metrics in the Nov 8 set, and the NIST row adds CNA CPE pass-through, provisional dictionary matches, the status change log and nvd@nist.gov request counts. `index.html` was re-rendered for section 4 only, using the committed Nov 8 values (10 of 23; 29 of 29 resolved, 1 pending); the local CSV is from Nov 7, so a full build was not run. **Not done:** the brief draft itself; sections 1–3 still describe the rule at EPSS 10% (the measured re-queue table and simulator default).
