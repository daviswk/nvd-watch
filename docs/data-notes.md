# Data notes

Running notes on each pull: what the numbers say, how they were checked, and what they cannot say. Every figure here is reproducible from `data/processed/` plus the script named.

Sections are appended in order, so later sections can revise earlier ones. When that happens the earlier passage is marked **Superseded** in place, with a pointer, and this list is updated. **Read this list first; it is the current state.**

## Current conclusions (as of Nov 9, 2026)

- **Weekly pulls (from Nov 8):** `.github/workflows/rebuild.yml` re-pulls a rolling 30-day window every Monday and rebuilds the page, so the live figures move weekly. Cite a figure with its pull date and take every figure in one document from the same `data/history/YYYY-MM-DD/` folder. The Nov 7 figures below are the analysed pull; Nov 8 and Nov 9 values are given beside them where they differ. See *Pull 2 — Nov 8, 2026* and *Pull 3 — Nov 9, 2026*.
- **Audit (Nov 9):** the pipeline was recomputed end to end and the figures hold; see *Pull 3*. Two corrections came out of it. "No EPSS score yet" counted Rejected records (Nov 7: 787 printed, 659 of them Rejected, 128 real); the count now covers non-rejected CVEs without CPE and outside KEV, from the next pull. The Nov 8 "reproduction" of the re-check load ran on the same feed snapshot (timestamp Nov 7), so it checks the code, not a second sample.
- **Coverage:** 22.6% of non-rejected CVEs published Oct 8 – Nov 7 have CPE (3,863 of 17,070); 77.4% do not. Nov 8 pull (Oct 9 – Nov 8): 22.3% (3,795 of 17,035). Nov 9 pull (Oct 10 – Nov 9): 22.1% (3,745 of 16,919). Coverage matures: the Apr 15 – Jun 15 cohort is at 57.3% five months on, with 37.9% still Not Scheduled. See *Pull 1* and *Verification pulls*.
- **"When defenders need it"** = **before** the KEV listing, compared by timestamp. Score **readiness** (CPE before listing) separately from **NIST's goal** (CPE within one business day of the later of listing and NVD publication). See *KEV cohort extended…* (last section), which replaces the day-based definition in *KEV CVEs: was CPE there…*.
- **KEV result:** of the 35 CVEs added to KEV in the window (any publication year), 34 met the goal (1 pending), every first CPE record from NIST. Readiness: of 23 public before listing and not enriched pre-triage (35 − 6 listed on or before NVD publication − 6 with pre-triage CPE), 10 had CPE beforehand; several got it within minutes of NVD logging the listing. Claim the defender's view (no CPE visible until CISA listed them), not that NIST starts work at the listing. See *Fourth red-team round*. Nov 8 pull: 30 CVEs, 29 met the goal (1 pending), readiness still 10 of 23 (30 − 6 − 1); the 5 that left were all listed Oct 8. Nov 9 pull: the same 30 CVEs and the same figures. Three pulls whose windows share 30 of 31 days: no independent check of stability yet (`scripts/stability.py`). From Nov 9, a listed CVE with no CPE counts as a miss once more than one business day has passed; before, it stayed pending.
- **Superseded by the next bullet (Nov 7); kept for the record, do not cite.** **Re-check volume:** Floodline day-30 rate × our volume = 16–46 a month (simulator default 16), $8K–$66K a year (default $8K–$23K). **Rough, biased both ways, not a lower bound:** 7 of the 10 CVEs at EPSS ≥ 0.10 are in KEV, whose listing tends to raise EPSS (pushes it down); of the 3 outside KEV, 2 lack CPE; later crossings, the older stock and SSVC triggers are uncounted (push it up). The OIG's ~$400K a year is a scale comparison, not spare money. See the last section, which revises *Re-check volume from CVE Floodline*.
- **Re-check load, measured (Nov 7):** two parts. One-time: 303 stock CVEs (Not Scheduled, Awaiting or Received; no CPE; not KEV) already at EPSS ≥ 0.10. Monthly: ~11–28 re-queues at 0.10, mostly CVEs over 90 days old. The stock is 76,217 CVEs. Day-90 cohort (Jun 15 – Jul 14): 0.442% ever ≥ 0.10 vs 0.263% by day 30, but only 7 of 8,376 need a re-queue. The 16–46 total is in range, but its composition was wrong (new CVEs, mostly with CPE). Source: `docs/research/notes/open_items_recheck_volume.md`, `scripts/research/recheck_volume.py`. On the page since Nov 7 (`data/processed/recheck_measured.json`). **Since Nov 8 the page's rule uses EPSS ≥ 0.05:** 443 once, then 11–36 a month (34, 36, 11, 32 in the same four windows, change history included; `scripts/research/recheck_flow_corrected.py`), simulator default 36, the highest month; the 0.10 figures are shown beside it.
- **Orphaned CVEs (Nov 7):** of 13,207 CVEs without CPE, 72.1% (9,528) are in no package advisory OSV aggregates; 8.8% are in a language-package advisory and 19.0% only in distro advisories (including all 901 Linux kernel CVEs). Not Scheduled: 85.2% orphaned. Orphans are WordPress components and small projects as much as enterprise vendors (Oracle, IBM, HPE, Juniper); not "mostly appliances". One young window; see *Orphaned CVEs*. On the page as a row under the section 1 status table, plus a paragraph; `build_site.py` shows both only while `osv_orphans.json` covers the same window as `summary.json`, so a new pull drops them until the script is re-run.
- **Legacy share (Nov 7):** 30 of 285 KEV additions in 2026 (10.5%) were published 4+ years before listing; 9.6 / 11.3 / 14.3% in 2023–25, no trend (`kev_lag.json`, on the page in section 2). CVE age, not code age. The re-check stock is not "legacy" (most of it is from 2026). A CPE-revision proxy (20 of 34 KEV CVEs revised after first CPE) is too blunt to show. See *Legacy share and a CPE-revision proxy*.
- **CVSS shares (Nov 7):** use the non-rejected denominator: 94.5% of new CVEs carry some CVSS, 77.8% from the CNA that published the record, most of the rest from CISA-ADP (Vulnrichment), 2.8% from NIST. "CNAs score 94.5%" was wrong on the page until Nov 7. See *CVSS shares*.
- **EPSS model:** v5 (`v2026.06.15`) since Jun 15, 2026, not v4.
- **Vendor split:** Microsoft 92.4% with CPE; Linux, Mozilla and Red Hat 0%, in three different statuses. The cause is not observable from outside. See *CPE coverage by vendor*.
- **Retired figures:** 250–470 re-queues a month, $270K–$510K a year, $7K–$58K a year, 21.7% non-KEV coverage, "lower bound".

## Pull 1 — Nov 7, 2026 (30 days)

**Command:** `python scripts/fetch_sample.py --days 30` with an NVD API key.
**Window:** CVEs published 2026-10-08 19:18 UTC to 2026-11-07 19:18 UTC.
**Outputs:** `data/processed/cves_sample.csv` (one row per CVE), `data/processed/summary.json`, raw records in `data/raw/nvd_sample.json` (63 MB, git-ignored).

### Headline figures

| Measure | Value | Note |
|---|---|---|
| CVEs published in window | 17,729 | 659 are Rejected |
| Share with NVD CPE (all) | 21.8% | `has_cpe` = `configurations` present |
| Share with NVD CPE (excluding Rejected) | 22.6% | 3,863 of 17,070 |
| Share with NIST-sourced CVSS | 2.7% | source `nvd@nist.gov`; Rejected in the denominator. **Use 2.8% of non-rejected** |
| Share with any CVSS | 91.0% | CNA, CISA-ADP, or NIST; **Rejected in the denominator. Use 94.5% of non-rejected** (see *CVSS shares*, last section) |
| Share with a CWE | 90.5% | |
| In CISA KEV | 18 | 17 of 18 have CPE |
| CPE share, not in KEV | 22.6% | 3,846 of 17,052, Rejected excluded (an earlier draft of this table showed 21.7%, with Rejected in the denominator; `summary.json` was already right) |

### CPE by status (excluding Rejected)

| API status | Display label | CVEs | Share of window | With CPE |
|---|---|---|---|---|
| Deferred | Not Scheduled | 6,967 | 40.8% | 0.0% |
| Awaiting Analysis | Awaiting Enrichment | 4,187 | 24.5% | 0.0% |
| Analyzed | Enriched | 3,170 | 18.6% | 100% |
| Received | Received | 1,346 | 7.9% | 0.0% |
| Undergoing Analysis | Undergoing Enrichment | 709 | 4.2% | 0.3% |
| Modified | Modified After Enrichment | 691 | 4.0% | 100% |

CPE exists only on Analyzed and Modified records, so "share with CPE" and "share enriched" are the same number in this data.

### Time to enrichment (crude)

For the 3,170 Analyzed CVEs, `lastModified − published`: median 7.2 days, 90th percentile 16.0 days, max 27 days. Two caveats: `lastModified` can reflect edits after enrichment, and the window right-censors the slow cases (CVEs still Awaiting are not counted). A proper measure needs the NVD change history per CVE.

### EPSS

787 of 17,729 CVEs had no EPSS score or a score of exactly 0 (FIRST scores new CVEs with a lag). (**Corrected Nov 9:** 659 of the 787 are Rejected records, which never get a score. The count that fits "no score yet" is 128: non-rejected CVEs, all published Nov 7, all without CPE and outside KEV. See *Pull 3*.) Among CVEs without CPE and not in KEV: 288 had EPSS ≥ 0.01, 7 had ≥ 0.05, and 2 had ≥ 0.10 (CVE-2026-59774, Deferred, 0.283; CVE-2026-77690, Awaiting Analysis, 0.156). None had ≥ 0.50.

**Consequence for the re-check rule estimate.** The 250–470 CVEs/month figure cannot be reproduced from newly published CVEs. New CVEs rarely carry high EPSS; the trigger fires later, on the stock of older unenriched CVEs as scores rise. A monthly rate needs a backlog-based method: pull Deferred and Awaiting CVEs over a longer period and count threshold crossings per month. **Superseded:** the rate now comes from CVE Floodline's day-30 crossing data (see *Re-check volume from CVE Floodline* and its revision in the last section). A backlog-based count is still an optional refinement.

### CNA product data (`affected` field)

The NVD API now returns the CNA's `affected` block (vendor, product, versions as free text). Among the 17,070 non-rejected CVEs:

| Measure | Value |
|---|---|
| CNA names a real vendor and product | 16,041 (94.0%) |
| CNA names a real version as well | 15,667 (91.8%) |
| Real CNA product data but no NVD CPE | 12,178 (71.3%) |
| NVD CPE but no real CNA product data | 0 |

"Real" means the vendor and product strings are not placeholders such as `n/a` or `unknown`. Deferred CVEs have the lowest rate (87.5%).

**Consequence for framing.** Most CVEs are not "without product data." They lack *standardized, scanner-matchable* product identifiers (CPE). The page and brief must say CPE, and the CISA/CNA recommendation should be about structured, machine-readable product data rather than product data as such.

### Weekly volume

Published per week in the window: 1,124 (partial week), 5,499, 4,211, 3,645, 3,250 (partial). That is about 17,700 per 30 days including Rejected. Google GTIG's 10,740 is a single month (August 2026, a record at the time), not a monthly average. Our NVD count for August is 12,719, and volume has kept rising since, so most of the gap is timing. See the monthly series under "Verification pulls" below.

### KEV rows worth a look

- CVE-2026-118527 has a KEV `dateAdded` (Oct 30) four days before its NVD publish date (Nov 3): KEV listed it before the NVD record existed.
- CVE-2026-19868 was added to KEV on Nov 6 and is still Undergoing Analysis, the only KEV CVE in the window without CPE.

## Verification pulls — Nov 7, 2026

Run for `docs/source-verification.md`. Scripts are not in the repo: a scratch script pulled the CISA KEV JSON (catalog 2026.11.06, 1,769 entries) and the NVD API (`hasKev`; publish-date windows; `cvehistory` for PHP2Shell).

**KEV additions by `dateAdded` year:** 2021: 311 · 2022: 555 · 2023: 187 · 2024: 186 · **2025: 245** · 2026 to Nov 6: 285. This confirms CISA's 245 for 2025.

**Median CVE-to-KEV lag, calendar days** (KEV `dateAdded` − NVD `published` date), by KEV-added year:

| Cohort rule | 2023 | 2024 | 2025 | 2026 YTD |
|---|---|---|---|---|
| All KEV additions | 12 | 21.5 | 26 | 14 |
| CVE published 2022+ (Barracuda's rule) | 4 | 7 | 10 | 9 |
| Same as above, cut at Jul 24, 2026 | 4 | 7 | 10 | 11 |
| CVE published same or prior year | 4 | 6 | 7 | 7 |
| CVSS ≥ 7, all (Rapid7's subset) | 8.5 | 22 | 26 | 12 |
| *Barracuda, as published* | *6* | *9* | *12* | *14* |

To Jul 24 under Barracuda's rule: 654 newer CVEs (Barracuda: 608) and 133 pre-2022 (Barracuda: 132); overall median 8 days (Barracuda: 9); 50% listed within a week (Barracuda: 48%). The rise through 2025 reproduces under every rule. The levels run 2–3 days lower, possibly because Barracuda's data ends earlier or uses CVE.org publish dates (untested). 2026 has fallen back since July. Sixty-six CVEs have NVD publish dates after their KEV date (47 by more than a day). Those are kept as negative lags.

**Volerion window (published Apr 15–Jun 15, 2026), status as of today:** 13,551 published, 13,426 non-rejected (Volerion: 13,441). 7,694 have CPE (57.3%). 2,984 have NIST-sourced CVSS (Volerion at mid-June: 2,645). Status: Analyzed 6,030 · Deferred 5,087 · Modified 1,556 · Awaiting Analysis 640 · Undergoing 113. Coverage keeps rising for months after publication, so our 30-day 22.6% is not comparable with window figures taken later. The page should say so. Five months on, 5,087 (37.9%) of this cohort are still Not Scheduled, against 640 (4.8%) Awaiting Analysis. This is one snapshot, with no June status to compare, but it fits the reading that Awaiting CVEs get worked through and Not Scheduled ones stay put.

**NVD CVEs by publish month, 2026** (`totalResults`, including Rejected): Jan 5,143 · Feb 4,808 · Mar 6,304 · Apr 5,885 · May 6,985 · Jun 8,001 · Jul 9,919 · Aug 12,719 · Sep 15,074 · Oct 17,481.

**PHP2Shell (CVE-2026-109618, -109619):** NVD published both Oct 21, 14:17 UTC. NIST's Initial Analysis added CPE configurations at 17:01 UTC the same day. KEV `dateAdded` is Oct 26, and NVD logged the KEV update Oct 27, 01:00 UTC. CPE preceded the KEV listing by five days.

## Status name mapping (for metric 5)

From https://nvd.nist.gov/vuln/vulnerability-status, "Updated Apr 14, 2026":

| NVD display status | NVD API value |
|---|---|
| Received | Received |
| Awaiting Enrichment | Awaiting Analysis |
| Undergoing Enrichment | Undergoing Analysis |
| Enriched | Analyzed |
| Modified After Enrichment | Modified |
| Not Scheduled | Deferred |
| Rejected | Rejected |

NIST's "Not Scheduled" definition: the CVE is not currently scheduled for enrichment, either out of declared scope or not prioritized for resource reasons; requests may be made to schedule it.

## Re-check volume from CVE Floodline — Nov 7, 2026

**Why:** our 30-day pull shows current EPSS scores, which are low on fresh CVEs. CVE Floodline (RogoLabs, Apache-2.0) re-scores each day's CVE cohort against the dated EPSS archive at day 0, 7, 30, and 90, so it measures how often an EPSS trigger fires as the score matures. We reuse its published `data/floodline.json` (fetched by `fetch_floodline()` in `scripts/fetch_sample.py`) rather than rebuilding the pipeline.

**What the file says (generated 2026-11-07, cohorts Aug 7 to Nov 4, 2026, EPSS model v2026.06.15):**

| Horizon | CVEs with a score at that horizon | Crossed EPSS > 10% | Share | Crossed > 50% |
|---|---|---|---|---|
| Day 0 | 44,079 | 4 | 0.009% | 1 |
| Day 7 | 42,359 | 12 | 0.028% | 4 |
| Day 30 | 28,618 | 27 | 0.094% | 8 |
| Day 90 | 350 (3 cohorts) | 0 | not yet observable | 0 |

Same-cohort view (the 28,618 CVEs old enough for a day-30 score): 1 crossed 10% on day 0, 6 by day 7, 27 by day 30. Floodline's README quotes an earlier window at 0.3 → 1.3 → 2.7 crossings per 1,000 (0.27% at day 30). Mean volume in the window: 483 net CVEs/day.

**Old estimate (retired):** 250–470 CVEs/month, 5–9% of NIST's ~5,000/month ceiling, ~$270K–$510K/yr. Traced to reading Floodline's "2.7 per 1,000 at day 30" as 2.7%: 2.7% × ~15,000 CVEs/month ≈ 400. Not reproducible from any data.

**New estimate:** share crossing 10% by day 30 (0.094% now; 0.27% in the earlier window) × our 17,070 non-rejected CVEs per 30 days = 16 to 46 re-queues a month, 0.3% to 0.9% of capacity. At 20/45/60 analyst-minutes and $120/h: $8K to $66K a year (16 × 12 × 20 min ≈ $7.7K; 46 × 12 × 60 min ≈ $66K). Compare with the OIG's ~$400K a year for scale only: NIST already stopped that re-scoring in April 2026, so it is not spare money. An earlier $7K–$58K range is retired: it does not follow from 16–46 a month and matches about 15,000 CVEs a month rather than 17,070. The page's simulator defaults to the current-data figure and labels it; the pipeline recomputes it weekly.

**What it does not count:** (**Superseded:** this paragraph first called the estimate a lower bound. It is not: Floodline's rate also counts crossings by CVEs that already have CPE, and 8 of the 10 CVEs at EPSS ≥ 0.10 in our window did, 7 of them through KEV. The bias runs both ways; see *Fourth red-team round* for how to state it.) Crossings between day 30 and day 90 (Floodline's day-90 cells are mostly null for now), crossings from the older Not Scheduled stock outside Floodline's 90-day window, and the SSVC / third-party-evidence triggers. A lower threshold changes the picture: in our own pull, 288 CVEs without CPE scored ≥ 0.01 on current scores, versus 7 at ≥ 0.05 and 2 at ≥ 0.10.

**Reuse and license:** Floodline's code is Apache-2.0; its data derives from the FIRST EPSS archive (empiricalsec/epss_scores), CISA KEV (public domain), and cvelistV5 (CVE Program terms). We read one summary file and attribute it on the page; no code was copied. Field names were checked against `pipeline/floodline/compute.py`: `maturation[h].thresholds["10"]` counts scores strictly above 0.10 on the dated file at day+h.

## KEV CVEs: was CPE there when exploitation was confirmed? — Nov 7, 2026

**Why:** red-team objections #1 and #21 ("where's the harm?"; "'when defenders need it' is undefined"). We define *when defenders need it* as **the KEV listing date**, the day CISA confirms exploitation. (**Superseded:** the definition is now *before* the listing, compared by timestamp, and scored separately from NIST's one-business-day goal. See the last section. The counts below are still correct for the 18-CVE sample; the conclusions are revised there.) The CSV's `last_modified` cannot answer this, so `scripts/kev_enrichment.py` asks the NVD CVE Change History API (`/rest/json/cvehistory/2.0?cveId=`) for each KEV CVE in the 30-day sample and takes the first event that added a `CPE Configuration`. Output: `data/processed/kev_enrichment.json` (copied to `site/data/`). Run it after `fetch_sample.py` and before `build_site.py`; the build exits if it is missing or covers a different KEV count.

**Result (18 KEV CVEs published Oct 8 – Nov 7, 2026):**

| | Count |
|---|---|
| Have CPE now | 17 |
| CPE by the KEV listing day (3 of them before listing: PHP2Shell ×2, CVE-2026-97229). *Day-based; mixes readiness with same-day enrichment. Replaced by the timestamp measure in the last section: 3 of 12 public before listing* | 7 |
| CPE within one business day of listing (metric 3, NIST's goal) | 17 of 17 enriched |
| First CPE change made by `nvd@nist.gov` | 17 |
| Longest calendar gap | 4 days (CVE-2026-118527: listed in KEV Oct 30, *before* NVD published it Nov 3; CPE the day NVD published) |
| No CPE yet | CVE-2026-19868, listed Nov 6, "Undergoing Analysis" on Nov 7 (still within the goal) |

**Rules:** the one-business-day clock starts at the later of KEV `dateAdded` and NVD publication, since NIST can't enrich an unpublished CVE. Weekdays only, no federal-holiday calendar. Dates are UTC days. Parser checked by hand against the raw history of CVE-2026-110447 (KEV event Fri Oct 23 22:00 UTC → NIST "Initial Analysis" with CPE Mon Oct 26 16:48 UTC).

**What it means:** (**Superseded in part.**) NIST meets its goal *after* listing; that still holds, now for all 35 KEV additions in the window. But "the claim rests on CVEs that don't reach KEV" understated it. Most KEV CVEs that were public before listing lacked CPE until the listing (13 of 23), so the gap also covers the wait *before* KEV. The brief should still lead with this result (red-team #5).

**Limits:** one 30-day window, 18 CVEs. CVEs published before the window but listed in it are not counted here. (**Resolved:** the last section covers all 35 KEV additions in the window, back to 2015.) VulnCheck's broader exploited list (free account and token needed) was not checked.

**At-risk example, not confirmed exploited:** CVE-2026-59774 (Gitea Org-mode INCLUDE file read, chainable to command execution per the CNA), published Oct 14, Not Scheduled, no CPE, CNA `affected` names Gitea < 1.27.1, EPSS 0.283 on Nov 7, not in KEV. Exploitation sources other than KEV were not checked. Runner-up: CVE-2026-77690 (ManageEngine Key Manager Plus command injection, Awaiting Enrichment, EPSS 0.156).

## CPE coverage by vendor — Nov 7, 2026 (verified)

**Why:** a side finding from the 3D prototype round (see the AI log) said Linux, Mozilla and Red Hat CVEs in the window had no CPE against 92% for Microsoft. A second red-team suggested it as a headline. Recomputed from `data/raw/nvd_sample.json`: vendor = first vendor named in the CNA `affected` block; CPE = the record has `configurations`; Rejected excluded.

| Vendor | CVEs | With CPE | NVD status (API value) |
|---|---|---|---|
| Microsoft | 1,475 | 1,363 (92.4%) | Analyzed 1,361 · Awaiting Analysis 82 · Undergoing Analysis 30 · Modified 2 |
| Linux | 901 | 0 | **Received 900** · Awaiting Analysis 1 |
| Mozilla | 268 | 0 | Deferred (Not Scheduled) 257 · Awaiting Analysis 11 |
| Red Hat | 203 | 0 | Awaiting Analysis 202 · Undergoing Analysis 1 |

**What it shows:** three different conditions, not one. Linux kernel CVEs (all from the kernel CNA) are spread across 13 publication days from Oct 9 to Nov 7, yet 900 are still "Received", so NIST has not triaged them. Mozilla's were triaged and set aside (published in batches, mostly Oct 13 and Oct 27). Red Hat's (`secalert@redhat.com`) are queued.

**Two more checks:** the 900 Linux records are 900 of the 1,346 Received CVEs in our window (66.9%), not of the whole NVD. Of the 257 Not Scheduled Mozilla CVEs, 246 name Firefox and 251 name Thunderbird in the CNA `affected` block (a CVE can name both). Why kernel CVEs sit in Received is not documented in anything we have read. A claim that it reflects a NIST Linux-tooling pilot was unsourced and is not used.

**What it does not show:** why. Firefox and Red Hat Enterprise Linux are widely used by the federal government, so "the federal-software tier covers proprietary software and skips open source" does not fit. NIST does not publish tier assignments, so the cause can't be observed from outside. Report it as status by vendor, and use it as support for the "publish tier assignments" recommendation. Not on the page yet.

**Also corrected (from the same review):** 12,178 (71.3%) is the CVEs where the CNA names a product *and* there is no CPE. All CVEs without CPE: 13,207 of 17,070 (77.4%). The 57.3% for the Apr 15 – Jun 15 cohort (section above) is our recount as of Nov 7, not Volerion's figure (≈50%).

## KEV cohort extended to every listing in the window; readiness vs goal — Nov 7, 2026

**Why:** a third red-team round raised two points. The sample cohort (KEV CVEs *published* in the window) skips older CVEs that reach KEV later, some of which NIST may have parked. And "by the listing day" mixed two different tests. `scripts/kev_enrichment.py` now also covers every CVE CISA *added* to KEV between Oct 8 and Nov 7 (from the KEV feed, any publication year). It compares the CPE event with NVD's own KEV-update event **by timestamp**, not by day.

**Two benchmarks, kept separate:**
- **Readiness (when defenders need it = before the listing):** among CVEs that were public before CISA listed them and had not been enriched before the April 15, 2026 triage, did CPE exist before the listing?
- **Goal (metric 3):** CPE within one business day of the later of listing and NVD publication.

| | Sample (published in window) | All KEV additions in window |
|---|---|---|
| CVEs | 18 | 35 (17 published earlier, oldest 2015) |
| Met the one-business-day goal | 17 (1 pending, listed Nov 6) | 34 (same pending CVE) |
| First CPE record from NIST | 17 of 17 | 34 of 34 |
| Public before listing, not enriched before the triage | 12 | 23 |
| ... CPE before the listing | 3 | 10 |
| ... CPE only after the listing | 9 | 13 |
| ... of those, CPE within 2 hours of NVD's KEV event | 3 | 4 |
| Longest public-without-CPE wait until listing | 15 days | 90 days (CVE-2026-41709, published Jul 30, listed Oct 28, CPE Oct 29) |

Six of the older CVEs had CPE from before the triage (2015–2024), so they say nothing about the current rules and are excluded from readiness.

**Reading:** NIST meets its goal once a CVE is listed, including older ones. Before the listing, 13 of 23 lacked CPE, and several got it within minutes of the KEV event: CVE-2026-102764 (10 min), CVE-2026-114625 (29 min), CVE-2026-21589 (40 min, public 10 days), CVE-2026-111357 (89 min, public 15 days). That is direct evidence that the KEV listing is what triggers enrichment for these CVEs. (**Superseded:** too strong. The timestamps show CPE appearing right after NVD logged the listing, not that NIST starts work then; see *Fourth red-team round*.)

**Pushback on the red-team's framing:** "only 3 of 18 had CPE before listing" counts six CVEs that were published and listed on the same day (or listed before NVD published them), with no time to be enriched first. The fair denominator is the CVEs that were public before listing: 3 of 12 in the sample, 10 of 23 overall. Status before listing is not in the change history, so we cannot say which of the 13 were Not Scheduled rather than Awaiting.

**Re-check volume bias, both directions:** of the 10 CVEs in the window currently at EPSS >= 0.10, 8 already have CPE (7 in KEV). (**Superseded framing:** state it by KEV status, not as "8 of 10 covered"; see *Fourth red-team round*.) Floodline's rate counts all crossings, so 16–46 a month overstates re-queues of *new* CVEs, possibly by several times (n = 10, so the size is not reliable). It also leaves out crossings after day 30, the older Not Scheduled stock, and SSVC or third-party triggers. It is a rough estimate, not a lower bound.

## Fourth red-team round: how to state three results — Nov 7, 2026

No new data; these restate existing results so they can't be misread.

**High-EPSS CVEs, by KEV status.** Of the 10 non-rejected CVEs in the window with EPSS ≥ 0.10 on Nov 7: 7 are in KEV, all with CPE. 3 are not: CVE-2026-111214 (Analyzed, has CPE, 0.108), CVE-2026-77690 (Awaiting, no CPE, 0.156), CVE-2026-59774 (Not Scheduled, no CPE, 0.283). The EPSS scores were read after the KEV listings, and EPSS tends to rise after a listing (Nucleus Security; see `source-verification.md`). So "8 of 10 already have CPE" is not evidence that NIST's triage catches high-EPSS CVEs: for 7 of them, the listing drove both the CPE and the score. Report counts, not "two-thirds" (n = 3). A claim that KEV is an input feature of the EPSS model (attributed to Jacobs et al. 2023) has not been verified in our sources and is not used.

**Readiness arithmetic.** 35 KEV additions − 6 listed on or before the day NVD published them (CVE-2026-104935, -96951, -76519, -0322, -19868 the same day; -118527 listed four days before publication) = 29 public before listing − 6 with CPE from before the Apr 15, 2026 triage = 23. The page now prints both exclusions.

**What the timestamps show.** NVD's "CVE CISA KEV Update" events land on the hour (19:00, 22:00, 23:00 UTC), so they record NVD's KEV sync, not when CISA published. CPE following within 10–89 minutes is consistent with NIST starting at the listing, but also with NIST releasing prepared work or acting on earlier notice from CISA. We can't tell these apart. The claim we can make is the defender's view: NVD users did not see CPE for these 13 CVEs until CISA listed them.

**Tier publishing and OPSEC.** Per-CVE "federal software" tags could reveal agency inventories. The fallback is quarterly counts by tier, which is enough for metrics 1 and 2. A single combined "federal or EO 14028" flag does not fully solve it: a flagged CVE in software outside the public EO 14028 categories still implies federal use.

## Orphaned CVEs: no CPE and no package advisory — Nov 7, 2026

**Question:** the objection "CPE is a dying standard; purl and OSV advisories will cover it." Of the CVEs in Pull 1 without CPE, how many does no package advisory cover either?

**Script:** `scripts/research/osv_orphans.py OSV_DIR` → `data/processed/osv_orphans.json` (per-CVE ecosystems in `data/raw/osv_orphans_per_cve.json`, git-ignored). Input: all 45 OSV ecosystem exports downloaded Nov 7 (about 3.1 GB; the GIT export is skipped because its ranges are commits, not package names). A CVE counts as covered if any non-withdrawn OSV advisory that names a package ecosystem lists it as its ID, alias, upstream or related.

**Method note:** a first version queried `api.osv.dev/v1/vulns/<CVE>` per CVE. It found GHSA aliases for 273 of 277 PyPI CVEs, but linked only 784 of the 3,351 window CVEs that Debian's export covers, so it called most Linux kernel CVEs orphans. Replaced by the bulk exports, which recover all 3,351 Debian, 277 PyPI and 155 Go CVEs.

| Non-rejected CVEs, Oct 8 – Nov 7 | n | Language-package advisory | Distro / kernel / container only | **No package advisory (orphaned)** |
|---|---|---|---|---|
| Without CPE | 13,207 | 1,167 (8.8%) | 2,512 (19.0%) | **9,528 (72.1%)** |
| · Not Scheduled (Deferred) | 6,967 | 394 | 640 | **5,933 (85.2%)** |
| · Awaiting Enrichment | 4,187 | 579 | 832 | 2,776 (66.3%) |
| · Received | 1,346 | 38 | 961 | 347 (25.8%) |
| · Undergoing Analysis | 707 | 156 | 79 | 472 (66.8%) |
| With CPE | 3,863 | 233 | 925 | 2,705 (70.0%) |

**What it shows**
- **Package advisories cover about 28% of the CVEs without CPE; 72% have neither.** Most of the covered ones are in Linux-distribution advisories, not language ecosystems (8.8%). So "OSV will cover it" holds for open-source packages and the kernel, not for the gap as a whole. The gap narrows from 13,207 to 9,528 CVEs; it does not go away.
- **The vendor split is mostly absorbed by distros.** All 901 Linux kernel CVEs and 264 of 268 Mozilla CVEs (0% CPE in *CPE coverage by vendor*) are in distro advisories. A Linux-package scanner sees them; an NVD-CPE scanner does not.
- **Not Scheduled is the worst-covered status (85.2% orphaned).** Received is mostly kernel CVEs, so mostly covered.
- **Who the orphans are (by assigning CNA, top 15):** VulnCheck 1,819; Patchstack 903, Wordfence 676 and WPScan 574 (WordPress plugins and themes, 2,153 together, 23%); VulDB 725; GitHub 705 (repository advisories not yet in GitHub's reviewed database: two sampled GHSA IDs return 404 from both OSV and `api.github.com/advisories`); Oracle 538; IBM 308; Apache 214; MITRE 204; HPE 174; Juniper 169; JetBrains 96; Dell (EMC) 91; Red Hat 89. Enterprise and appliance vendors are a real block (Oracle, IBM, HPE, Juniper, Dell, Cisco, Siemens, Tanium all appear) but **not the majority**: WordPress components and small open-source or PHP projects are larger. Do not write that the orphans are "mostly commercial appliances and industrial software."
- **Exploitation signal is thin in this window:** 1 orphan is in KEV, 2 at EPSS ≥ 0.10, 6 at ≥ 0.05, 250 at ≥ 0.01. As with the re-check volume, the risk sits in the older stock, not in one month of new CVEs.
- **Package coverage is not a CPE substitute even where CPE exists:** 70% of CVEs *with* CPE also have no package advisory. CPE and package advisories serve different software (commercial and appliance products vs. packaged open source).

**Checks:** spot-checked 10 orphans against the live OSV API (4 Gitea, 1 Zebra and 1 Eclipse ThreadX CVE carry GHSA aliases whose IDs OSV and GitHub's global database do not have; 4 WordPress plugin CVEs are 404 in OSV). The Debian, PyPI and Go sets above were built by a separate script over the same exports, so they test the code, not the method.

**Caveats:** OSV aggregates open advisories only; vendor bulletins and commercial scanner feeds are invisible here, so "orphaned" means "no open package advisory", not "no advisory anywhere". A 30-day window is young; package advisories (especially reviewed GHSA) arrive later, so the orphan share will fall as the window ages. Re-run against an older cohort before quoting it as a steady state. Scanner exposure by tool is still one analyst's rating (Lilting, see `source-verification.md` §6), not measured here.

## Legacy share and a CPE-revision proxy — Nov 7, 2026

**Legacy share (on the page, section 2; defined in Definitions).** `scripts/kev_lag.py` now also writes `legacy_by_year` to `kev_lag.json`: of the CVEs CISA added to KEV in each year (any publication year), the share NVD published four or more years (1,461 days) before `dateAdded`. Catalog 2026.11.06, 1,769 entries, none missing from NVD.

| Year added | KEV additions | Published 4+ years earlier | Share |
|---|---|---|---|
| 2023 | 187 | 18 | 9.6% |
| 2024 | 186 | 21 | 11.3% |
| 2025 | 245 | 35 | 14.3% |
| 2026 (to Nov 6) | 285 | 30 | 10.5% |

No trend; the page lists the years without a trend verb. **CVE age, not code age:** a CVE published this year can sit in code from 2014 (GitLab CVE-2026-110264 reaches back to version 7.0), so this understates how old exploited code is. Cross-check: the earlier recount (133 of 787 KEV additions from Jan 1, 2023 to Jul 24, 2026 published before 2022) reproduces exactly. Re-running `kev_lag.py` left the lag medians unchanged (same catalog).

**Not "legacy backlog."** The re-check stock (76,217 CVEs; 303 at EPSS ≥ 0.10) is not relabeled: about 45,000 of the 76,217 were published after Apr 15, 2026 (`open_items_recheck_volume.md`). 29,017 were published before Mar 1, 2026.

**CPE-revision proxy (not on the page; too blunt).** For the 34 KEV CVEs in `kev_enrichment.json` that have CPE, the NVD change history shows a later "CPE Configuration" event after the first one for **20**. Of those, 5 only *added* configurations (new affected products, e.g. downstream vendors), 15 include a Changed or Removed action, one of them a routine "CPE Deprecation Remap". Most later events are "Modified Analysis" after the CVE record itself changed. A revision is not an error, so this does not measure enrichment quality; it would need a diff-level review of what changed and why. Small n, KEV only (16 of the 20 were first enriched in 2026). Scratch script; input `kev_enrichment.json`, NVD CVE Change History API.

## CVSS shares: non-rejected denominator, and who scores — Nov 7, 2026

Pull 1's headline table gave 91.0% (any CVSS) and 2.7% (NIST) with the 659 Rejected records in the denominator; the page uses the non-rejected 17,070: **94.5% any, 2.8% NIST**. Rejected records carry no scores, so non-rejected is the right base; use it in the brief.

The page also said "CNAs already score 94.5%", which was wrong. "Any CVSS" counts every scoring source. Split by source (raw file, same window):

| Non-rejected CVEs (17,070) | CVEs | Share |
|---|---|---|
| Any CVSS | 16,133 | 94.5% |
| From the CNA that published the record (metric `source` = record `sourceIdentifier`) | 13,273 | 77.8% |
| From CISA-ADP (Vulnrichment, source `134c704f-…`) | 14,987 | 87.8% |
| CISA-ADP is the only score | 2,719 | 15.9% |
| From NIST (`nvd@nist.gov`) | 483 | 2.8% |

The settled point stands (severity scores are not the gap), but the supplier is CNAs *and* CISA, not CNAs alone. `fetch_sample.py` now writes `has_cna_cvss` and `pct_with_cna_cvss_live`; the Nov 7 `summary.json` was backfilled from the same raw file with the same function (any and NIST shares re-derived identically) rather than re-running `--from-raw`, which would re-fetch KEV, EPSS and Floodline and move other figures.

## Pull 2 — Nov 8, 2026 (first weekly rebuild)

**How:** first run of `.github/workflows/rebuild.yml`, started by hand (run 42450443302, Nov 8 05:21 UTC; all steps passed). The runner ran `fetch_sample.py --days 30`, `kev_enrichment.py`, `kev_lag.py`, `build_site.py`, committed the outputs as github-actions[bot] (`b80cd47`) and deployed Pages. The live page was checked byte-for-byte against the committed `site/index.html`.
**Window:** CVEs published 2026-10-09 05:21 UTC to 2026-11-08 05:21 UTC, about 10 hours later than Pull 1, so the two windows share almost all their CVEs. This is a check that the pipeline runs unattended, not a new sample.

| Measure | Pull 1 (Nov 7) | Pull 2 (Nov 8) |
|---|---|---|
| CVEs in window (non-rejected) | 17,729 (17,070) | 17,691 (17,035) |
| With CPE, non-rejected | 22.6% (3,863) | 22.3% (3,795) |
| CPE share, not in KEV | 22.6% | 22.2% |
| NIST-sourced CVSS, non-rejected | 2.8% | 2.6% |
| Any CVSS / CNA CVSS, non-rejected | 94.5% / 77.8% | 94.5% / 77.8% |
| Received (status) | 1,346 | 1,423 |
| Enriched (Analyzed) | 3,170 | 3,103 |
| Median time to enrichment (crude) | 7.2 days | 7.6 days |
| No CPE, not KEV, EPSS ≥ 0.10 | 2 | 2 |
| Published in window and in KEV | 18 (17 with CPE) | 18 (17 with CPE) |
| KEV listings in window: goal met | 34 of 35 (1 pending) | 29 of 30 (1 pending) |
| KEV listings in window: readiness | 10 of 23 | 10 of 23 |

**Why coverage fell slightly.** Moving the window drops the oldest ~10 hours (CVEs most likely to be enriched by now) and adds the newest (none enriched yet). Enriched fell by 67 and Received rose by 77. Expect the same small downward edge effect whenever the window moves by less than a week.

**Why the KEV cohort fell from 35 to 30.** The window now starts Oct 9, so every listing dated Oct 8 left the cohort: CVE-2015-3306, CVE-2015-5477, CVE-2016-3081, CVE-2021-3199, CVE-2023-22894. All five are old CVEs that had CPE before NIST's April 2026 triage, so they were outside the readiness denominator; readiness is unchanged (24 public before listing − 1 with pre-triage CPE = 23; 10 with CPE before listing). No CVE entered. With n this small, one listing day can move the goal count; check which CVEs moved before reporting a change.

**Other effects.**
- The section 1 orphan row is gone, as designed: `osv_orphans.json` still covers Oct 8 – Nov 7. `site/data/osv_orphans.json` stays published, so the sources link works. Re-run `scripts/research/osv_orphans.py` only if the brief needs a current orphan count.
- `kev_lag.json` came out identical (same KEV catalog). Floodline's file was unchanged (generated Nov 7).
- `recheck_measured.json` stays dated Nov 7 by design (one-time measurement).
- **The local `data/processed/cves_sample.csv` is now stale.** The runner's CSV is not committed (git-ignored), so the local CSV is still the Nov 7 pull while `summary.json` is Nov 8. `build_site.py` cross-checks the two and will stop. *(Fixed Nov 8: the build now detects a CSV from another pull, warns, skips the cross-check and reads the in-window KEV lag from `kev_enrichment.json`; a local build from committed data reproduces the bot's page.)*

## Pull 3 — Nov 9, 2026 (first scheduled rebuild) and the audit of the same day

**How:** first scheduled run of `.github/workflows/rebuild.yml` (Monday 12:47 UTC cron; pull at 12:52 UTC, bot commit `8f8a81c` at 12:54 UTC). The live page was fetched and is identical to the committed `site/index.html`.
**Window:** CVEs published 2026-10-10 12:52 UTC to 2026-11-09 12:52 UTC. It shares 30 of 31 calendar days with Pull 2, so it is again a check that the pipeline runs unattended, not a new sample.

| Measure | Pull 2 (Nov 8) | Pull 3 (Nov 9) |
|---|---|---|
| CVEs in window (non-rejected) | 17,691 (17,035) | 17,571 (16,919) |
| With CPE, non-rejected | 22.3% (3,795) | 22.1% (3,745) |
| CPE share, not in KEV | 22.2% | 22.1% |
| Not Scheduled | 6,962 (40.9%) | 6,739 (39.8%) |
| Awaiting Enrichment | 4,149 (24.4%) | 4,003 (23.7%) |
| Received (status) | 1,423 | 1,574 |
| Enriched (Analyzed) | 3,103 | 3,053 |
| NIST-sourced CVSS, non-rejected | 2.6% | 2.5% |
| Any CVSS / CNA CVSS, non-rejected | 94.5% / 77.8% | 94.2% / 77.6% |
| Median time to enrichment (crude) | 7.6 days | 7.7 days |
| No CPE, not KEV, EPSS ≥ 0.10 / 0.05 / 0.01 | 2 / 7 / 285 | 2 / 7 / 284 |
| Published in window and in KEV | 18 (17 with CPE) | 18 (17 with CPE) |
| KEV listings in window: goal met | 29 of 30 (1 pending) | 29 of 30 (1 pending) |
| KEV listings in window: readiness | 10 of 23 | 10 of 23 |

**KEV cohort.** The same 30 CVEs as Pull 2, and every row is identical: no listing was dated Oct 9, and CISA has added nothing since Nov 6 (`kev_lag.json` is unchanged, catalog through Nov 6). The pending CVE is still CVE-2026-19868 (listed Friday Nov 6, Undergoing Analysis). At the pull it was at one business day, so CPE on Monday Nov 9 still meets the goal. CPE from Tuesday Nov 10 on, or none by the next pull, is a miss, and the next pull will show it as one.

**Floodline.** File generated Nov 8: 26 of 28,720 CVEs with a day-30 score had crossed EPSS 10% (0.091%).

### Audit, Nov 9 (Claude Fable 5.2): does the process hold and do the numbers line up?

Yes. What was recomputed, each by code written apart from the pipeline:

- **Page from data.** `build_site.py` run on the committed Nov 9 files gives the committed `site/index.html` exactly (line endings aside).
- **Arithmetic and cross-file agreement.** 228 checks on the Nov 9 files and each `data/history/` folder: totals and status counts add up; shares follow from counts; the `site/data/` and history copies equal `data/processed/`; the KEV statistics recounted from the rows equal the stored ones in all three pulls (business days counted without numpy); the change-history CPE count equals the `configurations` count for KEV CVEs (17 and 17, two independent sources); `recheck_measured.json` equals `recheck_flow_corrected.json`; the cost figures quoted in the docs follow from 45 minutes and $120 an hour.
- **Pull 1 from the raw file.** All 17,729 records recounted from `data/raw/nvd_sample.json`: 17,070 non-rejected, 3,863 with CPE, the CVSS shares, the status counts, the CNA-product shares, and the KEV and EPSS counts from the CSV all match the Nov 7 `summary.json`.
- **Research measurements, re-run offline.** `recheck_volume.py` prints the same figures (stock 76,217; 303 / 443 / 3,384; the same window counts). `recheck_flow_corrected.py` and `automated_mapping.py` write files identical to the committed ones.

**What the audit corrected**

- **"No score yet."** `summary.json` carried `epss_missing_or_zero`, a count over every record, and the page printed it after the EPSS tiers as "had no score yet". Rejected records never get an EPSS score, so most of the count was Rejected: 659 of 787 in Pull 1, leaving 128 (all published Nov 7, all without CPE and outside KEV). `fetch_sample.py` now writes `epss_without_cpe_not_kev.unscored`, the same group as the tiers, and drops the old key. The committed Nov 9 summary still has only the old count (978), so until the next pull the page prints "978 of the 17,571 records in the window, Rejected ones included". The Nov 9 value of the new count is not known: the runner's per-CVE file is not committed.
- **"Reproduced Nov 8 on fresh feeds."** The NVD yearly feeds downloaded on Nov 8 (05:43 UTC) carry the feed timestamp 2026-11-07T03:00, and the Nov 8 output is byte-identical to the Nov 7 output. Both re-runs (Nov 8 and Nov 9) check the code on one snapshot. A second snapshot has not been measured.
- **Pending for ever.** A KEV-listed CVE with no CPE was counted as pending however long it waited, and the page could say "NIST meets its goal" beside it. `kev_enrichment.py` now records the business days gone without CPE; above one, the CVE counts as a miss (`overdue_without_cpe`). No effect on the three pulls so far.
- **Smaller fixes.** `stats()` failed with a `TypeError` if a CVE had CPE but NVD had logged no KEV event (no such row yet). The readiness sentence said "The other 13" even if a pending CVE made it 14 others. `kev_cumulative.json` listed 2 pulls of 3. The Definitions section printed the pull date as its freeze date. `build_site.py` accepted a `kev_enrichment.json` from another pull if the KEV count matched (18 in all three). `scripts/check_kev_cases.py` now tests these cases on a fixture.

**Found and left for Will (page wording):** see `CLAUDE.md`, *Known open items*, first bullet. The main one: section 3's rule text still lists LEV, SSVC and third-party triggers beside "well under one percent of existing capacity", while `trigger_table.json` puts SSVC PoC at 46.1% of NIST's peak month and LEV ≥ 0.10 at 6.5%.

**Research-script notes (no page figure affected).** `trigger_volume.py`'s last window ends Nov 7 and `recheck_volume.py`'s ends Nov 6, so the LEV and SSVC flows in `trigger_table.json` have one 31-day window. SSVC decisions before Jun 16, 2026 cannot be dated from the NVD change history, so "0 of 98" for the EPSS v4 era means "not datable", not zero. `recheck_flow_corrected.py` counts 2–4 crossers a window that are in KEV; if the listing came before the crossing, the rule would not have re-queued them, so the 0.05 flow could be 8–34 a month, not 11–36 (the page's figure is the higher one).
