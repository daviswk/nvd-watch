# Data notes

Running notes on each pull: what the numbers say, how they were checked, and what they cannot say. Every figure here is reproducible from `data/processed/` plus the script named.

Sections are appended in order, so later sections can revise earlier ones. When that happens the earlier passage is marked **Superseded** in place, with a pointer, and this list is updated. **Read this list first; it is the current state.**

## Current conclusions (as of Nov 7, 2026)

- **Coverage:** 22.6% of non-rejected CVEs published Oct 8 – Nov 7 have CPE (3,863 of 17,070); 77.4% do not. Coverage matures: the Apr 15 – Jun 15 cohort is at 57.3% five months on, with 37.9% still Not Scheduled. See *Pull 1* and *Verification pulls*.
- **"When defenders need it"** = **before** the KEV listing, compared by timestamp. Score **readiness** (CPE before listing) separately from **NIST's goal** (CPE within one business day of the later of listing and NVD publication). See *KEV cohort extended…* (last section), which replaces the day-based definition in *KEV CVEs: was CPE there…*.
- **KEV result:** of the 35 CVEs added to KEV in the window (any publication year), 34 met the goal (1 pending), every first CPE record from NIST. Readiness: of 23 public before listing and not enriched pre-triage, 10 had CPE beforehand; several got it within minutes of the KEV event. KEV is the trigger.
- **Re-check volume:** Floodline day-30 rate × our volume = 16–46 a month (simulator default 16), $8K–$66K a year (default $8K–$23K). **Rough, biased both ways, not a lower bound:** 8 of the 10 CVEs at EPSS ≥ 0.10 already had CPE (pushes it down); later crossings, the older stock and SSVC triggers are uncounted (push it up). The OIG's ~$400K a year is a scale comparison, not spare money. See the last section, which revises *Re-check volume from CVE Floodline*.
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
| Share with NIST-sourced CVSS | 2.7% | source `nvd@nist.gov` |
| Share with any CVSS | 91.0% | CNA, CISA-ADP, or NIST |
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

787 of 17,729 CVEs had no EPSS score or a score of exactly 0 (FIRST scores new CVEs with a lag). Among CVEs without CPE and not in KEV: 288 had EPSS ≥ 0.01, 7 had ≥ 0.05, and 2 had ≥ 0.10 (CVE-2026-59774, Deferred, 0.283; CVE-2026-77690, Awaiting Analysis, 0.156). None had ≥ 0.50.

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

**What it does not count:** (**Superseded:** this paragraph first called the estimate a lower bound. It is not: Floodline's rate also counts crossings by CVEs that already have CPE, and 8 of the 10 CVEs at EPSS ≥ 0.10 in our window did. The bias runs both ways; see the last section.) Crossings between day 30 and day 90 (Floodline's day-90 cells are mostly null for now), crossings from the older Not Scheduled stock outside Floodline's 90-day window, and the SSVC / third-party-evidence triggers. A lower threshold changes the picture: in our own pull, 288 CVEs without CPE scored ≥ 0.01 on current scores, versus 7 at ≥ 0.05 and 2 at ≥ 0.10.

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

**Reading:** NIST meets its goal once a CVE is listed, including older ones. Before the listing, 13 of 23 lacked CPE, and several got it within minutes of the KEV event: CVE-2026-102764 (10 min), CVE-2026-114625 (29 min), CVE-2026-21589 (40 min, public 10 days), CVE-2026-111357 (89 min, public 15 days). That is direct evidence that the KEV listing is what triggers enrichment for these CVEs.

**Pushback on the red-team's framing:** "only 3 of 18 had CPE before listing" counts six CVEs that were published and listed on the same day (or listed before NVD published them), with no time to be enriched first. The fair denominator is the CVEs that were public before listing: 3 of 12 in the sample, 10 of 23 overall. Status before listing is not in the change history, so we cannot say which of the 13 were Not Scheduled rather than Awaiting.

**Re-check volume bias, both directions:** of the 10 CVEs in the window currently at EPSS >= 0.10, 8 already have CPE (7 in KEV). Floodline's rate counts all crossings, so 16–46 a month overstates re-queues of *new* CVEs, possibly by several times (n = 10, so the size is not reliable). It also leaves out crossings after day 30, the older Not Scheduled stock, and SSVC or third-party triggers. It is a rough estimate, not a lower bound.
