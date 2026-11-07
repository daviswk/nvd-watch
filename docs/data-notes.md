# Data notes

Running notes on each pull: what the numbers say, how they were checked, and what they cannot say. Every figure here is reproducible from `data/processed/` plus the script named.

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
| CPE share, not in KEV | 21.7% | |

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

**Consequence for the re-check rule estimate.** The 250–470 CVEs/month figure cannot be reproduced from newly published CVEs. New CVEs rarely carry high EPSS; the trigger fires later, on the stock of older unenriched CVEs as scores rise. A monthly rate needs a backlog-based method: pull Deferred and Awaiting CVEs over a longer period and count threshold crossings per month.

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

Published per week in the window: 1,124 (partial week), 5,499, 4,211, 3,645, 3,250 (partial). That is about 17,700 per 30 days including Rejected, higher than the ~10,700/month reported by Google GTIG for August 2026. Different denominators (Rejected, reserved-then-published) likely explain part of the gap; verify before citing either.

### KEV rows worth a look

- CVE-2026-118527 has a KEV `dateAdded` (Oct 30) four days before its NVD publish date (Nov 3): KEV listed it before the NVD record existed.
- CVE-2026-19868 was added to KEV on Nov 6 and is still Undergoing Analysis, the only KEV CVE in the window without CPE.

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

**New estimate:** share crossing 10% by day 30 (0.094% now; 0.27% in the earlier window) × our 17,070 non-rejected CVEs per 30 days = 16 to 46 re-queues a month, 0.3% to 0.9% of capacity. At 20/45/60 analyst-minutes and $120/h: $7K to $58K a year, against the OIG's ~$400K. The page's simulator defaults to the current-data figure and labels it; the pipeline recomputes it weekly.

**What it does not count (so it is a lower bound):** crossings between day 30 and day 90 (Floodline's day-90 cells are mostly null for now), crossings from the older Not Scheduled stock outside Floodline's 90-day window, and the SSVC / third-party-evidence triggers. A lower threshold changes the picture: in our own pull, 288 CVEs without CPE scored ≥ 0.01 on current scores, versus 7 at ≥ 0.05 and 2 at ≥ 0.10.

**Reuse and license:** Floodline's code is Apache-2.0; its data derives from the FIRST EPSS archive (empiricalsec/epss_scores), CISA KEV (public domain), and cvelistV5 (CVE Program terms). We read one summary file and attribute it on the page; no code was copied. Field names were checked against `pipeline/floodline/compute.py`: `maturation[h].thresholds["10"]` counts scores strictly above 0.10 on the dated file at day+h.
