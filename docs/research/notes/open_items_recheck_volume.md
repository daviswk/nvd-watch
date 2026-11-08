# Re-check volume: the day-90 horizon, the Not Scheduled stock, and EPSS on unenriched CVEs

Research date: 2026-11-07. Primary sources: FIRST EPSS pages and API docs, the EPSS daily archive (empiricalsec/epss_scores, linked from FIRST), the NVD JSON 2.0 yearly feeds and the NVD API (live tests), the NVD CVE Change History API, the CISA KEV JSON (catalog 2026.11.06, 1,769 entries), NIST's Apr 15, 2026 news release, the Commerce OIG report OIG-26-020-I (PDF text extracted), and CVE Floodline's source code and data. One vendor press release (EPSS v5) is used as labelled secondary context.

All new numbers come from `scripts/research/recheck_volume.py` (run on NVD feeds timestamped 2026-11-07T03:00, EPSS files 2026-06-15 to 2026-11-07, KEV 2026.11.06), plus two scratch steps described inline (change-history check; pre-KEV EPSS lookup). Inputs were downloaded to a temp folder and are not committed.

**Threshold note.** The script counts EPSS **≥** t. Floodline counts **>** t. "Stock" below means NVD status Deferred ("Not Scheduled"), Awaiting Analysis or Received, no CPE (`configurations` empty), and not in KEV. Status and CPE are as of Nov 7.

---

## Bottom line

### 1. Day-90 horizon
- **Floodline will never answer this.** Its window is 90 days (`WINDOW_DAYS = 90`) and its last horizon is day 90, so only the 2–3 oldest cohorts ever have a day-90 cell. Today that is Aug 7–9: 350 CVEs, 0 above 10%. It also measures EPSS *on* day 90 (point in time), not "ever crossed by day 90". A trigger fires on the first crossing, so the "ever" measure is the one that matters.
- **Our own cohort.** We took 8,376 non-rejected CVEs NVD-published Jun 15 – Jul 14, 2026, all scored by EPSS v5. The share whose EPSS reached 0.10 at any point rose from **0.263% by day 30 (22)** to **0.442% by day 90 (37)**. Days 31–90 add **68%** on top of day 30.
- **Point-in-time undercounts.** Measured Floodline's way, the counts *fall* over time: 19 at or above 0.10 on day 30, 13 on day 90.
- **Few of the late crossers need a re-queue.** Of the 15 late crossers, only **4** lack CPE today and are not in KEV. Over the full 90 days, 7 of 8,376 (0.084%) would need a re-queue, about **14 a month** on ~17,000 CVEs a month. This is small-n.
- **Confidence:** medium for the cohort numbers. Low for extrapolating from one 30-day cohort, since Floodline's window gives 0.09% at day 30 and this cohort gives 0.26%.

### 2. The Not Scheduled stock
- **Stock size:** **76,217** CVEs, none of them in KEV.
  - Deferred: 61,216. Of these, 29,017 were published before Mar 1, 2026. That matches the "~29,000" reported for NIST's backlog move.
  - Awaiting Analysis: 9,853.
  - Received: 5,148.
- **One-time load** (stock at or above the threshold on Nov 7):

  | Threshold | Stock CVEs | Published before Mar 1, 2026 |
  |---|---|---|
  | ≥ 0.10 | 303 | 258 |
  | ≥ 0.05 | 443 | — |
  | ≥ 0.01 | 3,384 | — |

  At 0.10 that is about 6% of one month's demonstrated capacity, done once.
- **Monthly flow** (stock CVEs whose EPSS first reached 0.10 in a 30-day window, Jul 10 – Nov 6): **9–21 per month**. Change history shows **2–7 more per month** that crossed while still without CPE and were enriched afterwards. That gives **~11–28 re-queues a month**, mean ~18.5.
- **Where the flow comes from:** most crossers were published **more than 90 days** before crossing (6–14 a month). Very few are new CVEs (0–4 a month, ages 0–30 days).
- **What this does to the 16–46 estimate:** total volume is the same order of magnitude, but the composition differs. The Floodline-based figure counts mostly *new* CVEs that already have CPE. The measured re-queue flow comes mostly from old stock.
- **Lower thresholds** raise the flow: 8–30 a month at 0.05 and **183–656 a month at 0.01** before the change-history correction. **Nov 8:** with the correction, 0.05 is **34, 36, 11, 32** (11–36; `scripts/research/recheck_flow_corrected.py`, which reproduced 28, 23, 11, 12 at 0.10).
- **Confidence:** high for the stock counts (full census). Medium for the flow (four windows, all under one EPSS model, about 2–28 events each).

### 3. EPSS accuracy on unenriched CVEs
- **The model in use is now EPSS v5, not v4.** Model `v2026.06.15` has published since **Jun 15, 2026** (FIRST "Get the Data" page; the file headers change from `v2025.03.14` on Jun 14 to `v2026.06.15` on Jun 15). This contradicts CLAUDE.md and `epss_prioritization.md`, which call v4 current.
- **What FIRST says v5 uses:** ~2,850 features. The categories are:
  - exploit code and tooling;
  - "chatter" by source domain;
  - CVSS *metrics*;
  - tags derived from descriptions;
  - "vendor and some product information";
  - age and reference volume.
- **NVD-derived inputs are confirmed only in part.** FIRST's training description refers to "which CVSS metrics NVD had published by then" and "which weakness classifications had been assigned". So NVD CVSS (and probably CWE) are features. FIRST does not say whether vendor/product features come from NVD CPE or CNA `affected` data, or whether the v4 "CNA/ADP as backup to NVD" fallback carried into v5.
- **No published evaluation splits EPSS performance by NVD enrichment status.** Not found at FIRST, Empirical Security, arXiv, or in the papers FIRST lists.
- **Small pilot from our data:** of 13 KEV CVEs with no CPE before listing, **1** was at or above 0.10 the day before CISA listed it. 3 were unscored. Of 10 that had CPE, 4 were at or above 0.10. This is small-n, confounded, and not a test.
- **Confidence:** high that no study exists. Medium on the feature list, since it comes from FIRST prose with no feature table.

---

## 1. Day-90 horizon — details

**What Floodline measures.** Source: [README](https://github.com/RogoLabs/cvefloodline.org/blob/main/README.md), [`pipeline/floodline/compute.py`](https://github.com/RogoLabs/cvefloodline.org/blob/main/pipeline/floodline/compute.py), [`sources.py`](https://github.com/RogoLabs/cvefloodline.org/blob/main/pipeline/floodline/sources.py), [`data/floodline.json`](https://github.com/RogoLabs/cvefloodline.org/blob/main/data/floodline.json), generated 2026-11-07T17:05Z.
- **Cohorts:** CVEs grouped by cvelistV5 `datePublished`, not NVD publication date.
- **Horizons:** `HORIZONS = [0, 7, 30, 90]`. Each cell counts scores *strictly above* each threshold on the dated EPSS file at D+h: `sum(1 for s in scores if s > t/100)`.
- **Day 0:** uses a ±3-day nearest-file fill.
- **Window:** `WINDOW_DAYS = 90`, recomputed daily, with the newest 3 days held back. A day-90 cell is therefore only possible for cohorts 90 or more days old *inside* a 90-day window.
- **Day-90 cells in today's file:** 3 of 90 days (Aug 7–9), 350 CVEs, 0 above 10%. Aug 7 had 1 CVE above 10% on day 30 and 0 on day 90.
- **Other horizons in today's file:**

  | Horizon | Cohorts | CVEs | Above 10% |
  |---|---|---|---|
  | Day 0 | 90 | 44,079 | 4 |
  | Day 7 | 86 | 42,359 | 12 |
  | Day 30 | 63 | 28,618 | 27 |

- **The README's "not shown until enough time passes"** is true only for those 2–3 days at the edge. A rolling 90-day window never accumulates day-90 data.
- **Model version:** `latest_epss_model_version` is `v2026.06.15` (EPSS v5).

**Can we compute day 90 ourselves? Yes, from the archive, not the API.**
- **API** ([api.first.org/epss](https://api.first.org/epss)):
  - `date=YYYY-MM-DD` (since 2021-04-14) gives historic scores.
  - `scope=time-series` gives "the last 30 days (or what is available)". Thirty days of history cannot reach day 90 for a past cohort.
  - `cve=` takes comma lists up to 2,000 characters (roughly 120 IDs).
  - Rate limit: 1,000 requests per minute unauthenticated ([api.first.org](https://api.first.org/)).
  - FIRST's [Get the Data page](https://www.first.org/epss/data) says the API "is designed for lookup, not bulk access" and points to the daily CSV and the GitHub archive for historical work.
  - *Note:* `https://www.first.org/epss/api` returns 404. The API docs now live at api.first.org/epss.
- **Archive:** [github.com/empiricalsec/epss_scores](https://github.com/empiricalsec/epss_scores), one file per day, `YYYY/epss_scores-YYYY-MM-DD.csv.gz`, back to 2021-04-14.
  - Each file is 2.2–2.8 MB gzipped. The Jun 15 file had 340,249 lines and the Nov 7 file 401,677.
  - We downloaded Jun 8 – Nov 7 (153 files, 376 MB) in under a minute through raw.githubusercontent.com. No rate limit was hit.
  - The current file is at `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` (it redirects).

**Method used** (`recheck_volume.py`):
1. The cohort is non-rejected CVEs with NVD `published` between Jun 15 and Jul 14, 2026 (8,376). Starting at Jun 15 keeps every score under one model.
2. For each CVE, record the first daily file from Jun 15 on which EPSS ≥ t.
3. "Ever by day h" means that first date minus NVD publication is h days or less.
4. Point-in-time on day h means the score on the file dated publication + h.
5. Every cohort CVE had an EPSS score. The median lag from NVD publication to the first EPSS file was 1 day.

**Results for the Jun 15 – Jul 14, 2026 cohort** (n = 8,376; 4,319 with CPE now; 22 in KEV):

| t | ever by d0 | by d7 | by d30 | by d90 | on day 30 (point) | on day 90 (point) | first crossed d31–90 | of those, no CPE now and not KEV |
|---|---|---|---|---|---|---|---|---|
| 0.10 | 0 | 7 (0.084%) | 22 (0.263%) | 37 (0.442%) | 19 | 13 | 15 | 4 |
| 0.05 | 0 | 14 (0.167%) | 29 (0.346%) | 51 (0.609%) | 27 | 25 | 22 | 9 |
| 0.01 | 29 (0.346%) | 186 (2.221%) | 248 (2.961%) | 414 (4.943%) | 230 | 357 | 166 | 69 |

- Of the 22 cohort CVEs that reached 0.10 by day 30: 19 have CPE now, 8 are in KEV, and 3 have neither.
- At 0.10, the share that would need a re-queue (no CPE now, not KEV) is 3 by day 30 and 7 by day 90.
- **Cross-check:** our 0.263% by day 30 matches the Floodline README's earlier window ("2.7 per 1,000"). Floodline's current window gives 0.094% (point in time, strict >). Cohorts vary roughly threefold.

**Bias in "no CPE now":** a crosser that was enriched *because* it later entered KEV drops out of the count. Section 2 measures how big this is for the stock flow (small).

## 2. The Not Scheduled stock — details

**Can the NVD API filter by status? No.** Live test, Nov 7:
- `GET /rest/json/cves/2.0?resultsPerPage=1&vulnStatus=Deferred` returns HTTP 404 with header `message: Invalid parameter: vulnStatus.`
- A made-up parameter returns the same pattern (`Invalid parameter: fooBar.`).
- `hasKev` and `noRejected` return 200.
- The developer page (nvd.nist.gov/developers/vulnerabilities) is now rendered by JavaScript and could not be read by fetch.

So the stock has to come from a full pull. We used the **NVD JSON 2.0 yearly feeds** (`https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-YYYY.json.gz`, 2002–2026, 236 MB in total). These are grouped by CVE-ID year and carry `vulnStatus` and `configurations`. That is cheaper than about 210 paged API calls.

**Census (non-rejected, Nov 7):**

| Status | Count |
|---|---|
| Modified | 245,638 |
| Analyzed | 78,695 |
| Deferred | 61,216 |
| Awaiting Analysis | 9,853 |
| Received | 5,148 |
| Undergoing Analysis | 1,074 |
| **Total non-rejected** | **401,624** |

- **No Deferred or Awaiting Analysis record has CPE.** Of the 77,154 non-rejected CVEs without CPE, 811 are Undergoing Analysis and 126 are Modified; those are outside the stock definition.
- **Stock = 76,217.** None of these CVEs is in KEV, which is consistent with NIST's statement below.

| Stock by publication date | Deferred | Awaiting | Received |
|---|---|---|---|
| before Mar 1, 2026 | 29,017 | 3 | 0 |
| Mar 1 – Apr 14, 2026 | 2,330 | 307 | 0 |
| from Apr 15, 2026 | 29,869 | 9,543 | 5,148 |

- By publication year: 2024: 7,764 · 2025: 17,956 · 2026: 50,497.
- The earliest Deferred CVE was published 2024-02-13. This fits NIST moving last year's (pre-2018) Deferred records to "Modified After Enrichment".

**What NIST and the OIG say:**
- **NIST, "NIST Updates NVD Operations to Address Record CVE Growth"** ([Apr 15, 2026](https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth)):
  - "Starting in early 2024, the NVD developed a significant backlog of unenriched CVEs." The release gives **no backlog count**.
  - All backlogged CVEs published before Mar 1, 2026 move to "Not Scheduled". NIST "will consider enriching those earlier vulnerabilities" as "resources allow".
  - "The backlog does not include any CVEs in the KEV Catalog."
  - Users can request enrichment by emailing nvd@nist.gov.
  - The NVD Dashboard was updated to report status "in real time". It is a JavaScript page and could not be read here.
  - CVEs Deferred "last year" move to "Modified After Enrichment".
  - **The release says nothing about re-checking Not Scheduled CVEs if their risk rises.** That is the gap the rule fills.
- **Commerce OIG, OIG-26-020-I** ([PDF](https://www.oig.doc.gov/wp-content/OIGPublications/OIG-26-020-I-SECURED.pdf), text extracted; page numbers are the report's printed numbers unless marked PDF):
  - p. 5: the backlog grew "from about 13,000 vulnerabilities at the start of June 2024 to over 27,000 by the end of 2025".
  - p. 6: OIG projects more than 60,000 reported vulnerabilities in 2026.
  - p. 7: NIST "Did Not Effectively Prioritize the Processing of Critical Vulnerabilities"; its informal priority list included KEV, widely used products, and "considerable public attention".
  - Rec. 1 asks for a backlog plan with "processes that prioritize critical vulnerabilities". NIST concurred and is "preparing a new process for prioritizing critical vulnerabilities" (PDF p. 30, NIST response).
  - The report never mentions EPSS or the Deferred status.
- **Reconciliation:** our 29,017 Deferred CVEs published before Mar 1 is consistent with OIG's ">27,000 by end of 2025" plus Jan–Feb 2026 inflow. The 76,217 total stock includes ~45,000 CVEs published since Apr 15 that the new triage left Not Scheduled or still waiting.

**One-time load** (stock CVEs at or above t on the Nov 7 EPSS file; all 76,217 are scored):

| t | stock ≥ t | Deferred | Awaiting | Received | published before Mar 1 | context: all non-rejected CVEs ≥ t |
|---|---|---|---|---|---|---|
| 0.10 | **303** | 293 | 10 | 0 | 258 | 17,524 |
| 0.05 | **443** | 414 | 29 | 0 | 346 | 31,010 |
| 0.01 | **3,384** | 2,986 | 392 | 6 | 1,598 | 148,568 |

FIRST's [FAQ](https://www.first.org/epss/faq) says 0.10 "currently sits around the 95th percentile". Our 17,524 of 401,624 (4.4%) agrees.

**Monthly flow from the stock.** Method:
- For each CVE, find the first daily file from Jun 15 on with EPSS ≥ t.
- A CVE already at or above t on Jun 15 belongs to the one-time load, not the flow.
- Count first crossings in four windows, split by age at crossing (crossing date minus NVD publication).

At t = 0.10:

| Window | All CVEs crossing | Stock crossers (no CPE now, not KEV): 0–30d / 31–90d / >90d | + crossed before CPE, enriched later (change history) | Re-queues |
|---|---|---|---|---|
| Jul 10 – Aug 8 | 183 | **21**: 3 / 9 / 9 | 7 (2 now in KEV) | 28 |
| Aug 9 – Sep 7 | 254 | **21**: 4 / 3 / 14 | 2 (2 in KEV) | 23 |
| Sep 8 – Oct 7 | 109 | **9**: 0 / 2 / 7 | 2 (2 in KEV) | 11 |
| Oct 8 – Nov 6 | 123 | **10**: 3 / 1 / 6 | 2 (2 in KEV) | 12 |

**How the change-history correction was done** (scratch step; logic copied from `scripts/kev_enrichment.py`):
1. Candidates were all 279 crossers published on or after 2024-02-01 that now have CPE or are in KEV.
2. For each, we queried `cvehistory/2.0?cveId=` and took the first "CPE Configuration" Added/Changed event.
3. 266 had CPE before crossing, so they were not re-queues. 13 got CPE on or after the crossing date.
4. CVEs published before Feb 2024 were not checked; nearly all were enriched before the backlog.
5. Whether the 8 KEV CVEs crossed before or after their KEV listing was not checked. If after, the KEV queue already covered them.

**Other thresholds** (stock crossers only, without the change-history correction):
- t = 0.05: 23, 30, 8 and 25 per window.
- t = 0.01: 183, 386, 656 and 474 per window. Most were 0–30 days old: 137, 220, 338 and 317.

**What the rule costs, on this measurement:**
- **Monthly:** 11–28 re-queues, about 0.2–0.6% of the ~5,000 a month OIG says NIST has never exceeded (OIG p. 6). At 20–60 analyst-minutes and $120/h, that is **~$5K–$40K a year**.
- **One-time:** the 303 stock CVEs already at or above 0.10 cost **~$12K–$36K** on the same assumptions.
- The minutes and the hourly rate are assumptions, as before.

**How this compares with the 16–46 a month in CLAUDE.md:**
- The measured total, 11–28 a month, is in the same range.
- The **composition** differs. The old figure assumed the crossings were new CVEs (0–30 days). The measured re-queue flow is mostly old stock, and new-CVE re-queues are 0–4 a month.
- **The page should present two parts:** a one-time stock load and a monthly flow.

## 3. EPSS v5 inputs and enrichment — details

**Version:**
- [FIRST, Get the Data](https://www.first.org/epss/data): "EPSS v5 (v2026.06.15): started publishing 2026-06-15". Earlier versions: v4 (v2025.03.14) from 2025-03-17; v3 from 2023-03-07.
- Confirmed in the archive headers: Jun 14 `#model_version:v2025.03.14`, Jun 15 `#model_version:v2026.06.15`.
- FIRST's [Research page](https://www.first.org/epss/research) says the 2023 v3 paper's techniques "are still used in Version 5 today".
- Secondary context: an Empirical Security press release ([EIN Presswire syndication, May 13, 2026](https://lifestyle.folsomlocalnews.com/story/664260/empirical-security-releases-epss-v5/); vendor, not peer-reviewed) claims a "23% improvement" over v4 (0.514 → 0.633 on an unnamed metric) and new unnamed data feeds. It does not mention NVD, CPE or CWE.

**Features, per FIRST's [How EPSS Works](https://www.first.org/epss/how-it-works):**
- About 2,850 features in five categories:
  - exploit code and offensive tooling (including Nuclei and Shodan);
  - chatter, with each source domain as a feature;
  - vulnerability characteristics: CVSS exploitability and impact *metrics* (scores ignored), description-derived tags, and "Vendor and some product information … as individual features";
  - age and reference volume. Age "contributes more to individual predictions than any other single vulnerability characteristic".
- Exploitation activity from about a dozen partners is the training label.
- Training is point-in-time: each daily record holds "which CVSS metrics NVD had published by then, which weakness classifications had been assigned … and what the vulnerability record(s) contained", and "If NVD hadn't published a CVSS score yet, that day's record reflects that absence."
- XGBoost "handles missing values naturally without requiring gap-filling".
- The training corpus is about 120 million rows by 2,850 columns over a 12-month window, calibrated to 30-day probability.
- FIRST lists as a limitation: "Sparse signal on newly disclosed vulnerabilities."

**Reading:**
- NVD-published CVSS metrics are an input, and CWE probably is ("weakness classifications").
- The source of the vendor/product features (NVD CPE or CNA `affected`) is **not stated**. Neither is whether CNA CVSS substitutes when NVD has none. The v4 post (Empirical Security, Mar 2025, cited in `epss_prioritization.md`) said "cve.org CNA/ADP information as backup to NVD enrichment (CPE/CVSS)". No v5 equivalent was found.
- Because the model is trained on records with the *same* missingness that unenriched CVEs have in production, it should be calibrated for them on average. That does not mean it ranks them as well as enriched CVEs.

**Published evaluation by enrichment status: not found.** Searched:
- FIRST's how-it-works, FAQ, research and data pages;
- Empirical Security's research index (no v5 technical post found);
- arXiv / web search ("EPSS unenriched", "NVD backlog EPSS accuracy").

FIRST's listed independent evaluations (Parla 2024; Koscinski et al. 2025; Ravalico et al. 2025; Mell & Spring CSWP 41) do not split results by NVD enrichment.

**Pilot from our data** (scratch step: the 23 KEV CVEs in `data/processed/kev_enrichment.json` that were public before listing and not enriched before triage; EPSS from the file dated the day before KEV `dateAdded`):

| Group | n | EPSS ≥ 0.10 the day before | ≥ 0.01 | unscored |
|---|---|---|---|---|
| no CPE before KEV | 13 | 1 (CVE-2026-111497, 0.36) | 4 | 3 (published ≤ 1 day before listing) |
| CPE before KEV | 10 | 4 (incl. PHP2Shell, 0.9998 / 0.99997) | 5 | 0 |

- This is not an accuracy test: n is tiny, and outcome and enrichment are confounded.
- It is relevant to the rule anyway. At 0.10, the trigger would have re-queued **1 of 13** CVEs before CISA listed them. This fits CLAUDE.md's "19% before KEV" and supports keeping SSVC and third-party-evidence triggers in the rule.

**A feasible test (not run):**
1. For each score date S (e.g. the 1st of each month, Jul–Oct 2026, all under v5), take every CVE published within 120 days before S that was not in KEV on S.
2. Label enrichment *as of S* using NVD change history (first CPE event before S). History is needed only for CVEs that have CPE now; Deferred, Awaiting and Received CVEs never had it.
3. The outcome is a KEV `dateAdded` in (S, S+30]. Add the EPSS partner signal if accessible; it is not public, so KEV is a proxy with its own lag.
4. Compare PR-AUC, and coverage/efficiency at 0.10 and 0.01, for enriched-at-S vs unenriched-at-S, plus calibration (mean EPSS vs observed KEV rate).
5. Expect about 30–70 positives per month in total, so pool the four months and bootstrap confidence intervals.
6. Main confounder: NIST enriches federal and critical software first, and those vendors are listed in KEV more often. Stratify by vendor, or compare within vendor.

---

## Still unknown

- The day-90 rate for more than one cohort. Floodline cannot supply it. Running `recheck_volume.py` with another `COHORT` (e.g. Jul 15 – Aug 6, also v5) would add a second point.
- Crossings after day 90 for new CVEs, beyond what the stock flow already captures.
- Whether the flow is stable. All four windows fall in one model's first five months, and v5 started 3.5 weeks before the first window, so early-model drift is possible.
- The LEV part of max(EPSS, KEV, LEV): not computed. LEV needs each CVE's score history and would add CVEs with a long run of moderate scores.
- SSVC (CISA ADP "Exploitation: PoC/Active") as a trigger: its volume on the stock is not measured.
- The change-history correction at 0.05 and 0.01: not run.
- Whether the 8 KEV crossers (from the correction) crossed before or after their listing.
- The source of v5's vendor/product features (NVD CPE or CNA `affected`); FIRST does not say.
- Whether EPSS ranks unenriched CVEs worse: unmeasured anywhere (see the test above).
- NIST's own current backlog count: the NVD Dashboard is JavaScript-only and could not be read; NIST's release gives no number.

## Possible AI-log entries

- **EPSS version was stale.** `epss_prioritization.md` (Nov 6) said v4 is current and "No v5 was found". FIRST's data page and the archive file headers show v5 since Jun 15, 2026. The AI research pass missed a primary source, the archive's own header line. CLAUDE.md's open item "Does EPSS v4 accuracy degrade…" should say v5.
- **Floodline's day-90 "not yet" is structural.** CLAUDE.md and data-notes say the day-90 horizon is "not yet observable". Floodline's code (`WINDOW_DAYS = 90`, `HORIZONS = [0, 7, 30, 90]`) means it will never be observable beyond 2–3 edge cohorts. Its point-in-time definition also *falls* between day 30 and day 90 (19 → 13 in our cohort).
- **Stale "lower bound" comment.** The `note` string in `fetch_floodline()` (`scripts/fetch_sample.py`) still says "so this is a lower bound". That contradicts the settled "not a lower bound" in CLAUDE.md and data-notes, and the string is written into `summary.json`. Not edited (out of scope); flag for a fix.
- **The 16–46 figure has the wrong composition.** It came from new-CVE crossings, most of which already have CPE. Measured re-queues come mostly from stock older than 90 days. The total is similar by coincidence.
- **The NVD API has no `vulnStatus` filter.** The brief for this task suggested checking for one; the API answers `Invalid parameter: vulnStatus.`
- **Dead FIRST URL.** `https://www.first.org/epss/api` returns 404. The documentation is at `https://api.first.org/epss`.
- **No vendor press release confirms the v5 date.** It is dated May 13, 2026, while publishing started Jun 15 (FIRST). A search summary called this a "timing conflict"; it is a release announcement before go-live, not a contradiction. Cite FIRST for the date.
- **"~29,000 pre-March backlog" confirmed.** Previously secondary (Help Net Security); our census gives 29,017 Deferred plus 3 Awaiting published before Mar 1, 2026. NIST's own release gives no number.
