# NVD Watch — project plan

## One-sentence pitch
A public scorecard that measures whether the U.S. vulnerability warning system still warns defenders in time, and prices a simple rule change that would close the gap.

## Background in five facts
1. **Apr 15, 2026:** NIST fully enriches only CVEs in CISA KEV, federal software, or EO 14028 critical software; it no longer routinely re-scores CVEs a CNA already scored; older backlog moved to "Not Scheduled." Its one public target: enrich KEV CVEs within one business day.
2. **The backlog predates AI.** It began Feb 2024 when an enrichment contract lapsed (Commerce OIG, OIG-26-020-I, May 26, 2026). NIST cites a 263% rise in submissions (2020–2025), not AI.
3. **Volume is surging.** Monthly CVEs ~5,045 (Jan) → ~10,740 (Aug 2026) (Google GTIG); only ~0.23% seen exploited.
4. **Product data has no free substitute.** CISA Vulnrichment stopped adding CPE on Dec 10, 2024; NVD CPE coverage for 2024 CVEs was ~41% vs ~77% from a commercial service (VulnCheck via CSA).
5. **KEV is slow and narrow.** Median CVE→KEV lag 4 (2023) → 10 days (2025), 9 in 2026 to Nov 6 (our count, `scripts/kev_lag.py`; Barracuda, Jul 24, 2026, reports 6 → 14). VulnCheck logged 884 exploited CVEs in 2025 vs 245 added to CISA KEV.

## Recommendations (brief)
| Stakeholder | Recommendation |
|---|---|
| **NIST** | Three parts (decided Nov 8; `docs/brief-outline.md`, Page 3). **1A:** automated day-0 CPE: pass through CNA-supplied `cpes` and assign provisional, product-level CPE on exact vendor:product dictionary matches (29.1% of window CVEs without CPE, Nov 7 pull). **1B:** a daily EPSS ≥ 0.05 re-check: move any CVE still without CPE (Not Scheduled, Awaiting Enrichment, or Received) into the KEV queue, under the existing one-business-day goal; log every re-queue. Broader triggers (LEV, SSVC PoC) break the budget (`trigger_table.json`). **1C:** publish the five quarterly metrics with frozen definitions, plus counts by priority tier and nvd@nist.gov request volume and turnaround. |
| **CISA** | As CVE sponsor, phase in structured, machine-matchable product data in CNA records, starting with the largest vendor CNAs and building on the Supplier ADP pilot. As KEV owner, publish listing lag and speed review when credible third-party exploitation reports arrive. |
| **Congress** | Commerce-Justice-Science appropriations report language directing NIST to publish the quarterly metrics and the tier and request counts; make them the yardstick in the GAO review that Ranking Members Thompson and Lofgren requested (June 6, 2025). No new money (decided Nov 8; the earlier "any CVE-codification bill" vehicle is dropped, since the FY2027 NDAA texts have none). Treat the rule as use of existing capacity (under 1% of peak output); cite the OIG re-scoring figure for scale only. |

## Build roadmap
| Step | Output | Done when |
|---|---|---|
| 1. Data pull | `data/processed/cves_sample.csv`, `summary.json` | A 30–90 day NVD window joined to KEV and EPSS, with CPE / NIST-CVSS / any-CVSS / CWE flags per CVE |
| 2. Definitions | `docs/metric-definitions.md` | Each of the five metrics defined in one paragraph with the exact field logic |
| 3. KEV lag | `data/processed/kev_lag.json` (`scripts/kev_lag.py`), **done** | Median CVE-published → KEV dateAdded by year, reproducing (or disagreeing with) Barracuda |
| 3b. KEV enrichment timing | `data/processed/kev_enrichment.json` (`scripts/kev_enrichment.py`), **done** | Readiness before listing and the one-business-day goal, from NVD change history |
| 4. Re-check estimate | `data/processed/recheck_measured.json` (`scripts/research/recheck_volume.py`), **done** | Measured from the whole NVD stock: 76,217 CVEs without CPE; at EPSS ≥ 0.05 (the threshold since Nov 8), 443 once ($18K–$53K), then 11–36 a month (~$39K a year at the default 36); at 0.10, 303 once and 11–28 a month. The earlier Floodline-based 16–46 a month is retired; Floodline now feeds only the section 2 maturation figures |
| 5. Scorecard page | `site/index.html` | Four sections populated only from processed data + cited constants |
| 6. Brief | `brief/brief.md` → PDF | ≤3 pages, numbers match the site |
| 7. AI log | `docs/ai-collaboration-log.md` | Final pass: every entry has a verification note |
| 8. (Stretch) weekly rebuild | GitHub Action | Runs fetch + build on a schedule |

## AI sources: when to add one
AI accelerates a capacity problem that already existed; it did not cause it (settled Nov 7). The brief uses AI only as why-now, the cost of waiting, pressure on the pipeline, and the future test. **Add a new AI source only if it changes a metric or a recommendation**, for example published accuracy of AI-assisted enrichment, or a credible estimate of the share of new CVEs that are AI-found. Another report that AI finds many bugs does not qualify.

## Presentation
Use `docs/learning/primer.html` (three-minute talk track and likely audience questions are inside). It predates the Nov 8 decisions (0.05 threshold, three-part NIST ask, our 4 → 10 → 9 lag count); take current figures and wording from `docs/learning/ste-explainer-2026-11-09.html`.
