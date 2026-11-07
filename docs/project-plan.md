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
| **NIST** | Publish a re-check rule: move any CVE without CPE (Not Scheduled, Awaiting Enrichment, or Received) into the KEV queue, under the existing one-business-day goal, when max(EPSS, KEV, LEV) (CSWP 41) crosses a published threshold, CISA SSVC marks exploitation PoC/Active, or credible third-party exploitation evidence arrives. Log every re-queue. Publish five quarterly metrics with frozen definitions. Publish each CVE's priority tier. |
| **CISA** | As CVE sponsor, phase in structured, machine-matchable product data in CNA records, starting with the largest vendor CNAs and building on the Supplier ADP pilot. As KEV owner, publish listing lag and speed review when credible third-party exploitation reports arrive. |
| **Congress** | Attach the metrics to existing vehicles (the GAO review of CVE/NVD requested in June 2025; any CVE-codification bill, since the FY2027 NDAA texts have none) rather than new appropriations. Treat the rule as use of existing capacity (under 1% of peak output); cite the OIG re-scoring figure for scale only. |

## Build roadmap
| Step | Output | Done when |
|---|---|---|
| 1. Data pull | `data/processed/cves_sample.csv`, `summary.json` | A 30–90 day NVD window joined to KEV and EPSS, with CPE / NIST-CVSS / any-CVSS / CWE flags per CVE |
| 2. Definitions | `docs/metric-definitions.md` | Each of the five metrics defined in one paragraph with the exact field logic |
| 3. KEV lag | `data/processed/kev_lag.json` (`scripts/kev_lag.py`), **done** | Median CVE-published → KEV dateAdded by year, reproducing (or disagreeing with) Barracuda |
| 3b. KEV enrichment timing | `data/processed/kev_enrichment.json` (`scripts/kev_enrichment.py`), **done** | Readiness before listing and the one-business-day goal, from NVD change history |
| 4. Re-check estimate | `summary.json` (`floodline` block, via `fetch_floodline()`), **done** | Floodline day-30 crossing rate × our 30-day volume; rough, biased both ways (see `data-notes.md`) |
| 5. Scorecard page | `site/index.html` | Four sections populated only from processed data + cited constants |
| 6. Brief | `brief/brief.md` → PDF | ≤3 pages, numbers match the site |
| 7. AI log | `docs/ai-collaboration-log.md` | Final pass: every entry has a verification note |
| 8. (Stretch) weekly rebuild | GitHub Action | Runs fetch + build on a schedule |

## Presentation
Use `docs/learning/primer.html` (three-minute talk track and likely audience questions are inside).
