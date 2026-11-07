# Policy brief outline (≤ 3 pages)

**Title (working):** Re-check, Then Measure: Closing the Product-Data Gap in the National Vulnerability Database

## Page 1 — Background
- What the NVD does, and why product data (CPE) is what lets scanners tell an organization it is affected.
- NIST's April 15, 2026 triage: KEV, federal, and EO 14028 critical software first; no routine re-scoring of CNA-scored CVEs.
- Why now: CVE volume roughly doubled in 2026; AI discovery accelerates a capacity gap that began with a February 2024 contract lapse (OIG).
- Hook figure: median CVE-to-KEV lag 4 → 10 days (2023 → 2025; 9 in 2026 to Nov 6), our count from KEV + NVD (`scripts/kev_lag.py`). Barracuda reports 6 → 14 for the same population.

## Page 2 — Challenges and opportunities
**Challenges**
- KEV is the gate for CPE on software outside NIST's federal and critical-software priorities, and it is slow and narrow (VulnCheck's 884 vs CISA's 245 exploited CVEs in 2025; different inclusion rules). PHP2Shell shows the listing lag, but PHP got CPE the day it was published, as federally used software.
- Coverage numbers conflict (≈50% vs 8.4%) because no official definition exists; status labels changed mid-series.
- EPSS can't reliably flag brand-new CVEs (leads KEV in only 19% of cases).
- Who bears the gap: state/local governments (MS-ISAC lost federal funding in 2025), hospitals, small businesses — organizations that can't buy commercial enrichment.
- One limit, stated plainly: some threats never reach a matchable CVE record. The Aug 2026 joint advisory on Siemens S7 PLCs (AA26-231A) listed no CVE IDs, so no enrichment rule helps there.

**Opportunities**
- EPSS leads KEV by ~201 days when it leads at all, which makes it a good re-check trigger for stalled CVEs.
- NIST already designed the composite (CSWP 41: max of EPSS, KEV, LEV). FedRAMP's 2026 rules already use KEV (not EPSS).
- The OIG estimated NIST could put ~$800K over two years to better use by minimizing re-scoring (~$400K/yr). NIST disputes this in the report's Appendix 4.
- The CVE Program's Supplier ADP pilot already lets product vendors add affected-product data to other CNAs' records: Siemens and Red Hat have covered 3,349 CVEs since April 2026 (SADP Tracker). CISA, as CVE sponsor, could expand it. It fills CVE's `affected` field, not CPE, so it complements rather than replaces NIST enrichment.
- NIST's RFI (question 7(e)) asked the public for metrics. NVD Watch is a working answer. Independent open-source trackers (CVE.ICU, CVE Floodline, CNA Scorecard, CNAPulse) measure volume and CNA quality, but none measures NIST's enrichment performance.

## Page 3 — Recommendations
1. **NIST:** adopt and publish a re-check rule; log every re-queue; publish five quarterly metrics with frozen definitions.
2. **CISA:** require product data in CNA records (as CVE sponsor); publish KEV listing lag; speed review on credible third-party reports.
3. **Congress:** route oversight through the GAO review House ranking members requested in June 2025 (no GAO product yet) and any CVE-codification bill (none in the FY2027 NDAA texts); tie it to the metrics, not new spending.

Cost box: re-check rule at an EPSS 10% threshold ≈ 16–46 CVEs/month (CVE Floodline day-30 crossing rate × our 30-day volume), well under 1% of NIST's ~5,000/month peak output (OIG), ~$8K–$66K/yr at 20–60 analyst-minutes and $120/h, vs. the OIG's ~$800K over two years (~$400K/yr). Lower bound: day-90 crossings, the older Not Scheduled stock, and SSVC/third-party triggers are not counted. (The earlier 250–470/month and $270K–$510K figures are retired; see `docs/data-notes.md`.)

## Checks before submitting
- [ ] Every number matches the scorecard and its source
- [ ] Vendor-sourced figures are attributed
- [ ] Under 3 pages including any figure
