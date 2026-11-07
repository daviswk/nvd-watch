# Policy brief outline (≤ 3 pages)

**Title (working):** Re-check, Then Measure: Closing the Product-Data Gap in the National Vulnerability Database

## Page 1 — Background
- What the NVD does, and why product data (CPE) is what lets scanners tell an organization it is affected.
- NIST's April 15, 2026 triage: KEV, federal, and EO 14028 critical software first; no routine re-scoring of CNA-scored CVEs.
- Why now: CVE volume roughly doubled in 2026; AI discovery accelerates a capacity gap that began with a February 2024 contract lapse (OIG).
- Hook figure: median CVE-to-KEV lag 6 → 14 days (2023 → 2026).

## Page 2 — Challenges and opportunities
**Challenges**
- KEV is the gate for CPE on most software, and it is slow and narrow (884 vs 245 exploited CVEs in 2025).
- Coverage numbers conflict (≈50% vs 8.4%) because no official definition exists; status labels changed mid-series.
- EPSS can't reliably flag brand-new CVEs (leads KEV in only 19% of cases).
- Who bears the gap: state/local governments (MS-ISAC lost federal funding in 2025), hospitals, small businesses — organizations that can't buy commercial enrichment.
- One limit, stated plainly: some threats never get a CVE (e.g., 2026 Siemens S7 PLC campaign), so no enrichment rule helps.

**Opportunities**
- EPSS leads KEV by ~201 days when it leads at all, which makes it a good re-check trigger for stalled CVEs.
- NIST already designed the composite (CSWP 41: max of EPSS, KEV, LEV). FedRAMP's 2026 rules already use KEV and EPSS.
- The OIG found re-scoring effort NIST can redirect (~$400K/yr).
- The CVE Program's Supplier ADP pilot already lets product vendors add affected-product data to other CNAs' records: Siemens and Red Hat have covered 3,349 CVEs since April 2026 (SADP Tracker). CISA, as CVE sponsor, could expand it. It fills CVE's `affected` field, not CPE, so it complements rather than replaces NIST enrichment.
- NIST's RFI (question 7(e)) asked the public for metrics. NVD Watch is a working answer. Independent open-source trackers (CVE.ICU, CVE Floodline, CNA Scorecard, CNAPulse) measure volume and CNA quality, but none measures NIST's enrichment performance.

## Page 3 — Recommendations
1. **NIST:** adopt and publish a re-check rule; log every re-queue; publish five quarterly metrics with frozen definitions.
2. **CISA:** require product data in CNA records (as CVE sponsor); publish KEV listing lag; speed review on credible third-party reports.
3. **Congress:** route oversight through the pending GAO review and CVE-codification language; tie it to the metrics, not new spending.

Cost box: re-check rule at an EPSS 10% threshold ≈ 16–46 CVEs/month (CVE Floodline day-30 crossing rate × our 30-day volume), well under 1% of NIST capacity, ~$7K–$58K/yr at 20–60 analyst-minutes and $120/h, vs. ~$400K/yr OIG offset. Lower bound: day-90 crossings, the older Not Scheduled stock, and SSVC/third-party triggers are not counted. (The earlier 250–470/month and $270K–$510K figures are retired; see `docs/data-notes.md`.)

## Checks before submitting
- [ ] Every number matches the scorecard and its source
- [ ] Vendor-sourced figures are attributed
- [ ] Under 3 pages including any figure
