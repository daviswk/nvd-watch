# Policy brief outline (≤ 3 pages)

**Title (working):** Re-check, Then Measure: Closing the Product-Data Gap in the National Vulnerability Database

**Lead with measurement, not failure.** Opening line: no one publishes how quickly NIST attaches product data to CVEs; here are the numbers. The first result partly vindicates NIST: once CISA lists a CVE as exploited, NIST attaches CPE within its one-business-day goal (17 of 18 in our window; the 18th was listed the day before the pull). The gap is *before and outside* KEV. The brief has to work whatever the weekly data shows.

**Shape (red-team #23):** three findings, three recommendations. Everything else goes to the scorecard's methods and an appendix link. The brief must stand alone without the site (#17).

## Page 1 — Background
- What the NVD does, and why product data (CPE) is what lets scanners tell an organization it is affected.
- NIST's April 15, 2026 triage: KEV, federal, and EO 14028 critical software first; no routine re-scoring of CNA-scored CVEs.
- Why now: CVE volume roughly doubled in 2026; AI discovery accelerates a capacity gap that began with a February 2024 contract lapse (OIG).
- Hook figure: median CVE-to-KEV lag 4 → 10 days (2023 → 2025; 9 in 2026 to Nov 6), our count from KEV + NVD (`scripts/kev_lag.py`), grouped by year added. Barracuda reports 6 → 14 for the same population. Know the biases (#6): grouping by year added mixes in old CVEs listed late (pushes up); the current year is incomplete (pushes down).
- Definition (#21): CPE arrives "when defenders need it" if it is there **by the day CISA confirms exploitation** (KEV listing).

## Page 2 — Challenges and opportunities
**Three findings**
1. **After KEV, NIST performs.** 17 of 18 KEV-listed CVEs in the Oct 8 – Nov 7 window got CPE within one business day, all by NIST, 7 of them by the listing day (`scripts/kev_enrichment.py`, NVD change history).
2. **Before KEV, nothing re-checks.** 22.6% of non-KEV CVEs have CPE; 40.8% of new CVEs are Not Scheduled. Example: CVE-2026-59774 (Gitea unauthenticated file read, chainable to command execution per the CNA), Not Scheduled, no CPE, EPSS 0.28 on Nov 7, not in KEV. Present it as at risk; it is *not* confirmed exploited, and we checked only KEV.
3. **KEV is late and narrow.** It lists after attacks begin (PHP2Shell: KEV nine days after the first attempt; PHP got CPE on day one as federally used software, so it shows listing lag, not the CPE gap), and it is narrow (VulnCheck's 884 vs CISA's 245 exploited CVEs in 2025; vendor figure, different inclusion rules).

**Context (one line each)**
- Coverage numbers conflict (≈50% vs 8.4%) because no official definition exists; status labels changed mid-series.
- Format-neutral (#12): 94% of new CVEs carry CNA free-text product data, but 71.3% have it without CPE. The gap is machine-matchable product data from any source (CPE, structured `affected`, purl); NVD Watch measures coverage regardless of who supplies it (#14). Distributed enrichment (EU vulnerability database, GCVE, vendors) complements this; the NVD stays the free baseline FedRAMP and PCI reference.
- Who bears the gap: state/local governments (MS-ISAC lost federal funding in 2025), hospitals, small businesses — organizations that can't buy commercial enrichment.
- Limits stated plainly: counts are CVEs, not risk (#22). A missing label on an obscure plugin is not the same as one on a firewall; the EPSS cuts are a partial exposure weighting. Some threats never reach a matchable CVE record (the Aug 2026 Siemens S7 advisory AA26-231A listed no CVE IDs).

**Opportunities**
- EPSS leads KEV by ~201 days when it leads at all (Barracuda, KEV-only sample, #8), so it is a re-check trigger for stalled CVEs, not an intake screen. Precision (how many re-queued CVEs later prove exploited) is unmeasured, and so is EPSS accuracy on unenriched CVEs (#9). Both should be stated as open.
- NIST already designed the composite (CSWP 41: max of EPSS, KEV, LEV). FedRAMP's 2026 rules already use KEV (not EPSS).
- The CVE Program's Supplier ADP pilot already lets product vendors add affected-product data to other CNAs' records: Siemens and Red Hat have covered 3,349 CVEs since April 2026 (SADP Tracker). It fills CVE's `affected` field, not CPE.
- NIST's RFI (question 7(e)) asked the public for metrics. NVD Watch is a working answer. RogoLabs' trackers measure the CVE ecosystem; none measures NIST's enrichment performance (#19).

## Page 3 — Recommendations
1. **NIST:** adopt and publish a re-check rule; log every re-queue; publish five quarterly metrics with frozen definitions; **publish each CVE's priority tier** (KEV, federal, EO 14028, none) so the triage itself can be checked (#3). Until it does, metrics 1 and 2 are reported by observable tiers: KEV status and NVD status.
2. **CISA:** as CVE sponsor, **phase in** structured product data in CNA records, starting with the largest vendor CNAs and building on the Supplier ADP pilot (#15); as KEV owner, publish listing lag and set a review clock for credible third-party reports.
3. **Congress:** route oversight through the GAO review House ranking members requested in June 2025 (no GAO product yet) and any CVE-codification bill (none in the FY2027 NDAA texts); tie it to the metrics, not new spending.

Cost box (#4): re-check rule at an EPSS 10% threshold ≈ 16–46 CVEs/month (CVE Floodline day-30 crossing rate × our 30-day volume), **0.3–0.9% of NIST's ~5,000/month peak output** (OIG), ~$8K–$66K/yr at 20–60 analyst-minutes and $120/h. For scale only: about 2–17% of the ~$400K/yr (≈$800K over two years) the OIG put on routine re-scoring, which NIST stopped in April 2026 and NIST disputes. That capacity already went to triage, so it is a comparison, not found money. Lower bound: day-90 crossings, the older Not Scheduled stock, and SSVC/third-party triggers are not counted.

**What would change the recommendation (#5, say it in the brief):** if high-EPSS CVEs that are Not Scheduled or Awaiting get CPE anyway within a few weeks, without a rule, the rule adds nothing and the ask shrinks to the metrics. If NIST stopped meeting its KEV goal, the priority would shift from the re-check rule to KEV compliance.

**RAND (#10), one sentence:** RAND has not studied the NVD directly; this project applies RAND frameworks (incentives, accountability, continuous measurement) to it, and EPSS's lineage includes RAND-affiliated authors.

## Checks before submitting
- [ ] Every number matches the scorecard and its source (`summary.json`, `kev_enrichment.json`)
- [ ] Vendor-sourced figures are attributed
- [ ] Under 3 pages including any figure
- [ ] Each number in the brief has a "how verified" note in the AI log (#20)
