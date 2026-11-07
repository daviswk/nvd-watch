# Predictive vulnerability prioritization (EPSS and complements) as a basis for an NVD enrichment trigger, 2019 to Nov 6, 2026

Research date: 2026-11-06. Roughly 25 sources were searched or fetched. Some primary documents could not be opened: the full Commerce OIG report PDF is marked "SECURED," and the FIRST EPSS changelog page was not fetched. Where a finding rests on a secondary source, these notes say so.

## Q1. Current EPSS model version, its inputs, and its dependence on NVD enrichment

### Takeaway
EPSS v4, released March 17, 2025, is the current model. No v5 was found as of Nov 6, 2026. EPSS v3 drew most of its roughly 1,477 features from NVD enrichment fields: CVSS vectors, CWE, and CPE-derived vendor labels. v4 explicitly falls back to CNA and ADP data on cve.org when NVD enrichment is missing. The student's concern is therefore partly mitigated: the dependency is real, but the model is not left without inputs. Threat-activity signals (exploit code, chatter, scanners, telemetry), which do not depend on NVD, drive the daily score changes.

### Cited Findings
**Versions and dates**
- v1 public scores began Jan 7, 2021. v2 came Feb 4, 2022, v3 Mar 7, 2023, and v4 Mar 17, 2025 (FIRST, "EPSS Version 4 Released," 17 Mar 2025). No v5 is listed. — [Wikipedia, EPSS](https://en.wikipedia.org/wiki/Exploit_Prediction_Scoring_System) (secondary source; only the v4 date is cited to FIRST. The v2 and v3 dates are uncited there.)
- The original EPSS paper (Jacobs, Romanosky, Edwards, Roytman, Adjerid; Cyentia/RAND) was posted in 2019. — [arXiv 1908.04856](https://arxiv.org/pdf/1908.04856)
- FIRST FAQ: "Model updates are driven by evidence of performance degradation, not a fixed calendar… retraining has occurred approximately annually." The first line of each daily CSV names the model version that produced the scores. — [FIRST EPSS FAQ](https://www.first.org/epss/faq)
- The first.org/epss landing page and model page name no current version number. They link to a "version changelog," which I did not fetch. — [FIRST EPSS](https://www.first.org/epss/); [FIRST EPSS model](https://www.first.org/epss/model)

**v3 features (Jacobs et al. 2023, "Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with Community-Driven Insights," arXiv 2302.14172, v1 Feb 27, 2023, rev. Jun 15, 2023)** — [arXiv HTML](https://arxiv.org/html/2302.14172v2)
- The model has 1,477 features, reduced from 28,724 before sparsity reduction. It uses XGBoost.
- Feature groups (Table I):
  - Exploitation activity labels: Fortinet, AlienVault, Shadowserver, GreyNoise.
  - Published exploit code (3): Exploit-DB, GitHub, Metasploit.
  - Lists (3): CISA KEV, Google Project Zero, ZDI.
  - Twitter mentions (3).
  - Scanners (4): Intrigue, sn1per, jaeles, nuclei.
  - References with labels (17): MITRE CVE List **and NVD**.
  - Description keywords (147): MITRE CVE text.
  - **CVSS metrics (15, one-hot): NVD.**
  - **CWE (188): NVD.**
  - **Vendor labels (1,096): NVD.** The paper's own text says 1,040 here, so the paper is internally inconsistent.
  - Age of the CVE: MITRE.
- By my count, about 1,299 of the 1,477 features (CVSS, CWE, and vendor) come from NVD-sourced fields, plus part of the 17 reference features. This is a feature count, not a measure of importance. I did not obtain SHAP importance rankings.
- Missing-data handling in v3:
  - 21,570 CVEs had no CWE. The model has explicit "CWE unavailable" flags.
  - For 73,327 CVEs scored only with CVSS v2, a neural network imputed v3 vectors. It matched the exact vector 74.9% of the time.
  - For vendors: "no attempt was made to fill in missing information."

**v4 changes (Jay Jacobs, Empirical Security, "Introducing EPSS Version 4," dated "Mar 16"; the year is inferred as 2025 from the release date)** — [Empirical Security](https://research.empiricalsecurity.com/research/introducing-epss-version-4)
- v4 is "Using cve.org CNA/ADP information as backup to NVD enrichment (CPE/CVSS)."
- It adds web and RSS mentions from hundreds of sources, Shodan-scanned vulnerabilities, and HackerOne Hacktivity. Stale sources were removed.
- CWEs are collapsed into 22 top-level categories plus CWE-1400.
- Exploitation labels now include malware activity and endpoint detections, about 12,000 vulnerabilities per month.
- REJECTED CVEs are no longer scored.
- No v4 feature count is given (v3 had about 1,500). The post does not explicitly discuss how CVEs with no CVSS, CPE, or CWE from any source are scored.

**Inputs according to the FIRST FAQ** — [FIRST EPSS FAQ](https://www.first.org/epss/faq)
- "EPSS uses all individual CVSS metrics as input features (scores are ignored)."
- Daily changes are driven by "exploit code availability, discussions, posts and chatter, reference volume and others."
- Partner telemetry is shared "under agreements that prohibit redistribution."
- Scoring of reserved-but-unpublished CVE IDs is "underway."
- The FIRST model page says model selection tests whether to use "all of the CWE's (there are nearly 600 unique CWE's used in NVD)" or parent nodes. — [FIRST EPSS model](https://www.first.org/epss/model)
- A Cloud Security Alliance research note (Apr 26, 2026) says EPSS v4 scores every published CVE "regardless of NVD status," using CNA-supplied data plus exploit and PoC signals for unenriched CVEs. **Caveat:** the document states it is AI-assisted and has not had official CSA review. — [CSA research note, Apr 26, 2026](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_nist_nvd_riskbased_enrichment_governance_20260426-csa-styled.pdf)

**Availability of the replacement inputs**
- Commerce OIG (OIG-26-020-I, May 26, 2026), as reported by Tech Times: 80% of submissions already arrive with a submitter severity score. — [Tech Times, Jun 2, 2026](https://www.techtimes.com/articles/317594/20260602/nist-national-vulnerability-database-severity-scores-wrong-88-time-inspector-general-finds.htm); [OIG report page](https://www.oig.doc.gov/reports/?entry=70787)
- The CSA note puts CVSS v3.1 coverage on 2026 records "above 85%," citing "ecosystem reporting." It estimates a gap of about 40% in CPE applicability for post-April-2026 CVEs, derived by inverting an earlier coverage figure. Both numbers are soft. — [CSA research note](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_nist_nvd_riskbased_enrichment_governance_20260426-csa-styled.pdf)
- CISA ADP (Vulnrichment) stopped adding CPE strings on Dec 10, 2024. — [cisagov/vulnrichment README](https://github.com/cisagov/vulnrichment)

### Inferences
- EPSS's structural features lean heavily on NVD in v3, but v4's CNA/ADP fallback means the collapse in NVD coverage weakens EPSS's inputs more than it removes them. CNAs now supply most CVSS vectors (about 80–85%+) and many CWEs.
- The input most at risk is vendor/product identification, which v3 drew from NVD CPE. CPE is the field with no free replacement. CNA "affected" vendor fields on cve.org may partly substitute, but I did not confirm that EPSS v4 uses them for vendor features.
- There is a likely second-order effect. If NVD CWE and CVSS are absent and CNA data is inconsistent (see Q2 on the OIG finding of 1–2 point CNA scoring variance), base-rate scores for new CVEs may become noisier. I found no published study that measures EPSS accuracy separately for NVD-enriched and unenriched CVEs. **This is the key unverified point.**
- Because EPSS's threat signals (exploit code, chatter, scanners, telemetry) do not depend on NVD, a trigger built on EPSS should keep working for CVEs that attract exploitation attention, even after enrichment collapses.

### Gaps
- FIRST's own v4 technical documentation (feature list, feature count, importance) was not found. The FIRST changelog was not fetched.
- No quantitative study of EPSS v4 performance on CVEs that lack NVD enrichment, before or after the April 2026 triage change.
- No public breakdown of how much of EPSS's predictive power comes from NVD-derived features versus threat signals.
- The Q3 2026 NVD coverage figure of about 8.4% was not checked here.

## Q2. Published EPSS performance, and criticism (cold start, lag, volatility, gaming)

### Takeaway
On FIRST's own metrics, EPSS greatly outperforms CVSS thresholds. In 2023, EPSS at 0.10 flagged about 2.7% of CVEs and caught about 63% of exploited ones. CVSS 7+ flagged about 57% of CVEs and caught about 82%. Independent critiques find that EPSS often trails exploitation instead of predicting it for newly disclosed CVEs, and that ranking systems disagree with one another. This matters because about 29% of exploited CVEs in 2025 were exploited on or before their publication day.

### Cited Findings
**Developer-reported performance**
- v3 (2023 paper):
  - PR AUC: 0.7795 for v3, 0.4288 for v2, 0.2998 for v1, and 0.051 for CVSS v3.x.
  - At the F1 point, v3 flags 3.5% of CVEs with 78.5% efficiency (precision) and 67.8% coverage (recall). CVSS flags 13.7% of CVEs with 6.5% efficiency and 32.3% coverage.
  - At about 82% coverage, v3 needs about 7.3% of CVEs, versus 58.1% for CVSS High/Critical.
  - The paper also states an "82% improvement" over v2.
  - — [arXiv 2302.14172](https://arxiv.org/html/2302.14172v2)
- FIRST model page, October 2023 example on CVEs with NVD CVSS 3.x scores:
  - CVSS 7+: effort 57.4%, coverage 82.2%, efficiency 3.96%.
  - EPSS ≥ 0.10 (called "arbitrary"): effort 2.7%, coverage 63.2%, efficiency 65.2%.
  - — [FIRST EPSS model](https://www.first.org/epss/model)
- EPSS v4 post:
  - CVSS 7+ baseline: about 50.7% effort, 74.6% coverage, 6% efficiency.
  - EPSS at similar coverage: about 6% effort and 47% efficiency. The version is unstated.
  - v3 accuracy had "slowly and just slightly degraded over the last two years."
  - — [Empirical Security](https://research.empiricalsecurity.com/research/introducing-epss-version-4)
- FIRST FAQ on thresholds:
  - "There is no universal threshold… A threshold of 0.10 (10%) is commonly cited in the field but carries no special authority from EPSS."
  - "If direct evidence of active exploitation exists, that evidence should supersede EPSS."
  - "EPSS is not a complete risk score."
  - If a CVE is on KEV with a low EPSS, "Follow KEV."
  - — [FIRST EPSS FAQ](https://www.first.org/epss/faq)

**Limitations stated by the EPSS authors** — [arXiv 2302.14172](https://arxiv.org/html/2302.14172v2)
- Partner sensors give partial visibility and detection is signature-based.
- Network-attack bias: IoT, ICS/OT, automotive, and medical devices are underrepresented.
- The model cannot separate research scanning from malicious activity.
- Labels are noisy.
- Twitter signals are unvalidated.
- Adversarial poisoning and gaming were "not investigated."

**Independent critiques**
- Parla, "Efficacy of EPSS in High Severity CVEs found in KEV," arXiv 2411.02618 (Nov 4, 2024) — [arXiv PDF](https://arxiv.org/pdf/2411.02618)
  - Sample: about 90 KEV CVEs with CVSS ≥ 9.0, added Mar 2023 to Jul 2024.
  - Of 57 CVEs from 2023 onward, 42 had "consistently low (mostly single digit)" EPSS before KEV inclusion.
  - Across 250 KEV CVEs, "more than two thirds" were below the 36% threshold just before KEV addition.
  - Fortinet CVE-2024-21762 stayed "near zero" for six months.
  - Conclusion: EPSS "appears to be a trailing indicator of exploitation rather than a predictive system."
  - Limitation: the paper evaluates v3 only and is a single-author study.
- The same paper notes a Log4j volatility case from EPSS v2: removing a Metasploit module dropped the score by more than 30 points, and it recovered about 25 days later.
- Koscinski et al., "Conflicting Scores, Confusing Signals: An Empirical Study of Vulnerability Scoring Systems," arXiv 2508.13644 (Aug 19, 2025). The study covers 600 Microsoft Patch Tuesday CVEs across CVSS, SSVC, EPSS, and the Exploitability Index. It finds "significant disparities in how scoring systems rank the same vulnerabilities." The abstract I read gave no specific figures. — [arXiv 2508.13644](https://arxiv.org/abs/2508.13644)

**The cold-start problem in context**
- VulnCheck, "2026 State of Exploitation," covering 2025 data:
  - 884 KEVs with first-time exploitation evidence in 2025.
  - "28.96% of KEVs in 2025 were exploited on or before the day their CVE was published," up from 23.6% in the prior report.
  - Time to exploitation: 9% within 1–31 days, 26% within 32–365 days, and 36% after more than one year.
  - — [VulnCheck 2026 State of Exploitation PDF](https://wwv.vulncheck.com/hubfs/Research/2026-StateofExploitation.pdf?hsLang=en)
- SANS ISC (Xavier Mertens, Apr 20, 2026) cites about 110 new CVEs per day and "~1,400 signals updated daily." Its tiers (≥0.90 critical, ≥0.50 high, ≥0.10 medium) are the author's own choice, not FIRST guidance. — [SANS ISC diary](https://isc.sans.edu/diary.html?date=2026-04-20)

### Inferences
- **What a ≥0.10 trigger would cost.** On the 2023 whole-corpus figures, an EPSS ≥ 0.10 trigger would flag about 2.7% of scored CVEs. That is a small, manageable add-on to the NIST queue. The share among *newly published* CVEs in their first days is probably lower, since scores start low. That is an inference: I found no published distribution of EPSS scores at publication time.
- **Where EPSS helps.** It is weakest exactly where NVD triage acts: at publication, before exploit signals accumulate. It is strongest on older, unenriched CVEs that later attract exploit code or chatter. An EPSS trigger therefore works better as a *re-queue* mechanism, pulling "Not Scheduled" or backlog CVEs back into enrichment when their score crosses a threshold, than as an intake filter.
- **Gaming.** No paper documents gaming of EPSS. The developers acknowledge it as uninvestigated. A public government trigger tied to EPSS could create an incentive to inflate chatter or references. That risk is speculative.

### Gaps
- No independent peer-reviewed evaluation of EPSS v4 specifically.
- No published data on EPSS score distributions at the time of CVE publication.
- No study of EPSS for AI-discovered vulnerabilities.
- The Koscinski et al. agreement statistics were not extracted (only the abstract was read).
- The cvedaily.io post "EPSS Accuracy Tested Against 1,673 Exploited CVEs" (Aug 21, 2026) appeared in search but was not fetched. It is a low-provenance blog.

## Q3. NIST CSWP 41, "Likely Exploited Vulnerabilities" (Mell and Spring, 2025)

### Takeaway
CSWP 41 (May 19, 2025) is a NIST-authored metric built *directly on EPSS score histories*. It estimates the probability that a CVE has *already* been exploited. NIST frames it as a complement to KEV, for checking KEV completeness and flagging CVEs that KEV or EPSS may miss. Its error margin is "currently unknown," and it has not been empirically validated. It strengthens the case that NIST already treats EPSS as a legitimate input. It also inherits EPSS's input dependencies and adds lag of its own.

### Cited Findings
All findings in this section come from [NIST CSWP 41 PDF](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.41.pdf). The CSRC announcement is [here](https://csrc.nist.gov/news/2025/nist-publishes-cybersecurity-white-paper-41).

**What LEV is**
- Peter Mell (NIST, listed as a former NIST employee) and Jonathan Spring (CISA). Dated May 19, 2025.
- LEV is a "proposed metric" that aims to "measure probabilities that vulnerabilities have been observed to be exploited in the past."
- LEV is one minus the product of (1 − EPSS × window weight) across 30-day windows of a CVE's EPSS history. LEV2 is a daily variant that costs more to compute.
- Adding EPSS scores "can only increase" LEV. Missing days lower it, so LEV is treated as a lower bound.
- Example: CVE-2023-1730 has a peak EPSS of 0.16 but an LEV of 0.70.

**Results**
- On 2025-01-16, about 1,006 of 66,125 CVEs with EPSS v3 scores (1.5%) were expected to be exploited. Across all CVEs, the figure was 39,925 of 273,979 (14.6%).
- KEV had 1,228 entries in December 2024 (about 0.5% of CVEs).
- Even at a 0.1 threshold, an LEV list covers no more than 60% of KEV. Several hundred CVEs have LEV near 1.0 but are not on the tested KEV lists.

**Uses and limits**
- Stated uses:
  - Measure the expected proportion of exploited CVEs.
  - Estimate how comprehensive KEV is.
  - Augment KEV-based prioritization.
  - Augment EPSS-based prioritization.
- The paper proposes a composite score: max(EPSS, KEV=1.0, LEV). It suggests a threshold of about 20% may give a manageable list, while stating this "will NOT produce a comprehensive KEV list."
- Limitations:
  - EPSS underestimates the probability for vulnerabilities that were already exploited.
  - LEV "inevitably has a margin of error which is currently unknown."
  - No empirical performance data exists yet. NIST is seeking industry partners for exploitation datasets.
- The paper relies on NVD only for the CVE list, publish dates, and descriptions.

### Inferences
- CSWP 41 is the strongest precedent for the student's proposal. It shows NIST itself designing KEV-plus-EPSS composite prioritization.
- "max(EPSS, KEV, LEV) ≥ threshold" maps naturally onto an extra triage criterion: enrich if a CVE is on KEV, or if EPSS or LEV crosses X.
- LEV needs score history, so it suits backlog re-prioritization, such as the roughly 29,000 "Not Scheduled" pre-March-2026 CVEs. It does not suit day-zero intake.
- I found no evidence that NIST has adopted LEV operationally in the NVD or in the April 2026 triage criteria.

### Gaps
- No public follow-up validation of LEV through Nov 2026.
- No evidence of LEV deployment in NVD or CISA tooling.
- The equations in the fetched text were partly garbled. Exact notation should be checked against the PDF.

## Q4. CISA Vulnrichment (the CISA ADP container): 2026 status and whether it substitutes for NVD

### Takeaway
Vulnrichment is still active in 2026. It adds SSVC decision points (Exploitation, Automatable, Technical Impact) to CVE records, plus KEV flags. It adds CVSS and CWE only for higher-risk CVEs with enough evidence, and it has added no CPE since Dec 10, 2024. It is a partial complement, not a substitute for NVD, because product applicability (CPE) is the missing piece. The OIG also found NIST and CISA duplicating enrichment work.

### Cited Findings
- Scope, from the README — [cisagov/vulnrichment](https://github.com/cisagov/vulnrichment):
  - It is "the public repository of CISA's enrichment of public CVE records through CISA's ADP (Authorized Data Publisher) container."
  - SSVC is added to every analyzed CVE.
  - CWE and CVSS are added for higher-risk CVEs "where possible." Those are CVEs rated Total Technical Impact, Automatable, or with Exploitation of PoC or Active.
  - CPE was discontinued Dec 10, 2024.
  - CNA data is not overwritten, and CISA drops its own values if the CNA later supplies them.
  - The README gives no coverage statistics. The repo has about 12,978 commits, year folders through 2026, and is "under active development."
- Launch: CISA announced Vulnrichment in May 2024. — [SecurityWeek](https://www.securityweek.com/cisa-announces-cve-enrichment-project-vulnrichment/amp/); [Help Net Security](https://helpnetsecurity.com/?p=300848) (from search snippets only, not fetched)
- Coverage claim: the CSA note says CISA ADP publishes SSVC decisions on "most non-priority CVEs within days of publication." This comes from an AI-assisted, unreviewed source and was not confirmed against CISA data. — [CSA research note](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_nist_nvd_riskbased_enrichment_governance_20260426-csa-styled.pdf)
- Commerce OIG (OIG-26-020-I, May 26, 2026), as reported by Tech Times — [Tech Times](https://www.techtimes.com/articles/317594/20260602/nist-national-vulnerability-database-severity-scores-wrong-88-time-inspector-general-finds.htm):
  - At least 21,000 instances of duplicated NIST/CISA enrichment from May 2024 to Dec 2025, costing about $200,000 deemed unallowable or unreasonable.
  - CISA stopped CPE applicability statements in Dec 2024, leaving NIST as the sole federal CPE provider.
- VulnCheck has written on automating SSVC, which suggests SSVC can be derived from exploitation and automatability data. Not fetched. — [VulnCheck blog, "Automating SSVC"](https://www.vulncheck.com/blog/automating-ssvc)

### Inferences
- SSVC's "Exploitation" decision point (none / PoC / active) is a categorical alternative to EPSS for a trigger: for example, enrich if CISA ADP marks Exploitation as PoC or Active. It has the advantage of being a federal, human-reviewed signal. Its coverage and latency in 2026 are unverified.
- A trigger combining Vulnrichment SSVC with EPSS would hedge EPSS's cold-start weakness with CISA analyst judgment.

### Gaps
- No authoritative 2026 statistics on what share of new CVEs carry CISA ADP SSVC data, or how quickly.
- No CISA announcement in 2025 or 2026 changing Vulnrichment's scope was found.
- The OIG's six recommendations were not obtained, because the full PDF is marked "SECURED."

## Q5. Workload and cost of enriching a CVE (to replace the "20 minutes per CVE" assumption)

### Takeaway
I found **no published analyst-minutes-per-CVE figure** from NIST, the OIG (in the reporting I could read), or the trade press. The defensible numbers are throughput and budget:
- NIST enriched about 42,000 CVEs in 2025.
- Its target was about 6,200 per month, and it never exceeded 5,000 in any month.
- CISA had provided about $3.8M a year to NVD until FY2024.
- The backlog exceeded 27,000 by the end of 2025.

The "20 minutes" figure should be presented as an assumption with sensitivity ranges, or replaced with throughput-based capacity math.

### Cited Findings
- NIST enriched "nearly 42,000" CVEs in 2025, 45% more than any prior year and "not enough to keep up." CVE submissions rose 263% from 2020 to 2025. — [Help Net Security, Apr 16, 2026](https://www.helpnetsecurity.com/2026/04/16/nist-national-vulnerability-database-nvd-enrichment/)
- April 2026 triage policy:
  - Priority goes to CVEs that are on KEV (target of one business day), in federal-government software, or in EO 14028 critical software.
  - Others are ingested but marked "Not Scheduled." CVEs published before Mar 1, 2026 will not be enriched (about 29,000 records).
  - NIST will rely on CNA CVSS scores instead of adding its own.
  - Requests go to nvd@nist.gov.
  - Harold Booth of NIST: "our ability to keep up is just not there."
  - — [Help Net Security](https://www.helpnetsecurity.com/2026/04/16/nist-national-vulnerability-database-nvd-enrichment/); [CSA research note](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_nist_nvd_riskbased_enrichment_governance_20260426-csa-styled.pdf)
- Commerce OIG, "Evaluation of NIST's Management of the National Vulnerability Database," OIG-26-020-I (May 26, 2026). Report page: [OIG](https://www.oig.doc.gov/reports/?entry=70787). The figures below come from secondary reporting by [Tech Times, Jun 2, 2026](https://www.techtimes.com/articles/317594/20260602/nist-national-vulnerability-database-severity-scores-wrong-88-time-inspector-general-finds.htm):
  - Backlog: about 13,000 in June 2024, more than 27,000 by end of 2025.
  - Throughput: target about 6,200 per month, never above 5,000.
  - Contract history: the enrichment contract lapsed in Feb 2024; Analygence was awarded a contract in May 2024; there was no fully trained team until Nov 2024.
  - Funding: CISA's roughly $3.8M a year for NVD was not renewed in FY2024.
  - Savings: about $800K over two years could be freed by scaling back NIST re-scoring.
  - Re-scoring check: only 8 of 69 sampled NIST scores matched OIG re-scores. The "88%" figure is a mismatch rate, not verified error.
  - NIST concurred with all six recommendations, with an action plan due Jul 31, 2026.
- The full OIG PDF is marked SECURED: [OIG-26-020-I PDF](https://www.oig.doc.gov/wp-content/OIGPublications/OIG-26-020-I-SECURED.pdf). I could not extract staffing, FTE, or contract-value figures from it.
- The CSA note explicitly gives no staffing, budget, cost-per-CVE, or analyst-time figures. — [CSA research note](https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/04/CSA_research_note_nist_nvd_riskbased_enrichment_governance_20260426-csa-styled.pdf)

### Inferences
- **Capacity frame.** Use about 5,000 CVEs per month as a demonstrated ceiling, or about 42,000 per year in 2025. Pair it with the incoming volume of about 110 CVEs per day ([SANS ISC](https://isc.sans.edu/diary.html?date=2026-04-20)), which is about 3,300 per month. That figure is not authoritative, and the 2026 volume is reportedly about one-third higher year over year (per the CSA note). The question for the proposal then becomes how many extra CVEs per month an EPSS trigger adds, not minutes per CVE.
- **Size of the EPSS add-on.** An EPSS ≥ 0.10 trigger flagging about 2.7% of CVEs (2023 FIRST figure) would add roughly 100 or fewer CVEs per month at current intake, before deduplicating against KEV and federal/critical-software CVEs. A ≥ 0.50 trigger would add fewer. This is an order-of-magnitude estimate built on cross-period numbers and should be labeled as such.
- **Cost proxy.** If the student needs one, CISA's $3.8M a year against about 42,000 CVEs a year implies about $90 per CVE. This is a crude upper-bound framing only: the $3.8M was a past CISA contribution, not NVD's total budget, and the two figures cover different years.
- **Re-scoring savings.** The OIG's finding that NIST re-scoring is largely redundant (80% of CVEs arrive with CNA scores) supports the student's argument that freed capacity could be redirected to EPSS-triggered CPE/applicability enrichment.

### Gaps
- No public NVD staffing count, NVD line-item budget, contract value (Analygence), or analyst time per CVE was found.
- NIST budget justifications and congressional testimony were not located in this pass.
- The OIG's six recommendations are unknown.
