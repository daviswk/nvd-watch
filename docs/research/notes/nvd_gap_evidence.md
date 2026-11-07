# NVD Enrichment Gap and CISA KEV Timeliness: Evidence Review (2024 to Nov 6, 2026)

Research date: 2026-11-06. All URLs were retrieved during this session unless marked "not verified." Where a source page had no visible publication date, that is noted.

## Q1. What independent analyses measure NVD enrichment coverage, backlog, or time-to-enrichment (2024 to 2026)?

### Takeaway
Independent measurements exist, but they cover different windows, use different definitions of "enriched," and disagree. The strongest post-policy data point (Volerion via Dark Reading, Apr 15 to Jun 15, 2026) found NIST enriched about half of newly published CVEs. That contradicts both CSA's pre-policy estimate (15 to 20% full enrichment) and the student's Cyber Strategy Institute figure (~8.4% in Q3 2026). I could not find the CSI report at all. A big jump in CVE volume in H2 2026 (about 2.2x year over year) could plausibly reconcile some of the gap, but nobody has published that reconciliation.

### Cited Findings
**NIST's own figures (April 15, 2026 policy)**
- CVE submissions rose 263% between 2020 and 2025. Q1 2026 submissions ran "nearly one-third higher" than Q1 2025. NIST enriched nearly 42,000 CVEs in 2025, 45% more than any prior year. The new prioritization took effect April 15, 2026. Backlogged CVEs with an NVD publish date before March 1, 2026 moved to "Not Scheduled." KEV CVEs have a goal of enrichment "within one business day of receipt." NIST will no longer routinely add its own score when a CNA has already provided one. NIST will reanalyze modified CVEs only when the change materially affects enrichment. Users can request enrichment by emailing nvd@nist.gov ("as resources allow"). The release gives no backlog count and no staffing figures. — [NIST news release, Apr 2026](https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth)
- NIST says it updated the NVD Dashboard to report status "in real time." The one-business-day KEV goal is the only performance target NIST stated. — [NIST news release](https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth)

**Size of the "Not Scheduled" move (the ~29,000 figure)**
- CSA says "~29,000 CVEs published before March 1, 2026" were moved to "Not Scheduled." It estimates that only 15 to 20% of projected annual CVE volume will get full NIST enrichment, with about 80% catalogued without full CPE, CVSS and CWE. — [CSA Research Note, Apr 29, 2026 (modified May 20, 2026)](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-enrichment-overhaul-20260429-csa/)
- Infosecurity Magazine gives no count of Not Scheduled CVEs. The ~29,000 figure does not appear in its piece. NIST's April release also gives no count. **The ~29,000 figure traces to CSA (secondary), not to a NIST primary statement.** — [Infosecurity Magazine, Apr 16, 2026](https://www.infosecurity-magazine.com/news/nvd-enrichment-premarch-2026/); [Help Net Security, Apr 16, 2026](https://helpnetsecurity.com/2026/04/16/nist-national-vulnerability-database-nvd-enrichment) (also gives "no backlog total, no count of unscheduled CVEs")
- **Conflicting dashboard counts.** Brian Martin (jericho) logged the NVD dashboard's "Not Scheduled" count: 123,755 on Apr 15, 2026 and 103,786 on Apr 16, with further drops of 18,835 (Apr 22 to 23) and 19,906 (Apr 28 to 29), reaching 46,788 by May 7. That is about 77,000 records leaving the category, and no other status category explains where they went. He also says "Awaiting Analysis" disappeared and was replaced by "Awaiting Enrichment," and that "Deferred" was renamed "Not Scheduled." He calls the reporting a "shell game" whose numbers cannot be reconciled. — [jericho.blog, May 7, 2026](https://jericho.blog/2026/05/07/the-nvd-shell-game-schrodingers-enriched-vulnerability/)
  - Implication: "Not Scheduled" on the dashboard counts something other than the ~29,000 pre-March backlog. It appears to include previously "Deferred" (pre-2018 and other) records, and NIST's status relabeling makes time series unstable.

**Post-policy coverage and timeliness (Volerion via Dark Reading)**
- From Apr 15 to Jun 15, 2026: 13,441 accepted CVEs were published to NVD. NIST prioritized 8,342 for enrichment ("more than half"). It enriched 6,759 (≈50.3% of all published, ≈81% of prioritized), and 1,583 were left unanalyzed. Only 2,645 enriched CVEs got a NIST CVSS vector (≈19.7% of published), consistent with NIST no longer scoring CNA-scored CVEs. Median time-to-analysis was "nearly four days in May." Weekly "Awaiting Analysis" items were excluded from NIST's timeliness metrics. — [Dark Reading (no visible date; data window ends Jun 15, 2026, so likely mid to late June 2026)](https://darkreading.com/vulnerabilities-threats/nist-enrichment-reductions-cve-coverage-accuracy)
- Accuracy: Volerion found that about one-third of its disagreements with NIST involved Attack Complexity. Example: on CVE-2026-8856, NIST scored 9.1, IBM 7.7 and Volerion 4.4. Volerion notes FedRAMP requires NIST CVSS scores. — [Dark Reading](https://darkreading.com/vulnerabilities-threats/nist-enrichment-reductions-cve-coverage-accuracy)

**CVE volume in H2 2026 (denominator problem)**
- From January through October 2026, NVD recorded 92,319 CVEs, versus 41,213 in the same months of 2025 (2.24x). October 2026 alone had 17,481 versus 4,389 (17,060 versus 4,273 excluding rejected). These are RuntimeWire's own NVD API counts; RuntimeWire gives no enrichment percentages. — [RuntimeWire, Nov 1, 2026](https://runtimewire.com/article/nvd-recorded-2-24-times-as-many-cves-from-january-through-october-as-in-the-same)
- Pre-year forecasts: FIRST forecast ~50,000 CVEs in 2026. Jerry Gamblin (cveforecast.org) forecast 70,135, a 45.6% rise over 48,171 in 2025. — [Infosecurity Magazine, Apr 16, 2026](https://www.infosecurity-magazine.com/news/nvd-enrichment-premarch-2026/). Actual 2026 volume (≈92k through October) has already far exceeded both forecasts per [RuntimeWire](https://runtimewire.com/article/nvd-recorded-2-24-times-as-many-cves-from-january-through-october-as-in-the-same).

**2024 to 2025 independent coverage figures**
- VulnCheck: as of Sep 21, 2024, 18,358 of 25,357 CVEs added since Feb 12, 2024 (72.4%) were unanalyzed, down from 93.4% on May 19, 2024. 85.9% had some CVSS record (from CNAs or CISA). — [VulnCheck, "NVD backlog: exploitation lurking" (no visible date; data as of Sep 21, 2024)](https://www.vulncheck.com/blog/nvd-backlog-exploitation-lurking)
- VulnCheck NVD++ for 2024 CVEs: 76.95% CPE coverage versus 41.35% for NIST NVD, with CPE arriving about 4 days faster (VulnCheck data as cited by CSA). — [CSA Research Note, Apr 29, 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-enrichment-overhaul-20260429-csa/)
- VulnCheck (Apr 16, 2026) claims it "continues to outperform NIST NVD CPE enrichment in both volume of CVEs and speed," but publishes no numbers in the text. — [VulnCheck, Apr 16, 2026](https://www.vulncheck.com/blog/expanding-vulnerability-enrichment)
- Socket: "awaiting analysis" stood at 13,358 in June 2024 and nearly 18,000 about 3.5 months later. — [Socket, Oct 1, 2024](https://socket.dev/blog/nist-misses-2024-deadline-to-clear-nvd-backlog)
- Joe Toomey (Coalition): NVD has 21 analysts. About three-quarters of submitted CVEs went unprocessed at the early-2024 peak. — [Just Security, Apr 27, 2026](https://www.justsecurity.org/136914/nist-cant-keep-up/)

### Inferences
- Several numbers stand in apparent conflict: ~50% enrichment (Apr to Jun 2026, Volerion), CSA's projected 15 to 20%, and CSI's ~8.4% for Q3 2026. They may all be "right" under different definitions: share of prioritized CVEs, share of all published CVEs, share with a NIST CVSS vector, or share with CPE. A rising denominator matters too, since October 2026 volume was about 4x October 2025. NVD Watch should state its definition explicitly and publish a reproducible query.
- For "full enrichment," the share with a NIST-assigned CVSS vector (≈20% in Apr to Jun) and the share with any CVSS (CNA or NIST) are very different numbers. Using the first understates the protection defenders actually have.
- NIST's status relabeling (Awaiting Analysis to Awaiting Enrichment, Deferred to Not Scheduled) breaks time series across April 15, 2026. Any 2025 versus 2026 comparison has to harmonize categories.

### Gaps
- **The Cyber Strategy Institute "The Count Broke First" report (Oct 23, 2026) could not be found** by two searches. Its figures (~87% enrichment in 2025, ~8.4% in Q3 2026, ~2,070 unenriched 2026 CVEs with EPSS ≥ 0.10) are unverified and uncorroborated by any other source I found.
- I found no 2025 or 2026 enrichment-coverage studies from Anchore, Sonatype, Cyentia, Flashpoint, Rapid7 or Socket, and no arXiv paper, in this session's searches. Any such papers may exist but were not surfaced.
- No independent Q3 2026 enrichment-rate measurement was found.
- NIST has published no official count of the CVEs moved to Not Scheduled.

## Q2. What does the evidence show on KEV timeliness and coverage compared with alternatives (e.g., VulnCheck KEV)?

### Takeaway
CISA KEV is narrow and getting somewhat slower. The median from CVE publication to KEV listing rose from 6 days (2023) to 14 days (2026 YTD). VulnCheck KEV listed 884 exploited CVEs in 2025 against CISA's 245, usually earlier. In the PHP2Shell case, the "first exploitation" date depends on whether you count unsuccessful probes. Measured from confirmed successful exploitation, the lag is only about 1 to 2 days. That weakens a "KEV was 9 days late" framing.

### Cited Findings
- Barracuda measured the gap from CVE publication to KEV addition for 740 CVEs added to KEV since 2023. For 608 "new" CVEs (published 2022 or later), the median was 9 days overall: 6 days (2023), 9 (2024), 12 (2025), 14 (2026 so far). 48% were listed within 7 days. 132 of the 740 were "resurrection" CVEs published before 2022, typically about 5.5 years old at listing. Barracuda notes the KEV date "is the day CISA added the bug, not the day attacks began." — [Barracuda blog, Jul 24, 2026](https://blog.barracuda.com/2026/07/24/KEV-gap-how-fast-do-exploited-bugs-get-flagged)
- EPSS versus KEV (EPSS ≥ 0.10 threshold): EPSS crossed first in 19% of cases, KEV listed first in 57%, and EPSS never crossed in 23%. When EPSS led, it led by an average of 201 days. EPSS led in 17% of cases before the 2025-09-17 EPSS v4 switch and in 24% after. — [Barracuda, Jul 24, 2026](https://blog.barracuda.com/2026/07/24/KEV-gap-how-fast-do-exploited-bugs-get-flagged)
- VulnCheck 2025: 884 CVEs with first-time exploitation evidence in VulnCheck KEV versus 245 added to CISA KEV. VulnCheck KEV covered 518 vendors and 672 products; CISA KEV covered 99 vendors and 146 products. 28.96% were exploited on or before CVE publication day, up from 23.6% in 2024. VulnCheck says its evidence predated CISA's listing in most cases by "days, months, or even years" but gives no median lag. — [VulnCheck "State of Exploitation 2026," Jan 21, 2026](https://www.vulncheck.com/blog/state-of-exploitation-2026)
- 2024 KEV enrichment gap: as of Sep 2024, 92 of 197 KEVs (46.7%) added since Feb 12, 2024 were unanalyzed in NVD (50.8% in May 2024). — [VulnCheck](https://www.vulncheck.com/blog/nvd-backlog-exploitation-lurking); [Socket, Oct 1, 2024](https://socket.dev/blog/nist-misses-2024-deadline-to-clear-nvd-backlog)
- **PHP2Shell (CVE-2026-109618/109619) timeline. Sources conflict on the "first exploitation" date:**
  - Wiz found the flaw Aug 19, 2026 and reported it to PHP Aug 24. A leaked archive was submitted to VirusTotal Oct 21 at 02:29 UTC. Patchstack reported exploitation incidents Oct 21 at 07:34 UTC. The patch shipped Oct 21 at 13:52 UTC (8.2.35, 8.3.36, 8.4.27, 8.5.12). Both CVEs are CVSS v4.0 9.2; the scorer is not stated. — [Recorded Future, Oct 21, 2026](https://www.recordedfuture.com/blog/php2shell-vulnerability-exploitation)
  - Amazon Threat Intelligence said targeting began "four days before security patches were released" (≈Oct 17). Several firms (Cloudflare, Amazon, Hadrian, watchTowr, Patchstack and others) tagged the pre-disclosure attempts as **unsuccessful**. Successful in-the-wild exploitation was confirmed Oct 24 to 25 (honeypot, Perplexity's Adel Karimi). CISA added both CVEs to KEV Mon Oct 26 with an Oct 29 FCEB deadline under BOD 26-04. — [BleepingComputer, Oct 27, 2026](https://bleepingcomputer.com/news/security/cisa-confirms-php2shell-vulnerabilities-now-exploited-in-attacks)
  - So the student's "first exploitation Oct 17, KEV Oct 26" is supported by Amazon's attribution of *targeting*. But KEV was about 1 to 2 days after the first confirmed *successful* exploitation and 5 days after the patch.

### Inferences
- The lengthening median (6 to 14 days) is real evidence of declining KEV timeliness. But it measures publication-to-listing, not exploitation-to-listing.
- KEV entry is the *trigger* for NIST priority enrichment. Any lag in KEV therefore passes straight into the KEV-based tier of the triage policy. A KEV-gated policy can be no faster than KEV.
- PHP2Shell is a weak test of the *enrichment* gap. PHP almost certainly qualifies as federally used and/or EO 14028 critical software, so it would be prioritized regardless of KEV. Enrichment status of these CVEs in NVD was not reported by either source. Its main lesson concerns KEV (and exploitation-evidence) latency.
- The ratio of VulnCheck KEV to CISA KEV (884 vs 245 in 2025) implies that roughly 70% of CVEs with public exploitation evidence never trigger the KEV pathway in a given year. That is the best quantitative case that a KEV-gated policy misses exploited bugs. It depends on VulnCheck's broader evidence threshold, and VulnCheck is a commercial competitor.

### Gaps
- I found no peer-reviewed study of exploitation-to-KEV lag for 2024 to 2026 in this session. A Nucleus Security white paper referenced as a "55-day exploit window before KEV listing" (May 27, 2026) could not be fetched; its figure is **unverified**. — [nhimg.org summary (fetch failed)](https://nhimg.org/articles/public-pocs-create-a-55-day-exploit-window-before-kev-listing/); [Nucleus white paper page (not fetched)](https://nucleussec.com/resources/white-papers/the-exploitability-intelligence-gap/)
- VulnCheck publishes no median lag between VulnCheck KEV and CISA KEV.
- I found no measurement of NIST's compliance with its one-business-day KEV enrichment goal.

## Q3. Has NIST published anything since August 2026 (RFI, V-etalon, metrics, budget or staffing)?

### Takeaway
The RFI is confirmed (91 FR 52042, Aug 12, 2026, docket NIST-2026-0100, comments closed Oct 13, 2026, question 7(e) asks about metrics). I found nothing published by NIST after the RFI: no comment summary, no metrics, no budget or staffing statement. **"V-etalon" could not be verified anywhere**, and the RFI text does not mention it.

### Cited Findings
- The RFI is FR Doc. 2026-16371, 91 FR 52042 to 52044, Wed Aug 12, 2026, docket NIST-2026-0100, with comments due Oct 13, 2026 at 11:59 pm ET via regulations.gov. Its seven sections run from vulnerability management process through a vision for the NVD. Q7(e) asks: "What metrics should be considered to track and evaluate the success of the NVD." The notice discusses AI throughout but **names no specific tool**. It contains no CVE-volume or backlog statistics, only that NVD ingests CVE records "within approximately an hour of publication." The contact is Cristina Ritfeld. — [GovInfo Federal Register text](https://www.govinfo.gov/content/pkg/FR-2026-08-12/html/2026-16371.htm)
- Trade press framed the RFI as NIST wanting to "outfit the NVD with AI." — [Nextgov, Aug 2026](https://nextgov.com/cybersecurity/2026/08/nist-wants-outfit-national-vulnerability-database-ai/415371) (not fetched; title only)
- Disclose.io (Aug 15, 2026) urged comments and called for AI-enrichment error rates, provenance labels, appeal paths and human review. It does not say whether it filed. — [blog.disclose.io, Aug 15, 2026](https://blog.disclose.io/nvd-modernization-rfi-2026/)
- An earlier April 2026 trade report said NIST was "exploring AI to help automate vulnerability categorization" and leaning toward a consortium model. — [SecureWorld, Apr 17, 2026](https://www.secureworld.io/industry-news/nist-nvd-course-correction?hs_amp=true)

### Inferences
- With the comment period closed, the absence of any NIST follow-up through Nov 6, 2026 is itself a scorecard data point. Q7(e) gives NVD Watch a direct hook: the scorecard can be framed as a public answer to the question NIST asked.

### Gaps
- **V-etalon: no source found.** The search for "V-etalon" NIST NVD returned only unrelated NIST Chemistry WebBook pages. The RFI does not name it. Treat it as unverified until a primary source is located.
- I found no public RFI comment submissions from notable organizations. The regulations.gov docket could not be queried in this session, and no comment count was found.
- I found no NVD budget figure (FY2025 to FY2027) or post-April staffing statement. The only staffing figure is "21 analysts" (Toomey, Just Security, Apr 27, 2026), a secondary claim with no NIST citation.

## Q4. What did the 2024 backlog crisis show about causes and fixes?

### Takeaway
The backlog began in February 2024. Contractor support (Analygence) and CISA Vulnrichment cut the unanalyzed share from 93% to 72% by September 2024 but did not clear the backlog by the FY2024 deadline. The Commerce OIG (May 2026) attributes the persistence to a lack of strategic planning, inefficient processes, NIST/CISA duplication and poor communication. That is a management diagnosis, not purely a funding one.

### Cited Findings
- Commerce OIG, "Evaluation of NIST's Management of the National Vulnerability Database," OIG-26-020-I, May 26, 2026. A backlog "began in February 2024" and kept growing because of "lack of strategic planning and decisive action." It found that efficiency improvements are needed. NIST and CISA run overlapping enrichment programs, wasting about $200,000 since May 2024. About $800,000 could be put to better use over two years. Insufficient communication eroded confidence. The report makes six recommendations, and NIST concurred with all six. — [OIG abstract PDF](https://www.oig.doc.gov/wp-content/OIGPublications/OIG-26-020-I_Abstract-SECURED.pdf)
- The Analygence contract was reported at $865,657 (Socket). Other outlets reported a five-year contract vehicle of up to $125M. — [Socket, Oct 1, 2024](https://socket.dev/blog/nist-misses-2024-deadline-to-clear-nvd-backlog); [OODA Loop headline](https://oodaloop.com/analysis/ooda-original/an-overview-of-the-nist-nvd-backlog-debacle-cybersecurity-company-brought-in-on-a-five-year-125m-contract-to-assist/); [Nextgov, May 2024](https://www.nextgov.com/cybersecurity/2024/05/nist-taps-analygence-help-fix-vulnerability-database-backlog/397028/) (latter two not fetched; **the $865,657 figure and the $125M figure conflict**, likely obligated amount versus ceiling)
- The backlog was 13,358 in June 2024 and nearly 18,000 by about October 2024. NIST missed its end-of-FY2024 clearance target. — [Socket, Oct 1, 2024](https://socket.dev/blog/nist-misses-2024-deadline-to-clear-nvd-backlog); [The Register, Oct 2, 2024](https://www.theregister.com/2024/10/02/cve_pileup_nvd_missed_deadline) (not fetched)
- VulnCheck's Patrick Garrity called NVD's use of CISA Vulnrichment for CVSS a "notable success." — [Socket, Oct 1, 2024](https://socket.dev/blog/nist-misses-2024-deadline-to-clear-nvd-backlog)
- CSA dates the start to an "early 2024 funding disruption" and says NIST contracted with CISA in August 2024 to address the backlog. — [CSA, Apr 29, 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-enrichment-overhaul-20260429-csa/)
- Even at record output (~42,000 enriched in 2025), NIST fell further behind. — [NIST](https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth); [Just Security, Apr 27, 2026](https://www.justsecurity.org/136914/nist-cant-keep-up/)

### Inferences
- 2024 showed that one-time surge capacity (contractors, CISA ADP) lowers the *share* unanalyzed but cannot keep up with compounding volume growth. That is the case for structural change, whether funded scale-up or triage.
- The OIG's duplication finding (NIST and CISA Vulnrichment) cuts both ways. It is evidence of waste, but it also shows a second enrichment source exists, which partly undercuts "no one enriches it."

### Gaps
- **The NVD Consortium** (announced in 2024) and **a Maryland Innovation and Security Institute (MISI) contract** were not verified by any source retrieved in this session. Do not cite the MISI contract without a primary source.
- The full OIG report text was not retrieved, only the abstract with its six recommendations unlisted. NIST's stated causes for 2024 (e.g., budget, staffing, interagency support changes) were not confirmed from a primary NIST statement in this session.

## Q5. Is there evidence that the gap matters less than claimed?

### Takeaway
There is real counter-evidence. NIST still enriched about half of new CVEs after the policy (Apr to Jun 2026). Most CVEs carry CNA- or CISA-supplied CVSS (85.9% even at the 2024 low). Commercial sources such as VulnCheck NVD++ exceed NVD CPE coverage. NIST's own scores are contested on accuracy. EPSS rarely beats KEV. Against this, CPE (product matching) remains the hard gap, CNA scores are inconsistent, and FedRAMP still requires NIST scores.

### Cited Findings
**Evidence the gap is smaller or less consequential**
- From Apr 15 to Jun 15, 2026, NIST prioritized 62% (8,342/13,441) of new CVEs and enriched about 50% (6,759), with a median of about 4 days to analysis. — [Dark Reading](https://darkreading.com/vulnerabilities-threats/nist-enrichment-reductions-cve-coverage-accuracy)
- Even in the depth of the 2024 crisis, 85.9% of CVEs added since Feb 12, 2024 had a CVSS record from a CNA or CISA. — [VulnCheck](https://www.vulncheck.com/blog/nvd-backlog-exploitation-lurking)
- VulnCheck NVD++ had 76.95% CPE coverage versus NVD's 41.35% for 2024 CVEs, about 4 days faster. — [CSA citing VulnCheck](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-enrichment-overhaul-20260429-csa/)
- Alternatives cited by practitioners include CISA Vulnrichment (ADP: SSVC, CVSS), ENISA's EUVD, OSV and the GitHub Advisory Database. — [Disclose.io, Aug 15, 2026](https://blog.disclose.io/nvd-modernization-rfi-2026/); [CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-enrichment-overhaul-20260429-csa/)
- NIST's own CVSS is not a gold standard. On CVE-2026-8856, NIST scored 9.1, IBM 7.7 and Volerion 4.4. About one-third of disagreements concerned Attack Complexity. — [Dark Reading](https://darkreading.com/vulnerabilities-threats/nist-enrichment-reductions-cve-coverage-accuracy)
- Practitioners argue exploitability, not database metadata, should drive priority (Trey Ford, Bugcrowd), and that CNA scores should become the default (Kip Boyle). — [SecureWorld, Apr 17, 2026](https://www.secureworld.io/industry-news/nist-nvd-course-correction?hs_amp=true)
- ENISA (Nuno Rodrigues Carvalho) argues against reliance on a "single point of failure" and says ENISA is becoming a top-level root CNA. That points toward distributed enrichment rather than restoring NVD. — [Help Net Security, Apr 16, 2026](https://helpnetsecurity.com/2026/04/16/nist-national-vulnerability-database-nvd-enrichment)
- EPSS ≥ 0.10 preceded KEV in only 19% of cases. 23% of KEV CVEs never crossed 0.10. — [Barracuda, Jul 24, 2026](https://blog.barracuda.com/2026/07/24/KEV-gap-how-fast-do-exploited-bugs-get-flagged)

**Evidence the gap still matters**
- CNA scores are uneven, get less scrutiny and can conflict. They also do **not** supply CPE, so scanner product matching still fails. — [CSA, Apr 29, 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-enrichment-overhaul-20260429-csa/)
- Tools relying on NVD CPE strings may miss unenriched critical CVEs, and vendors may downplay their own bugs (Mayuresh Dani, Qualys). — [SecureWorld](https://www.secureworld.io/industry-news/nist-nvd-course-correction?hs_amp=true)
- CNA vectors come from organizations with "varying levels of expertise, bias, and consistency." FedRAMP requires NIST CVSS. — [Dark Reading](https://darkreading.com/vulnerabilities-threats/nist-enrichment-reductions-cve-coverage-accuracy)
- Toomey argues for dedicated appropriations scaling with CVE volume and a "several-fold" expansion of analyst capacity, at a cost of "tens of millions of dollars" per year. — [Just Security, Apr 27, 2026](https://www.justsecurity.org/136914/nist-cant-keep-up/)

### Inferences
- The most defensible framing for NVD Watch is "*which* enrichment field is missing, for *which* CVEs, and *who else* supplies it," not "enrichment fell to X%." CPE is the field with the weakest substitute. CVSS has the strongest.
- The EPSS ≥ 0.10 screen (the CSI ~2,070 figure) is a weak proxy for "defenders need warning." By Barracuda's data, EPSS misses or lags KEV most of the time. A scorecard leaning on that threshold invites challenge.
- Cost anchors found: OIG's ~$800k in better-use savings over two years and ~$200k duplication, the reported Analygence $865,657 award (or $125M ceiling), and Toomey's unsourced "tens of millions per year." None is a rigorous cost-to-close estimate.

### Gaps
- I found no quantitative 2026 study of CNA-supplied CPE coverage in CVE 5.x records, nor of OSV/GitHub Advisory coverage of unenriched NVD CVEs.
- I found no evidence (case studies or incident data) of a breach attributed to an NVD enrichment gap in 2026.
- I found no independent cost model for restoring universal enrichment.
