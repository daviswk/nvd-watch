# KEV Lag, Not Scope, Undercuts NVD Triage

NIST's April 2026 triage probably moves fast on the vulnerabilities it covers. The problem is its gate. It can be no faster and no wider than CISA's Known Exploited Vulnerabilities (KEV) catalog, and KEV is slowing down while staying narrow. The median time from CVE publication to KEV listing rose from **6 days in 2023 to 14 days in 2026**. VulnCheck logged **884** newly exploited CVEs in 2025, against **245** that CISA added to KEV. No one can say whether NIST meets its one-business-day goal for KEV enrichment, because no one publishes that measure, NIST included. Two of the student's headline numbers need repair. The "8.4% enriched in Q3 2026" figure comes from one source that conflicts with an independent count of about 50% for April to June. The "87.1% in 2025" baseline appears to divide NIST's annual output by annual CVE volume, which is not a coverage rate. The EPSS proposal also needs a redesign. EPSS crossed 0.10 before KEV listing in only 19% of cases, so it fails as a screen at intake. When it did lead, though, it led by an average of 201 days. That makes it a good trigger for pulling stalled CVEs back into the queue, and NIST's own white paper CSWP 41 already defines the composite score to use. Closing the gap is cheap. A re-queue trigger at EPSS ≥ 0.10 would add roughly **250 to 470 CVEs a month**, about 5 to 9% of NIST's demonstrated throughput. On a crude proxy that costs **$0.27M to $0.51M a year**, similar to the **~$400K a year** the Commerce OIG says NIST could save by dropping redundant re-scoring. Publishing metrics costs little beyond committing to stable definitions. The project should do five things:

- Cut the contested headline.
- Correct the PHP2Shell and Mandiant wording.
- Narrow "enrichment" to CPE product data, the one field with no free substitute.
- Address the CNA data-quality ask to CISA, which sponsors the CVE program, instead of to CNAs.
- Add four stakeholders: FIRST, the bodies that govern CVE, the FedRAMP program office, and state and local governments.

## The coverage figures disagree because they measure different things

NIST describes the problem as volume. CVE submissions rose **263% from 2020 to 2025**. NIST enriched **nearly 42,000 CVEs in 2025**, 45% more than in any earlier year, and still fell behind. The April 15 policy fully enriches only CVEs that are on KEV, that affect software the federal government uses, or that affect EO 14028 critical software. It also moves backlogged CVEs published before March 1 to "Not Scheduled," and NIST stops routinely adding its own CVSS score when a CNA has supplied one ([NIST](https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth)). The only performance target NIST stated is enrichment of KEV entries "within one business day."

The best independent measure taken after the policy took effect comes from Volerion, reported by Dark Reading. It finds the gap much smaller than the student's scorecard suggests:

| Measure (Apr 15 to Jun 15, 2026) | Count | Share |
|---|---|---|
| CVEs published to NVD | 13,441 | — |
| Prioritized for enrichment | 8,342 | 62% of published |
| Enriched | 6,759 | **≈50% of published; ≈81% of prioritized** |
| Given a NIST CVSS vector | 2,645 | ≈20% of published |
| Median time to analysis (May) | about 4 days | — |

NIST's timeliness figures also excluded the weekly "Awaiting Analysis" items ([Dark Reading](https://darkreading.com/vulnerabilities-threats/nist-enrichment-reductions-cve-coverage-accuracy)).

The scorecard leads with a different series from the Cyber Strategy Institute's "The Count Broke First": **87.1% (2025) → 60.7% → 29.5% → 8.4% (Q3 2026)** ([CSI](https://cyberstrategyinstitute.com/cve-state-of-risk-october-2026/)). The coordinator fetched that page directly. Three researchers could not find it through search, and its quarterly and year-to-date totals do not fully reconcile. It is a single source that contradicts the only other measurement taken after the policy took effect.

Two explanations reconcile most of the conflict, and both argue against using the series as a headline.

**The 2025 baseline is likely not a coverage rate.** NIST's ~42,000 enrichments divided by the **48,185 CVEs published in 2025** ([CSA](https://labs.cloudsecurityalliance.org/research/csa-whitepaper-nvd-infrastructure-crisis-ai-vulnerability-di/)) comes to **87.2%**, almost exactly CSI's figure. But those 42,000 enrichments include backlog CVEs from earlier years. The same CSA paper reports that only **32% of CVE-2025 entries were fully enriched by early 2026**. The Commerce OIG put the backlog at **more than 27,000 by the end of 2025** ([Tech Times on OIG-26-020-I](https://www.techtimes.com/articles/317594/20260602/nist-national-vulnerability-database-severity-scores-wrong-88-time-inspector-general-finds.htm)). Read this way, "down from 87.1%" compares a throughput ratio with a coverage share.

**The Q3 drop is real in direction but probably overstated in size.** CVE volume did surge. NVD recorded **92,319 CVEs from January through October 2026, 2.24 times the same months of 2025**, and October alone had 17,481 ([RuntimeWire](https://runtimewire.com/article/nvd-recorded-2-24-times-as-many-cves-from-january-through-october-as-in-the-same)). Google's threat intelligence group counted 10,477 disclosures in July and 10,740 in August ([GTIG](https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era)). Assume Q3 volume was around 30,000. Then 8.4% implies about 2,500 enrichments in the quarter, roughly a quarter of the ~10,000 pace NIST sustained from April to June. That inference leaves three possibilities. NIST's output collapsed in Q3, which no source reports. Or CSI used a stricter definition, such as a NIST-assigned CVSS vector, which covered only 20% even in the spring. Or CSI measured Q3 CVEs before the queue caught up with them.

The definitions problem goes deeper than one report. Brian Martin tracked NVD's dashboard after the policy began. The "Not Scheduled" count fell from **123,755 to 46,788 between April 15 and May 7**, and no other status category accounts for where those records went. Meanwhile "Awaiting Analysis" became "Awaiting Enrichment" and "Deferred" became "Not Scheduled." He calls this a "shell game" ([jericho.blog](https://jericho.blog/2026/05/07/the-nvd-shell-game-schrodingers-enriched-vulnerability/)). The widely repeated figure of **~29,000 CVEs moved to Not Scheduled** comes from the Cloud Security Alliance, not from NIST. NIST has published no count ([CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-enrichment-overhaul-20260429-csa/)).

The more useful finding is about which field is missing. Severity scores are mostly covered by others:

- Even at the worst point in 2024, **85.9%** of new CVEs carried a CVSS score from a CNA or CISA ([VulnCheck](https://www.vulncheck.com/blog/nvd-backlog-exploitation-lurking)).
- The OIG found that **80%** of submissions arrive with a CNA score already attached.
- NIST's own re-scores matched the OIG's independent assessment in only **8 of 69** sampled cases ([Tech Times](https://www.techtimes.com/articles/317594/20260602/nist-national-vulnerability-database-severity-scores-wrong-88-time-inspector-general-finds.htm)).

CPE, the product-applicability data that scanners use to match a CVE to installed software, is a different story:

- CISA's Vulnrichment program **stopped adding CPE on December 10, 2024** ([cisagov/vulnrichment](https://github.com/cisagov/vulnrichment)). That left NIST as the only federal source of CPE.
- For 2024 CVEs, NVD's CPE coverage was **41.35%**, against **76.95%** from VulnCheck's commercial NVD++ ([CSA citing VulnCheck](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-enrichment-overhaul-20260429-csa/)).
- CNA records do not supply CPE at all, so scanner product matching fails without it.

The half of NIST's policy that drops re-scoring of CNA-scored CVEs is defensible, and the brief should not attack it. The half that leaves CPE unassigned outside the priority tiers is where defenders actually lose coverage.

## KEV now takes a median 14 days and misses most exploited CVEs

Barracuda measured 608 KEV entries for CVEs published since 2022. The median time from publication to KEV listing was **6 days in 2023, 9 in 2024, 12 in 2025 and 14 so far in 2026**. Barracuda stresses that the KEV date "is the day CISA added the bug, not the day attacks began" ([Barracuda](https://blog.barracuda.com/2026/07/24/KEV-gap-how-fast-do-exploited-bugs-get-flagged)). Coverage is narrow as well:

- VulnCheck's own KEV listed **884** newly exploited CVEs in 2025, compared with CISA's **245**.
- VulnCheck's list spanned **518 vendors** against CISA's **99** ([VulnCheck](https://www.vulncheck.com/blog/state-of-exploitation-2026)).

VulnCheck sets a lower bar for evidence, and it sells the alternative product. Even so, the ratio suggests that roughly 70% of CVEs with public exploitation evidence never trigger NIST's KEV pathway in the year they appear. NIST's policy fully enriches what KEV lists. Every day of KEV lag and every exploited bug KEV misses passes straight into NVD. Those misses are caught only when the software also happens to be federal or EO 14028 critical.

The "in time" question also needs a realistic baseline. Mandiant's original report confirms the commentary figure the student cites: average time-to-exploit fell from **63 days (2018–19) to 5 days (2023)**. The 5-day figure, however, excludes 15 outliers. With them, 2023 averages **about 47 days**. Part of the decline also comes from a rising share of zero-days, which count as exploited before a patch exists ([Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/time-to-exploit-trends-2023)). The newest figure, from M-Trends 2026, is a mean of **−7 days**: exploitation now routinely comes before the patch. Mandiant explicitly declines to call 2025 the year AI caused breaches ([M-Trends 2026](https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/)). VulnCheck adds that **28.96%** of KEVs in 2025 were exploited on or before the day their CVE was published ([VulnCheck](https://www.vulncheck.com/blog/state-of-exploitation-2026)). For these bugs no database enrichment, however fast, is a first warning. NVD's real job is the second step: telling defenders *whether they run the affected product*. "In time" should therefore be measured as time to CPE relative to KEV listing and to first confirmed exploitation.

PHP2Shell (CVE-2026-109618/109619) illustrates KEV latency, but the scorecard states the timeline wrong. The sequence was:

1. Amazon reported targeting that began about four days before the patch, around October 17.
2. Several firms tagged those early attempts as **unsuccessful**.
3. The patch shipped October 21 ([Recorded Future](https://www.recordedfuture.com/blog/php2shell-vulnerability-exploitation)).
4. Successful exploitation was confirmed **October 24 to 25**.
5. CISA added both CVEs to KEV on **October 26** ([BleepingComputer](https://bleepingcomputer.com/news/security/cisa-confirms-php2shell-vulnerabilities-now-exploited-in-attacks)).

KEV was therefore 9 days behind the first targeting but only 1 to 2 days behind confirmed compromise. PHP is also almost certainly federally used software, so NIST would have prioritized it with or without KEV. No source reported the CVEs' enrichment status in NVD. The case shows how KEV timing works. It does not show the enrichment gap.

The researchers found **no source for the Ivanti CVE-2026-104935 "6–12 days" lag**, and no measurement anywhere of NIST's compliance with its one-business-day goal.

The strongest opposing argument deserves a direct answer:

- Google found that only **0.23%** of 2026 disclosures were ever seen exploited ([GTIG](https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era)).
- FIRST reports that "actionable exploitability" (CVEs on KEV or with EPSS above 10%) is **flat** even as disclosures soar ([FIRST](https://www.first.org/blog/20260615-vulnerability-forecast-update)).
- The researchers found no breach attributed to an NVD enrichment gap.

On this view, NIST's triage is a sensible match between scarce capacity and the small slice of CVEs that matters. The rebuttal is that the slice is growing in absolute terms. Exploited vulnerabilities averaged **10.5 a month in 2025 and 18 a month in January to August 2026** (GTIG). And triage assumes someone can tell *which* CVE is in the slice before it reaches KEV. That is exactly what a predictive trigger tries to do.

## EPSS fails as an intake screen but works as a re-queue trigger

EPSS's headline performance holds up. On FIRST's October 2023 example, an EPSS threshold of 0.10 flagged **2.7%** of CVEs and caught **63.2%** of exploited ones with 65.2% precision. A CVSS 7+ rule flagged **57.4%** of CVEs to catch 82.2%, at 3.96% precision ([FIRST](https://www.first.org/epss/model)). Version 3 reached a PR-AUC of 0.78, against 0.05 for CVSS ([Jacobs et al. 2023](https://arxiv.org/html/2302.14172v2)). Version 4, released in March 2025, uses CNA and ADP data from cve.org as a fallback when NVD enrichment is missing ([Empirical Security](https://research.empiricalsecurity.com/research/introducing-epss-version-4)). That partly answers the worry that an NVD collapse would starve EPSS of inputs. The worry is not fully answered. By feature count, about 1,299 of v3's 1,477 features came from NVD fields, and no study has measured EPSS accuracy on unenriched CVEs.

The challenges hit the specific mechanism the student proposed:

- **Barracuda:** EPSS crossed 0.10 before KEV listing in only **19%** of cases. KEV came first in **57%**, and EPSS never crossed in **23%** ([Barracuda](https://blog.barracuda.com/2026/07/24/KEV-gap-how-fast-do-exploited-bugs-get-flagged)).
- **Parla:** of 57 high-severity KEV CVEs from 2023 onward, 42 had consistently low EPSS scores before listing. Parla concludes that EPSS behaves as "a trailing indicator of exploitation rather than a predictive system" ([arXiv 2411.02618](https://arxiv.org/pdf/2411.02618)).
- **FIRST itself:** the 0.10 threshold "carries no special authority." If a CVE is on KEV with a low EPSS, "Follow KEV" ([FIRST FAQ](https://www.first.org/epss/faq)).

Taken together, a screen applied at publication time would add few CVEs and would mostly flag them after KEV already had.

The same Barracuda data also points to a better design. **When EPSS did lead KEV, it led by an average of 201 days.** EPSS's lead time sits with older CVEs that later attract exploit code and chatter, which is exactly the population NIST has parked as "Not Scheduled." NIST has already built the tool for this. CSWP 41 (Mell and Spring, May 2025) defines "Likely Exploited Vulnerabilities" (LEV) from a CVE's EPSS history. It proposes a composite score of **max(EPSS, KEV = 1.0, LEV)** and suggests a threshold around 0.20 for a manageable list. It is candid about limits: at 0.1 an LEV list covers no more than 60% of KEV, and its margin of error is "currently unknown" ([NIST CSWP 41](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.41.pdf)).

Federal compliance is already moving the same way. FedRAMP's 2026 Vulnerability Evaluation and Reporting ruleset, available for optional adoption from July 4, 2026, replaces timing based on NVD CVSS with KEV, EPSS and reachability ([Endor Labs](https://www.endorlabs.com/learn/fedramp-2026-vulnerability-rules-make-reachability-a-requirement); [fedramp.gov](https://www.fedramp.gov/2026/reference/vulnerability-evaluation-and-reporting/)). NIST already offers an informal re-queue: anyone can email nvd@nist.gov to request enrichment "as resources allow." The revised proposal turns that inbox into a published rule.

Under the revised recommendation, any lowest-priority or "Not Scheduled" CVE would re-enter the queue for CPE enrichment when any of three signals appears:

- The CSWP 41 composite crosses a published threshold.
- CISA's Vulnrichment record marks Exploitation as "PoC" or "Active" (federal, human-reviewed signal; its 2026 coverage is unverified).
- CISA receives credible exploitation evidence from a third party, which the student's CISA recommendation already covers.

This keeps EPSS but stops asking it to predict on day zero, and it answers both Barracuda and Parla directly. The developers themselves say that gaming of EPSS was "not investigated" ([Jacobs et al.](https://arxiv.org/html/2302.14172v2)), so a public government trigger should log and publish every re-queue it makes.

## Closing the gap costs hundreds of thousands of dollars, not tens of millions

The scorecard's default of 20 analyst-minutes per CVE has no published basis. The researchers found no per-CVE time figure from NIST, the OIG or the trade press. A rough cross-check suggests 20 is the low end: 21 analysts ([Just Security](https://www.justsecurity.org/136914/nist-cant-keep-up/)) × ~1,800 hours ÷ 42,000 CVEs ≈ **54 minutes per CVE**. That assumes the analysts did nothing else, and it ignores contractors. Throughput is a firmer anchor. NIST targeted **6,200 enrichments a month and never exceeded 5,000** ([Tech Times on OIG](https://www.techtimes.com/articles/317594/20260602/nist-national-vulnerability-database-severity-scores-wrong-88-time-inspector-general-finds.htm)). For a dollar proxy, CISA's lapsed **$3.8M a year** contribution divided by 42,000 CVEs gives about **$90 per CVE** (same source). That is crude: the $3.8M was not NVD's whole budget, and the two figures come from different years.

| Option | CVEs added | Share of 5,000/mo ceiling | Analyst hours (20 / 60 min) | Crude cost at ~$90/CVE |
|---|---|---|---|---|
| One-time re-queue of 2026 CVEs with EPSS ≥ 0.10 (CSI's ~2,070, single source) | ~2,070 once | — | 690 / 2,070 | ~$186K once |
| Same at EPSS ≥ 0.50 (CSI's ~490) | ~490 once | — | 163 / 490 | ~$44K once |
| Ongoing ≥ 0.10 at 2026 average volume (2.7% of ~9,230/mo) | ~250/mo | ~5% | 1,000 / 3,000 per yr | ~$270K/yr |
| Ongoing ≥ 0.10 at October 2026 volume (2.7% of 17,481) | ~470/mo | ~9% | 1,890 / 5,660 per yr | ~$510K/yr |
| Quarterly performance metrics | — | — | negligible | near zero; the dashboard already exists |
| Restore universal enrichment | all | — | — | "tens of millions" a year (Toomey, unsourced) |

These rows are upper bounds. The 2.7% rate is a whole-corpus figure from 2023, and new CVEs start with low scores. Some flagged CVEs would also already fall in NIST's priority tiers. CSI's ~2,070 backlog over roughly ten months works out to about 200 a month, which roughly matches the 250 estimate, but it is the same unverified source.

The offset is direct. The OIG estimated that NIST could put **about $800,000 over two years** to better use by scaling back redundant re-scoring, and it found **about $200,000** wasted on enrichment that NIST and CISA both performed ([OIG abstract](https://www.oig.doc.gov/wp-content/OIGPublications/OIG-26-020-I_Abstract-SECURED.pdf)). A re-queue rule therefore costs about what the OIG says NIST is already wasting. That is a stronger argument than asking Congress for new money.

Metrics are cheaper still, but they require a commitment rather than a budget line. NIST's own RFI asks commenters directly (question 7(e)): "What metrics should be considered to track and evaluate the success of the NVD" ([Federal Register, 91 FR 52042](https://www.govinfo.gov/content/pkg/FR-2026-08-12/html/2026-16371.htm)). Comments closed October 13, and NIST had published no follow-up as of November 6. Volerion computed its figures from public data, which shows the measurement is feasible. Martin's tracking shows that unstable definitions are the real barrier. Five quarterly numbers would answer the policy question:

1. Share of new CVEs with CPE, from any source and from NIST, by priority tier.
2. Median and 90th-percentile time to enrichment, by tier.
3. Compliance with the one-business-day KEV goal.
4. Re-queue counts and the time each re-queue took.
5. A change log for status-category definitions.

The EU offers a model of statutory clocks. Under the Cyber Resilience Act, manufacturers must report actively exploited vulnerabilities on a **24-hour, 72-hour and 14-day** schedule ([Help Net Security](https://www.helpnetsecurity.com/2026/09/14/enisa-cra-single-reporting-platform/)). CISA's September 2026 "Quality Era" framework for CVE published no metrics either ([CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-cisa-cve-quality-era-20260929-csa-styled/)). The measurement gap therefore spans both agencies.

## AI worsens a capacity failure that began in 2024

Claim 1 of the student's evidence ladder is directionally right but overstated as a cause. The NVD backlog began in **February 2024**, when an enrichment contract lapsed. CISA's roughly $3.8M a year in support was not renewed for FY2024 ([Tech Times on OIG](https://www.techtimes.com/articles/317594/20260602/nist-national-vulnerability-database-severity-scores-wrong-88-time-inspector-general-finds.htm)). The OIG blamed a "lack of strategic planning and decisive action" ([OIG abstract](https://www.oig.doc.gov/wp-content/OIGPublications/OIG-26-020-I_Abstract-SECURED.pdf)). NIST's April notice cites a 263% surge and never mentions AI. The link between AI and the NVD crisis is asserted mainly by the Cloud Security Alliance ([CSA](https://labs.cloudsecurityalliance.org/research/csa-whitepaper-nvd-infrastructure-crisis-ai-vulnerability-di/)).

AI is real and accelerating:

- Monthly disclosures rose from **5,045 in January to 10,740 in August 2026** (GTIG).
- Anthropic's Glasswing found that **90.6%** of 1,752 assessed findings were valid, but only **75 of ~530** disclosed high or critical bugs had been patched at the first update ([Anthropic](https://www.anthropic.com/research/glasswing-initial-update)).
- curl's maintainer says AI slop has given way to "high volume, high quality" ([Stenberg](https://daniel.haxx.se/blog/2026/10/22/ignore-the-slop/)).
- Torvalds called the kernel security list "almost entirely unmanageable" ([Tom's Hardware](https://tomshardware.com/software/linux/linus-torvalds-says-ai-bug-reports-have-made-the-linux-security-mailing-list-almost-entirely-unmanageable)).

Part of the surge, though, is structural. FIRST credits GitHub Security Advisory growth (**+449%**) and VulnCheck's role as CNA of Last Resort (**+3,119%**) ([FIRST](https://www.first.org/blog/20260615-vulnerability-forecast-update)). GTIG ties roughly 5,000 Linux kernel CVEs, with zero exploited in-the-wild zero-days, to the kernel's automated CNA assignment policy.

Three AI-era sources need careful labels:

- **GPT-6 Cyber (November 5, 2026).** Press reports say it found 81 Firefox bugs and built exploits for 948 Linux kernel vulnerabilities, 588 of them previously unknown ([CyberScoop](https://cyberscoop.com/openai-gpt-6-cyber-security-model/)). OpenAI's own page did not load, and a researcher's search found no confirmation. Cite these as *press-reported*.
- **"V-etalon," NIST's AI enrichment tool.** It appears only in Socket ([Socket](https://socket.dev/blog/nist-nvd-ai-automation)). NIST's RFI names no tool.
- **AI-assisted enrichment.** It remains unproven. CSA's proposed pilot covers 1,000 CVEs on an $85K budget and reports no results ([CSA](https://labs.cloudsecurityalliance.org/research/vulnerability-management-ai-assisted-nvd-enrichment-v3/)).

The literature review turned up one policy essay that treats NVD as public infrastructure: Joe Toomey's piece in Just Security, which calls triage a "scarcity-driven adaptation" and argues for appropriations that scale with CVE volume ([Just Security](https://www.justsecurity.org/136914/nist-cant-keep-up/)). The searches found no NVD-specific work from Lawfare, CSIS, Brookings, R Street, CSET or Belfer. Those searches were limited, so the student should run targeted site searches before claiming a gap in the literature.

## The brief leaves out the bodies that run CVE, set compliance rules and absorb the cost

The brief names four audiences: NIST, Congress, CISA (as the owner of KEV) and CNAs or vendors. The evidence points to four more that belong in a three-page brief, each with its own lever.

| Stakeholder | Why it matters to this question | Lever |
|---|---|---|
| **FIRST** (steward of EPSS) | Any EPSS trigger depends on FIRST's model, thresholds and release cadence. FIRST also says 0.10 "carries no special authority" ([FIRST FAQ](https://www.first.org/epss/faq)) | Publishes EPSS; could publish score distributions at CVE publication time |
| **CISA as CVE sponsor, MITRE as operator, CVE Board** | MITRE holds final authority and the 24-member board is advisory ([CSO Online](https://www.csoonline.com/article/4142600/cve-program-funding-secured-easing-fears-of-repeat-crisis.html)). CNA rules, not CNA goodwill, decide whether records ship with product data. The Quality Era framework treats enrichment as part of CVE's mission ([CSA](https://labs.cloudsecurityalliance.org/research/csa-research-note-cisa-cve-quality-era-20260929-csa-styled/)) | Can require affected-product data from CNAs |
| **FedRAMP PMO (GSA)** | The 2024 rules require the NVD CVSS score. NIST no longer adds one when a CNA has scored, so CNA scores now drive federal remediation deadlines. The 2026 ruleset already uses EPSS and KEV ([CSA compliance map](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-riskbased-enrichment-governance-2/)) | Federal precedent for the proposal |
| **State, local, tribal and territorial governments; MS-ISAC/CIS** | MS-ISAC served ~19,000 entities and lost federal funding in 2025. Warner's restoration bill has not advanced ([Nextgov](https://www.nextgov.com/cybersecurity/2026/06/warner-unveils-bill-restore-cyber-information-sharing-program-funding/414010/)). These are the users who cannot buy commercial enrichment ([Just Security](https://www.justsecurity.org/136914/nist-cant-keep-up/)) | The equity case for the brief |

Several other actors deserve a sentence each:

- **Commercial enrichment vendors** (VulnCheck, Volerion): they fill the gap, but their evidence comes with a conflict of interest.
- **ENISA**: it runs EUVD, became a CVE Root in November 2025, and now operates CRA reporting ([ENISA](https://www.enisa.europa.eu/news/consult-the-european-vulnerability-database-to-enhance-your-digital-security)). It warns against a "single point of failure" ([Help Net Security](https://helpnetsecurity.com/2026/04/16/nist-national-vulnerability-database-nvd-enrichment)).
- **Open-source maintainers and the Linux kernel CNA**: they drive volume but have little capacity to supply CPE.
- **AI labs**: they now report bugs at high volume.
- **Congress beyond appropriators:**
  - House Homeland Security and House Science, whose Democratic ranking members (Thompson and Lofgren) asked GAO to review CVE and NVD in June 2025 ([House Homeland Democrats](https://democrats-homeland.house.gov/news/correspondence/ranking-members-thompson-and-lofgren-request-gao-review-of-cve-and-nvd-federal-cybersecurity-programs)).
  - The NDAA process, where an amendment from Reps. Ramirez and Whitesides to codify CVE under CISA and add enrichment to its mission was not made in order ([Nextgov](https://www.nextgov.com/cybersecurity/2026/06/planned-ndaa-amendment-would-codify-cisas-role-cyber-vulnerability-program/414286/)).

Those two vehicles give the brief's "tie funding to metrics" recommendation somewhere concrete to land.

## Conclusion

The policy design question is not *which software* NIST should cover but *which signal* should pull a CVE back into the queue. NIST has already published the answer in CSWP 41, and FedRAMP has adopted the same signals. The student's best argument is therefore not that NIST should try something new. It is that NIST should apply its own composite score to its own backlog, paid for with the re-scoring effort its Inspector General already called low-value. That is a cheaper and more defensible ask than new appropriations, and it survives the strongest criticism of EPSS.

The conflicting coverage numbers are the project's strongest evidence, not an embarrassment. Two credible-looking sources disagree by a factor of six about the same database in the same year because no official, stable definition exists. A scorecard that publishes its own reproducible definition and query, with CPE as the key measure, would be a direct public answer to the question NIST itself asked in RFI question 7(e). That is a more durable contribution than any single headline percentage.

## Prioritized change list

### Cut

| # | Cut | Replace with |
|---|---|---|
| 1 | Scorecard headline "8.4% of new CVEs enriched in Q3 2026, down from 87.1% in 2025" | The student's own NVD API count of CPE coverage by priority tier, with the definition stated. If time is short, show the disputed range instead: "≈50% (Volerion, Apr–Jun) to 8.4% (CSI, Q3); sources define enrichment differently" |
| 2 | Ivanti CVE-2026-104935 "6–12 days" | Barracuda's median trend (unless the student holds primary sources dating both first exploitation and the KEV add) |
| 3 | EPSS as a screen at intake ("trigger at publication") | The re-queue rule (see Reframe, row 4) |
| 4 | Simulator default of 20 minutes as a point estimate | A 20/45/60-minute range, with output shown as % of the ~5,000/mo ceiling and ~$90/CVE, plus a line for the OIG's ~$400K/yr offset |
| 5 | "CNAs/vendors ship CVSS/CPE/CWE" as a voluntary fourth audience | Fold it into the CISA recommendation: as CVE sponsor, CISA requires affected-product data in CNA records |
| 6 | Any mention of "V-etalon" as fact | Drop it, or label it "reported only by Socket" |

### Correct

| # | Current wording | Corrected wording |
|---|---|---|
| 1 | PHP2Shell: "9 days from first exploitation Oct 17 to KEV Oct 26" | "Probing began Oct 17 (unsuccessful); patch Oct 21; successful exploitation confirmed Oct 24–25; KEV Oct 26: 9 days after first targeting, 1–2 days after confirmed compromise." Present it as a KEV-latency example, since PHP likely already qualified as federally used software |
| 2 | Mandiant "63 → 5 days" (cited via RAND commentary) | Cite Mandiant's report directly: "63 days (2018–19) to 5 days (2023, excluding outliers; ~47 with them); M-Trends 2026 puts the mean at −7 days. Mandiant does not attribute the drop to AI" |
| 3 | Claim 1 implies AI caused the NVD crisis | "AI discovery is accelerating a capacity gap that began with a February 2024 contract lapse; NIST cites a 263% surge, not AI" |
| 4 | "NIST no longer scores CVEs a CNA already scored" | "NIST no longer *routinely* adds its own score when a CNA has scored" |
| 5 | Claim 5, "nobody measures" | "NIST publishes a live status dashboard but no performance metrics beyond a one-business-day KEV goal that no one verifies, and its status categories changed in April" |
| 6 | "~29,000 moved to Not Scheduled" stated as NIST's figure | Attribute it to CSA; NIST published no count |
| 7 | OIG "88% wrong" (if used) | "NIST re-scores matched the OIG's in only 8 of 69 sampled cases" (a mismatch, not verified error) |
| 8 | GPT-6 Cyber figures stated as fact | "As reported by CyberScoop and others; OpenAI's own page not confirmed" |
| 9 | ~2,070 / ~490 EPSS counts | Relabel as "re-queue candidates (CSI; single source)," or recompute them from the NVD API plus FIRST's daily EPSS CSV |

### Add: sources (each fills a specific slot)

| # | Source | Slot |
|---|---|---|
| 1 | Volerion via [Dark Reading](https://darkreading.com/vulnerabilities-threats/nist-enrichment-reductions-cve-coverage-accuracy) | Claim 2; scorecard gap section |
| 2 | [Barracuda, Jul 24, 2026](https://blog.barracuda.com/2026/07/24/KEV-gap-how-fast-do-exploited-bugs-get-flagged) | Claim 3 (KEV lag 6 → 14 days); Claim 4 challenge (19% lead, 201-day lead time) |
| 3 | [VulnCheck State of Exploitation 2026](https://www.vulncheck.com/blog/state-of-exploitation-2026) | Claim 3 (884 vs 245; 28.96% exploited by publication day) |
| 4 | [NIST CSWP 41](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.41.pdf) | Claim 4: NIST's own composite score. Replaces the EPSS 2019 paper as the lead citation, alongside [Jacobs et al. 2023](https://arxiv.org/html/2302.14172v2) |
| 5 | [FIRST EPSS FAQ](https://www.first.org/epss/faq) and [Parla 2024](https://arxiv.org/pdf/2411.02618) | Claim 4 limits, stated openly |
| 6 | [jericho.blog](https://jericho.blog/2026/05/07/the-nvd-shell-game-schrodingers-enriched-vulnerability/) | Claim 5 (definitions changing mid-series) |
| 7 | [FIRST forecast update](https://www.first.org/blog/20260615-vulnerability-forecast-update) and GTIG's 0.23% figure | Steelman and non-AI drivers for Claim 1 |
| 8 | [FedRAMP 2026 ruleset](https://www.fedramp.gov/2026/reference/vulnerability-evaluation-and-reporting/) | Federal precedent for the EPSS/KEV proposal |
| 9 | [Just Security (Toomey)](https://www.justsecurity.org/136914/nist-cant-keep-up/) | Policy literature; anchor for the cost of universal restoration |

### Add: stakeholders

| # | Stakeholder | One-line role in the brief |
|---|---|---|
| 1 | FIRST | Owns EPSS; must be consulted on thresholds |
| 2 | CISA as CVE sponsor, MITRE, CVE Board | Sets CNA data rules; the right target for the product-data ask |
| 3 | FedRAMP PMO (GSA) | Compliance owner already moving to KEV/EPSS |
| 4 | State, local, tribal and territorial governments; MS-ISAC | The users who pay for the gap and cannot buy commercial enrichment |
| 5 | (one sentence) Commercial vendors, ENISA, open-source maintainers, AI labs, House Homeland Security and Science, NDAA conferees | Context, alternatives and vehicles |

### Reframe

| # | Reframe |
|---|---|
| 1 | **Revised policy question:** "Does NIST's April 2026 triage leave exploited vulnerabilities outside KEV and federal software without product (CPE) data when defenders need it, and would a published exploitation-signal re-queue rule plus quarterly NVD performance metrics close that gap at a cost NIST can absorb?" |
| 2 | **Revised framing line:** "NIST prioritizes by who uses the software or confirmed attacks; we propose re-checking the rest when attack signals rise, and publishing whether it works." |
| 3 | Narrow the gap from "enrichment" to **CPE**: CVSS has substitutes and CPE does not |
| 4 | **NIST recommendation:** re-queue any lowest-priority or "Not Scheduled" CVE when max(EPSS, KEV, LEV) ≥ a published threshold, CISA SSVC marks exploitation PoC/Active, or credible third-party exploitation evidence arrives. Publish five quarterly metrics with frozen definitions |
| 5 | **Congress recommendation:** attach the metrics to existing vehicles (the GAO review, CVE codification text), not to new appropriations; cite the OIG offset |
| 6 | Present NVD Watch as a public answer to **RFI question 7(e)** |
| 7 | **AI collaboration log:** add one entry recording how AI-surfaced claims were checked and how each was handled: the unsearchable CSI report and its conflict with Volerion; V-etalon, found in one source; GPT-6 Cyber, confirmed by press only; the PHP2Shell date ambiguity. This replaces generic process notes rather than adding pages |
