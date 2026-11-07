# Governance Landscape and Stakeholders Around U.S. Vulnerability Data Infrastructure (NVD, CVE, KEV), 2024 to Nov 6, 2026

Scope note: These notes cover stakeholders, institutions and policy developments that a 3-page brief on NIST's April 2026 NVD enrichment triage may be missing. Items marked [UNVERIFIED] come from a single secondary source or I could not check them against a primary source. "Announced" and "implemented" are kept separate throughout.

## 1. CVE Program governance: the April 2025 MITRE scare, its resolution, the CVE Foundation, 2026 status. Who governs CVE now?

### Takeaway
CVE is still run by MITRE under a CISA contract. MITRE holds final decision authority, and the CVE Board only advises. After the April 2025 near-lapse, CISA said in early 2026 that the program is "fully funded" and reportedly moved it to a protected budget line. Contract terms remain undisclosed. In September 2026 CISA announced a "Quality Era" framework, and a June 2026 House NDAA amendment to codify CVE under CISA did not get a floor vote. The CVE Foundation exists but has not taken over operations. The brief's stakeholder list leaves out MITRE, the CVE Board and CVE Foundation, ENISA (now a CVE Root), and the House Homeland Security Committee.

### Cited Findings
**April 2025 scare (implemented, resolved)**
- On April 15, 2025, MITRE VP Yosry Barsoum wrote to CVE Board members that the funding would lapse. CISA's $57.8M contract with MITRE expired April 16, 2025, but included an option to extend to March 16, 2026. CISA exercised that option on the evening of April 15 to "ensure there will be no lapse in critical CVE services." — [The Record, Apr 16, 2025](https://therecord.media/cisa-extends-cve-program-contract-with-mitre)
- A CISA official later blamed a "broad internal contracting review" for the brief renewal delay. MITRE was kept as operator. — [Nextgov, Aug 7, 2026](https://www.nextgov.com/cybersecurity/2026/08/cisa-cautions-against-rigid-rules-future-cyber-vulnerability-program/415282/)

**CVE Foundation (announced April 16, 2025; not operating the program)**
- A coalition of CVE Board members launched the CVE Foundation as an independent nonprofit on April 16, 2025, to reduce dependence on a single sponsor. — [CSA research note, Sept 29, 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-cisa-cve-quality-era-20260929-csa-styled/)
- Its stated goals are a diversified funding model (grants, sponsorships, donations, an endowment), international governance, transparent finances, and a neutral structure "outside sole government control." The goals page names no founders and gives no board composition. — [CVE Foundation, Apr 28, 2025](https://www.thecvefoundation.org/newsroom/posts/2025-04-28-goals)
- As of March 2026 the Foundation was "reassessing its next steps given the improved funding outlook." Co-founder and CVE Board member Pete Allor called transparency "an open question, and it can't be secret." — [CSO Online, Mar 9, 2026](https://www.csoonline.com/article/4142600/cve-program-funding-secured-easing-fears-of-repeat-crisis.html)
- "The independent CVE Foundation has not yet taken over operations, so long-term governance is unresolved." — [Just Security (Toomey), Apr 27, 2026](https://www.justsecurity.org/136914/nist-cant-keep-up/)

**Funding and governance in 2026**
- CISA acting director Nick Andersen said the "CVE program is fully funded." Sources say it moved from a discretionary item to a "protected line" in CISA's budget. January 21, 2026 Board minutes said there would be "no funding cliff in March." MITRE has declined a board member's requests for the contract terms, and a FOIA request is unanswered. An anonymous source called it "a mystery contract with a mystery number." — [CSO Online, Mar 9, 2026](https://www.csoonline.com/article/4142600/cve-program-funding-secured-easing-fears-of-repeat-crisis.html) [Funding claims rest mostly on unnamed sources and unpublished contract terms.]
- Governance: MITRE holds final decision-making authority. The 24-member CVE Board is advisory. — [CSO Online, Mar 9, 2026](https://www.csoonline.com/article/4142600/cve-program-funding-secured-easing-fears-of-repeat-crisis.html)
- VulnCheck reserved blocks of CVE identifiers as a continuity hedge. — [CSO Online, Mar 9, 2026](https://www.csoonline.com/article/4142600/cve-program-funding-secured-easing-fears-of-repeat-crisis.html)
- In September 2025, CISA published a CVE "vision" pledging government stewardship and stronger international partnerships. — [The Register, Sept 12, 2025](https://www.theregister.com/2025/09/12/cisas_vision_for_cve/); [CSO Online](https://www.csoonline.com/article/4142600/cve-program-funding-secured-easing-fears-of-repeat-crisis.html)

**September 2026 "Quality Era" framework (announced, not demonstrated)**
- On Sept 22, 2026, CISA published "CVE Program: Establishing a Quality Era Framework." It covers four dimensions (program governance, ecosystem participation, data infrastructure, CVE record content) and six lines of effort, including government sponsorship, transparency, data quality and a "CNA of Last Resort" program. It includes no new SLAs, enrichment guarantees, published quality metrics, staffing or timelines. VulnCheck's Caitlin Condon called it a statement of intent and noted CISA has not published metrics. — [CSA research note, Sept 29, 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-cisa-cve-quality-era-20260929-csa-styled/); CISA bulletin: [GovDelivery](https://content.govdelivery.com/accounts/USDHSCISA/bulletins/42c23fb) [I did not fetch the CISA primary document.]
- Over 67,000 CVEs had been published by Sept 18, 2026. CVEForecast.org projects about 96,000 by year-end. — [CSA research note, Sept 29, 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-cisa-cve-quality-era-20260929-csa-styled/)
- Related CISA action [UNVERIFIED against cisa.gov]: BOD 26-04 took effect June 10, 2026, replacing BOD 22-01. It prioritizes remediation by real-world risk rather than CVSS alone, with deadlines as short as 3 days. KEV held about 1,705 entries as of September 2026. CISA discontinued its weekly vulnerability bulletin on Sept 28, 2026. — [CSA research note, Sept 29, 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-cisa-cve-quality-era-20260929-csa-styled/)

**Congressional codification attempt (proposed, not adopted)**
- A planned FY2027 NDAA amendment would formally place CVE within CISA, require a CISA-NIST joint modernization plan, create a 15-member CVE Board (permanent seats for CISA, NIST and top-level CVE authorities; rotating seats for industry, academia, researchers and foreign governments), and make "vulnerability enrichment" part of CVE's formal mission. — [Nextgov, June 18, 2026](https://www.nextgov.com/cybersecurity/2026/06/planned-ndaa-amendment-would-codify-cisas-role-cyber-vulnerability-program/414286/); amendment text: [House Rules Committee PDF](https://amendments-rules.house.gov/amendments/CVE%20NDAA%20Amendment260618150434529.pdf) [PDF not fetched]
- Sponsors were Reps. Delia Ramirez (D-IL) and George Whitesides (D-CA). The House Rules Committee did not make it in order, so it got no floor vote. At Black Hat on Aug 6, 2026, CISA's Lindsey Cerkovnik said codifying CVE could help but warned that "When you overdefine how to execute the thing, it can make it very restrictive." She also called CVE "a global program and not just a U.S.-centric program." — [Nextgov, Aug 7, 2026](https://www.nextgov.com/cybersecurity/2026/08/cisa-cautions-against-rigid-rules-future-cyber-vulnerability-program/415282/)
- Moira Bergen, Democratic cyber policy lead on House Homeland Security: "While CISA is certainly authorized to execute this program, it's not specifically tasked with doing it." — [Nextgov, June 18, 2026](https://www.nextgov.com/cybersecurity/2026/06/planned-ndaa-amendment-would-codify-cisas-role-cyber-vulnerability-program/414286/)
- The House passed H.R. 8800 on July 22, 2026 (216-212). Cloture on the Senate bill S. 4784 failed 50-46 on July 14. The FY2027 NDAA had not been enacted as of Sept 1, 2026. — [CRS Insight IN12704, Sept 1, 2026](https://www.everycrsreport.com/files/2026-09-01_IN12704_0edccfce0eac32645d58df69e701a50e75373c35.pdf)

### Inferences
- "Who governs CVE now?" De facto, CISA funds and sponsors, MITRE decides and operates, and the CVE Board advises. No statute assigns the role. The brief treats CISA only as the KEV owner, but CISA is also CVE's sponsor. That gives CISA a direct lever over CNA data quality: CNA rules, ADP/Vulnrichment and the CNA of Last Resort program. The brief's "CNAs ship CVSS/CPE/CWE" recommendation is therefore better aimed at CISA/MITRE and the CVE Board, which set CNA rules, than at CNAs acting voluntarily.
- Both the Ramirez-Whitesides amendment and the Quality Era framework treat enrichment as part of CVE's mission. That suggests a possible institutional shift of enrichment toward CVE records produced upstream by CNAs and ADPs, and away from downstream NVD analysis. The brief should acknowledge this alternative path.
- Opacity of the contract terms is a governance problem in its own right. The brief's metrics-transparency recommendation for NIST has a parallel for CISA/MITRE on CVE.

### Gaps
- I could not confirm the current MITRE contract vehicle, value or end date after March 16, 2026. The only sources are CSO Online's unnamed sources and "protected line" language.
- I did not verify whether any CVE codification language appears in the House-passed H.R. 8800 base text or the Senate bill, or in any conference text after Sept 2026.
- I could not determine whether the GAO review requested in June 2025 (see Q4) has produced a report.
- I did not check the CVE Foundation for activity after March 2026.

## 2. International alternatives: ENISA EUVD, the EU CRA reporting obligations, GCVE (CIRCL), China's CNNVD

### Takeaway
The EU is building a parallel layer: EUVD (live May 13, 2025), an ENISA CVE Root (Nov 2025, 20 CNAs by Aug 2026), and the CRA Single Reporting Platform (live Sept 11, 2026). It still uses CVE IDs, ingests CVE and KEV, and is not yet a full enrichment substitute for NVD. GCVE offers a decentralized ID model that is compatible with CVE. China's CNNVD largely mirrors CVE but sits under disclosure-restricting rules. Together these reduce U.S. *gatekeeping* centrality more than they reduce NVD *enrichment* centrality. They also introduce fragmentation risk and give the brief comparative models.

### Cited Findings
**EUVD**
- ENISA launched the European Vulnerability Database on May 13, 2025, "as provided for by the NIS2 Directive." It aggregates CVE data (transferred automatically), vendor advisories, CISA's KEV catalog and national CSIRT inputs. It has three dashboards: critical, exploited and EU-coordinated. ENISA has been a CNA since January 2024 with a limited scope. — [ENISA, May 13, 2025](https://www.enisa.europa.eu/news/consult-the-european-vulnerability-database-to-enhance-your-digital-security)
- EUVD runs on CIRCL's vulnerability-lookup software. — [CyberScoop, Jan 21, 2026](https://cyberscoop.com/gcve-vulnerability-database-launches/)
- Just Security's assessment is that EUVD is "not yet a true alternative to the NVD." — [Just Security, Apr 27, 2026](https://www.justsecurity.org/136914/nist-cant-keep-up/)
- ENISA became a CVE Root on Nov 20, 2025. By Aug 6, 2026 its Root covered 20 CNAs (12 onboarded directly, 8 transferred from the MITRE Root), including NATO NCIA and AISLE. — [cyberresilienceact.eu (independent commentary), Aug 2026](https://www.cyberresilienceact.eu/news/enisa-cve-root-20-cnas-6-august-2026.html); AISLE is described as the first primarily AI-driven vulnerability discovery firm to get CNA authority — [CSA research note, Sept 29, 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-cisa-cve-quality-era-20260929-csa-styled/)

**EU Cyber Resilience Act reporting (implemented Sept 11, 2026)**
- ENISA opened the CRA Single Reporting Platform on Sept 11, 2026, the day Article 14 reporting obligations took effect. Manufacturers must report actively exploited vulnerabilities and severe incidents with an early warning within 24h, a notification within 72h, and a final report within 14 days of a fix becoming available. Reports go to a coordinating CSIRT, with ENISA receiving a copy at the same time. — [Help Net Security, Sept 14, 2026](https://www.helpnetsecurity.com/2026/09/14/enisa-cra-single-reporting-platform/); [ENISA announcement](https://www.enisa.europa.eu/news/the-cra-single-reporting-platform-is-launched) [ENISA page not fetched]
- Under CRA Art. 17(5), once a fix exists, ENISA adds notified, publicly known vulnerabilities to the EUVD "in agreement with the manufacturer." EUVD ID is an optional field next to CVE ID in notifications. — [cyberresilienceact.eu](https://www.cyberresilienceact.eu/news/enisa-cve-root-20-cnas-6-august-2026.html) [secondary commentary; not checked against regulation text]
- [UNVERIFIED] There are "discussions about amending the EU CRA to reference an ENISA-managed identifier instead of CVE." An ENISA spokesperson said ENISA remains committed to CVE but lacks visibility into the U.S. funding arrangements. — [CSO Online, Mar 9, 2026](https://www.csoonline.com/article/4142600/cve-program-funding-secured-easing-fears-of-repeat-crisis.html)

**GCVE (CIRCL, Luxembourg)**
- GCVE ("Global CVE Allocation System"), run by CIRCL, publicly launched around Jan 21, 2026. Independent numbering authorities allocate IDs "without seeking blocks pre-allocated from a central body." CVE IDs map to GCVE-0 (e.g., CVE-2023-40224 → GCVE-0-2023-40224). No adoption figures are available. — [CyberScoop, Jan 21, 2026](https://cyberscoop.com/gcve-vulnerability-database-launches/)
- Critics warn of fragmentation. — [Dark Reading](https://darkreading.com/cyber-risk/gcve-raises-concerns-fragmentation-vulnerability-database); [CSO Online, "EU's answer to CVE solves dependency issue, adds fragmentation risks"](https://www.csoonline.com/article/4123225/eus-answer-to-cve-solves-dependency-issue-adds-fragmentation-risks.html) [headlines only; not fetched]

**China CNNVD/CNVD**
- CNNVD appears to mirror nearly all CVEs and publishes within a week of CVE about 84% of the time (CNVD about 27%). Only about 0.55% of CNNVD entries came before CVE, and CNVD has published no early entries since late 2021. China's July 2021 RMSV regulation requires reporting to MIIT within 48 hours and bars disclosure before a patch is available. The author raises, but does not confirm, possible withholding. The data is manual and inconsistently structured. — [Bitsight, Feb 18, 2026](https://www.bitsight.com/blog/chinese-vulnerability-database-analysis-cnvd-cnnvd)
- Background (outside the date range): Atlantic Council, "Sleight of Hand: How China Weaponizes Software Vulnerabilities" (2023). — [Atlantic Council](https://www.atlanticcouncil.org/in-depth-research-reports/report/sleight-of-hand-how-china-weaponizes-software-vulnerability/) [not fetched; check the date]

### Inferences
- The EU now holds legal mandates (NIS2 Art. 12, CRA Art. 14/17) that the U.S. NVD lacks. The CRA's 24h/72h/14d clock is a concrete model for the brief's KEV-lag and CNA-completeness metrics.
- ENISA is now an upstream CVE Root and also a KEV consumer. That makes it a stakeholder in NIST/CISA decisions, and a reason CISA calls CVE "global." The brief could add "international partners (ENISA)" as a stakeholder, or at least name ENISA as a constraint.
- If NVD enrichment keeps shrinking, EUVD and commercial databases (VulnCheck and others) may fill the gap. This complicates the argument that Congress must fund NVD, though it also strengthens the sovereignty argument for funding it.
- AISLE as an AI-driven CNA under the ENISA Root links the brief's "frontier AI labs as high-volume reporters" stakeholder to international CNA governance.

### Gaps
- I did not verify whether EUVD provides its own CVSS/CPE/CWE enrichment or EPSS. ENISA's page does not mention EPSS.
- The CRA identifier amendment is single-source and unverified. I could not find a primary EU Commission or Parliament document. A Feb 2026 Commission cybersecurity package exists ([Mayer Brown](https://www.mayerbrown.com/en/insights/publications/2026/02/european-commission-proposes-major-cybersecurity-package-to-strengthen-eu-cyber-resilience), not fetched), but I did not confirm a link to CVE identifiers.
- No quantitative data on GCVE adoption.

## 3. Downstream dependents with NVD hard-coded into compliance

### Takeaway
Several compliance regimes are built on NVD CVSS scores. The clearest is FedRAMP's 2024 Vulnerability Scanning Requirements, which require the CVSS v3 score "assigned in the latest version of the NVD." In 2026, FedRAMP began moving to an evaluation-first ruleset that uses KEV/EPSS and reachability, which is a real-world example of the brief's EPSS idea. MS-ISAC, a key state and local channel, lost federal funding in 2025. The brief's stakeholder list leaves out FedRAMP PMO/GSA, DoD/DISA, the PCI Security Standards Council, auditors, MS-ISAC/CIS and SLTT governments, and open-source CNAs (Linux kernel).

### Cited Findings
**FedRAMP**
- FedRAMP Vulnerability Scanning Requirements v3.0 (Feb 15, 2024) requires CSPs to use the CVSS v3 base score "assigned in the latest version of the NVD." CVSS v2 and then scanner scores are fallbacks only. Remediation windows of 30, 90 and 180 days are tied to the CVSS bands. CSA rates FedRAMP's NVD dependency as high. — [CSA CISO Compliance Playbook, Apr 26, 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-riskbased-enrichment-governance-2/)
- The "FedRAMP Consolidated Rules for 2026," specifically the Vulnerability Evaluation and Reporting ruleset, became "effective for optional adoption on July 4, 2026." It is evaluation-first, with reachability and exploitability factors and EPSS/KEV signals. Evaluation is due within 2 to 14 days of detection, unremediated items must be "accepted" after 192 days, and monthly activity reports are required. The page also refers to undefined "December 2026 dates." — [Endor Labs, Aug 26, 2026](https://www.endorlabs.com/learn/fedramp-2026-vulnerability-rules-make-reachability-a-requirement); primary: [fedramp.gov ruleset](https://www.fedramp.gov/2026/reference/vulnerability-evaluation-and-reporting/) [primary not fetched; status is optional adoption, not yet mandatory, per secondary source]

**Other frameworks (per CSA analysis)**
- NIST SP 800-53 RA-5 / FISMA refers to "credible vulnerability sources" without naming NVD (medium dependency). ATO packages that name NVD will need addenda. — [CSA, Apr 26, 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-riskbased-enrichment-governance-2/)
- PCI DSS v4.0.1 Req. 6.3.1 requires risk ranking by "industry-recognized practices," usually read as NVD CVSS. ASV external scans fail at CVSS 4.0 or higher. — [CSA, Apr 26, 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-riskbased-enrichment-governance-2/)
- DoD RMF / CMMC 2.0 dependency is high: DISA STIG and ACAS workflows depend on enriched NVD content. Federal-software CVEs stay in NIST's priority scope, so the remaining gap falls mostly on contractor-only inventories. No CMMC practice number is cited. — [CSA, Apr 26, 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-riskbased-enrichment-governance-2/)
- SOC 2 CC7.1: auditors have generally accepted "NVD CVSS score" as default evidence. HIPAA §164.308 and ISO 27001 8.8 have low direct dependency. — [CSA, Apr 26, 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-riskbased-enrichment-governance-2/)

**NIST's April 2026 change (context for dependents)**
- Effective April 15, 2026, NIST prioritizes KEV CVEs (target: enrichment within one business day), CVEs in software used by the federal government, and EO 14028 critical software. Others are labeled "Lowest Priority - not scheduled for immediate enrichment," with enrichment available by request to nvd@nist.gov. NIST no longer routinely adds its own CVSS when the CNA provides one. Backlogged CVEs published before March 1, 2026 move to "Not Scheduled." The NVD Dashboard now reports status in real time. Congress is not mentioned, and no staffing or budget figures are given. — [NIST, Apr 15, 2026](https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth)
- About 29,000 backlogged CVEs moved to "Not Scheduled." — [noze.it, July 26, 2026](https://www.noze.it/en/insights/432-linux-kernel-cves-two-days/) [secondary]

**MS-ISAC / state and local**
- DHS ended CISA's funding agreement with CIS for MS-ISAC in 2025. MS-ISAC serves about 19,000 government entities and had $27M in FY2025 appropriations, according to CIS CEO John Gilligan. On June 4-5, 2026, Sen. Mark Warner unveiled the "Guaranteeing Universal Access to Cybersecurity Act," which would authorize $50M a year from FY2027 for no-cost services. It was introduced only, with no committee action. CISA points SLTTs to its regional teams. — [Nextgov, June 5, 2026](https://www.nextgov.com/cybersecurity/2026/06/warner-unveils-bill-restore-cyber-information-sharing-program-funding/414010/); letter: [Warner to DHS Sec. Mullin, June 4, 2026](https://www.warner.senate.gov/wp-content/uploads/2026/06/Mullin_CISA_MS-ISAC_06-04-26-1.pdf) [PDF not fetched]
- Federal funding ran out around Oct 2025, and MS-ISAC lost thousands of members. — [Route Fifty, Oct 2025](https://www.route-fifty.com/cybersecurity/2025/10/federal-funding-runs-out-cyber-info-sharing-center/408612/); [Cybersecurity Dive](https://www.cybersecuritydive.com/trendline/threat-intelligence/605/) [headlines only; I did not confirm exact dates or membership counts]
- Just Security names hospitals, rural municipalities, water utilities, rural school districts and small businesses as the users who depend most on free NVD enrichment. — [Just Security, Apr 27, 2026](https://www.justsecurity.org/136914/nist-cant-keep-up/)

**Open source / Linux kernel CNA**
- The Linux kernel became a CNA in February 2024. It issued 4,325 CVEs in 2024 (third-largest CNA) and was the largest CNA in 2025 at about 50 CVEs per week. It published 432 CVEs on July 19-20, 2026 (a review-queue flush). — [noze.it, July 26, 2026](https://www.noze.it/en/insights/432-linux-kernel-cves-two-days/)
- AI-driven reports: on May 17, 2026, Linus Torvalds called the kernel security list "almost entirely unmanageable," with reports up from 2-3 a week to 5-10 a day. Greg Kroah-Hartman said "The number of llm-found issues is only on the rise." FIRST's June forecast of about 66,000 CVEs for 2026 cited vulnerability-hunting agents (Anthropic Mythos, OpenAI GPT-5.4-Cyber). — [noze.it, July 26, 2026](https://www.noze.it/en/insights/432-linux-kernel-cves-two-days/) [secondary aggregation; Torvalds and Kroah-Hartman quotes not checked against primary posts]
- NIST had piloted tools to automate Linux kernel CVE enrichment, and planned "gap filling" by accepting CNA CVSS and CWE without revalidation (VulnCon, Apr 10, 2025). — [Socket, Apr 10, 2025](https://socket.dev/blog/vulncon-2025-nvd-scraps-consortium-plan)

### Inferences
- FedRAMP's 2026 ruleset moves from NVD-CVSS clocks to KEV/EPSS/reachability evaluation. That is a federal precedent for the brief's EPSS trigger. It also shows that one downstream compliance owner is already decoupling from NVD scores, which the brief should cite. FedRAMP PMO/GSA is a missing stakeholder with its own lever.
- If BOD 26-04 is confirmed, it also points federal agencies toward risk-based prioritization instead of CVSS alone.
- Because NIST stopped adding its own CVSS where a CNA provided one, CNA-supplied scores now feed FedRAMP, PCI and DoD compliance clocks directly. That raises the stakes of CNA data quality and of conflict-of-interest scoring (vendors scoring their own bugs).
- MS-ISAC's defunding removes a likely buffer for SLTTs that cannot buy commercial enrichment. SLTTs are an equity-focused stakeholder missing from the brief.
- The Linux kernel CNA (assigns CVEs to every qualifying fix) and AI-driven discovery are the volume drivers. Open-source maintainers are a stakeholder distinct from vendor CNAs, and they have little capacity to supply CPE/CVSS.

### Gaps
- I found no source on how FDA premarket cybersecurity guidance (Section 524B, SBOM/vulnerability monitoring) depends on NVD. Not researched within the budget.
- DoD/CMMC: no primary DISA or CMMC document confirmed. The dependency rating is CSA's judgment.
- PCI SSC: no statement from the PCI Security Standards Council responding to the NVD change was found.
- OpenSSF: no formal statement on the NVD triage was found.
- FedRAMP: I did not confirm the mandatory effective date for the 2026 ruleset or whether the 2024 NVD-CVSS requirement is formally superseded.

## 4. Congressional activity 2025-2026 on NVD/CVE and NIST budget/staffing

### Takeaway
Congress has been active through letters, bills and amendments, but nothing on NVD/CVE has been enacted. The main items are the June 2025 Thompson-Lofgren GAO request on CVE and NVD, the June 2026 Ramirez-Whitesides NDAA amendment to codify CVE (not made in order), and earlier AI-related NVD bills (2024). The NVD has about 21 analysts. FY2026 NIST appropriations were enacted Jan 23, 2026, but I could not find an NVD-specific line or report language. House Homeland Security (Democrats) and the Senate Cybersecurity Caucus (Warner/Tillis) are congressional stakeholders the brief does not name beyond "appropriations/science."

### Cited Findings
- On June 6, 2025, House Homeland Security Ranking Member Bennie Thompson and House Science Ranking Member Zoe Lofgren asked GAO to assess the effectiveness of CISA's CVE program and NIST's NVD, citing "funding challenges at NIST resulted in a backlog of thousands of vulnerabilities in the NVD." — [House Homeland Democrats, June 11, 2025](https://democrats-homeland.house.gov/news/correspondence/ranking-members-thompson-and-lofgren-request-gao-review-of-cve-and-nvd-federal-cybersecurity-programs); letter: [PDF](https://democrats-homeland.house.gov/download/2025-06-06-f-thompsonlofgren-t-dodaro-cve-nvd&download=1)
- June 2026: the Ramirez-Whitesides amendment to codify CVE under CISA, with a CISA-NIST modernization plan and a 15-member board. The House Rules Committee did not make it in order. — [Nextgov, June 18, 2026](https://www.nextgov.com/cybersecurity/2026/06/planned-ndaa-amendment-would-codify-cisas-role-cyber-vulnerability-program/414286/); [Nextgov, Aug 7, 2026](https://www.nextgov.com/cybersecurity/2026/08/cisa-cautions-against-rigid-rules-future-cyber-vulnerability-program/415282/)
- 2024 precedents: the Senate Secure AI Act (Warner/Tillis, May 1, 2024) would have directed NIST to update NVD for AI systems and CISA to update CVE or create an AI flaw process. A Warner spokesperson said he "supports full funding for NIST." — [The Record, May 1, 2024](https://therecord.media/senate-legislation-update-nvd-cve-program-artificial-intelligence). The House companion, H.R. 9720 (AI Incident Reporting and Security Enhancement Act; Ross, Obernolte, Beyer), cleared House Science by voice vote on Sept 25, 2024, "subject to the availability of appropriations." — [CyberScoop, Sept 25, 2024](https://cyberscoop.com/nist-artificial-intelligence-vulnerability-reporting-congress/) [I found no evidence of enactment.]
- NVD staffing: the NVD program has 21 analysts. A funding disruption in early 2024 left about three-quarters of submitted CVEs unprocessed at peak. A 2024 expert open letter to Congress and the Commerce Secretary called NVD "critical infrastructure" but produced no funding fix. — [Just Security, Apr 27, 2026](https://www.justsecurity.org/136914/nist-cant-keep-up/); open letter context: [CramHacks](https://www.cramhacks.com/p/nvd-program-delays) [not fetched]
- NIST dropped its 2024-announced NVD industry consortium (CRADA) plan as "too heavyweight" (VulnCon, Apr 10, 2025). It now relies on informal workshops and plans ADP integration (including CISA) and a CPE console for CNAs. — [Socket, Apr 10, 2025](https://socket.dev/blog/vulncon-2025-nvd-scraps-consortium-plan)
- FY2026 NIST appropriations: the compromise bill H.R. 6938 was released Jan 5, 2026 and signed Jan 23, 2026, after the FY2026 request (May/June 2025) proposed large cuts. — [AIP FYI NIST budget tracker](https://www.aip.org/fyi/fy2026-national-institute-of-standards-and-technology); proposed cuts: [Axios, May 2, 2025](https://www.axios.com/pro/tech-policy/2025/05/02/trump-budget-proposes-big-cuts-to-tech-and-science-agencies) [Dollar figures not retrievable (Tableau chart); Axios not fetched]
- NIST officials have publicly described the effect of staff cuts on cybersecurity work. — [CyberScoop](https://cyberscoop.com/encryption-nist-officials-detail-staff-cuts-impact/); [SC World](https://www.scworld.com/brief/nist-outlines-cybersecurity-efforts-amid-staffing-constraints) [headlines only; not fetched]
- Just Security's recommendation: fund NIST enrichment as critical infrastructure through dedicated appropriations scaled to CVE volume, estimated at "tens of millions of dollars annually" plus a several-fold expansion of analysts. — [Just Security, Apr 27, 2026](https://www.justsecurity.org/136914/nist-cant-keep-up/)

### Inferences
- The brief's "Congress ties funding to metrics" recommendation has natural vehicles: the pending GAO review (if completed) and the codification proposal's CISA-NIST joint modernization plan. Folding NVD metrics into the CVE codification text would be a concrete hook.
- The relevant committees are wider than appropriations and science: House and Senate Homeland Security (CISA/CVE), House Science (NIST/NVD), Armed Services (NDAA vehicle) and the Senate Cybersecurity Caucus.
- Partisan dynamics: the 2025-2026 NVD/CVE oversight actions found here are Democratic-led (Thompson, Lofgren, Ramirez, Whitesides, Warner). The 2024 AI-NVD bills were bipartisan. This matters for feasibility.

### Gaps
- I could not find FY2026 or FY2027 appropriations report language that mentions NVD specifically. Check House and Senate CJS reports (e.g., S.Rept. for S.2354, H.R. 5342 report).
- I did not find a GAO product responding to the June 2025 request.
- I could not confirm NIST FY2026 enacted dollars, ITL/cyber line amounts, NVD budget or headcount changes beyond "21 analysts."
- I found no congressional hearing dedicated to NVD/CVE in 2025-2026.

## 5. Think-tank and academic policy analyses (2024-2026)

### Takeaway
Policy analysis treating NVD/CVE as public infrastructure is thinner than expected from the named think tanks (CSIS, Brookings, R Street, CSET, Belfer, RAND). I found nothing from them in this pass. The most directly relevant pieces are a Just Security essay (Apr 2026), Cloud Security Alliance research notes (industry), Bitsight research on Chinese databases, and an Atlantic Council China vulnerability report (background). This gap is itself useful: a RAND student brief would fill a real hole.

### Cited Findings
- Just Security, "NIST Can't Keep Up. The Whole Digital Ecosystem Will Soon Feel It." (Joe Toomey, Coalition, Apr 27, 2026). Argues NVD is a public good. Calls triage a "scarcity-driven adaptation" and says Congress should fund enrichment as critical infrastructure. Notes that automation "cannot substitute for investment." Names insurers as stakeholders. — [Just Security](https://www.justsecurity.org/136914/nist-cant-keep-up/)
- Cloud Security Alliance research notes on the NVD change and the CVE Quality Era (Apr-Sept 2026). These are industry analyses with compliance-dependency ratings. — [CSA Apr 26, 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-riskbased-enrichment-governance-2/); [CSA Sept 29, 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-cisa-cve-quality-era-20260929-csa-styled/); [CSA Apr 29, 2026](https://labs.cloudsecurityalliance.org/research/csa-research-note-nist-nvd-enrichment-overhaul-20260429-csa/) [last not fetched]
- Bitsight, "Red Vulns Rising" (Feb 18, 2026), on CNNVD/CNVD. — [Bitsight](https://www.bitsight.com/blog/chinese-vulnerability-database-analysis-cnvd-cnnvd)
- Atlantic Council, "Sleight of Hand: How China Weaponizes Software Vulnerabilities." — [Atlantic Council](https://www.atlanticcouncil.org/in-depth-research-reports/report/sleight-of-hand-how-china-weaponizes-software-vulnerability/) [not fetched; likely 2023, outside the window]
- Institute for Security and Technology (IST) maintains a CVE/vulnerability-management resource topic. — [IST](https://securityandtechnology.org/resource_topic/cve) [not fetched; contents unknown]
- An academic paper on GCVE exists on arXiv. — [arXiv 2606.00856](https://arxiv.org/pdf/2606.00856) [not fetched; title and authors unverified]
- MSR 2026 paper, "Linux Kernel: Recency Matters, CVE Severity Doesn't, and History Fades." — [MSR 2026](https://2026.msrconf.org/details/msr-2026-technical-papers/31/Linux-Kernel-Recency-Matters-CVE-Severity-Doesn-t-and-History-Fades) [not fetched; title suggests CVSS severity is a poor prioritizer, which would support EPSS/KEV-based triage]
- RSIS commentary (Singapore, Sept 2025), CO25194, possibly on the CVE crisis. — [RSIS PDF](https://rsis.edu.sg/wp-content/uploads/2025/09/CO25194.pdf) [not fetched; topic unverified]

### Inferences
- Missing stakeholders named in this literature: cyber insurers (Coalition), commercial vulnerability-intelligence vendors that fill gaps and benefit from NVD shrinkage (VulnCheck, Sonatype, Tenable), FIRST (EPSS steward and CVE forecaster), and CVE Board members. FIRST in particular should be named if the brief recommends EPSS, since FIRST governs EPSS.
- Commercial substitutes create a policy tension the brief should address: is NVD triage a public-goods failure or an acceptable market handoff? The equity answer hinges on SLTTs, small businesses and open-source users.

### Gaps
- I found no 2024-2026 NVD/CVE-specific publications from Lawfare, CSIS, Brookings, R Street, CSET, Belfer or RAND in this search budget. That does not prove none exist. Targeted site searches (e.g., site:lawfaremedia.org CVE) are recommended before claiming a literature gap.
- I did not fetch or verify the arXiv GCVE paper, the MSR 2026 paper, or the RSIS commentary.
