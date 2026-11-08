# Key sources

Full annotated list with more links: `docs/research/evidence-review.md`. Vendor or advocacy sources are marked (V).

## Government
- NIST, NVD operations update (Apr 15, 2026): https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth
- NIST RFI, Modernizing the NVD in the Age of AI, 91 FR 52042 (Aug 12, 2026), docket NIST-2026-0100: https://www.federalregister.gov/documents/2026/08/12/2026-16371/request-for-information-rfi-on-modernizing-the-national-vulnerability-database-in-the-age-of
- Commerce OIG, OIG-26-020-I (May 26, 2026), abstract: https://www.oig.doc.gov/wp-content/OIGPublications/OIG-26-020-I_Abstract-SECURED.pdf
- NIST CSWP 41, Likely Exploited Vulnerabilities (Mell & Spring, May 2025): https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.41.pdf
- FedRAMP 2026 vulnerability evaluation and reporting rules: https://www.fedramp.gov/2026/reference/vulnerability-evaluation-and-reporting/
- CISA Vulnrichment: https://github.com/cisagov/vulnrichment
- CISA KEV catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

## RAND
- RR-A3892-2, AI agents put offensive cyber within reach of novices (Jun 2026): https://www.rand.org/pubs/research_reports/RRA3892-2.html
- RR-1751, Zero Days, Thousands of Nights (2017): https://www.rand.org/pubs/research_reports/RR1751.html
- RR-1700, A Framework for Exploring Cybersecurity Policy Options (2016): https://www.rand.org/content/dam/rand/pubs/research_reports/RR1700/RR1700/RAND_RR1700.pdf
- Polley, To Disclose, or Not to Disclose (Pardee RAND dissertation, 2022): https://www.rand.org/content/dam/rand/pubs/rgs_dissertations/RGSDA1900/RGSDA1954-1/RAND_RGSDA1954-1.pdf
- Jacobs, Romanosky et al., EPSS (2019): https://arxiv.org/pdf/1908.04856
- Tierney et al., RR-A1888-2, Quantifying Vulnerability Lifespans for U.S. Marine Corps Joint Cyber Weapons (Nov 14, 2023): https://www.rand.org/pubs/research_reports/RRA1888-2.html — ICS minor updates every 178 days on average
- Alhajjar, Romanosky, Kilian & Uchill, RR-A4983-1, A Structured Approach to Identifying and Characterizing AI Vulnerabilities (Jul 30, 2026): https://www.rand.org/pubs/research_reports/RRA4983-1.html — 31 classes of AI vulnerabilities
- Background: Sarma & Fisher, "Tipping the Cyber Balance" (Feb 2026)

## Measurement and analysis
- Barracuda, The KEV gap (Jul 24, 2026) (V): https://blog.barracuda.com/2026/07/24/KEV-gap-how-fast-do-exploited-bugs-get-flagged
- Volerion via Dark Reading (2026) (V): https://darkreading.com/vulnerabilities-threats/nist-enrichment-reductions-cve-coverage-accuracy
- VulnCheck, State of Exploitation 2026 (V): https://www.vulncheck.com/blog/state-of-exploitation-2026
- Cyber Strategy Institute, The Count Broke First (Oct 23, 2026) — disputed: https://cyberstrategyinstitute.com/cve-state-of-risk-october-2026/
- Brian Martin, The NVD shell game (May 7, 2026): https://jericho.blog/2026/05/07/the-nvd-shell-game-schrodingers-enriched-vulnerability/
- Jacobs et al., EPSS v3 (2023): https://arxiv.org/html/2302.14172v2
- FIRST EPSS FAQ: https://www.first.org/epss/faq
- Parla, EPSS critique (arXiv 2411.02618): https://arxiv.org/pdf/2411.02618
- Mandiant, Time-to-exploit trends 2023: https://cloud.google.com/blog/topics/threat-intelligence/time-to-exploit-trends-2023
- Mandiant, M-Trends 2026: https://cloud.google.com/blog/topics/threat-intelligence/m-trends-2026/
- Google GTIG, Vulnerability trends in the AI era (Sep 30, 2026): https://cloud.google.com/blog/topics/threat-intelligence/vulnerability-discovery-and-exploitation-trends-in-the-ai-era
- FIRST, 2026 vulnerability forecast update (Jun 15, 2026): https://www.first.org/blog/20260615-vulnerability-forecast-update

## Related public tools (RogoLabs, Jerry Gamblin; https://rogolabs.net)
These measure the CVE ecosystem; NVD Watch measures NIST. Link or cite, don't rebuild.
- CVE.ICU, CVE counts by year/day/publisher/CWE/CPE reference: https://cve.icu (repo: https://github.com/rogolabs/cve.icu)
- CVE Floodline, daily CVE cohorts re-scored against the dated EPSS archive at day 0/7/30/90, plus KEV lag: https://cvefloodline.org (repo: https://github.com/RogoLabs/cvefloodline.org, Apache-2.0; data file `data/floodline.json`). Reused for the re-check volume estimate.
- CNA Scorecard, CNA record completeness over the last six months: https://cnascorecard.org (repo: https://github.com/RogoLabs/CNAScoreCard)
- CNAPulse, CNA publishing activity vs. a 12-month baseline, 545 CNAs: https://cnapulse.org (repo: https://github.com/RogoLabs/CNAPulse; data from CVEProject/cvelistV5)
- SADP Tracker, the CVE Program's Supplier ADP pilot (Siemens from Apr 14, 2026; Red Hat from Jun 30, 2026; 3,349 unique CVEs / 3,391 records with supplier-added affected-product data as of Nov 7, 2026): https://rogolabs.github.io/SADP-Tracker/index.html (repo: https://github.com/RogoLabs/SADP-Tracker; records from https://github.com/CVEProject/sadp-pilot)

## Policy writing
- Toomey, NIST Can't Keep Up. The Whole Digital Ecosystem Will Soon Feel It., Just Security (Apr 27, 2026): https://www.justsecurity.org/136914/nist-cant-keep-up/ — argument, no new data; asks Congress for appropriations scaled to CVE volume
- Schwartz & Shen, CCPL Report: Ensuring the Longevity of the CVE Program, Center for Cybersecurity Policy and Law (Jul 17, 2025): https://centerforcybersecuritypolicy.org/insights-and-research/ccpl-report-ensuring-the-longevity-of-the-cve-program (PDF: https://cdn.prod.website-files.com/660ab0cd271a25abeb800460/6878fd092e452b1737e1c394_CCPL_CVE-Whitepaper_2025.07_FINAL.pdf) — CVE funding and governance questions; NVD only as background
- Ma & Hatangadi, The Global Cyber Vulnerability Database Cannot Run on Unstable Funding, FDD policy brief (Jul 29, 2025): https://www.fdd.org/analysis/2025/07/29/the-global-cyber-vulnerability-database-cannot-run-on-unstable-funding/ — joint, stable CVE funding with international partners and industry
- Health-ISAC, Hacking Healthcare weekly blog (Aug 13, 2026), TLP:WHITE: https://www.aha.org/system/files/media/file/2026/08/h-isac-tlp-white-hacking-healthcare-8-13-2026.pdf — summarizes NIST's NVD RFI for the health sector
- House Energy and Commerce (Walden, Harper, Blackburn, Latta), letters to DHS and MITRE on the CVE program (Aug 27, **2018**), via HSToday: https://www.hstoday.us/federal-pages/dhs/house-energy-committee-leaders-urge-dhs-to-reform-critical-cybersecurity-database/ — history, not current oversight

## Data quality and tool exposure
- Anwar, Abusnaina, Chen, Li & Mohaisen, Cleaning the NVD: Comprehensive Quality Assessment, Improvements, and Analyses, IEEE TDSC 19(6):4255–4269 (2022), doi:10.1109/TDSC.2021.3125270: https://faculty.cc.gatech.edu/~frankli/papers/nvd_tdsc2022.pdf — peer-reviewed; NVD snapshot of May 21, 2018
- "Ikesan", NIST NVD goes risk-based: which SCA tools still miss Deferred CVEs, Lilting Channel (May 12, 2026) (V, single analyst, untested): https://lilting.ch/en/articles/nist-nvd-risk-based-cve-enrichment

## AI and code durability
- Anthropic Frontier Red Team, LLMs are making formal software verification feasible at a much larger scale (Oct 22, 2026) (V; the project uses Claude): https://www.anthropic.com/research/formal-verification
- Stenberg, ignore the slop (Oct 22, 2026): https://daniel.haxx.se/blog/2026/10/22/ignore-the-slop/
- Tom's Hardware (Luke James), Torvalds on AI bug reports, May 18, 2026: https://www.tomshardware.com/software/linux/linus-torvalds-says-ai-bug-reports-have-made-the-linux-security-mailing-list-almost-entirely-unmanageable
- GitLab CVE-2026-110264 (NVD), affects GitLab from 7.0; v7.0.0 tagged Jun 20, 2014: https://gitlab.com/gitlab-org/gitlab/-/tags/v7.0.0

## Cases
- PHP2Shell: Recorded Future https://www.recordedfuture.com/blog/php2shell-vulnerability-exploitation ; The Register (Oct 27, 2026) https://www.theregister.com/cyber-crime/2026/10/27/cisa-confirms-php2shell-under-attack-as-researchers-clock-successful-exploits/5305681
