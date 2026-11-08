# M5: the existing channel for requesting enrichment of a Not Scheduled CVE

Research date: 2026-11-07/08 (red-team round 6, task M5). Sources are NIST/NVD pages only. A research subagent (Claude Opus 5.5) read them in a browser, because a plain fetch of nvd.nist.gov returns an empty Angular page. No form was submitted and no email was sent.

## What NIST publishes

| Question | What the page says | Source (page date) |
|---|---|---|
| Definition | The Not Scheduled (API `Deferred`) row ends: "Requests may be made to schedule for enrichment." | [NVD vulnerability status](https://nvd.nist.gov/vuln/vulnerability-status) (updated Apr 14, 2026) |
| How to request | By email to nvd@nist.gov. The Apr 15 announcement says users can request enrichment of any lowest-priority CVE this way. No required fields are named. Rescore and reanalysis requests go to the same address. | [NIST news, Apr 15, 2026](https://www.nist.gov/news-events/news/2026/04/nist-updates-nvd-operations-address-record-cve-growth) (updated Apr 17); same text on [nist.gov/itl/nvd](https://www.nist.gov/itl/nvd) (modified Aug 26, 2026) |
| Web form | The [NVD contact form](https://nvd.nist.gov/contact/contact-form) offers General, CVE Rescore Request, CVE Configuration Update Request, CPE URIs Missing and CVMAP. It has no "enrichment request" category. | (no date shown) |
| CVE page | The banner on a Not Scheduled CVE says the record is not being prioritized. It gives no request route (example: [CVE-2026-59774](https://nvd.nist.gov/vuln/detail/CVE-2026-59774)). | live |
| Turnaround | Requests are reviewed and scheduled "as resources allow". The only time goal NIST states is one business day for KEV CVEs ([CVE process](https://nvd.nist.gov/general/cve-process), updated Apr 14, 2026). | Apr 15 news page |
| Request counts | None published. The [NVD dashboard](https://nvd.nist.gov/general/nvd-dashboard) shows only status counts (Nov 7 snapshot: Deferred 61,425). The Aug 12 blog and the RFI (91 FR 52042; [govinfo PDF](https://www.govinfo.gov/content/pkg/FR-2026-08-12/pdf/2026-16371.pdf)) do not mention the request process. | live |

## Reading

The side door exists. It is an email-only route, with:

- no published criteria;
- no service goal;
- no reporting.

So pushback point 4 is right that a request channel exists. What NIST does not publish is how often the channel is used or how fast it works. That gap is what metric 4 (re-queue counts and time to enrichment after re-queue) would measure.

## Not verified

- Any count of requests.
- Any turnaround time.
- Whether contact-form submissions count as enrichment requests.

## Live test: Will's to do

Submitting a real request, for example for CVE-2026-59774 (Gitea; Not Scheduled; EPSS 0.28), is an outside action. This session did not do it. If Will sends one, he should log the send time and NVD's status changes for that CVE (change history API), so the result becomes a first data point for metric 4.
