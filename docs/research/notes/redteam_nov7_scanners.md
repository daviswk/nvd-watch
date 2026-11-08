# S2: who is actually blind without CPE? (Grype, Trivy, WPScan)

Research date: 2026-11-07/08 (red-team round 6, `docs/red-team-nov7.md` task S2). Primary sources are the projects' own docs and source code, gathered by a research subagent (Claude Opus 5.5). Claude checked the claims against the cited URLs listed below. The orphan sample check is in `docs/red-team-nov7-response.md`.

## Grype (Anchore)

- **Data sources.** Grype's data comes from Vunnel providers: Alpine, Amazon, Azure, Debian, Echo, GitHub Security Advisories, NVD, Oracle, RedHat, SLES, Ubuntu and Wolfi. Source: [anchore/vunnel README](https://github.com/anchore/vunnel), "Supported data sources".
- **CPE matching against NVD is off by default for language ecosystems.**
  - `defaultMatchConfig` in [`cmd/grype/cli/options/match.go`](https://github.com/anchore/grype/blob/main/cmd/grype/cli/options/match.go) (about lines 115–132) sets `UseCPEs: false` for java, dotnet, golang, javascript, python, ruby, rust, hex, dpkg and rpm.
  - It sets `true` only for `jvm` and `stock`.
  - The [configuration reference](https://oss.anchore.com/docs/reference/grype/configuration/) agrees.
- **Unknown software and binaries match only through NVD CPE.** The `stock` matcher handles any package that has no ecosystem matcher. It calls `MatchPackageByEcosystemAndCPEs(..., UseCPEs)`, and `UseCPEs` is on by default for it. Source: `grype/matcher/stock/matcher.go`.
- **Why the defaults look like this.** Anchore's Oct 12, 2023 [blog post](https://anchore.com/blog/say-goodbye-to-false-positives/) gives two reasons:
  - CPE matching is the most common source of false positives.
  - Binaries are not in the GitHub Advisory Database, so they still need CPE.

## Trivy (Aqua)

- **Detection sources.** Trivy uses:
  - distro advisories for OS packages;
  - for language packages: GitHub Advisory Database, Go vulndb, Ruby and PHP advisory databases, OSV (Rust) and GitLab advisories (C/C++).

  Source: [trivy.dev vulnerability scanner docs](https://trivy.dev/latest/docs/scanner/vulnerability/).
- **NVD is not a detection source.** The docs say Trivy consumes only the advisories listed there. NVD is used only as a fallback for severity and CVSS.
- **Third-party, self-compiled packages and binaries are not supported.** The exceptions are Go and Rust binaries with embedded module info, and SBOMs.

## WPScan

- The [WPScan homepage](https://wpscan.com/) describes a WordPress vulnerability database maintained by its own security staff, with a submission form.
- Not verified: whether WPScan is independent of NVD CPE. The about page returned 404.

## What this means for the harm chain

| Software type | Trivy | Grype (default) | Needs NVD CPE? |
|---|---|---|---|
| Distro package (deb/rpm/apk) | distro feed | distro feed | No |
| Language package with GHSA/OSV advisory | GHSA/OSV | GHSA | No |
| Vendor appliance, closed-source product, binary with no package metadata | not scanned | stock matcher, **NVD CPE only** | **Yes** |
| WordPress plugin | not scanned | only if Syft assigns a CPE (not checked) | Yes for Grype; WPScan is a separate path |

## Not verified

- The body of `MatchPackageByEcosystemAndCPEs`.
- Whether Syft catalogs WordPress plugins.
- The Grype version in which each default changed.
- Commercial scanners (Tenable, Qualys, Rapid7): not researched this round. How they match is unknown here.
