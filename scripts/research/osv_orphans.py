"""osv_orphans.py — which CVEs without CPE does no package advisory cover either?

Research script (Nov 7, 2026), not part of the site build. Tests the objection "CPE is a
dying standard; purl/OSV advisories will cover it": of the CVEs in our pull that lack CPE,
how many appear in no package advisory that OSV aggregates (GitHub GHSA, PyPI, Go, npm,
Maven, Debian, Ubuntu, Red Hat, SUSE, Alpine, container distros, ...)? Those are "orphaned":
a scanner can match them neither by CPE nor by package name.

Method: read every OSV ecosystem export and index each advisory under its own ID and every
ID in its `aliases`, `upstream` and `related` fields. A CVE in our pull is "covered" if any
non-withdrawn advisory that names a package ecosystem points to it. Coverage is split into
  language  an application-package ecosystem (PyPI, npm, Maven, Go, Packagist, crates.io, ...)
  distro    only Linux-distribution, container-OS or Linux-kernel packages
  none      no package advisory: orphaned
The GIT export is skipped: its ranges are commits, not package names, and OSV generates many
of its records from the CVE record itself.

Why not the per-CVE API (GET api.osv.dev/v1/vulns/<CVE>)? Tried first. It resolves GHSA
aliases (273 of 277 PyPI CVEs found) but links only 784 of the 3,351 window CVEs that
Debian's export covers, so it overstates orphans, mostly Linux kernel CVEs.

Caveats: "orphaned" means no open package advisory, not no advisory anywhere (vendor-only
bulletins and commercial feeds are invisible to OSV). Snapshot as of the export date;
advisories keep arriving, so a 30-day window's orphan share falls as it ages.

Inputs (download first; nothing is fetched here):
  osv_dir   one <Ecosystem>.zip per line of
            https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt (spaces -> _),
            from https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip
            (about 3.1 GB without GIT, Nov 7, 2026)

Usage: python -I scripts/research/osv_orphans.py OSV_DIR    (from the repo root)
Writes data/processed/osv_orphans.json and data/raw/osv_orphans_per_cve.json (git-ignored).
"""

import csv
import json
import sys
import zipfile
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CSV = ROOT / "data/processed/cves_sample.csv"
RAW = ROOT / "data/raw/nvd_sample.json"
OUT = ROOT / "data/processed/osv_orphans.json"

DISTRO = {"AlmaLinux", "Alpaquita", "Alpine", "Azure Linux", "BellSoft Hardened Containers",
          "Chainguard", "CleanStart", "Debian", "Echo", "Linux", "Mageia", "MinimOS", "Red Hat",
          "Red Hat Lightwell", "Rocky Linux", "Root", "SUSE", "TuxCare", "Ubuntu", "Wolfi",
          "openEuler", "openSUSE"}
PLACEHOLDERS = {"", "n/a", "unknown", "unspecified", "-"}


def index_exports(osv_dir, wanted):
    """CVE ID -> set of ecosystems whose advisories point to it (only IDs in `wanted`)."""
    hits = defaultdict(set)
    zips = sorted(Path(osv_dir).glob("*.zip"))
    for zpath in zips:
        with zipfile.ZipFile(zpath) as z:
            for name in z.namelist():
                d = json.loads(z.read(name))
                if d.get("withdrawn"):
                    continue
                ecos = {(a.get("package") or {}).get("ecosystem", "").split(":")[0]
                        for a in d.get("affected") or []} - {"", "GIT"}
                if not ecos:
                    continue
                refs = [d["id"]] + (d.get("aliases") or []) + (d.get("upstream") or []) + (d.get("related") or [])
                for ref in refs:
                    if ref in wanted:
                        hits[ref] |= ecos
        print(f"{zpath.name}: {len(hits)} window CVEs covered so far", file=sys.stderr)
    return hits, [z.stem for z in zips]


def kind(ecos):
    if not ecos:
        return "none"
    return "distro" if ecos <= DISTRO else "language"


def first_vendor(cve):
    for block in cve.get("affected") or []:
        for item in block.get("affectedData") or []:
            v = (item.get("vendor") or "").strip()
            if v.lower() not in PLACEHOLDERS:
                return v
    return "(none named)"


def main(osv_dir):
    rows = [r for r in csv.DictReader(open(CSV, encoding="utf-8")) if r["vuln_status"] != "Rejected"]
    ids = {r["cve_id"] for r in rows}
    vendors = {v["cve"]["id"]: first_vendor(v["cve"]) for v in json.load(open(RAW, encoding="utf-8"))}
    hits, exports = index_exports(osv_dir, ids)
    cov = {i: kind(hits.get(i, set())) for i in ids}

    def tally(subset):
        c = Counter(cov[r["cve_id"]] for r in subset)
        n = len(subset)
        return {"n": n, **{k: c.get(k, 0) for k in ("language", "distro", "none")},
                "pct_none": round(100 * c.get("none", 0) / n, 1) if n else None}

    def epss(r):
        return float(r["epss"]) if r["epss"] else 0.0

    no_cpe = [r for r in rows if r["has_cpe"] == "False"]
    orphans = [r for r in no_cpe if cov[r["cve_id"]] == "none"]
    out = {
        "run_date": date.today().isoformat(),
        "source": "OSV ecosystem exports (osv-vulnerabilities.storage.googleapis.com), GIT excluded; "
                  "scripts/research/osv_orphans.py",
        "exports_read": exports,
        "window": f"{min(r['published'] for r in rows)[:10]} to {max(r['published'] for r in rows)[:10]}",
        "definitions": {"language": "named in an application-package advisory",
                        "distro": "only in Linux distribution, container-OS or kernel advisories",
                        "none": "in no package advisory OSV aggregates (orphaned)"},
        "all_non_rejected": tally(rows),
        "with_cpe": tally([r for r in rows if r["has_cpe"] == "True"]),
        "without_cpe": tally(no_cpe),
        "without_cpe_by_status": {s: tally([r for r in no_cpe if r["vuln_status"] == s])
                                  for s in sorted({r["vuln_status"] for r in no_cpe})},
        "without_cpe_cna_names_product": tally([r for r in no_cpe if r["cna_names_product"] == "True"]),
        "orphans": {"n": len(orphans),
                    "pct_of_live": round(100 * len(orphans) / len(rows), 1),
                    "pct_cna_names_product": round(100 * sum(r["cna_names_product"] == "True" for r in orphans)
                                                   / len(orphans), 1) if orphans else None,
                    "in_kev": sum(r["in_kev"] == "True" for r in orphans),
                    "epss_ge_0.10": sum(epss(r) >= 0.10 for r in orphans),
                    "epss_ge_0.05": sum(epss(r) >= 0.05 for r in orphans),
                    "epss_ge_0.01": sum(epss(r) >= 0.01 for r in orphans)},
        "top_orphan_vendors": Counter(vendors.get(r["cve_id"], "(none named)") for r in orphans).most_common(30),
        "top_covered_no_cpe_vendors": Counter(vendors.get(r["cve_id"], "(none named)") for r in no_cpe
                                              if cov[r["cve_id"]] != "none").most_common(15),
        "ecosystems_covering_no_cpe": Counter(e for r in no_cpe for e in hits.get(r["cve_id"], ())).most_common(),
    }
    OUT.write_text(json.dumps(out, indent=2), encoding="utf-8")
    (ROOT / "data/raw/osv_orphans_per_cve.json").write_text(
        json.dumps({i: sorted(hits.get(i, ())) for i in sorted(ids)}), encoding="utf-8")
    print(json.dumps({k: out[k] for k in ("window", "all_non_rejected", "with_cpe", "without_cpe",
                                          "without_cpe_by_status", "orphans")}, indent=1))


if __name__ == "__main__":
    main(sys.argv[1])
