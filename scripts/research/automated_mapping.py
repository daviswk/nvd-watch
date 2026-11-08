"""automated_mapping.py — could CNA product data be turned into CPE automatically? (S1)

Question, for CVEs in the current 30-day pull (data/processed/cves_sample.csv) that NVD has not given CPE:
  (a) what share have a CNA `affected` entry whose vendor + product exactly match a CPE dictionary
      vendor:product pair? Rule: lower-case both sides and replace spaces with "_" (CPE's convention);
      nothing else (no fuzzy matching, no punctuation stripping, no alias tables). A CVE counts if
      any of its affected entries matches.
  (b) what share of CNA records already carry `affected[].cpes` (a field in the CVE Record Format
      schema, product.cpes)? Checked in the CVE record itself (cvelistV5), since NVD's API does not
      pass that field through as CPE configurations. `affected[].packageURL` is counted alongside.
Both are reported over all non-rejected window CVEs without NVD CPE, with n.

Inputs:  data/processed/cves_sample.csv; NVD CPE dictionary nvdcpe-2.0.tar.gz
         (https://nvd.nist.gov/feeds/json/cpe/2.0/); cvelistV5 bulk cves.zip
Output:  data/processed/automated_mapping.json
Run:     python -I scripts/research/automated_mapping.py CPE_TARGZ CVES_ZIP
"""
import json
import sys
import tarfile
import zipfile
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[2]


def norm(s):
    return " ".join(str(s).lower().split()).replace(" ", "_")


def cpe_unescape(s):
    return s.replace("\\", "")


def dictionary_pairs(targz):
    pairs = set()
    with tarfile.open(targz) as t:
        for m in t.getmembers():
            if not m.name.endswith(".json"):
                continue
            for p in json.load(t.extractfile(m)).get("products", []):
                f = p["cpe"]["cpeName"].split(":")
                pairs.add((cpe_unescape(f[3]), cpe_unescape(f[4])))
    return pairs


def main(cpe_targz, cves_zip):
    df = pd.read_csv(ROOT / "data" / "processed" / "cves_sample.csv")
    df = df[df.vuln_status != "Rejected"]
    target = set(df[~df.has_cpe].cve_id)
    print(f"window CVEs (non-rejected): {len(df):,}; without NVD CPE: {len(target):,}")
    pairs = dictionary_pairs(cpe_targz)
    print(f"CPE dictionary vendor:product pairs: {len(pairs):,}")

    found = {}
    with zipfile.ZipFile(cves_zip) as z:
        for name in z.namelist():
            cve = name.rsplit("/", 1)[-1][:-5]
            if name.endswith(".json") and cve in target:
                found[cve] = json.loads(z.read(name))["containers"].get("cna", {}).get("affected", [])
    n = len(found)
    with_affected = [c for c, a in found.items() if a]
    exact = [c for c, a in found.items()
             if any((norm(x.get("vendor", "")), norm(x.get("product", ""))) in pairs for x in a)]
    vendors = {v for v, _ in pairs}
    vendor_only = [c for c, a in found.items() if any(norm(x.get("vendor", "")) in vendors for x in a)]
    cpes = [c for c, a in found.items() if any(x.get("cpes") for x in a)]
    purl = [c for c, a in found.items() if any(x.get("packageURL") for x in a)]
    examples = sorted(exact)[:10]
    out = {
        "rule": "exact vendor:product match after lower-casing and spaces->'_' (CPE dictionary, NVD feed nvdcpe-2.0)",
        "window_published": [df.published.min(), df.published.max()],   # the local CSV's own pull
        "without_nvd_cpe": len(target), "found_in_cvelist": n,
        "with_cna_affected": len(with_affected),
        "a_exact_vendor_product_match": len(exact),
        "a_vendor_name_match_only_context": len(vendor_only),
        "b_cna_affected_cpes": len(cpes),
        "b_cna_affected_packageURL": len(purl),
        "dictionary_pairs": len(pairs),
        "examples_exact": examples,
    }
    (ROOT / "data" / "processed" / "automated_mapping.json").write_text(json.dumps(out, indent=1))
    for k, v in out.items():
        print(k, v if not isinstance(v, int) or k in ("dictionary_pairs",) else f"{v:,} ({100 * v / n:.1f}%)" if n else v)


if __name__ == "__main__":
    main(*sys.argv[1:3])
