"""trigger_table.py — one table: each re-check trigger's recall, load, flow, cost and benefit (M3, M4).

Combines, without fetching anything:
  recall       data/processed/kev_trigger_recall.json   (kev_trigger_recall.py)
  EPSS volume  data/processed/recheck_measured.json     (0.10, change-history corrected) and
               data/processed/recheck_volume_rerun_2026-11-08.txt (recheck_volume.py re-run on Nov 8
               feeds; 0.05 / 0.01 monthly flows = stock-status crossers, no change-history correction)
  SSVC, LEV    data/processed/trigger_volume.json       (trigger_volume.py)
  cost         scripts/cost_model.py at 45 minutes and $120/h (one-time load cost; yearly flow cost)
  benefit      sum of current EPSS over the one-time load = expected CVEs with exploitation activity in
               the next 30 days (EPSS = 30-day probability of exploitation activity, not compromise)
Output: data/processed/trigger_table.json and a markdown table on stdout.
Run:    python scripts/research/trigger_table.py
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import cost_model as cm  # noqa: E402

P = ROOT / "data" / "processed"
rec = json.loads((P / "kev_trigger_recall.json").read_text())["recall"]
rm = json.loads((P / "recheck_measured.json").read_text())
tv = json.loads((P / "trigger_volume.json").read_text())
flows10 = [w["requeues"] for w in rm["monthly_flow"]["windows"]]
FLOW_RERUN = {"0.05": [23, 30, 8, 25], "0.01": [183, 384, 655, 449]}   # "in stock statuses", rerun file


def recall_cells(key):
    a, v4, v5 = rec["all"], rec["epss_v4"], rec["epss_v5"]
    return f"{a[key]} of {a['n']}", f"{v4[key]} of {v4['n']}", f"{v5[key]} of {v5['n']}"


rows = []
for t, key in (("0.10", "epss_ge_0.10"), ("0.05", "epss_ge_0.05"), ("0.01", "epss_ge_0.01")):
    flow = flows10 if t == "0.10" else FLOW_RERUN[t]
    rows.append({"trigger": f"EPSS >= {t}", "recall": recall_cells(key),
                 "one_time": tv["epss"][t]["one_time_load"], "flow": [min(flow), max(flow)],
                 "benefit_30d": tv["epss"][t]["expected_events_30d"]})
lv = tv["lev"]["0.10"]
lf = [w["requeues"] for w in lv["monthly_flow"]]
rows.append({"trigger": "LEV >= 0.10 (from EPSS)", "recall": recall_cells("lev_ge_0.10"),
             "one_time": lv["one_time_load"], "flow": [min(lf), max(lf)], "benefit_30d": lv["expected_events_30d"]})
sf = [w["requeues"] for w in tv["ssvc"]["monthly_flow"]]
rows.append({"trigger": "SSVC poc/active, >= 24 h before listing", "recall": recall_cells("ssvc_poc_or_active_24h_before"),
             "one_time": tv["ssvc"]["one_time_load"], "flow": [min(sf), max(sf)],
             "benefit_30d": tv["ssvc"]["expected_events_30d"]})
rows.append({"trigger": "SSVC poc/active, any time before listing", "recall": recall_cells("ssvc_poc_or_active_any_time_before"),
             "one_time": tv["ssvc"]["one_time_load"], "flow": [min(sf), max(sf)],
             "benefit_30d": tv["ssvc"]["expected_events_30d"]})

print("| Trigger | Recall, all (2025–26) | Recall, EPSS v4 era | Recall, EPSS v5 era | One-time load | Cost once (45 min) "
      "| Monthly flow | Cost/yr at max flow | Capacity at max flow | Expected exploited-activity CVEs, next 30 d (one-time load) |")
print("|---|---|---|---|---|---|---|---|---|---|")
for r in rows:
    hi = cm.outputs(r["flow"][1], minutes=45, one_time=r["one_time"])
    r.update({"cost_once": hi["once"], "cost_year_max_flow": hi["cost"], "capacity_max_flow": hi["capacity"]})
    print(f"| {r['trigger']} | {r['recall'][0]} | {r['recall'][1]} | {r['recall'][2]} | {r['one_time']:,} | {r['cost_once']} "
          f"| {r['flow'][0]:,}–{r['flow'][1]:,} | {r['cost_year_max_flow']} | {r['capacity_max_flow']} | {r['benefit_30d']} |")
(P / "trigger_table.json").write_text(json.dumps({"minutes": 45, "rate": cm.RATE, "rows": rows}, indent=1))
