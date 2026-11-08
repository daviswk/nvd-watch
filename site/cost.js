/* NVD Watch — the re-check cost rule in the browser.
   Mirrors scripts/cost_model.py: same arithmetic, half-up rounding, same money format. Constants and
   wording are NOT written here; they come from the model the build writes into the page
   (<script id="cost-model">) and into data/cost_model.json. scripts/check_cost_model.py runs this
   file under Node and fails if any string differs from the Python.
   Used by app.js (the simulator) and story.js (the 3D story). */
var NVDCost = (function () {
  "use strict";

  function halfUp(x) { return Math.floor(x + 0.5); }
  function num(n) { return halfUp(n).toLocaleString("en-US"); }
  function money(n) {
    if (n >= 1e6) return "$" + (halfUp(n / 1e4) / 100).toFixed(2).replace(/\.?0+$/, "") + "M";
    return "$" + num(n / 1000) + "K";
  }
  function fill(template, values) {
    return template.replace(/\{(\w+)\}/g, function (_, k) { return values[k]; });
  }

  // Every string the estimate shows, for one set of inputs (cost_model.outputs in Python).
  function outputs(model, cves, minutes, rate, oneTime) {
    var hours = cves * 12 * minutes / 60;
    var cost = hours * rate;
    var mins = model.minutes;
    var lo = cves * 12 * Math.min.apply(null, mins) / 60 * rate;
    var hi = cves * 12 * Math.max.apply(null, mins) / 60 * rate;
    var capacity = (halfUp(1000 * cves / model.capacity_per_month) / 10).toFixed(1) + "%";
    var ratio = cost / model.oig_per_year;
    var share = ratio <= 1
      ? fill(model.share_under, { pct: halfUp(100 * ratio) })
      : fill(model.share_over, { times: String(halfUp(ratio * 10) / 10) });
    var verdict = fill(model.verdict, { share: share, oig: money(model.oig_per_year) });
    return {
      hours: num(hours),
      capacity: capacity,
      cost: money(cost),
      low_high: money(lo) + " to " + money(hi),
      offset: halfUp(100 * ratio) + "%",
      once: money((oneTime || 0) * minutes / 60 * rate),
      sentence: fill(model.sentence, {
        cves: num(cves), minutes: minutes, hours: num(hours), capacity: capacity,
        cost: money(cost), rate: num(rate), verdict: verdict
      })
    };
  }

  return { outputs: outputs, money: money, num: num };
})();

if (typeof module !== "undefined") module.exports = NVDCost;
