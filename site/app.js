/* NVD Watch — progressive enhancement only.
   The page is complete without this script: every number is rendered at build time.
   This adds (1) the re-check cost simulator and (2) the Copy citation button. */
(function () {
  "use strict";

  /* ---------- Re-check cost simulator ---------- */
  var CAPACITY_PER_MONTH = 5000;   // OIG: NIST has never processed more than 5,000 CVEs in a month (peak output, not a stated ceiling)
  var OIG_OFFSET = 400000;         // OIG: ~$800K over two years from minimizing re-scoring, i.e. ~$400K a year

  var form = document.getElementById("sim-form");
  if (form) {
    var cvesInput = form.elements.cves;
    var rateInput = form.elements.rate;
    var out = {
      hours: document.getElementById("sim-hours"),
      capacity: document.getElementById("sim-capacity"),
      cost: document.getElementById("sim-cost"),
      lowHigh: document.getElementById("sim-low-high"),
      offset: document.getElementById("sim-offset"),
      once: document.getElementById("sim-once"),
      sentence: document.getElementById("sim-sentence")
    };
    // Defaults are rendered into the form at build time (data-default-cves), so the script never
    // carries a number the page does not.
    var defaults = { cves: Number(form.getAttribute("data-default-cves")) || 40, minutes: 45, rate: 120 };
    var oneTime = Number(form.getAttribute("data-one-time")) || 0;

    function money(n) {
      if (n >= 1e6) return "$" + (n / 1e6).toFixed(2).replace(/\.?0+$/, "") + "M";
      return "$" + Math.round(n / 1000) + "K";
    }
    function num(n) { return Math.round(n).toLocaleString("en-US"); }
    function clamp(v, lo, hi, fallback) {
      v = Number(v);
      if (!isFinite(v)) return fallback;
      return Math.min(hi, Math.max(lo, v));
    }
    function compute(cves, minutes, rate) {
      var hours = cves * 12 * (minutes / 60);
      return { hours: hours, cost: hours * rate, capacity: 100 * cves / CAPACITY_PER_MONTH };
    }
    function minutesChecked() {
      var el = form.querySelector("input[name=minutes]:checked");
      return el ? Number(el.value) : defaults.minutes;
    }
    function render() {
      var cves = clamp(cvesInput.value, 0, 100000, defaults.cves);
      var rate = clamp(rateInput.value, 1, 10000, defaults.rate);
      var minutes = minutesChecked();
      var r = compute(cves, minutes, rate);
      var lo = compute(cves, 20, rate).cost, hi = compute(cves, 60, rate).cost;
      var ratio = r.cost / OIG_OFFSET;

      out.hours.textContent = num(r.hours);
      out.capacity.textContent = r.capacity.toFixed(1) + "%";
      out.cost.textContent = money(r.cost);
      out.lowHigh.textContent = money(lo) + " to " + money(hi);
      out.offset.textContent = Math.round(100 * ratio) + "%";
      // The one-time load is paid once, not every month: CVEs × minutes / 60 × rate.
      if (out.once) out.once.textContent = money(oneTime * minutes / 60 * rate);

      // Scale comparison only: NIST already stopped routine re-scoring in April 2026 and moved that
      // capacity to triage, so the OIG figure is not unspent money the rule can draw on.
      var share = ratio <= 1 ? "about " + Math.round(100 * ratio) + "% of" : "about " + (Math.round(ratio * 10) / 10) + " times";
      var verdict = share + " the value of the routine re-scoring NIST stopped in April 2026 (the Commerce OIG put it at roughly $400K a year; NIST disputes the figure). That capacity already went to triage, so this compares scale; it is not spare money";
      out.sentence.innerHTML =
        "Re-checking <b>" + num(cves) + " CVEs a month</b> at " + minutes + " analyst-minutes each takes about <b>" +
        num(r.hours) + " analyst-hours a year</b>, " + r.capacity.toFixed(1) + "% of NIST's peak monthly output, and costs about <b>" +
        money(r.cost) + " a year</b> at $" + num(rate) + " an hour: " + verdict + ".";
    }
    form.addEventListener("input", render);
    form.addEventListener("change", render);
    form.addEventListener("submit", function (e) { e.preventDefault(); render(); });
    var reset = document.getElementById("sim-reset");
    if (reset) {
      reset.addEventListener("click", function () {
        cvesInput.value = defaults.cves;
        rateInput.value = defaults.rate;
        var mid = form.querySelector("input[name=minutes][value='" + defaults.minutes + "']");
        if (mid) mid.checked = true;
        render();
        cvesInput.focus();
      });
    }
    render();
  }

  /* ---------- Copy citation ---------- */
  var btn = document.getElementById("copy-citation");
  var cite = document.getElementById("citation-text");
  // The build writes the canonical URL into the citation when SITE_URL is configured. When it is
  // not, and the page is served over HTTP(S), add the address the reader is actually at.
  if (cite && !cite.querySelector("a") && /^https?:/.test(location.href)) {
    cite.appendChild(document.createTextNode(" Available at " + location.href.split("#")[0] + "."));
  }
  if (btn && cite) {
    var label = btn.querySelector(".label");
    var original = label ? label.textContent : btn.textContent;
    var timer;
    function done(text) {
      if (label) label.textContent = text; else btn.textContent = text;
      clearTimeout(timer);
      timer = setTimeout(function () { if (label) label.textContent = original; else btn.textContent = original; }, 2200);
    }
    btn.addEventListener("click", function () {
      var text = cite.textContent.trim();
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () { done("Copied"); }, function () { fallback(); });
      } else {
        fallback();
      }
    });
    function fallback() {
      var range = document.createRange();
      range.selectNodeContents(cite);
      var sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
      cite.scrollIntoView({ block: "center" });
      done("Select and copy below");
    }
  }
})();
