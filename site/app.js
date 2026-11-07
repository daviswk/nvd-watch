/* NVD Watch — progressive enhancement only.
   The page is complete without this script: every number is rendered at build time.
   This adds (1) the re-check cost simulator and (2) the Copy citation button. */
(function () {
  "use strict";

  /* ---------- Re-check cost simulator ---------- */
  var CAPACITY_PER_MONTH = 5000;   // NIST's stated enrichment ceiling, CVEs per month (see Sources)
  var OIG_OFFSET = 400000;         // Commerce OIG: ~$400K/yr of re-scoring effort NIST could redirect

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
      sentence: document.getElementById("sim-sentence")
    };
    // Defaults are rendered into the form at build time (data-default-cves), so the script never
    // carries a number the page does not.
    var defaults = { cves: Number(form.getAttribute("data-default-cves")) || 40, minutes: 45, rate: 120 };

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

      var verdict = ratio <= 1
        ? "within the roughly $400K a year of re-scoring effort the Commerce OIG found NIST could redirect"
        : "about " + Math.round(100 * (ratio - 1)) + "% more than the roughly $400K a year of re-scoring effort the Commerce OIG found NIST could redirect";
      out.sentence.innerHTML =
        "Re-checking <b>" + num(cves) + " CVEs a month</b> at " + minutes + " analyst-minutes each takes about <b>" +
        num(r.hours) + " analyst-hours a year</b>, " + r.capacity.toFixed(1) + "% of NIST's stated capacity, and costs about <b>" +
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
