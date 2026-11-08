/* NVD Watch — progressive enhancement only.
   The page is complete without this script: every number is rendered at build time.
   This adds (1) the re-check cost simulator and (2) the Copy citation button. */
(function () {
  "use strict";

  /* ---------- Re-check cost simulator ---------- */
  // The rule (constants, wording, arithmetic) lives in cost.js and the model the build writes into
  // the page; this only wires the form to it.
  var form = document.getElementById("sim-form");
  var modelEl = document.getElementById("cost-model");
  if (form && modelEl && window.NVDCost) {
    var model = JSON.parse(modelEl.textContent);
    var cvesInput = form.elements.cves;
    var rateInput = form.elements.rate;
    var out = {
      hours: document.getElementById("sim-hours"),
      capacity: document.getElementById("sim-capacity"),
      cost: document.getElementById("sim-cost"),
      low_high: document.getElementById("sim-low-high"),
      offset: document.getElementById("sim-offset"),
      once: document.getElementById("sim-once"),
      sentence: document.getElementById("sim-sentence")
    };
    // Defaults are rendered into the form at build time, so the script never carries a number the page does not.
    var defaults = { cves: Number(form.getAttribute("data-default-cves")) || 0, minutes: model.default_minutes, rate: model.rate };
    var oneTime = Number(form.getAttribute("data-one-time")) || 0;

    function clamp(v, lo, hi, fallback) {
      v = Number(v);
      if (!isFinite(v)) return fallback;
      return Math.min(hi, Math.max(lo, v));
    }
    function minutesChecked() {
      var el = form.querySelector("input[name=minutes]:checked");
      return el ? Number(el.value) : defaults.minutes;
    }
    function render() {
      var cves = clamp(cvesInput.value, 0, 100000, defaults.cves);
      var rate = clamp(rateInput.value, 1, 10000, defaults.rate);
      var r = NVDCost.outputs(model, cves, minutesChecked(), rate, oneTime);
      Object.keys(out).forEach(function (k) {
        if (!out[k]) return;
        if (k === "sentence") out[k].innerHTML = r[k]; else out[k].textContent = r[k];
      });
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
