/* NVD Watch — the data in 3D (story.html).
   One point per CVE in the 30-day window, built from the status counts in data/summary.json.
   Scrolling moves the points through four states:
     0  a loose cloud
     1  towers by NVD status, height proportional to count; teal = has CPE
     2  the KEV-listed CVEs pulled forward into a ring
     3  the monthly re-queues lifted out of Not Scheduled into a ring
   Which point stands for which CVE is arbitrary; counts and colours are real. */
import * as THREE from "three";

const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;
const PEAK_MONTH = 5000;                       // OIG: NIST has never processed more than 5,000 CVEs in a month
const fmt = n => Math.round(n).toLocaleString("en-US");
const fmtDate = s => new Date(s).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric", timeZone: "UTC" });

const [data, lag, rm] = await Promise.all([
  fetch("data/summary.json").then(r => r.json()),
  fetch("data/kev_lag.json").then(r => (r.ok ? r.json() : null)).catch(() => null),
  fetch("data/recheck_measured.json").then(r => r.json()),
]);

/* ---------- numbers into the copy ---------- */
const live = data.cves_live;
// Re-check volume measured once from the whole NVD stock (data/recheck_measured.json); highest month shown.
const monthly = rm.monthly_flow.windows.map(w => w.requeues);
const requeue = Math.max(...monthly);
const cost = requeue * 12 * (45 / 60) * 120;
const years = lag ? Object.keys(lag.by_year).sort() : [];
const lagText = y => `${lag.by_year[y].median_days} days (${y})`;
const peakYear = years.reduce((a, y) => (!a || lag.by_year[y].median_days > lag.by_year[a].median_days ? y : a), null);
const fills = {
  live: fmt(live),
  window: `${fmtDate(data.window_utc[0])} to ${fmtDate(data.window_utc[1])}`,
  pct_cpe: `${data.pct_with_cpe_live}%`,
  with_cpe: fmt(data.with_cpe_live),
  kev: `${data.in_kev_with_cpe} of ${data.in_kev}`,
  lag_first: years.length ? lagText(years[0]) : "—",
  lag_peak: years.length ? lagText(peakYear) : "—",
  requeue: fmt(requeue),
  share_peak: `${(100 * requeue / PEAK_MONTH).toFixed(1)}%`,
  cost: `$${fmt(cost / 1000)}K`,
  one_time: fmt(rm.one_time_load.t_0_10),
  requeue_range: `${Math.min(...monthly)} to ${requeue}`,
  rq_measured: fmtDate(rm.measured_on),
  pulled: fmtDate(data.pulled_at_utc),
};
document.querySelectorAll("[data-fill]").forEach(el => { el.textContent = fills[el.dataset.fill] ?? ""; });

/* ---------- one record per CVE ---------- */
const statuses = data.statuses;                // six non-rejected statuses; counts sum to cves_live
const idx = api => statuses.findIndex(s => s.api_status === api);
const iEnriched = idx("Analyzed"), iUndergoing = idx("Undergoing Analysis"), iNotScheduled = idx("Deferred");
const pts = [];
statuses.forEach((s, si) => {
  const nCpe = Math.round(s.count * s.pct_with_cpe / 100);
  for (let j = 0; j < s.count; j++) pts.push({ si, j, cpe: j < nCpe, kev: false, rq: false });
});
// KEV: the ones with CPE are drawn from Enriched, the rest from Undergoing (this window's KEV CVE without CPE is Undergoing).
let k = 0;
for (const p of pts) if (p.si === iEnriched && k < data.in_kev_with_cpe) { p.kev = true; k++; }
let kNo = 0;
for (const p of pts) if (p.si === iUndergoing && !p.cpe && kNo < data.in_kev - data.in_kev_with_cpe) { p.kev = true; kNo++; }
let r = 0;
for (const p of pts) if (p.si === iNotScheduled && r < requeue) { p.rq = true; r++; }

/* ---------- target positions, colours and sizes for each state ---------- */
const N = pts.length, STATES = 4;
const P = Array.from({ length: STATES }, () => new Float32Array(N * 3));
const C = Array.from({ length: STATES }, () => new Float32Array(N * 3));
const Z = Array.from({ length: STATES }, () => new Float32Array(N));
const towerX = si => (si - (statuses.length - 1) / 2) * 2.25;
const setTower = (p, out, o) => {             // 20 × 10 dots per layer
  const layer = Math.floor(p.j / 200), rr = p.j % 200;
  out[o] = towerX(p.si) + ((rr % 20) - 9.5) * 0.105;
  out[o + 1] = layer * 0.13 - 2.6;
  out[o + 2] = (Math.floor(rr / 20) - 4.5) * 0.105;
};
const color = {
  cpe: new THREE.Color("#0e7c99"), noCpe: new THREE.Color("#cdc5b8"), faded: new THREE.Color("#e2ddd3"),
  cloud: new THREE.Color("#5f8591"), kevNoCpe: new THREE.Color("#9c9284"),
};
const setColor = (arr, i, c) => { arr[i * 3] = c.r; arr[i * 3 + 1] = c.g; arr[i * 3 + 2] = c.b; };
const DOT = 1.7, BIG = 7;
let kevI = 0, rqI = 0;
pts.forEach((p, i) => {
  const o = i * 3;
  // 0: cloud
  const rad = 6.2 * Math.cbrt(Math.random()), th = 2 * Math.PI * Math.random(), ph = Math.acos(2 * Math.random() - 1);
  P[0][o] = rad * Math.sin(ph) * Math.cos(th); P[0][o + 1] = rad * Math.cos(ph) * 0.7; P[0][o + 2] = rad * Math.sin(ph) * Math.sin(th);
  setColor(C[0], i, color.cloud); Z[0][i] = DOT;
  // 1: towers
  setTower(p, P[1], o); setColor(C[1], i, p.cpe ? color.cpe : color.noCpe); Z[1][i] = DOT;
  // 2: KEV ring
  if (p.kev) {
    const a = (kevI++ / data.in_kev) * Math.PI * 2;
    P[2][o] = Math.cos(a) * 1.7; P[2][o + 1] = Math.sin(a) * 1.7 + 0.4; P[2][o + 2] = 5;
    setColor(C[2], i, p.cpe ? color.cpe : color.kevNoCpe); Z[2][i] = BIG;
  } else { setTower(p, P[2], o); setColor(C[2], i, color.faded); Z[2][i] = DOT; }
  // 3: re-queue ring
  if (p.rq) {
    const a = (rqI++ / requeue) * Math.PI * 2;
    P[3][o] = towerX(iNotScheduled) * 0.7 + Math.cos(a) * 1.3; P[3][o + 1] = 0.6 + Math.sin(a) * 1.3; P[3][o + 2] = 4;
    setColor(C[3], i, color.cpe); Z[3][i] = BIG;
  } else { setTower(p, P[3], o); setColor(C[3], i, color.faded); Z[3][i] = DOT; }
});

/* ---------- scene ---------- */
const canvas = document.querySelector(".stage");
const renderer = new THREE.WebGLRenderer({ canvas, antialias: true, alpha: true });
renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
const scene = new THREE.Scene();
const camera = new THREE.PerspectiveCamera(38, 1, 0.1, 200);

const geo = new THREE.BufferGeometry();
const pos = new Float32Array(N * 3), col = new Float32Array(N * 3), size = new Float32Array(N);
geo.setAttribute("position", new THREE.BufferAttribute(pos, 3));
geo.setAttribute("color", new THREE.BufferAttribute(col, 3));
geo.setAttribute("size", new THREE.BufferAttribute(size, 1));
const mat = new THREE.ShaderMaterial({
  transparent: true, depthWrite: false,
  uniforms: { scale: { value: 1 }, time: { value: 0 } },
  vertexShader: `
    attribute float size; attribute vec3 color; varying vec3 vColor; varying float vBig;
    uniform float scale; uniform float time;
    void main() {
      vColor = color; vBig = step(2.0, size);
      vec4 mv = modelViewMatrix * vec4(position, 1.0);
      float pulse = 1.0 + vBig * 0.18 * sin(time * 3.0 + position.x * 4.0);
      gl_PointSize = size * pulse * scale * (44.0 / -mv.z);
      gl_Position = projectionMatrix * mv;
    }`,
  fragmentShader: `
    varying vec3 vColor; varying float vBig;
    void main() {
      float r = length(gl_PointCoord - 0.5);
      if (r > 0.5) discard;
      float ring = vBig * smoothstep(0.30, 0.36, r) * 0.25;
      gl_FragColor = vec4(vColor + ring, smoothstep(0.5, 0.42, r));
    }`,
});
scene.add(new THREE.Points(geo, mat));

const labelLayer = document.querySelector(".tower-labels");
const labels = statuses.map(s => {
  const el = document.createElement("span");
  el.innerHTML = `<b>${fmt(s.count)}</b>${s.label}`;
  labelLayer.appendChild(el);
  return el;
});

const resize = () => {
  const w = innerWidth, h = innerHeight;
  renderer.setSize(w, h, false);
  camera.aspect = w / h; camera.fov = w < 700 ? 58 : 38; camera.updateProjectionMatrix();
  mat.uniforms.scale.value = Math.min(devicePixelRatio, 2);
};
addEventListener("resize", resize); resize();

const mouse = { x: 0, y: 0 };
addEventListener("pointermove", e => { mouse.x = e.clientX / innerWidth - 0.5; mouse.y = e.clientY / innerHeight - 0.5; });

/* ---------- loop ---------- */
const progress = document.querySelector(".progress"), hint = document.querySelector(".scrollhint");
const smooth = t => t * t * (3 - 2 * t);
const v = new THREE.Vector3();
let stage = 0;
renderer.setAnimationLoop(t => {
  const scrolled = scrollY / innerHeight;    // one step per screen
  progress.style.width = `${100 * Math.min(1, scrolled / 4)}%`;
  hint.style.opacity = scrolled > 0.2 ? 0 : 1;
  stage += (Math.min(3, Math.max(0, scrolled)) - stage) * (REDUCED ? 1 : 0.08);
  const a = Math.floor(stage), b = Math.min(3, a + 1), f = smooth(stage - a);

  for (let i = 0; i < N; i++) {
    const o = i * 3;
    for (let c = 0; c < 3; c++) {
      pos[o + c] = P[a][o + c] + (P[b][o + c] - P[a][o + c]) * f;
      col[o + c] = C[a][o + c] + (C[b][o + c] - C[a][o + c]) * f;
    }
    size[i] = Z[a][i] + (Z[b][i] - Z[a][i]) * f;
  }
  geo.attributes.position.needsUpdate = geo.attributes.color.needsUpdate = geo.attributes.size.needsUpdate = true;
  mat.uniforms.time.value = REDUCED ? 0 : t / 1000;

  // Camera: slow drift in the cloud, mouse parallax, and a pan away from the copy (left on steps 0 and 2, right on 1 and 3).
  const drift = REDUCED ? 0 : 0.35 * Math.sin((1 - Math.min(1, stage)) * t / 9000);
  const orbit = drift + mouse.x * 0.25;
  // Narrow screens: pull back so all six towers fit the width, and look low so the scene sits above the copy.
  const wide = innerWidth > 900, phone = innerWidth < 600;
  const pan = wide ? [-3, 3.6, -3, 3.6] : [0, 0, 0, 0], dist = wide ? 23 : phone ? 31 : 20;
  const px = pan[a] + (pan[b] - pan[a]) * f;
  camera.position.set(px + Math.sin(orbit) * dist, 2.2 - mouse.y * 1.2, Math.cos(orbit) * dist);
  camera.lookAt(px, wide ? 0.2 : phone ? -6 : -2.5, 0);
  renderer.render(scene, camera);

  const show = Math.min(1, Math.max(0, 1 - Math.abs(stage - 1) * 1.4) + (stage > 1.5 ? 0.35 : 0));
  labels.forEach((el, si) => {
    v.set(towerX(si), -3.1, 0).project(camera);
    el.style.left = `${(v.x + 1) / 2 * innerWidth}px`;
    el.style.top = `${(1 - v.y) / 2 * innerHeight}px`;
    el.style.opacity = show;
  });
});
