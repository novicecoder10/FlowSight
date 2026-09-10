/* ── FlowSight Globe ── */
const canvas = document.querySelector('#globe-canvas');
const context = canvas.getContext('2d');
const routes = [];
const geoCache = new Map();
let rotation = -20;
let tilt = 15;
let zoomLevel = 1.0;
const MIN_ZOOM = 0.7;
const MAX_ZOOM = 2.2;
const statusDot = document.querySelector('#status-dot');
const statusLabel = document.querySelector('#status-label');
let livePacketReceived = false;

/* ── Starfield ── */
const stars = [];
const STAR_COUNT = 350;
const shootingStars = [];

function initStars() {
  for (let i = 0; i < STAR_COUNT; i++) {
    stars.push({
      x: Math.random(),          // 0-1 normalized
      y: Math.random(),
      size: Math.random() * 1.8 + 0.3,
      brightness: Math.random() * 0.6 + 0.4,
      twinkleSpeed: Math.random() * 2 + 1,
      twinkleOffset: Math.random() * Math.PI * 2,
    });
  }
}
initStars();

function spawnShootingStar(w, h) {
  shootingStars.push({
    x: Math.random() * w * 0.8,
    y: Math.random() * h * 0.4,
    vx: 3 + Math.random() * 4,
    vy: 1.5 + Math.random() * 2,
    life: 1.0,
    decay: 0.012 + Math.random() * 0.01,
    length: 40 + Math.random() * 60,
  });
}

function drawStars(w, h, now) {
  for (const s of stars) {
    const twinkle = 0.5 + 0.5 * Math.sin(now * 0.001 * s.twinkleSpeed + s.twinkleOffset);
    const alpha = s.brightness * twinkle;
    const px = s.x * w;
    const py = s.y * h;

    // Slight color variation
    if (s.brightness > 0.8) {
      context.fillStyle = `rgba(200, 220, 255, ${alpha})`;  // blue-white
    } else if (s.brightness > 0.6) {
      context.fillStyle = `rgba(255, 248, 230, ${alpha})`;  // warm white
    } else {
      context.fillStyle = `rgba(180, 200, 220, ${alpha * 0.8})`;  // dim blue
    }

    context.beginPath();
    context.arc(px, py, s.size * (0.7 + twinkle * 0.3), 0, Math.PI * 2);
    context.fill();

    // Glow on bright stars
    if (s.size > 1.2 && twinkle > 0.7) {
      context.fillStyle = `rgba(200, 220, 255, ${alpha * 0.15})`;
      context.beginPath();
      context.arc(px, py, s.size * 3, 0, Math.PI * 2);
      context.fill();
    }
  }

  // Shooting stars
  if (Math.random() < 0.004) spawnShootingStar(w, h);  // ~every 4 sec on avg
  for (let i = shootingStars.length - 1; i >= 0; i--) {
    const ss = shootingStars[i];
    ss.x += ss.vx;
    ss.y += ss.vy;
    ss.life -= ss.decay;
    if (ss.life <= 0) { shootingStars.splice(i, 1); continue; }

    const grad = context.createLinearGradient(
      ss.x, ss.y,
      ss.x - ss.vx * ss.length * 0.15, ss.y - ss.vy * ss.length * 0.15,
    );
    grad.addColorStop(0, `rgba(255, 255, 255, ${ss.life * 0.9})`);
    grad.addColorStop(1, 'rgba(255, 255, 255, 0)');
    context.strokeStyle = grad;
    context.lineWidth = 1.5;
    context.beginPath();
    context.moveTo(ss.x, ss.y);
    context.lineTo(ss.x - ss.vx * ss.length * 0.15, ss.y - ss.vy * ss.length * 0.15);
    context.stroke();
  }
}

function drawNebula(cx, cy, w, h) {
  // Subtle purple-teal nebula glow in a corner
  const n1 = context.createRadialGradient(w * 0.15, h * 0.2, 0, w * 0.15, h * 0.2, w * 0.35);
  n1.addColorStop(0, 'rgba(60, 30, 90, 0.08)');
  n1.addColorStop(0.5, 'rgba(30, 60, 80, 0.04)');
  n1.addColorStop(1, 'transparent');
  context.fillStyle = n1;
  context.fillRect(0, 0, w, h);

  const n2 = context.createRadialGradient(w * 0.85, h * 0.75, 0, w * 0.85, h * 0.75, w * 0.3);
  n2.addColorStop(0, 'rgba(20, 80, 60, 0.06)');
  n2.addColorStop(0.6, 'rgba(15, 40, 50, 0.03)');
  n2.addColorStop(1, 'transparent');
  context.fillStyle = n2;
  context.fillRect(0, 0, w, h);
}

/* ── Drag state ── */
let isDragging = false;
let dragStartX = 0;
let dragStartY = 0;
let dragStartRotation = 0;
let dragStartTilt = 0;
let autoRotate = true;
let autoRotateTimer = null;

/* ── Country geometry ── */
let countryFeatures = [];
let countryLabels = [];
const WORLD_ATLAS_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2.0.2/countries-110m.json';

const COUNTRY_NAMES = {
  '840': 'USA', '826': 'UK', '250': 'France', '276': 'Germany',
  '356': 'India', '156': 'China', '392': 'Japan', '036': 'Australia',
  '076': 'Brazil', '643': 'Russia', '710': 'S. Africa', '124': 'Canada',
  '484': 'Mexico', '380': 'Italy', '724': 'Spain', '410': 'S. Korea',
  '360': 'Indonesia', '764': 'Thailand', '818': 'Egypt', '566': 'Nigeria',
  '032': 'Argentina', '586': 'Pakistan', '704': 'Vietnam',
  '792': 'Turkey', '682': 'Saudi Arabia',
  '458': 'Malaysia', '404': 'Kenya',
};

async function loadCountries() {
  try {
    const res = await fetch(WORLD_ATLAS_URL);
    const topo = await res.json();
    const geo = topojson.feature(topo, topo.objects.countries);
    countryFeatures = geo.features;
    countryLabels = countryFeatures
      .filter((f) => COUNTRY_NAMES[f.id])
      .map((f) => ({ name: COUNTRY_NAMES[f.id], ...centroid(f.geometry) }));
  } catch (e) { console.warn('Atlas load failed:', e); }
}

function centroid(geom) {
  let tLat = 0, tLon = 0, n = 0;
  const rings = geom.type === 'Polygon' ? geom.coordinates
    : geom.type === 'MultiPolygon' ? geom.coordinates.flat() : [];
  for (const ring of rings) for (const [lon, lat] of ring) { tLon += lon; tLat += lat; n++; }
  return n ? { latitude: tLat / n, longitude: tLon / n } : { latitude: 0, longitude: 0 };
}

/* ── Helpers ── */
function setStatus(on) {
  statusDot.classList.toggle('connected', on);
  statusLabel.textContent = on ? 'Live capture' : 'Capture unavailable';
}

function isLoopbackIp(ip) {
  if (!ip) return true;
  const clean = String(ip).trim().toLowerCase();
  return clean === '::1' || clean === '127.0.0.1' || clean === '0.0.0.0' || clean === '::' || clean.startsWith('127.');
}

function isMulticastIp(ip) {
  if (!ip) return true;
  const clean = String(ip).trim().toLowerCase();
  if (clean.startsWith('ff') || clean.startsWith('224.') || clean.startsWith('239.')) return true;
  const p = clean.split('.').map(Number);
  return p.length === 4 && p[0] >= 224 && p[0] <= 239;
}

function isPrivateIp(ip) {
  if (!ip) return true;
  const clean = String(ip).trim().toLowerCase();
  if (clean === '::1' || clean === '127.0.0.1' || clean.startsWith('127.') || clean.startsWith('fe80:') || clean.startsWith('fd') || clean.startsWith('fc')) return true;
  const p = clean.split('.').map(Number);
  if (p.length === 4 && p.every((v) => v >= 0 && v <= 255)) {
    return p[0] === 10 || p[0] === 127 || (p[0] === 192 && p[1] === 168) ||
      (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || p[0] === 0 || (p[0] === 169 && p[1] === 254);
  }
  return false;
}

/* ── 3D projection ── */
function project(lat, lon, cx, cy, R) {
  const lonRad = (lon + rotation) * Math.PI / 180;
  const latRad = lat * Math.PI / 180;
  const tiltRad = tilt * Math.PI / 180;

  const x0 = Math.cos(latRad) * Math.sin(lonRad);
  const y0 = Math.cos(latRad) * Math.cos(lonRad);
  const z0 = Math.sin(latRad);

  // Tilt around X axis
  const depth = y0 * Math.cos(tiltRad) - z0 * Math.sin(tiltRad);
  const z1 = y0 * Math.sin(tiltRad) + z0 * Math.cos(tiltRad);

  return {
    x: cx + R * x0,
    y: cy - R * z1,
    visible: depth > 0,
  };
}

/* ── Grid ── */
function drawGrid(cx, cy, R) {
  context.strokeStyle = 'rgba(31,130,117,0.12)';
  context.lineWidth = 0.5;
  for (let lat = -60; lat <= 60; lat += 30) {
    context.beginPath();
    let penDown = false;
    for (let lon = -180; lon <= 180; lon += 4) {
      const p = project(lat, lon, cx, cy, R);
      if (!p.visible) { penDown = false; continue; }
      penDown ? context.lineTo(p.x, p.y) : context.moveTo(p.x, p.y);
      penDown = true;
    }
    context.stroke();
  }
  for (let lon = -180; lon < 180; lon += 30) {
    context.beginPath();
    let penDown = false;
    for (let lat = -90; lat <= 90; lat += 4) {
      const p = project(lat, lon, cx, cy, R);
      if (!p.visible) { penDown = false; continue; }
      penDown ? context.lineTo(p.x, p.y) : context.moveTo(p.x, p.y);
      penDown = true;
    }
    context.stroke();
  }
}

/* ── Countries ── */
function drawCountries(cx, cy, R) {
  if (!countryFeatures.length) return;
  context.strokeStyle = 'rgba(31,130,117,0.4)';
  context.fillStyle = 'rgba(31,130,117,0.08)';
  context.lineWidth = 0.7;

  for (const feat of countryFeatures) {
    const rings = feat.geometry.type === 'Polygon' ? feat.geometry.coordinates
      : feat.geometry.type === 'MultiPolygon' ? feat.geometry.coordinates.flat() : [];
    for (const ring of rings) {
      context.beginPath();
      let started = false;
      let prevVis = false;
      for (const [lon, lat] of ring) {
        const p = project(lat, lon, cx, cy, R);
        if (!p.visible) { prevVis = false; continue; }
        (!started || !prevVis) ? context.moveTo(p.x, p.y) : context.lineTo(p.x, p.y);
        started = true;
        prevVis = true;
      }
      if (started) { context.fill(); context.stroke(); }
    }
  }
}

/* ── Labels ── */
function drawLabels(cx, cy, R) {
  if (!countryLabels.length) return;
  const sz = Math.round(Math.max(10, 12 * zoomLevel));
  context.font = `600 ${sz}px 'Space Grotesk', sans-serif`;
  context.textAlign = 'center';
  context.textBaseline = 'middle';

  for (const l of countryLabels) {
    const p = project(l.latitude, l.longitude, cx, cy, R);
    if (!p.visible) continue;
    const dx = p.x - cx, dy = p.y - cy;
    const fade = Math.max(0, 1 - Math.sqrt(dx * dx + dy * dy) / (R * 0.85));
    if (fade < 0.15) continue;

    // Shadow
    context.fillStyle = `rgba(0,0,0,${0.6 * fade})`;
    context.fillText(l.name, p.x + 1, p.y + 1);
    // Label
    context.fillStyle = `rgba(203,243,107,${0.85 * fade})`;
    context.fillText(l.name, p.x, p.y);
  }
}

/* ── Route arc ── */
function drawRoute(route, cx, cy, R, now) {
  const age = now - route.createdAt;
  const a = Math.min(age / 600, 1) * (route.demo ? 0.35 : 0.8);

  // Arc — only draw visible segments
  context.strokeStyle = route.demo ? `rgba(31,130,117,${a})` : `rgba(203,243,107,${a})`;
  context.lineWidth = route.demo ? 1 : 1.5;
  context.beginPath();
  let penDown = false;
  let anyVisible = false;
  for (let i = 0; i <= 32; i++) {
    const t = i / 32;
    const arc = Math.sin(t * Math.PI) * 0.16 * 35;
    const lat = route.from.latitude + (route.to.latitude - route.from.latitude) * t + arc;
    const lon = route.from.longitude + (route.to.longitude - route.from.longitude) * t;
    const p = project(lat, lon, cx, cy, R);
    if (!p.visible) { penDown = false; continue; }
    anyVisible = true;
    penDown ? context.lineTo(p.x, p.y) : context.moveTo(p.x, p.y);
    penDown = true;
  }
  if (anyVisible) context.stroke();
  if (!anyVisible) return;

  // Pulse — only if visible
  const pulse = ((now / 4500) - route.startedAt) % 1;
  const pp = project(
    route.from.latitude + (route.to.latitude - route.from.latitude) * pulse + Math.sin(pulse * Math.PI) * 5,
    route.from.longitude + (route.to.longitude - route.from.longitude) * pulse,
    cx, cy, R,
  );
  if (pp.visible) {
    context.fillStyle = route.demo ? `rgba(31,130,117,${a})` : `rgba(255,118,95,${a})`;
    context.beginPath(); context.arc(pp.x, pp.y, route.demo ? 2 : 3, 0, Math.PI * 2); context.fill();
  }

  // Endpoints — only if visible
  const pFrom = project(route.from.latitude, route.from.longitude, cx, cy, R);
  const pTo = project(route.to.latitude, route.to.longitude, cx, cy, R);
  for (const ep of [pFrom, pTo]) {
    if (!ep.visible) continue;
    context.fillStyle = route.demo ? `rgba(31,130,117,${a * 0.7})` : `rgba(203,243,107,${a})`;
    context.beginPath(); context.arc(ep.x, ep.y, route.demo ? 2 : 3, 0, Math.PI * 2); context.fill();
  }
}

/* ── Main draw ── */
function draw(now = performance.now()) {
  const w = canvas.clientWidth;
  const h = canvas.clientHeight;
  const dpr = window.devicePixelRatio || 1;
  canvas.width = w * dpr;
  canvas.height = h * dpr;
  context.setTransform(dpr, 0, 0, dpr, 0, 0);
  context.clearRect(0, 0, w, h);

  const baseR = Math.min(w, h) * 0.42;
  const R = baseR * zoomLevel;
  const cx = w / 2;
  const cy = h / 2;

  // Space background
  context.fillStyle = '#050a08';
  context.fillRect(0, 0, w, h);
  drawNebula(cx, cy, w, h);
  drawStars(w, h, now);

  // Glow
  const glow = context.createRadialGradient(cx, cy, R * 0.92, cx, cy, R * 1.12);
  glow.addColorStop(0, 'rgba(31,130,117,0.06)');
  glow.addColorStop(1, 'rgba(31,130,117,0)');
  context.fillStyle = glow;
  context.beginPath(); context.arc(cx, cy, R * 1.12, 0, Math.PI * 2); context.fill();

  // Globe sphere
  const sphereGrad = context.createRadialGradient(cx - R * 0.25, cy - R * 0.25, R * 0.1, cx, cy, R);
  sphereGrad.addColorStop(0, '#172822');
  sphereGrad.addColorStop(1, '#0e1814');
  context.fillStyle = sphereGrad;
  context.beginPath(); context.arc(cx, cy, R, 0, Math.PI * 2); context.fill();

  // Clip everything to the sphere
  context.save();
  context.beginPath(); context.arc(cx, cy, R, 0, Math.PI * 2); context.clip();

  drawGrid(cx, cy, R);
  drawCountries(cx, cy, R);
  const nowTime = performance.now();
  const activeList = Array.from(routeMap.values()).filter(r => r.demo || (nowTime - r.lastSeen) < 30000);
  activeList.slice(0, 15).forEach((r) => drawRoute(r, cx, cy, R, now));
  drawLabels(cx, cy, R);

  context.restore();

  // Border
  context.strokeStyle = 'rgba(31,130,117,0.3)';
  context.lineWidth = 1.5;
  context.beginPath(); context.arc(cx, cy, R, 0, Math.PI * 2); context.stroke();

  // Zoom badge
  if (Math.abs(zoomLevel - 1) > 0.05) {
    const tag = `${Math.round(zoomLevel * 100)}%`;
    context.font = "500 11px 'DM Mono', monospace";
    context.textAlign = 'center';
    context.fillStyle = 'rgba(203,243,107,0.7)';
    context.fillText(tag, cx, cy + R + 20);
  }

  if (autoRotate) rotation = (rotation + 0.014) % 360;
  requestAnimationFrame(draw);
}

/* ── Mouse interaction ── */
canvas.style.cursor = 'grab';

canvas.addEventListener('mousedown', (e) => {
  isDragging = true;
  dragStartX = e.clientX;
  dragStartY = e.clientY;
  dragStartRotation = rotation;
  dragStartTilt = tilt;
  autoRotate = false;
  clearTimeout(autoRotateTimer);
  canvas.style.cursor = 'grabbing';
  e.preventDefault();
});

window.addEventListener('mousemove', (e) => {
  if (!isDragging) return;
  rotation = dragStartRotation + (e.clientX - dragStartX) * 0.35;
  tilt = Math.max(-50, Math.min(50, dragStartTilt + (e.clientY - dragStartY) * 0.35));
});

window.addEventListener('mouseup', () => {
  if (!isDragging) return;
  isDragging = false;
  canvas.style.cursor = 'grab';
  autoRotateTimer = setTimeout(() => { autoRotate = true; }, 5000);
});

// Double-click to reset view
canvas.addEventListener('dblclick', (e) => {
  e.preventDefault();
  rotation = -20;
  tilt = 15;
  zoomLevel = 1.0;
  autoRotate = true;
  clearTimeout(autoRotateTimer);
});

/* ── Touch interaction ── */
canvas.addEventListener('touchstart', (e) => {
  if (e.touches.length !== 1) return;
  isDragging = true;
  dragStartX = e.touches[0].clientX;
  dragStartY = e.touches[0].clientY;
  dragStartRotation = rotation;
  dragStartTilt = tilt;
  autoRotate = false;
  clearTimeout(autoRotateTimer);
}, { passive: true });

window.addEventListener('touchmove', (e) => {
  if (!isDragging || e.touches.length !== 1) return;
  rotation = dragStartRotation + (e.touches[0].clientX - dragStartX) * 0.35;
  tilt = Math.max(-50, Math.min(50, dragStartTilt + (e.touches[0].clientY - dragStartY) * 0.35));
}, { passive: true });

window.addEventListener('touchend', () => {
  if (!isDragging) return;
  isDragging = false;
  autoRotateTimer = setTimeout(() => { autoRotate = true; }, 5000);
});

/* ── Zoom — only when pointer is over the globe ── */
canvas.addEventListener('wheel', (e) => {
  // Only zoom if the pointer is inside the globe circle
  const rect = canvas.getBoundingClientRect();
  const mx = e.clientX - rect.left;
  const my = e.clientY - rect.top;
  const cx = rect.width / 2;
  const cy = rect.height / 2;
  const baseR = Math.min(rect.width, rect.height) * 0.42 * zoomLevel;
  const dist = Math.sqrt((mx - cx) ** 2 + (my - cy) ** 2);
  if (dist > baseR * 1.2) return; // outside globe — let page scroll normally

  e.preventDefault();
  const step = e.deltaY > 0 ? -0.06 : 0.06;
  zoomLevel = Math.max(MIN_ZOOM, Math.min(MAX_ZOOM, zoomLevel + step));
}, { passive: false });

/* ── Route aggregation & sidebar ── */
const routeMap = new Map();
let routeRenderQueued = false;

function scheduleRenderRoutes() {
  if (routeRenderQueued) return;
  routeRenderQueued = true;
  setTimeout(() => {
    routeRenderQueued = false;
    renderRoutes();
  }, 250);
}

function renderRoutes() {
  const now = performance.now();
  const live = Array.from(routeMap.values()).filter((r) => !r.demo && (now - r.lastSeen) < 30000);
  document.querySelector('#route-count').textContent = `${live.length} ACTIVE FLOWS`;
  document.querySelector('#route-list').innerHTML = live
    .sort((a, b) => b.lastSeen - a.lastSeen)
    .slice(0, 15)
    .map((r) =>
      `<div class="route-item"><strong>${r.fromLabel}</strong><span>to</span><strong>${r.toLabel}</strong><small>${r.protocol} (${r.packets.toLocaleString()} pkts)</small></div>`
    ).join('') || '<p class="empty">Waiting for geolocated traffic...</p>';
}

function fallbackCoordinates(ip) {
  if (isPrivateIp(ip)) {
    return { latitude: 20.5937, longitude: 78.9629, city: `LAN (${ip})`, country: 'LOCAL' };
  }
  return { latitude: 37.7749, longitude: -122.4194, city: ip, country: 'WAN' };
}

/* ── GeoIP ── */
async function locationFor(ip) {
  if (geoCache.has(ip)) return geoCache.get(ip) || fallbackCoordinates(ip);
  try {
    const res = await fetch(`/api/geoip?ip=${encodeURIComponent(ip)}`);
    if (!res.ok) { const fb = fallbackCoordinates(ip); geoCache.set(ip, fb); return fb; }
    const data = await res.json();
    const loc = data.location;
    const finalLoc = (loc?.latitude != null && loc?.longitude != null) ? loc : fallbackCoordinates(ip);
    geoCache.set(ip, finalLoc);
    return finalLoc;
  } catch {
    const fb = fallbackCoordinates(ip);
    geoCache.set(ip, fb);
    return fb;
  }
}

/* ── Packet handling ── */
let homeLocation = { latitude: 20.5937, longitude: 78.9629, city: 'Local', country: 'IN' };

async function addPacket(pkt) {
  if (isLoopbackIp(pkt.source) || isLoopbackIp(pkt.destination) || isMulticastIp(pkt.source) || isMulticastIp(pkt.destination)) return;
  const srcP = isPrivateIp(pkt.source), dstP = isPrivateIp(pkt.destination);
  let from, to;
  if (srcP && dstP) {
    from = homeLocation;
    to = fallbackCoordinates(pkt.destination);
  } else if (srcP) {
    from = homeLocation;
    to = await locationFor(pkt.destination);
  } else if (dstP) {
    from = await locationFor(pkt.source);
    to = homeLocation;
  } else {
    [from, to] = await Promise.all([locationFor(pkt.source), locationFor(pkt.destination)]);
  }
  if (!from || !to) return;

  const fromLabel = `${from.city}, ${from.country}`;
  const toLabel = `${to.city}, ${to.country}`;
  const key = `${fromLabel}->${toLabel}:${pkt.protocol}`;
  const now = performance.now();

  if (!livePacketReceived) {
    livePacketReceived = true;
    for (const [k, r] of routeMap.entries()) {
      if (r.demo) routeMap.delete(k);
    }
  }

  let route = routeMap.get(key);
  if (!route) {
    route = {
      from, to, fromLabel, toLabel,
      protocol: pkt.protocol,
      startedAt: now / 4500,
      createdAt: now,
      lastSeen: now,
      packets: 1,
      demo: false
    };
    routeMap.set(key, route);
  } else {
    route.packets += 1;
    route.lastSeen = now;
  }

  scheduleRenderRoutes();
}

/* ── Demo routes ── */
const DEMO_CITIES = [
  { latitude: 37.77, longitude: -122.42, city: 'San Francisco', country: 'US' },
  { latitude: 51.51, longitude: -0.13, city: 'London', country: 'GB' },
  { latitude: 35.68, longitude: 139.65, city: 'Tokyo', country: 'JP' },
  { latitude: -33.87, longitude: 151.21, city: 'Sydney', country: 'AU' },
  { latitude: 1.35, longitude: 103.82, city: 'Singapore', country: 'SG' },
  { latitude: 48.86, longitude: 2.35, city: 'Paris', country: 'FR' },
  { latitude: 55.76, longitude: 37.62, city: 'Moscow', country: 'RU' },
  { latitude: -23.55, longitude: -46.63, city: 'São Paulo', country: 'BR' },
  { latitude: 19.08, longitude: 72.88, city: 'Mumbai', country: 'IN' },
  { latitude: 28.61, longitude: 77.21, city: 'New Delhi', country: 'IN' },
  { latitude: 40.71, longitude: -74.01, city: 'New York', country: 'US' },
  { latitude: 25.20, longitude: 55.27, city: 'Dubai', country: 'AE' },
  { latitude: 52.52, longitude: 13.41, city: 'Berlin', country: 'DE' },
  { latitude: -1.29, longitude: 36.82, city: 'Nairobi', country: 'KE' },
  { latitude: 39.90, longitude: 116.41, city: 'Beijing', country: 'CN' },
];
const DEMO_PROTOS = ['TCP', 'UDP', 'HTTPS', 'DNS', 'TLS', 'HTTP'];

function addDemoRoute() {
  if (livePacketReceived) return;
  let a = Math.floor(Math.random() * DEMO_CITIES.length), b = a;
  while (b === a) b = Math.floor(Math.random() * DEMO_CITIES.length);
  const f = DEMO_CITIES[a], t = DEMO_CITIES[b];
  const key = `demo:${f.city}->${t.city}`;
  routeMap.set(key, {
    from: f, to: t,
    fromLabel: `${f.city}, ${f.country}`, toLabel: `${t.city}, ${t.country}`,
    protocol: DEMO_PROTOS[Math.floor(Math.random() * DEMO_PROTOS.length)],
    startedAt: performance.now() / 4500, createdAt: performance.now(), lastSeen: performance.now(),
    packets: 1, demo: true,
  });
}
for (let i = 0; i < 12; i++) addDemoRoute();
const demoIv = setInterval(() => { if (livePacketReceived) { clearInterval(demoIv); return; } addDemoRoute(); }, 2200);

async function hydrateHistory() {
  try {
    const res = await fetch('/api/history?limit=300');
    if (!res.ok) return;
    const packets = await res.json();
    for (const packet of packets) {
      await addPacket(packet);
    }
  } catch (err) {
    console.error('Failed to fetch packet history for globe:', err);
  }
}

/* ── SSE ── */
const stream = new EventSource('/api/stream');
stream.addEventListener('status', (e) => setStatus(JSON.parse(e.data).running));
stream.addEventListener('packet', (e) => { addPacket(JSON.parse(e.data)); setStatus(true); });
stream.onerror = () => setStatus(false);

/* ── Boot ── */
window.addEventListener('resize', () => draw());
loadCountries();
renderRoutes();
draw();
hydrateHistory();