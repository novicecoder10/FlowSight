const applications = new Map();
const addresses = new Map();
let eventCount = 0;
let renderQueued = false;
const statusDot = document.querySelector('#status-dot');
const statusLabel = document.querySelector('#status-label');
const fieldMap = (metadata) => Object.fromEntries(metadata.split(';').map((item) => { const separator = item.indexOf('='); return separator < 0 ? [item, ''] : [item.slice(0, separator), item.slice(separator + 1)]; }));
const knownApplications = [
  ['google', /(^|\.)google\./i, 'Google'],
  ['youtube', /(^|\.)youtube\./i, 'YouTube'],
  ['spotify', /(^|\.)spotify\./i, 'Spotify'],
  ['signal', /(^|\.)signal\./i, 'Signal'],
  ['whatsapp', /(^|\.)whatsapp\./i, 'WhatsApp'],
  ['instagram', /(^|\.)instagram\./i, 'Instagram'],
  ['facebook', /(^|\.)facebook\./i, 'Facebook'],
  ['netflix', /(^|\.)netflix\./i, 'Netflix'],
  ['microsoft', /(^|\.)microsoft\./i, 'Microsoft'],
  ['apple', /(^|\.)apple\./i, 'Apple'],
];
function applicationName(host, fallback) { return knownApplications.find(([, pattern]) => pattern.test(host))?.[2] || fallback; }

function setStatus(connected, error = '') { statusDot.classList.toggle('connected', connected); statusLabel.textContent = connected ? 'Live capture' : 'Capture unavailable'; document.querySelector('#capture-mode').textContent = connected ? 'LIVE' : 'IDLE'; document.querySelector('#capture-label').textContent = connected ? 'receiving application events' : (error || 'start with capture permissions'); }

function render() {
  const ordered = [...applications.values()].sort((left, right) => right.count - left.count);
  const total = ordered.reduce((sum, application) => sum + application.count, 0);
  const maximum = ordered[0]?.count || 1;
  document.querySelector('#event-count').textContent = eventCount.toLocaleString();
  document.querySelector('#application-count').textContent = ordered.length;
  document.querySelector('#application-tag').textContent = `${ordered.length} APPLICATIONS`;
  const orderedIps = [...addresses.entries()].sort((left, right) => right[1] - left[1]);
  document.querySelector('#ip-tag').textContent = `${orderedIps.length} IPS`;
  document.querySelector('#top-application').textContent = ordered[0]?.name || '--';
  document.querySelector('#top-application-count').textContent = ordered[0] ? `${ordered[0].count.toLocaleString()} events` : 'waiting for traffic';
  document.querySelector('#application-list').innerHTML = ordered.slice(0, 30).map((application) => `<div class="application-row"><div class="application-header"><div><strong>${escapeHtml(application.name)}</strong><span class="application-protocol">${escapeHtml(application.protocol)}</span></div><b>${application.count.toLocaleString()}</b></div><div class="bar"><span style="width:${application.count / maximum * 100}%"></span></div><div class="application-meta"><span>${Math.round(application.count / Math.max(total, 1) * 100)}% of observed events</span><span>${escapeHtml(application.host)}</span></div></div>`).join('') || '<p class="empty">Waiting for application traffic...</p>';
  const ipMaximum = orderedIps[0]?.[1] || 1;
  document.querySelector('#ip-list').innerHTML = orderedIps.slice(0, 30).map(([address, count]) => `<div class="application-row"><div class="application-header"><strong>${escapeHtml(address)}</strong><b>${count.toLocaleString()}</b></div><div class="bar"><span style="width:${count / ipMaximum * 100}%"></span></div><div class="application-meta"><span>${Math.round(count / Math.max(eventCount * 2, 1) * 100)}% of observed endpoints</span><span>source or destination</span></div></div>`).join('') || '<p class="empty">Waiting for IP traffic...</p>';
}

function processPacket(packet) {
  const metadata = fieldMap(packet.metadata || '');
  const host = metadata.host || metadata.sni || packet.destination;
  const proto = packet.app || metadata.app || packet.protocol;
  const name = applicationName(host, proto);
  const protocol = proto;
  const key = `${protocol}:${name}`;
  const current = applications.get(key) || { name, protocol, host, destination: packet.destination, count: 0 };
  current.count += 1;
  current.host = host;
  applications.set(key, current);
  addresses.set(packet.source, (addresses.get(packet.source) || 0) + 1);
  addresses.set(packet.destination, (addresses.get(packet.destination) || 0) + 1);
  eventCount += 1;
}

async function hydrateHistory() {
  try {
    const res = await fetch('/api/history?limit=500');
    if (!res.ok) return;
    const packets = await res.json();
    for (const packet of packets) {
      processPacket(packet);
    }
    render();
  } catch (err) {
    console.error('Failed to fetch packet history:', err);
  }
}

const stream = new EventSource('/api/stream');
stream.addEventListener('status', (event) => { const status = JSON.parse(event.data); setStatus(status.running, status.error); });
stream.addEventListener('packet', (event) => {
  const packet = JSON.parse(event.data);
  processPacket(packet);
  setStatus(true);
  scheduleRender();
});
stream.onerror = () => setStatus(false);

render();
hydrateHistory();