const httpEvents = [];
const tlsEvents = [];
const serviceEvents = [];
let opaqueTlsEvents = 0;
let renderQueued = false;
const statusDot = document.querySelector('#status-dot');
const statusLabel = document.querySelector('#status-label');
const fields = (metadata) => Object.fromEntries(metadata.split(';').map((item) => { const separator = item.indexOf('='); return separator < 0 ? [item, ''] : [item.slice(0, separator), item.slice(separator + 1)]; }));
const time = (value) => new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
const cell = (value) => escapeHtml(value || '--');

function selectView(view) {
  document.querySelectorAll('.view-tab').forEach((tab) => tab.classList.toggle('active', tab.dataset.view === view));
  document.querySelectorAll('.view-panel').forEach((panel) => panel.classList.toggle('active', panel.dataset.viewPanel === view));
  history.replaceState(null, '', `#${view}`);
}

function render() {
  document.querySelector('#l7-count').textContent = httpEvents.length + tlsEvents.length;
  document.querySelector('#http-count').textContent = httpEvents.length;
  document.querySelector('#tls-count').textContent = tlsEvents.length;
  document.querySelector('#tls-note').textContent = `${opaqueTlsEvents} encrypted packets without handshake fields`;
  document.querySelector('#http-tag').textContent = `${httpEvents.length} EVENTS`;
  document.querySelector('#tls-tag').textContent = `${tlsEvents.length} ENRICHED`;
  document.querySelector('#tls-opaque').textContent = `Encrypted TLS packets without handshake metadata: ${opaqueTlsEvents}`;
  document.querySelector('#service-tag').textContent = `${serviceEvents.length} EVENTS`;
  document.querySelector('#http-table').innerHTML = httpEvents.slice(-60).reverse().map((event) => `<tr><td>${time(event.timestamp)}</td><td>${cell(event.method || event.status)}</td><td title="${cell(event.url)}">${cell(event.url)}</td><td>${cell(event.host)}</td><td title="${cell(event.referer)}">${cell(event.referer)}</td><td title="${cell(event.user_agent)}">${cell(event.user_agent)}</td></tr>`).join('') || '<tr><td colspan="6" class="empty">Waiting for plaintext HTTP...</td></tr>';
  document.querySelector('#tls-table').innerHTML = tlsEvents.slice(-60).reverse().map((event) => `<tr><td>${time(event.timestamp)}</td><td>${cell(event.sni)}</td><td title="${cell(event.ja3)}">${cell(event.ja3)}</td><td title="${cell(event.ja3s)}">${cell(event.ja3s)}</td><td title="${cell(event.ja4)}">${cell(event.ja4)}</td><td title="${cell(event.ja4s)}">${cell(event.ja4s)}</td></tr>`).join('') || '<tr><td colspan="6" class="empty">No enriched TLS handshake captured yet.</td></tr>';
  document.querySelector('#service-table').innerHTML = serviceEvents.slice(-60).reverse().map((event) => `<tr><td>${time(event.timestamp)}</td><td><span class="protocol-pill">${cell(event.app)}</span></td><td>${escapeHtml(event.source)}:${Number(event.sourcePort)}</td><td>${escapeHtml(event.destination)}:${Number(event.destinationPort)}</td><td title="${escapeHtml(event.metadata)}">${escapeHtml(event.metadata)}</td></tr>`).join('') || '<tr><td colspan="5" class="empty">Waiting for application service events...</td></tr>';
}

function scheduleRender() {
  if (renderQueued) return;
  renderQueued = true;
  window.setTimeout(() => { renderQueued = false; render(); }, 150);
}

function setStatus(connected, error = '') { statusDot.classList.toggle('connected', connected); statusLabel.textContent = connected ? 'Live capture' : 'Capture unavailable'; document.querySelector('#capture-mode').textContent = connected ? 'LIVE' : 'IDLE'; document.querySelector('#capture-label').textContent = connected ? 'receiving L7 events' : (error || 'start with capture permissions'); }

function processPacket(packet) {
  const metadata = fields(packet.metadata || '');
  const app = packet.app || metadata.app;
  if (app === 'HTTP') {
    httpEvents.push({ ...packet, ...metadata });
  } else if (app === 'TLS') {
    if (metadata.sni || metadata.ja3 || metadata.ja3s || metadata.ja4 || metadata.ja4s) {
      tlsEvents.push({ ...packet, ...metadata });
    } else {
      opaqueTlsEvents += 1;
    }
  } else if (app && app !== 'Other') {
    serviceEvents.push({ ...packet, ...metadata, app });
  }
  if (httpEvents.length > 500) httpEvents.shift();
  if (tlsEvents.length > 500) tlsEvents.shift();
  if (serviceEvents.length > 500) serviceEvents.shift();
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
document.querySelectorAll('.view-tab').forEach((tab) => tab.addEventListener('click', () => selectView(tab.dataset.view)));
selectView(location.hash.slice(1) || 'http');
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