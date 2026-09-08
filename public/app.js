const packets = [];
const counts = {};
const startedAt = Date.now();
const maxRows = 80;
const trafficBuckets = Array.from({ length: 60 }, () => 0);
const bandwidthBuckets = Array.from({ length: 10 }, () => 0);
let renderQueued = false;

const elements = {
  statusDot: document.querySelector('#status-dot'), statusLabel: document.querySelector('#status-label'), captureLabel: document.querySelector('#capture-label'),
  packetCount: document.querySelector('#packet-count'), packetRate: document.querySelector('#packet-rate'), bandwidth: document.querySelector('#bandwidth'), bandwidthDetail: document.querySelector('#bandwidth-detail'), protocolCount: document.querySelector('#protocol-count'), topProtocol: document.querySelector('#top-protocol'), topShare: document.querySelector('#top-protocol-share'),
  protocolList: document.querySelector('#protocol-list'), flowTable: document.querySelector('#flow-table'), flowCount: document.querySelector('#flow-count'), captureMode: document.querySelector('#capture-mode'), interfaceLabel: document.querySelector('#interface-label')
};

const chart = document.querySelector('#traffic-chart');

function drawChart() {
  const context = chart.getContext('2d');
  const width = chart.clientWidth;
  const height = chart.clientHeight;
  const scale = window.devicePixelRatio || 1;
  chart.width = width * scale;
  chart.height = height * scale;
  context.scale(scale, scale);
  context.clearRect(0, 0, width, height);
  const maximum = Math.max(...trafficBuckets, 1);
  const padding = { top: 12, right: 8, bottom: 28, left: 34 };
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;
  context.font = '10px DM Mono, monospace';
  context.fillStyle = '#70807a';
  context.strokeStyle = '#d8e0d9';
  context.lineWidth = 1;
  for (let row = 0; row <= 3; row += 1) {
    const y = padding.top + plotHeight * row / 3;
    context.beginPath(); context.moveTo(padding.left, y); context.lineTo(width - padding.right, y); context.stroke();
    context.fillText(String(Math.round(maximum * (3 - row) / 3)), 0, y + 4);
  }
  context.fillText('60s ago', padding.left, height - 6);
  context.fillText('now', width - padding.right - 22, height - 6);
  context.beginPath();
  trafficBuckets.forEach((value, index) => {
    const x = padding.left + plotWidth * index / (trafficBuckets.length - 1);
    const y = padding.top + plotHeight * (1 - value / maximum);
    if (index === 0) context.moveTo(x, y); else context.lineTo(x, y);
  });
  context.lineTo(width - padding.right, padding.top + plotHeight);
  context.lineTo(padding.left, padding.top + plotHeight);
  context.closePath();
  context.fillStyle = '#1f82751c'; context.fill();
  context.beginPath();
  trafficBuckets.forEach((value, index) => {
    const x = padding.left + plotWidth * index / (trafficBuckets.length - 1);
    const y = padding.top + plotHeight * (1 - value / maximum);
    if (index === 0) context.moveTo(x, y); else context.lineTo(x, y);
  });
  context.strokeStyle = '#1f8275'; context.lineWidth = 2; context.stroke();
}

function formatTime(value) { return new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }); }

function render() {
  const total = packets.length;
  const ordered = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const rate = Math.round(total / Math.max((Date.now() - startedAt) / 60000, 1 / 60));
  elements.packetCount.textContent = total.toLocaleString(); elements.packetRate.textContent = `${rate.toLocaleString()} / min`;
  const bytesPerSecond = bandwidthBuckets.reduce((sum, bytes) => sum + bytes, 0) / bandwidthBuckets.length;
  elements.bandwidth.textContent = `${(bytesPerSecond * 8 / 1000000).toFixed(2)} Mbps`;
  elements.bandwidthDetail.textContent = `${(bytesPerSecond / 1000000).toFixed(2)} MB/s average`;
  elements.protocolCount.textContent = ordered.length; elements.flowCount.textContent = `${total} EVENTS`;
  if (ordered.length) { elements.topProtocol.textContent = ordered[0][0]; elements.topShare.textContent = `${Math.round(ordered[0][1] / total * 100)}% of captured traffic`; }
  const max = ordered[0]?.[1] || 1;
  elements.protocolList.innerHTML = ordered.length ? ordered.map(([name, count]) => `<div class="protocol-row"><div class="protocol-label"><span>${escapeHtml(name)}</span><strong>${count}</strong></div><div class="bar"><span style="width:${count / max * 100}%"></span></div><div class="protocol-meta"><span>share</span><span>${Math.round(count / total * 100)}%</span></div></div>`).join('') : '<p class="empty">Listening for protocol data...</p>';
  elements.flowTable.innerHTML = packets.slice(-maxRows).reverse().map((packet) => `<tr><td>${formatTime(packet.timestamp)}</td><td>${escapeHtml(packet.source)}${packet.sourcePort ? `:${Number(packet.sourcePort)}` : ''}</td><td>${escapeHtml(packet.destination)}${packet.destinationPort ? `:${Number(packet.destinationPort)}` : ''}</td><td><span class="protocol-pill">${escapeHtml(packet.protocol)}</span></td><td title="${escapeHtml(packet.metadata)}">${escapeHtml(packet.metadata)}</td></tr>`).join('') || '<tr><td colspan="5" class="empty">No packets captured yet.</td></tr>';
  drawChart();
}

function scheduleRender() {
  if (renderQueued) return;
  renderQueued = true;
  window.setTimeout(() => { renderQueued = false; render(); }, 150);
}

function addPacket(packet, observedAt = Date.now()) {
  packets.push(packet);
  if (packets.length > 500) packets.shift();
  counts[packet.protocol] = (counts[packet.protocol] || 0) + 1;
  const ageSeconds = Math.max(0, Math.floor((Date.now() - observedAt) / 1000));
  if (ageSeconds < trafficBuckets.length) trafficBuckets[trafficBuckets.length - 1 - ageSeconds] += 1;
  if (ageSeconds < bandwidthBuckets.length) bandwidthBuckets[bandwidthBuckets.length - 1 - ageSeconds] += packet.bytes || 0;
}

async function hydrateHistory() {
  try {
    const response = await fetch('/api/history?limit=500');
    const result = await response.json();
    for (const row of result.rows.reverse()) {
      addPacket({
        id: `history-${row.id}`,
        timestamp: row.observed_at,
        source: row.source,
        destination: row.destination,
        protocol: row.protocol,
        sourcePort: row.source_port,
        destinationPort: row.destination_port,
        bytes: row.bytes,
        metadata: row.metadata,
      }, new Date(row.observed_at).getTime());
    }
    render();
  } catch {
    // The live stream remains usable when history is unavailable.
  }
}

function setConnected(connected, error = '') { elements.statusDot.classList.toggle('connected', connected); elements.statusLabel.textContent = connected ? 'Live capture' : 'Capture unavailable'; elements.captureLabel.textContent = connected ? 'Receiving packet events' : (error || 'Start with capture permissions'); elements.captureMode.textContent = connected ? 'LIVE' : 'IDLE'; }

const stream = new EventSource('/api/stream');
stream.addEventListener('status', (event) => { const status = JSON.parse(event.data); setConnected(status.running, status.error); });
stream.addEventListener('packet', (event) => { const packet = JSON.parse(event.data); addPacket(packet); setConnected(true); scheduleRender(); });
stream.onerror = () => setConnected(false);
elements.interfaceLabel.textContent = `interface: ${new URLSearchParams(location.search).get('device') || 'any'}`;
window.addEventListener('resize', drawChart);
setInterval(() => { trafficBuckets.shift(); trafficBuckets.push(0); bandwidthBuckets.shift(); bandwidthBuckets.push(0); drawChart(); scheduleRender(); }, 1000);
render();
hydrateHistory();