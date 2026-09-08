const detections = [];
let statsData = null;
let renderQueued = false;

const statusDot = document.querySelector('#status-dot');
const liveLabel = document.querySelector('#live-label');
const stream = new EventSource('/api/stream');

function setStatus(connected, error = '') {
  statusDot.classList.toggle('connected', connected);
  liveLabel.textContent = connected ? 'Live capture' : (error || 'Capture unavailable');
}

stream.addEventListener('status', (event) => {
  const status = JSON.parse(event.data);
  setStatus(status.running, status.error);
});

stream.addEventListener('vpn_detection', (event) => {
  const item = JSON.parse(event.data);
  addDetection(item);
});

stream.onerror = () => setStatus(false);

function addDetection(item) {
  detections.push(item);
  if (detections.length > 300) detections.shift();
  scheduleRender();
}

const formatTime = (value) => new Date(value).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function scheduleRender() {
  if (renderQueued) return;
  renderQueued = true;
  window.setTimeout(() => {
    renderQueued = false;
    render();
  }, 150);
}

function render() {
  // Update Metrics
  const activeTunnelsCount = statsData?.active_sessions_count || new Set(detections.map(d => `${d.client_ip}:${d.server_ip}`)).size;
  document.querySelector('#val-active-tunnels').textContent = activeTunnelsCount;
  
  const totalCount = statsData?.total_detections || detections.length;
  document.querySelector('#val-total-detections').textContent = totalCount.toLocaleString();

  let topProto = '—';
  if (statsData?.by_protocol && statsData.by_protocol.length > 0) {
    topProto = statsData.by_protocol[0].vpn_type;
  } else if (detections.length > 0) {
    const counts = {};
    detections.forEach(d => counts[d.vpn_type] = (counts[d.vpn_type] || 0) + 1);
    topProto = Object.entries(counts).sort((a, b) => b[1] - a[1])[0][0];
  }
  document.querySelector('#val-top-protocol').textContent = topProto;

  const highConfCount = statsData?.by_confidence?.find(c => c.confidence === 'High')?.count || detections.filter(d => d.confidence === 'High').length;
  document.querySelector('#val-high-confidence').textContent = highConfCount.toLocaleString();

  // Table count tag
  document.querySelector('#vpn-count-tag').textContent = `${detections.length} DETECTED`;

  // Render Live Detections Table
  const tbody = document.querySelector('#vpn-table tbody');
  if (detections.length === 0) {
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No VPN traffic detected yet</td></tr>';
  } else {
    tbody.innerHTML = detections.slice().reverse().map(d => {
      const confClass = `vpn-conf-${(d.confidence || 'low').toLowerCase()}`;
      return `<tr>
        <td>${formatTime(d.timestamp || d.observed_at)}</td>
        <td><code>${d.client_ip}</code></td>
        <td><code>${d.server_ip}</code></td>
        <td><span class="vpn-proto-pill">${d.vpn_type}</span></td>
        <td><span class="vpn-conf-badge ${confClass}">${d.confidence}</span></td>
        <td><small class="vpn-method-tag">${d.detection_method}</small></td>
        <td>${formatBytes(d.bytes_transferred || d.bytes)}</td>
      </tr>`;
    }).join('');
  }

  // Render Top Clients & Servers
  renderTables();

  // Render Detection Methods Panel
  renderConfidencePanel();

  // Render Chart
  drawProtocolChart();
}

function renderTables() {
  const clientsTable = document.querySelector('#vpn-clients-table tbody');
  const topClients = statsData?.top_clients || [];
  if (topClients.length === 0) {
    clientsTable.innerHTML = '<tr><td colspan="3" class="empty-state">No active clients</td></tr>';
  } else {
    clientsTable.innerHTML = topClients.map(c => `<tr>
      <td><code>${c.client_ip}</code></td>
      <td>${c.detections}</td>
      <td>${formatBytes(c.bytes)}</td>
    </tr>`).join('');
  }

  const serversTable = document.querySelector('#vpn-servers-table tbody');
  const topServers = statsData?.top_servers || [];
  if (topServers.length === 0) {
    serversTable.innerHTML = '<tr><td colspan="3" class="empty-state">No active servers</td></tr>';
  } else {
    serversTable.innerHTML = topServers.map(s => `<tr>
      <td><code>${s.server_ip}</code></td>
      <td><span class="vpn-proto-pill">${s.vpn_type}</span></td>
      <td>${s.detections}</td>
    </tr>`).join('');
  }
}

function renderConfidencePanel() {
  const panel = document.querySelector('#vpn-confidence-panel');
  const confData = statsData?.by_confidence || [];
  if (confData.length === 0) {
    panel.innerHTML = '<div class="empty-state">No confidence stats yet</div>';
    return;
  }
  const total = confData.reduce((acc, c) => acc + c.count, 0) || 1;
  panel.innerHTML = confData.map(c => {
    const pct = Math.round((c.count / total) * 100);
    const confClass = `vpn-conf-${c.confidence.toLowerCase()}`;
    return `<div class="feed-row" style="padding: 10px 16px;">
      <span class="vpn-conf-badge ${confClass}">${c.confidence}</span>
      <span class="feed-name" style="margin-left: 8px;">${c.confidence} Confidence Signatures</span>
      <span class="feed-count">${c.count} (${pct}%)</span>
    </div>`;
  }).join('');
}

function drawProtocolChart() {
  const chart = document.querySelector('#vpn-protocol-chart');
  if (!chart) return;
  const context = chart.getContext('2d');
  const width = chart.clientWidth;
  const height = chart.clientHeight;
  const scale = window.devicePixelRatio || 1;
  chart.width = width * scale;
  chart.height = height * scale;
  context.scale(scale, scale);
  context.clearRect(0, 0, width, height);

  const byProto = statsData?.by_protocol || [];
  if (byProto.length === 0) {
    context.font = '12px "DM Mono", monospace';
    context.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--muted').trim() || '#70807a';
    context.textAlign = 'center';
    context.fillText('No VPN protocol data available yet', width / 2, height / 2);
    return;
  }

  const docStyle = getComputedStyle(document.documentElement);
  const colorInk = docStyle.getPropertyValue('--ink').trim() || '#1a1a1a';
  const colorTeal = docStyle.getPropertyValue('--teal').trim() || '#00e5a3';
  const colorMuted = docStyle.getPropertyValue('--muted').trim() || '#70807a';

  const items = byProto.slice(0, 6);
  const max = Math.max(...items.map(x => x.count), 1);
  const padding = { top: 20, right: 60, bottom: 20, left: 140 };
  const plotWidth = width - padding.left - padding.right;
  const barHeight = 22;
  const gap = 14;

  context.font = '12px "DM Mono", monospace';

  items.forEach((item, i) => {
    const y = padding.top + i * (barHeight + gap);

    // Label
    context.fillStyle = colorInk;
    context.textAlign = 'right';
    context.textBaseline = 'middle';
    context.fillText(item.vpn_type, padding.left - 12, y + barHeight / 2);

    // Bar background
    context.fillStyle = 'rgba(255,255,255,0.05)';
    context.fillRect(padding.left, y, plotWidth, barHeight);

    // Bar fill
    const barWidth = (item.count / max) * plotWidth;
    context.fillStyle = colorTeal;
    context.fillRect(padding.left, y, barWidth, barHeight);

    // Count text
    context.fillStyle = colorInk;
    context.textAlign = 'left';
    context.fillText(`${item.count} (${formatBytes(item.bytes)})`, padding.left + barWidth + 10, y + barHeight / 2);
  });
}

window.addEventListener('resize', () => drawProtocolChart());

async function fetchStats() {
  try {
    const res = await fetch('/api/vpn/stats');
    if (res.ok) {
      statsData = await res.json();
      scheduleRender();
    }
  } catch (e) {
    console.error('Failed to fetch VPN stats:', e);
  }
}

async function init() {
  try {
    const res = await fetch('/api/vpn/detections?limit=150');
    if (res.ok) {
      const data = await res.json();
      const rows = data.detections || [];
      rows.forEach(item => {
        detections.push({
          id: item.id,
          timestamp: item.observed_at || item.timestamp,
          client_ip: item.client_ip,
          server_ip: item.server_ip,
          vpn_type: item.vpn_type,
          confidence: item.confidence,
          detection_method: item.detection_method,
          bytes_transferred: item.bytes_transferred,
          packet_id: item.packet_id
        });
      });
      scheduleRender();
    }
  } catch (e) {
    console.error('Failed to fetch VPN detections:', e);
  }

  await fetchStats();
  setInterval(fetchStats, 5000);
}

init();
