let currentSearchResults = [];
let currentHistogram = [];
let currentBreakdowns = {};
let currentQuery = '';
let currentTimerange = '1h';

const searchForm = document.querySelector('#search-form');
const searchInput = document.querySelector('#search-input');
const timerangeSelect = document.querySelector('#timerange-select');
const btnClear = document.querySelector('#btn-clear');
const statusDot = document.querySelector('#status-dot');
const liveLabel = document.querySelector('#live-label');

// SSE stream for status dot indicator
const stream = new EventSource('/api/stream');
stream.addEventListener('status', (event) => {
  const status = JSON.parse(event.data);
  statusDot.classList.toggle('connected', status.running);
  liveLabel.textContent = status.running ? 'Live capture' : 'Capture unavailable';
});
stream.onerror = () => statusDot.classList.remove('connected');
window.addEventListener('beforeunload', () => stream.close());

function getStartTimeISO(range) {
  const now = Date.now();
  switch (range) {
    case '5m': return new Date(now - 5 * 60 * 1000).toISOString();
    case '15m': return new Date(now - 15 * 60 * 1000).toISOString();
    case '1h': return new Date(now - 60 * 60 * 1000).toISOString();
    case '24h': return new Date(now - 24 * 60 * 60 * 1000).toISOString();
    default: return null;
  }
}

const formatTime = (value) => new Date(value).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

async function executeSearch() {
  const query = searchInput.value.trim();
  const range = timerangeSelect.value;
  currentQuery = query;
  currentTimerange = range;

  // Sync to URL parameters
  const url = new URL(window.location);
  if (query) url.searchParams.set('q', query);
  else url.searchParams.delete('q');
  url.searchParams.set('timerange', range);
  window.history.replaceState({}, '', url);

  const startTime = getStartTimeISO(range);
  let apiUrl = `/api/forensics/search?q=${encodeURIComponent(query)}&limit=200`;
  if (startTime) apiUrl += `&startTime=${encodeURIComponent(startTime)}`;

  const tbody = document.querySelector('#forensics-table tbody');
  tbody.innerHTML = '<tr><td colspan="8" class="empty-state">Searching packets database...</td></tr>';

  try {
    const res = await fetch(apiUrl);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = await res.json();

    currentSearchResults = data.results || [];
    currentHistogram = data.histogram || [];
    currentBreakdowns = data.field_breakdowns || {};

    renderResults(data);
    renderHistogram();
    renderFieldsBreakdown();
  } catch (err) {
    console.error('Forensics search failed:', err);
    tbody.innerHTML = `<tr><td colspan="8" class="empty-state" style="color:var(--coral);">Search error: ${err.message}</td></tr>`;
  }
}

function renderResults(data) {
  const total = data.total_matches || 0;
  document.querySelector('#histogram-summary').textContent = `${total.toLocaleString()} MATCHING EVENTS`;
  document.querySelector('#results-count-label').textContent = `Showing ${currentSearchResults.length} of ${total.toLocaleString()} packets`;

  const tbody = document.querySelector('#forensics-table tbody');
  if (currentSearchResults.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No packets matched your query</td></tr>';
    return;
  }

  const rowsHtml = [];
  currentSearchResults.forEach((p, idx) => {
    const protoClass = `proto-${(p.protocol || 'other').toLowerCase()}`;
    const rowId = `event-row-${idx}`;
    const drawerId = `drawer-${idx}`;

    rowsHtml.push(`
      <tr class="event-summary-row" data-drawer="${drawerId}">
        <td class="toggle-cell">▶</td>
        <td>${formatTime(p.observed_at)}</td>
        <td><code>${p.source}</code></td>
        <td><code>${p.destination}</code></td>
        <td><span class="vpn-proto-pill">${p.protocol}</span></td>
        <td><code>${p.destination_port}</code></td>
        <td>${formatBytes(p.bytes)}</td>
        <td class="truncate-cell">${p.metadata || '—'}</td>
      </tr>
      <tr id="${drawerId}" class="event-drawer-row" style="display: none;">
        <td colspan="8">
          <div class="event-detail-box">
            <div class="detail-grid">
              <div><strong>ID:</strong> ${p.id}</div>
              <div><strong>Observed At:</strong> ${p.observed_at}</div>
              <div><strong>Source IP:</strong> ${p.source} <button type="button" class="btn-filter-add" data-filter="src:${p.source}">+ filter</button></div>
              <div><strong>Destination IP:</strong> ${p.destination} <button type="button" class="btn-filter-add" data-filter="dst:${p.destination}">+ filter</button></div>
              <div><strong>Source Port:</strong> ${p.source_port}</div>
              <div><strong>Destination Port:</strong> ${p.destination_port} <button type="button" class="btn-filter-add" data-filter="port:${p.destination_port}">+ filter</button></div>
              <div><strong>Protocol:</strong> ${p.protocol} <button type="button" class="btn-filter-add" data-filter="proto:${p.protocol}">+ filter</button></div>
              <div><strong>Payload Size:</strong> ${p.bytes} bytes</div>
            </div>
            <div class="raw-meta-box">
              <strong>Raw Metadata:</strong>
              <code>${p.metadata || 'No metadata payload'}</code>
            </div>
          </div>
        </td>
      </tr>
    `);
  });

  tbody.innerHTML = rowsHtml.join('');

  // Event drawer accordion listeners
  tbody.querySelectorAll('.event-summary-row').forEach(row => {
    row.addEventListener('click', (e) => {
      if (e.target.tagName === 'BUTTON') return;
      const drawerId = row.getAttribute('data-drawer');
      const drawer = document.getElementById(drawerId);
      const toggle = row.querySelector('.toggle-cell');
      if (drawer.style.display === 'none') {
        drawer.style.display = 'table-row';
        toggle.textContent = '▼';
        row.classList.add('expanded');
      } else {
        drawer.style.display = 'none';
        toggle.textContent = '▶';
        row.classList.remove('expanded');
      }
    });
  });

  // Filter button listeners inside drawers
  tbody.querySelectorAll('.btn-filter-add').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const filter = btn.getAttribute('data-filter');
      appendFilterToQuery(filter);
    });
  });
}

function appendFilterToQuery(filter) {
  const current = searchInput.value.trim();
  if (current) {
    if (!current.includes(filter)) searchInput.value = `${current} ${filter}`;
  } else {
    searchInput.value = filter;
  }
  executeSearch();
}

function renderFieldsBreakdown() {
  const container = document.querySelector('#fields-breakdown-list');
  const sections = [
    { key: 'sources', title: 'Source IP', filterKey: 'src' },
    { key: 'destinations', title: 'Destination IP', filterKey: 'dst' },
    { key: 'protocols', title: 'Protocol', filterKey: 'proto' },
    { key: 'ports', title: 'Destination Port', filterKey: 'port' },
  ];

  let html = '';
  sections.forEach(sec => {
    const items = currentBreakdowns[sec.key] || [];
    if (items.length > 0) {
      html += `<div class="field-group">
        <div class="field-group-title">${sec.title}</div>
        <div class="field-values-list">`;
      items.forEach(item => {
        const valStr = String(item.value);
        html += `<div class="field-value-item" data-filter="${sec.filterKey}:${valStr}">
          <span class="field-val-name">${valStr}</span>
          <span class="field-val-count">${item.count}</span>
        </div>`;
      });
      html += `</div></div>`;
    }
  });

  if (!html) {
    container.innerHTML = '<div class="empty-state">No fields to display</div>';
  } else {
    container.innerHTML = html;
    container.querySelectorAll('.field-value-item').forEach(item => {
      item.addEventListener('click', () => {
        const filter = item.getAttribute('data-filter');
        appendFilterToQuery(filter);
      });
    });
  }
}

function drawHistogram() {
  const chart = document.querySelector('#histogram-chart');
  if (!chart) return;
  const context = chart.getContext('2d');
  const width = chart.clientWidth;
  const height = chart.clientHeight;
  const scale = window.devicePixelRatio || 1;
  chart.width = width * scale;
  chart.height = height * scale;
  context.scale(scale, scale);
  context.clearRect(0, 0, width, height);

  if (currentHistogram.length === 0) {
    context.font = '12px "DM Mono", monospace';
    context.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--muted').trim() || '#70807a';
    context.textAlign = 'center';
    context.fillText('No time histogram data available for query', width / 2, height / 2);
    return;
  }

  const max = Math.max(...currentHistogram.map(h => h.count), 1);
  const padding = { top: 20, right: 20, bottom: 25, left: 45 };
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;

  const docStyle = getComputedStyle(document.documentElement);
  const colorTeal = docStyle.getPropertyValue('--teal').trim() || '#00e5a3';
  const colorMuted = docStyle.getPropertyValue('--muted').trim() || '#70807a';
  const colorLine = docStyle.getPropertyValue('--line').trim() || 'rgba(255,255,255,0.1)';

  // Grid lines & Y-axis labels
  context.font = '10px "DM Mono", monospace';
  context.fillStyle = colorMuted;
  context.textAlign = 'right';
  context.textBaseline = 'middle';
  [0, 0.5, 1].forEach(ratio => {
    const y = padding.top + plotHeight * (1 - ratio);
    const val = Math.round(max * ratio);
    context.fillText(val.toString(), padding.left - 8, y);
    context.strokeStyle = colorLine;
    context.beginPath();
    context.moveTo(padding.left, y);
    context.lineTo(width - padding.right, y);
    context.stroke();
  });

  // Render Histogram Bars
  const barWidth = Math.max(2, (plotWidth / currentHistogram.length) - 2);

  currentHistogram.forEach((h, i) => {
    const x = padding.left + i * (plotWidth / currentHistogram.length);
    const hHeight = (h.count / max) * plotHeight;
    const y = padding.top + plotHeight - hHeight;

    context.fillStyle = colorTeal;
    context.fillRect(x, y, barWidth, hHeight);
  });
}

function renderHistogram() {
  drawHistogram();
}

window.addEventListener('resize', () => drawHistogram());

// Event Listeners
searchForm.addEventListener('submit', (e) => {
  e.preventDefault();
  executeSearch();
});

btnClear.addEventListener('click', () => {
  searchInput.value = '';
  executeSearch();
});

document.querySelectorAll('.preset-chip').forEach(btn => {
  btn.addEventListener('click', () => {
    const query = btn.getAttribute('data-query');
    searchInput.value = query;
    executeSearch();
  });
});

// CSV Export Generator
document.querySelector('#btn-export-csv').addEventListener('click', () => {
  if (currentSearchResults.length === 0) return alert('No results to export!');
  const headers = ['id', 'observed_at', 'source', 'destination', 'protocol', 'source_port', 'destination_port', 'bytes', 'metadata'];
  const csvRows = [headers.join(',')];

  currentSearchResults.forEach(r => {
    const row = [
      r.id,
      `"${r.observed_at}"`,
      `"${r.source}"`,
      `"${r.destination}"`,
      `"${r.protocol}"`,
      r.source_port,
      r.destination_port,
      r.bytes,
      `"${(r.metadata || '').replace(/"/g, '""')}"`
    ];
    csvRows.push(row.join(','));
  });

  const blob = new Blob([csvRows.join('\n')], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `flowsight_forensics_${Date.now()}.csv`;
  a.click();
});

// JSON Export Generator
document.querySelector('#btn-export-json').addEventListener('click', () => {
  if (currentSearchResults.length === 0) return alert('No results to export!');
  const blob = new Blob([JSON.stringify(currentSearchResults, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `flowsight_forensics_${Date.now()}.json`;
  a.click();
});

// Initialization
function init() {
  const urlParams = new URLSearchParams(window.location.search);
  const q = urlParams.get('q');
  const timerange = urlParams.get('timerange');

  if (q) searchInput.value = q;
  if (timerange) timerangeSelect.value = timerange;

  executeSearch();
}

init();
