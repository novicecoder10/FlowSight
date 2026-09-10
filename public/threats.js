const threats = [];
let renderQueued = false;
const stream = new EventSource('/api/stream');

stream.addEventListener('status', (event) => setCaptureStatus(JSON.parse(event.data)));
stream.onerror = () => setCaptureStatus('offline');

stream.addEventListener('threat', (event) => { 
  const threat = JSON.parse(event.data);
  addThreat(threat);
});
stream.onerror = () => setStatus(false);

function addThreat(threat) {
  threats.push(threat);
  if (threats.length > 500) threats.shift();
  scheduleRender();
}

const catMap = {
  'c2_communication': 'C2 Comms',
  'malware_fingerprint': 'Malware TLS',
  'reputation': 'Bad Reputation'
};

const formatTime = (value) => new Date(value).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
const cell = (value) => value || '--';

function render() {
  document.querySelector('#metric-total').textContent = threats.length;
  
  const critCount = threats.filter(t => (t.severity || '').toLowerCase() === 'critical').length;
  document.querySelector('#metric-critical').textContent = critCount;
  
  document.querySelector('#threat-tag').textContent = `${threats.length} DETECTED`;
  
  document.querySelector('#threat-table').innerHTML = threats.slice().reverse().map(t => {
    const sevClass = `severity-${(t.severity || 'low').toLowerCase()}`;
    const rowClass = `threat-row-${(t.severity || 'low').toLowerCase()}`;
    return `<tr class="${rowClass}">
      <td>${formatTime(t.timestamp)}</td>
      <td><span class="${sevClass}">${t.severity || 'Unknown'}</span></td>
      <td>${catMap[t.category] || t.category || '--'}</td>
      <td>${cell(t.source_ip)}</td>
      <td>${cell(t.destination_ip)}</td>
      <td>${cell(t.indicator)}</td>
      <td>${cell(t.malware)}</td>
      <td>${cell(t.feed)}</td>
    </tr>`;
  }).join('') || '<tr><td colspan="8" class="empty">No threats detected yet</td></tr>';
  
  drawChart();
}

function scheduleRender() {
  if (renderQueued) return;
  renderQueued = true;
  window.setTimeout(() => { renderQueued = false; render(); }, 150);
}

const chart = document.querySelector('#breakdown-chart');
function drawChart() {
  const context = chart.getContext('2d');
  const width = chart.clientWidth;
  const height = chart.clientHeight;
  const scale = window.devicePixelRatio || 1;
  chart.width = width * scale;
  chart.height = height * scale;
  context.scale(scale, scale);
  context.clearRect(0, 0, width, height);
  
  const malwareCounts = {};
  threats.forEach(t => {
    if (t.malware) {
      malwareCounts[t.malware] = (malwareCounts[t.malware] || 0) + 1;
    } else {
      malwareCounts['Unknown'] = (malwareCounts['Unknown'] || 0) + 1;
    }
  });
  
  const ordered = Object.entries(malwareCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);
  
  if (ordered.length === 0) {
    context.font = '12px "DM Mono", monospace';
    context.fillStyle = '#70807a';
    context.textAlign = 'center';
    context.fillText('No malware data yet', width / 2, height / 2);
    return;
  }
  
  const max = Math.max(...ordered.map(x => x[1]), 1);
  const padding = { top: 20, right: 40, bottom: 20, left: 120 };
  const plotWidth = width - padding.left - padding.right;
  const barHeight = 24;
  const gap = 16;
  
  context.font = '12px "DM Mono", monospace';
  
  const docStyle = getComputedStyle(document.documentElement);
  const colorInk = docStyle.getPropertyValue('--ink').trim() || '#1a1a1a';
  const colorTeal = docStyle.getPropertyValue('--teal').trim() || '#1f8275';
  
  ordered.forEach(([mw, count], i) => {
    const y = padding.top + i * (barHeight + gap);
    
    context.fillStyle = colorInk;
    context.textAlign = 'right';
    context.textBaseline = 'middle';
    context.fillText(mw, padding.left - 10, y + barHeight / 2);
    
    const barWidth = (count / max) * plotWidth;
    context.fillStyle = colorTeal;
    context.fillRect(padding.left, y, barWidth, barHeight);
    
    context.fillStyle = colorInk;
    context.textAlign = 'left';
    context.fillText(count.toString(), padding.left + barWidth + 8, y + barHeight / 2);
  });
}

window.addEventListener('resize', () => { if(threats.length) drawChart(); });

async function init() {
  try {
    const resp = await fetch('/api/threats?limit=200');
    if (resp.ok) {
      const data = await resp.json();
      const rows = data.rows || data;
      rows.forEach(t => {
         threats.push({
           id: t.id,
           timestamp: t.timestamp || t.observed_at,
           severity: t.severity,
           category: t.category,
           source_ip: t.source_ip,
           destination_ip: t.destination_ip,
           indicator: t.indicator,
           indicator_type: t.indicator_type,
           feed: t.feed,
           malware: t.malware,
           packet_id: t.packet_id
         });
      });
      if (threats.length > 500) threats.splice(0, threats.length - 500);
      scheduleRender();
    }
  } catch (e) {
    console.error("Failed to fetch threat history", e);
  }

  try {
    const resp = await fetch('/api/threat-feeds');
    if (resp.ok) {
      const feeds = await resp.json();
      let totalIndicators = 0;
      const html = feeds.map(f => {
        totalIndicators += (f.entry_count || 0);
        const age = Date.now() - new Date(f.last_updated).getTime();
        const isHealthy = age < 24 * 60 * 60 * 1000;
        const dotClass = isHealthy ? 'healthy' : 'stale';
        return `<div class="feed-row">
          <div class="feed-dot ${dotClass}"></div>
          <div class="feed-name">${f.feed_name}</div>
          <div class="feed-count">${(f.entry_count || 0).toLocaleString()} indicators</div>
          <div class="feed-time">Updated: ${new Date(f.last_updated).toLocaleString()}</div>
        </div>`;
      }).join('');
      document.querySelector('#feed-status').innerHTML = html;
      document.querySelector('#metric-feeds').textContent = feeds.length;
      document.querySelector('#metric-indicators').textContent = totalIndicators.toLocaleString();
    }
  } catch (e) {
    console.error("Failed to fetch threat feeds", e);
  }
}

init();
